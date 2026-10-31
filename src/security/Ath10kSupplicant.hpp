#pragma once
#include "Ath10kLegacyCryptoCheck.hpp"
#include "Ath10kSecurity.hpp"
#include "Ath10kSHA256.hpp"
#include "Ath10kTransitionDisable.hpp"
#include "Ath10kWPA1KeyData.hpp"
namespace AthSecurity {
// Crypto supplies HMAC-SHA1 and AES-128-ECB decrypt; SHA256 mode additionally
// requires HMAC-SHA256 and AES-128-ECB encrypt.
// RSN/PSK descriptor 2; opt-in PSK-SHA256 descriptor 3; separately opt-in SAE
// descriptor 0 from verified SAE or separately opt-in OWE-derived PMK.
// OWE group19 uses HMAC-SHA256-128 MIC, not SAE AES-CMAC.
// SHA256 mode requires CCMP group/pairwise and an AP not requiring PMF.
// Ordinary EAP AKM1 is separately opt-in and requires an OS-supplied PMK.
// Pairwise TKIP requires a separate explicit opt-in. SAE stages IGTK delivery; firmware PMF protection/key
// acknowledgement and replay counters remain caller responsibilities.
// Retransmitted M3 returns cached M4; never asks the driver to reinstall a key.
template<class Crypto,bool AllowSHA256=false,bool AllowSAE=false,bool AllowEAP=false,bool AllowTKIP=false,bool AllowWPA1=false,bool AllowOWE=false> class Supplicant {
 uint8_t pmk[32]{},ptk[64]{},snonce[32]{},anonce[32]{},local[6]{},ap[6]{};
 uint8_t apRSN[257]{},savedM3[512]{},m2[160]{},m4[128]{};
 size_t rsnLength=0,savedLength=0,m2Length=0,m4Length=0;
 uint64_t replay1=0,replay3=0,requestReplay=0;
 unsigned state=0;uint8_t selectedAKM=2,pairCipher=cipherCCMP;bool sha256=false,sae=false,owe=false,protectedManagement=false,havePMKID=false,wpa1=false,wpa1GroupReady=false;
 uint8_t saePMKID[16]{};
 uint8_t apRSNXE[18]{},apRSNXELength=0;bool rsnxeBound=false,saeH2E=false;
 TransitionDisableUpdate pendingTransitionDisable{};
 void recordTransitionDisable(const uint8_t *bitmap,size_t bytes,uint64_t replay){
  // Accumulate restrictions until the owner consumes them: a later weaker
  // update must not erase an authenticated, still-pending restriction.
  for(size_t i=0;i<bytes;++i)pendingTransitionDisable.bitmap[i]|=bitmap[i];
  if(bytes>pendingTransitionDisable.length)pendingTransitionDisable.length=uint8_t(bytes);
  copy(pendingTransitionDisable.station,local,6);copy(pendingTransitionDisable.bssid,ap,6);
  pendingTransitionDisable.replay=replay;
 }
 IGTKCMAC128 rememberedIGTK[2]{};bool rememberedIGTKValid[2]{};
 struct ManagementCandidate {
  IGTKCMAC128 key{};bool present=false,changed=false;
  ~ManagementCandidate(){wipe(&key,sizeof(key));}
 };
 uint8_t descriptor() const {return pairCipher==cipherTKIP?1:((sae || owe)?0:(sha256?3:2));}
 bool readManagement(const uint8_t *element,size_t bytes,ManagementCandidate &candidate){
  if(candidate.present)return false;
  candidate.present=true;
  if(!parseIGTKCMAC128(element,bytes,candidate.key))return false;
  candidate.changed=true;
  for(unsigned i=0;i<2;++i)if(rememberedIGTKValid[i] && equal(rememberedIGTK[i].key,candidate.key.key,16)){
   if(i!=candidate.key.keyID-4u)return false;candidate.changed=false;
  }
  return true;
 }
 void commitManagement(const ManagementCandidate &candidate){
  if(!candidate.present)return;
  auto &slot=rememberedIGTK[candidate.key.keyID-4];
  if(candidate.changed){slot=candidate.key;rememberedIGTKValid[candidate.key.keyID-4]=true;managementKey=candidate.key;}
  else if(candidate.key.ipn>slot.ipn)slot.ipn=candidate.key.ipn;
 }
 uint8_t establishedPTK[64]{},establishedANonce[32]{},establishedSNonce[32]{},currentGTK[32]{};
 uint8_t rememberedGTK[4][32]{};bool rememberedGTKValid[4]{};
 // Return -1 for reuse under another index, 1 for the existing slot, 0 for
 // new material. Retaining old slots prevents A -> B -> A reinstall requests.
 int knownGTK(const uint8_t *key,uint8_t index,size_t bytes) const {
  for(unsigned i=0;i<4;++i)if(rememberedGTKValid[i] && equal(rememberedGTK[i],key,bytes))return i==index?1:-1;
  return 0;
 }
 void rememberGTK(const uint8_t *key,uint8_t index,size_t bytes){
  wipe(rememberedGTK[index],32);copy(rememberedGTK[index],key,bytes);rememberedGTKValid[index]=true;
 }
 uint8_t savedGroup[512]{},groupAck[128]{};size_t savedGroupLength=0,groupAckLength=0;
 uint64_t groupReplay=0;uint8_t currentGTKIndex=0,groupCipher=0;bool pairRekey=false;
 bool derive(){
  uint8_t context[76]{};
  auto less=[](const uint8_t *a,const uint8_t *b,size_t n){for(size_t i=0;i<n;++i){if(a[i]!=b[i])return a[i]<b[i];}return false;};
  bool swap=less(local,ap,6);copy(context,swap?local:ap,6);copy(context+6,swap?ap:local,6);
  swap=less(snonce,anonce,32);copy(context+12,swap?snonce:anonce,32);copy(context+44,swap?anonce:snonce,32);
  if constexpr(AllowSHA256 || AllowSAE || AllowOWE){if(sha256){
   bool ok=SHA256Personal<Crypto>::derive(pmk,context,ptk);
   wipe(context,sizeof(context));return ok;
  }}
  bool ok=deriveSHA1PTK<Crypto>(pmk,context,ptk,pairCipher==cipherTKIP?64:48,sizeof(ptk));
  wipe(context,sizeof(context));return ok;
 }

 bool mic(uint8_t *p,size_t n){
  if constexpr(AllowOWE){if(owe){uint8_t digest[32]{};bool ok=Crypto::hmac256(ptk,16,p,n,digest);if(ok)copy(p+81,digest,16);wipe(digest,sizeof(digest));return ok;}}

  if constexpr(AllowTKIP || AllowWPA1){if((be16(p+5)&7)==1){uint8_t digest[16]{};bool ok=Crypto::hmacMD5(ptk,16,p,n,digest);if(ok)copy(p+81,digest,16);wipe(digest,16);return ok;}}
  if constexpr(AllowSHA256 || AllowSAE || AllowOWE){if(sha256){uint8_t digest[16]{};bool ok=SHA256Personal<Crypto>::mic(ptk,p,n,digest);if(ok)copy(p+81,digest,16);wipe(digest,16);return ok;}}
  uint8_t digest[20]{};bool ok=Crypto::hmac(ptk,16,p,n,digest);if(ok)copy(p+81,digest,16);wipe(digest,20);return ok;}
 size_t response(uint8_t *frame,const uint8_t *request,bool second,bool group=false){
  uint8_t station[47]{};size_t rsnBytes=0;
  if(second){
   if(!copyAssociationRSN(station,sizeof(station),rsnBytes))return 0;
   if(rsnxeBound){size_t extra=0;if(!copyAssociationRSNXE(station+rsnBytes,sizeof(station)-rsnBytes,extra))return 0;rsnBytes+=extra;}
  }
  size_t n=99+(second?rsnBytes:0);wipe(frame,n+14);copy(frame,ap,6);copy(frame+6,local,6);frame[12]=0x88;frame[13]=0x8e;
  uint8_t *p=frame+14;p[0]=request[0];p[1]=3;put16(p+2,uint16_t(n-4));p[4]=wpa1?254:2;
  uint16_t flags=second?0x0108:(group?0x0300:0x0308);
  if(wpa1){
   if(!second && !group)flags=uint16_t(0x0108|(be16(request+5)&0x200));
   if(group)flags|=be16(request+5)&0x30;
   copy(p+7,request+7,2);
  }
  put16(p+5,uint16_t(flags|(wpa1?(be16(request+5)&7):descriptor())));copy(p+9,request+9,8);
  if(second){copy(p+17,snonce,32);put16(p+97,uint16_t(rsnBytes));copy(p+99,station,rsnBytes);}
  return mic(p,n)?n+14:0;
 }
 bool unwrap(const uint8_t *in,size_t n,uint8_t *out,const uint8_t *iv,bool forceAES=false){
  if constexpr(AllowTKIP || AllowWPA1){if(pairCipher==cipherTKIP && !forceAES)return decryptWPA1KeyData(iv,ptk+16,in,n,out,384);}
  if(n<24||n>392||n%8)return false;
  uint8_t a[8],b[16],dec[16];copy(a,in,8);copy(out,in+8,n-8);size_t blocks=n/8-1;
  bool ok=true;
  for(int j=5;j>=0 && ok;--j)for(size_t i=blocks;i>0;--i){
   copy(b,a,8);uint64_t t=blocks*unsigned(j)+i;for(unsigned k=0;k<8;++k)b[7-k]^=uint8_t(t>>(8*k));
   copy(b+8,out+8*(i-1),8);if(!Crypto::decrypt(ptk+16,b,dec)){ok=false;break;}
   copy(a,dec,8);copy(out+8*(i-1),dec+8,8);
  }
  for(uint8_t c:a)if(c!=0xa6)ok=false;
  wipe(a,8);wipe(b,16);wipe(dec,16);if(!ok)wipe(out,n-8);return ok;
 }
public:
 enum Result { Ignore, Reply, Keys, Fatal, GroupKeys, PairKeys, ManagementKeys, InitialPairKeys, InitialGroupKeys };
 enum Change : uint8_t { PTKChanged=1,GTKChanged=2,IGTKChanged=4 };
 static constexpr size_t keyPayloadLength=72;
 // TK[16], GTK[32], group cipher[1], index[1], RSC[6], TKIP MIC keys[16].
 // MIC keys retain authenticator order here; firmware adapter swaps once.
 uint8_t output[160]{},keys[keyPayloadLength]{};size_t outputLength=0;
 // Last successful key-result payload only. Reply/Ignore never request installs.
 IGTKCMAC128 managementKey{};uint8_t keyChanges=0;
 const char *error="none";
 uint8_t pairwiseCipher() const {return pairCipher;}
 bool pairwisePending() const {return pairRekey && state==2;}
 // Only the owning authenticated SAE profile can consume this once. No
 // native message number or persistent macOS profile update is implied.
 bool takeTransitionDisable(const uint8_t *station,const uint8_t *bssid,TransitionDisableUpdate &out){
  out={};
  if(!protectedManagement || state!=3 || !station || !bssid || !pendingTransitionDisable.length ||
     !equal(station,local,6) || !equal(bssid,ap,6))return false;
  out=pendingTransitionDisable;wipe(&pendingTransitionDisable,sizeof(pendingTransitionDisable));return true;
 }
 // Replace only Enterprise master material between completed exchanges. The
 // caller must drain exported replies/firmware work before invoking this; this
 // crypto object cannot acknowledge transport ownership. Preserve replay floors,
 // installed-key history and cached retransmission responses until a new M3.
 bool replaceEAPMaster(const uint8_t *master,const uint8_t *station,const uint8_t *bssid){
  if(!AllowEAP || (selectedAKM!=1 && selectedAKM!=5) || state!=3 || pairRekey || (wpa1 && !wpa1GroupReady) || !master ||
     !station || !bssid || !equal(station,local,6) || !equal(bssid,ap,6))return false;
  copy(pmk,master,32);return true;
 }
 void cancelPairwiseAttempt(){
  if(!pairwisePending())return;
  copy(ptk,establishedPTK,sizeof(ptk));copy(anonce,establishedANonce,32);copy(snonce,establishedSNonce,32);
  pairRekey=false;state=3;outputLength=0;
  wipe(output,sizeof(output));wipe(m2,sizeof(m2));m2Length=0;
 }
 ~Supplicant(){reset();}
 void reset(){wipe(this,sizeof(*this));error="none";}
 bool begin(const uint8_t *master,const uint8_t *nonce,const uint8_t *station,const uint8_t *bssid,const uint8_t *rsn,size_t n,uint8_t akm=2,
     const uint8_t *pmkid=nullptr,size_t idBytes=0,uint8_t pair=cipherCCMP){
  reset();if(!master || !nonce || !station || !bssid)return false;
  if(akm==8){
   if(pair!=cipherCCMP || !AllowSAE || !validSAEPersonalRSN(rsn,n) || (idBytes && (idBytes!=16 || !pmkid)))return false;
  }else if(akm==5){
   if(!AllowEAP || !AllowSHA256 || pair!=cipherCCMP || idBytes || !validEAPSHA256RSN(rsn,n))return false;
  }else if(akm==18){
   if(!AllowOWE || pair!=cipherCCMP || idBytes || !validOWEPersonalRSN(rsn,n))return false;
  }else if(idBytes || (akm==1 && !AllowEAP) || (akm==6 && !AllowSHA256) ||
      !supportsSelectedRSN(rsn,n,akm,pair,AllowTKIP))return false;
  if constexpr(AllowTKIP){if(pair==cipherTKIP && !legacyHMACReady<Crypto>())return false;}
  pairCipher=pair;selectedAKM=akm;sae=akm==8;owe=akm==18;sha256=akm==5 || akm==6 || sae || owe;protectedManagement=sae || owe || akm==5;
  if(sae && idBytes){copy(saePMKID,pmkid,16);havePMKID=true;}
  RSNInfo selected{};if(!parseRSN(rsn,n,selected))return false;groupCipher=selected.group;
  copy(pmk,master,32);copy(snonce,nonce,32);copy(local,station,6);copy(ap,bssid,6);copy(apRSN,rsn,n);rsnLength=n;state=1;return true;
 }
 // WPA1 has a separate authenticated initial GTK exchange after M4. The
 // caller must not authorize the port on InitialPairKeys/M4 completion alone.
 bool beginWPA1(const uint8_t *master,const uint8_t *nonce,const uint8_t *station,const uint8_t *bssid,
     const uint8_t *ie,size_t bytes,uint8_t akm=2,uint8_t pair=cipherTKIP){
  reset();WPAInfo apInfo{};uint8_t selected[24]{};size_t selectedBytes=0;
  if(!AllowWPA1 || !master || !nonce || !station || !bssid || (akm==1 && !AllowEAP) ||
     !parseWPA(ie,bytes,apInfo) || !buildWPA1StationIE(ie,bytes,pair,akm,selected,sizeof(selected),selectedBytes))return false;
  if constexpr(AllowWPA1){if(!legacyHMACReady<Crypto>())return false;}
  wpa1=true;pairCipher=pair;groupCipher=apInfo.group;selectedAKM=akm;
  copy(pmk,master,32);copy(snonce,nonce,32);copy(local,station,6);copy(ap,bssid,6);
  copy(apRSN,ie,bytes);rsnLength=bytes;state=1;return true;
 }
 bool awaitingInitialGroup()const{return wpa1 && !wpa1GroupReady;}
 // Bind a native caller's AP snapshot once, before M1. Generic software
 // users that do not model RSNXE keep their existing explicit unbound behavior.
 bool bindRSNXE(const uint8_t *ie,size_t bytes,bool h2e){
  if(wpa1 || state!=1 || rsnxeBound || (h2e && !sae) || bytes>sizeof(apRSNXE) ||
     (bytes && !validRSNXE(ie,bytes)) || (h2e && !rsnxeHasH2E(ie,bytes)))return false;
  if(bytes)copy(apRSNXE,ie,bytes);apRSNXELength=uint8_t(bytes);saeH2E=h2e;rsnxeBound=true;return true;
 }
 bool copyAssociationRSNXE(uint8_t *out,size_t capacity,size_t &bytes) const {
  bytes=0;if(!state || !rsnxeBound || !out)return false;
  if(!saeH2E)return true;
  if(capacity<3)return false;out[0]=244;out[1]=1;out[2]=0x20;bytes=3;return true;
 }
 // Public RSNE/PMKID only; no PMK/PTK is exported. The same encoder serves
 // association and EAPOL M2 so profile changes cannot silently diverge them.
 bool copyAssociationRSN(uint8_t *out,size_t capacity,size_t &bytes) const {
  bytes=0;if(!state || !out)return false;
  if(wpa1)return buildWPA1StationIE(apRSN,rsnLength,pairCipher,selectedAKM,out,capacity,bytes);
  if constexpr(AllowEAP && AllowSHA256){if(selectedAKM==5)return buildEAPSHA256StationRSN(out,capacity,bytes);}
  if constexpr(AllowOWE){if(owe)return buildOWEStationRSN(out,capacity,bytes);}
  if constexpr(AllowSAE){if(sae)return buildSAEStationRSN(saePMKID,havePMKID?16:0,out,capacity,bytes);}
  return buildSelectedStationRSN(groupCipher,pairCipher,selectedAKM,out,capacity,bytes);
 }
 Result fail(const char *reason){error=reason;return Fatal;}
 Result receive(const uint8_t *frame,size_t length){
  outputLength=0;
  if(!frame||!state||length<113||length>512||!equal(frame,local,6)||!equal(frame+6,ap,6)||frame[12]!=0x88||frame[13]!=0x8e)return Ignore;
  const uint8_t *p=frame+14;size_t n=size_t(be16(p+2))+4;
  if((p[0]<1 || p[0]>3)||p[1]!=3||p[4]!=(wpa1?254:2)||n<99||n>length-14||size_t(be16(p+97))+99!=n)return Ignore;
  uint16_t info=be16(p+5);const auto version=info&7;
  if(wpa1){
   if(version!=1 && version!=2)return Ignore;
   if(pairCipher==cipherCCMP && version!=2 && ((info&8) || groupCipher==cipherCCMP))return Ignore;
  }else if(version!=descriptor())return Ignore;
  info=uint16_t((info&~7u)|2u);uint64_t replay=be64(p+9);
  if(info==0x008a){
   if(wpa1 && state>=3 && !wpa1GroupReady)return Ignore;
   if(be16(p+7)!=(pairCipher==cipherTKIP?32:16))return Ignore;
   uint8_t nz=0;for(unsigned i=0;i<32;++i)nz|=p[17+i];if(!nz)return Ignore;
   if(state>=3){
    if(replay<=replay3 || replay<=groupReplay || equal(p+17,anonce,32))return Ignore;
    // M1 is unauthenticated. Retain the established keys until a valid M3;
    // a timed-out candidate can be discarded without tearing down the link.
    if(!Crypto::random(snonce,32))return fail("Falha ao gerar nonce de renovação.");
    copy(anonce,p+17,32);if(!derive())return fail("Falha na derivação da nova PTK.");
    pairRekey=true;state=2;
   }
   if(state==2 && (replay<replay1 || !equal(p+17,anonce,32)))return Ignore;
   if(state==1){copy(anonce,p+17,32);if(!derive())return fail("Falha na derivação da PTK.");}
   replay1=replay;m2Length=response(m2,p,true);if(!m2Length)return fail("Falha no MIC da mensagem 2.");
   copy(output,m2,m2Length);outputLength=m2Length;state=2;return Reply;
  }
  if(wpa1)return receiveWPA1AfterM1(p,n,info,replay);
  if(state>=3 && info==0x1382){
   if(replay<groupReplay || replay<=replay3)return Ignore;
   if(replay==groupReplay){
    if(n!=savedGroupLength || !equal(p,savedGroup,n))return Ignore;
    copy(output,groupAck,groupAckLength);outputLength=groupAckLength;return Reply;
   }
   uint8_t check[512]{},plain[384]{},candidate[keyPayloadLength]{};ManagementCandidate management;
   copy(check,p,n);wipe(check+81,16);
   bool verified=mic(check,n) && equal(check+81,p+81,16);wipe(check,sizeof(check));
   if(!verified)return Ignore;
   size_t encrypted=be16(p+97);
   if(!unwrap(p+99,encrypted,plain,p+49)){wipe(plain,sizeof(plain));return fail("GTK de renovação inválida.");}
   size_t bytes=encrypted-(pairCipher==cipherTKIP?0:8),at=0;bool haveGTK=false,haveRSNXE=false,valid=true;
   copy(candidate+50,p+65,6);candidate[48]=groupCipher;
   while(at<bytes){
    if(plain[at]==221 && (at+1==bytes || plain[at+1]==0)){
     for(size_t j=at+1;j<bytes;++j)if(plain[j])valid=false;
     break;
    }
    if(bytes-at<2 || size_t(plain[at+1])+2>bytes-at){valid=false;break;}
    size_t len=size_t(plain[at+1])+2;
    if(plain[at]==48 && (len!=rsnLength || !equal(plain+at,apRSN,len)))valid=false;
    if(plain[at]==244){
     if(rsnxeBound && (haveRSNXE || len!=apRSNXELength || !equal(plain+at,apRSNXE,len)))valid=false;
     haveRSNXE=true;
    }
    if(plain[at]==221 && len>=6 && suite(plain+at+2,1)){
     const size_t gtkBytes=groupCipher==cipherTKIP?32:16;
     if(haveGTK || len!=8+gtkBytes || (plain[at+6]&0xf8) || plain[at+7])valid=false;
     else {candidate[49]=plain[at+6]&3;copy(candidate+16,plain+at+8,gtkBytes);}haveGTK=true;
    }
    if constexpr(AllowSAE || AllowOWE || AllowEAP){if(protectedManagement && plain[at]==221 && len>=6 && suite(plain+at+2,9))
     if(!readManagement(plain+at,len,management))valid=false;
    }
    at+=len;
   }
   if(!valid || (!haveGTK && !(protectedManagement && management.present))){wipe(candidate,sizeof(candidate));wipe(plain,sizeof(plain));return fail("KDE de GTK/IGTK inválida.");}
   const size_t gtkBytes=groupCipher==cipherTKIP?32:16;
   const int known=haveGTK?knownGTK(candidate+16,candidate[49],gtkBytes):1;
   const bool sameKey=known==1;
   if(known<0){wipe(candidate,sizeof(candidate));wipe(plain,sizeof(plain));return fail("GTK reutilizada em outro índice.");}
   groupAckLength=response(groupAck,p,false,true);
   if(!groupAckLength){wipe(candidate,sizeof(candidate));wipe(plain,sizeof(plain));return fail("Falha no MIC de renovação GTK.");}
   copy(savedGroup,p,n);savedGroupLength=n;groupReplay=replay;
   copy(output,groupAck,groupAckLength);outputLength=groupAckLength;
   if(!sameKey){copy(keys,candidate,keyPayloadLength);rememberGTK(candidate+16,candidate[49],gtkBytes);}
   if(haveGTK){copy(currentGTK,candidate+16,gtkBytes);currentGTKIndex=candidate[49];}
   const uint8_t changes=uint8_t((sameKey?0:GTKChanged)|(management.changed?IGTKChanged:0));
   commitManagement(management);if(changes)keyChanges=changes;
   wipe(candidate,sizeof(candidate));wipe(plain,sizeof(plain));
   return !sameKey?GroupKeys:(management.changed?ManagementKeys:Reply);
  }
  if(info!=0x13ca){
   // Unsupported descriptors cannot trigger key replacement.
   return Ignore;
  }
  if(state<2 || be16(p+7)!=(pairCipher==cipherTKIP?32:16) || !equal(p+17,anonce,32))return Ignore;
  if(state>=3){
   if(replay==replay3 && n==savedLength && equal(p,savedM3,n)){
    copy(output,m4,m4Length);outputLength=m4Length;return Reply;
   }
   // Authenticators may increment replay on a retry. Verify its MIC and
   // identical encrypted key data/RSC; acknowledge without reinstalling keys.
   if(replay>replay3 && n==savedLength && equal(p+65,savedM3+65,8) && equal(p+97,savedM3+97,n-97)){
    uint8_t check[512]{};copy(check,p,n);wipe(check+81,16);
    bool verified=mic(check,n) && equal(check+81,p+81,16);wipe(check,sizeof(check));
    if(verified){m4Length=response(m4,p,false);if(!m4Length)return fail("Falha no MIC da resposta repetida.");
     replay3=replay;copy(savedM3,p,n);copy(output,m4,m4Length);outputLength=m4Length;return Reply;}
   }
   return Ignore;
  }
  if(replay<=replay1)return Ignore;
  uint8_t check[512]{},plain[384]{};copy(check,p,n);wipe(check+81,16);
  if(!mic(check,n)){wipe(check,sizeof(check));return fail("Falha criptográfica.");}
  bool verified=equal(check+81,p+81,16);wipe(check,sizeof(check));
  if(!verified)return pairRekey?Ignore:fail("MIC inválido: confira a senha da rede.");
  size_t encrypted=be16(p+97);
  if(!unwrap(p+99,encrypted,plain,p+49)){wipe(plain,sizeof(plain));return fail("Dados de chave inválidos.");}
  size_t bytes=encrypted-(pairCipher==cipherTKIP?0:8),at=0,transitionOffset=0,transitionBytes=0;
  bool haveRSN=false,haveGTK=false,haveRSNXE=false,haveTransitionDisable=false,valid=true;
  uint8_t candidate[keyPayloadLength]{};ManagementCandidate management;
  copy(candidate,ptk+32,16);if(pairCipher==cipherTKIP)copy(candidate+56,ptk+48,16);copy(candidate+50,p+65,6);candidate[48]=groupCipher;
  while(at<bytes){
   if(plain[at]==221 && (at+1==bytes || plain[at+1]==0)){
    for(size_t j=at+1;j<bytes;++j)if(plain[j])valid=false;
    break;
   }
   if(bytes-at<2||size_t(plain[at+1])+2>bytes-at){valid=false;break;}
   size_t len=plain[at+1]+2;
   if(plain[at]==48){if(haveRSN||len!=rsnLength||!equal(plain+at,apRSN,len))valid=false;haveRSN=true;}
   if(plain[at]==244){
    if(rsnxeBound && (haveRSNXE || len!=apRSNXELength || !equal(plain+at,apRSNXE,len)))valid=false;
    haveRSNXE=true;
   }
   if(plain[at]==221 && len>=6 && suite(plain+at+2,1)){
    const size_t gtkBytes=groupCipher==cipherTKIP?32:16;
    if(haveGTK||len!=8+gtkBytes||(plain[at+6]&0xf8)||plain[at+7])valid=false;
    else {candidate[49]=plain[at+6]&3;copy(candidate+16,plain+at+8,gtkBytes);}haveGTK=true;
   }
   if constexpr(AllowSAE || AllowOWE || AllowEAP){if(protectedManagement && plain[at]==221 && len>=6 && suite(plain+at+2,9))
    if(!readManagement(plain+at,len,management))valid=false;
   }
   if constexpr(AllowSAE || AllowOWE || AllowEAP){if(protectedManagement && transitionDisableSelector(plain+at,len)){
    if(haveTransitionDisable || len<7)valid=false;
    haveTransitionDisable=true;transitionOffset=at+6;transitionBytes=len-6;
   }}
   at+=len;
  }
  if(rsnxeBound && bool(apRSNXELength)!=haveRSNXE)valid=false;
  if(protectedManagement && pairRekey && !haveGTK){copy(candidate+16,currentGTK,16);candidate[49]=currentGTKIndex;}
  if(!valid || !haveRSN || (!haveGTK && !(protectedManagement && pairRekey)) || (protectedManagement && !pairRekey && !management.present)){
   wipe(candidate,sizeof(candidate));wipe(plain,sizeof(plain));return fail("RSN ou GTK/IGTK inválida na mensagem 3.");
  }
  const int known=knownGTK(candidate+16,candidate[49],groupCipher==cipherTKIP?32:16);
  const bool gtkChanged=known==0;
  if(known<0){wipe(candidate,sizeof(candidate));wipe(plain,sizeof(plain));return fail("GTK reutilizada em outro índice.");}
  m4Length=response(m4,p,false);
  if(!m4Length){wipe(candidate,sizeof(candidate));wipe(plain,sizeof(plain));return fail("Falha no MIC da mensagem 4.");}
  // Publish a complete key transaction only after its acknowledgement is ready.
  // MIC, unwrap, RSN/RSNXE, GTK/IGTK and M4 generation all precede policy.
  // Cached/replayed M3 and group-key messages never enter this publication.
  if(protectedManagement && haveTransitionDisable)recordTransitionDisable(plain+transitionOffset,transitionBytes,replay);
  copy(keys,candidate,sizeof(keys));wipe(candidate,sizeof(candidate));wipe(plain,sizeof(plain));
  keyChanges=uint8_t(PTKChanged|(gtkChanged?GTKChanged:0)|(management.changed?IGTKChanged:0));commitManagement(management);
  copy(savedM3,p,n);savedLength=n;replay3=replay;state=3;
  const bool wasRekey=pairRekey;
  copy(establishedPTK,ptk,sizeof(ptk));copy(establishedANonce,anonce,32);copy(establishedSNonce,snonce,32);
  rememberGTK(keys+16,keys[49],groupCipher==cipherTKIP?32:16);
  copy(currentGTK,keys+16,groupCipher==cipherTKIP?32:16);currentGTKIndex=keys[49];pairRekey=false;
  copy(output,m4,m4Length);outputLength=m4Length;return wasRekey?PairKeys:Keys;
 }
 // Generate a qualified pairwise/group Michael error report for an RSN profile.
 // Caller must establish firmware key readiness and qualify the RX failure;
 // generating this packet neither sends it nor enforces countermeasures.
 // Keep its TX ownership separate from output/cached handshake responses.
 bool buildMICFailureReport(uint8_t *frame,size_t capacity,size_t &bytes,bool pairwise,uint8_t version=2){
  bytes=0;
  if(!frame || capacity<113 || version<1 || version>3 || (pairwise?pairCipher:groupCipher)!=cipherTKIP ||
     sha256 || (state!=3 && !pairRekey) || requestReplay==~uint64_t(0))return false;
  struct Temporary {uint8_t frame[113]{},digest[20]{};~Temporary(){wipe(this,sizeof(*this));}} t;
  copy(t.frame,ap,6);copy(t.frame+6,local,6);t.frame[12]=0x88;t.frame[13]=0x8e;
  uint8_t *p=t.frame+14;p[0]=version;p[1]=3;put16(p+2,95);p[4]=wpa1?254:2;
  // REQUEST | ERROR | SECURE | MIC, selected descriptor and failure type.
  put16(p+5,uint16_t(0x0f00|descriptor()|(pairwise?8:0)));
  for(unsigned i=0;i<8;++i)p[9+i]=uint8_t(requestReplay>>(56-8*i));
  bool ok=false;
  if constexpr(AllowTKIP || AllowWPA1){if(pairCipher==cipherTKIP)ok=Crypto::hmacMD5(establishedPTK,16,p,99,t.digest);
   else ok=Crypto::hmac(establishedPTK,16,p,99,t.digest);}
  else ok=Crypto::hmac(establishedPTK,16,p,99,t.digest);
  if(!ok)return false;
  copy(p+81,t.digest,16);copy(frame,t.frame,sizeof(t.frame));
  ++requestReplay;bytes=sizeof(t.frame);return true;
 }
 bool buildGroupMICFailureReport(uint8_t *frame,size_t capacity,size_t &bytes,uint8_t version=2){return buildMICFailureReport(frame,capacity,bytes,false,version);}
private:
 Result receiveWPA1AfterM1(const uint8_t *p,size_t n,uint16_t info,uint64_t replay){
  const size_t keyBytes=groupCipher==cipherTKIP?32:16;
  // ACK/MIC group message; index, TX/RX and SECURE are the only optional bits.
  if(state==3 && (info&~uint16_t(0x270))==0x182){
   if(replay<groupReplay || replay<=replay3)return Ignore;
   if(replay==groupReplay){
    if(n!=savedGroupLength || !equal(p,savedGroup,n))return Ignore;
    copy(output,groupAck,groupAckLength);outputLength=groupAckLength;return Reply;
   }
   const size_t encrypted=be16(p+97);const unsigned version=be16(p+5)&7;
   if(be16(p+7)!=keyBytes || p[71] || p[72] ||
      (version==1?(encrypted<keyBytes || encrypted>32):(encrypted<keyBytes+8 || encrypted>40 || encrypted%8)))return Ignore;
   struct Temporary {uint8_t check[512]{},plain[384]{},candidate[keyPayloadLength]{};~Temporary(){wipe(this,sizeof(*this));}} t;
   copy(t.check,p,n);wipe(t.check+81,16);
   if(!mic(t.check,n) || !equal(t.check+81,p+81,16))return Ignore;
   const bool decoded=version==1?decryptWPA1KeyData(p+49,ptk+16,p+99,encrypted,t.plain,sizeof(t.plain)):
       unwrap(p+99,encrypted,t.plain,p+49,true);
   if(!decoded)return fail("Invalid WPA1 GTK encryption.");
   const uint8_t index=uint8_t((info>>4)&3);const int known=knownGTK(t.plain,index,keyBytes);
   if(known<0)return fail("WPA1 GTK reused at another index.");
   groupAckLength=response(groupAck,p,false,true);if(!groupAckLength)return fail("WPA1 group acknowledgement MIC failed.");
   copy(t.candidate+16,t.plain,keyBytes);t.candidate[48]=groupCipher;t.candidate[49]=index;copy(t.candidate+50,p+65,6);
   const bool initial=!wpa1GroupReady;
   if(known==0){copy(keys,t.candidate,sizeof(keys));rememberGTK(t.plain,index,keyBytes);}
   copy(currentGTK,t.plain,keyBytes);currentGTKIndex=index;
   groupReplay=replay;copy(savedGroup,p,n);savedGroupLength=n;wpa1GroupReady=true;
   keyChanges=known==0?GTKChanged:0;
   copy(output,groupAck,groupAckLength);outputLength=groupAckLength;
   return initial?InitialGroupKeys:(known==0?GroupKeys:Reply);
  }
  // WPA1 M3 key data is authenticated plaintext IE data, not an RSN wrapped KDE.
  if((info&~uint16_t(0x200))!=0x1ca || state<2 ||
     be16(p+7)!=(pairCipher==cipherTKIP?32:16) || !equal(p+17,anonce,32))return Ignore;
  if(state==3){
   if(replay==replay3 && n==savedLength && equal(p,savedM3,n)){
    copy(output,m4,m4Length);outputLength=m4Length;return Reply;
   }
   if(replay<=replay3 || replay<=groupReplay || n!=savedLength ||
      !equal(p+65,savedM3+65,8) || !equal(p+97,savedM3+97,n-97))return Ignore;
  }else if(replay<=replay1)return Ignore;
  struct Temporary {uint8_t check[512]{},candidate[keyPayloadLength]{};~Temporary(){wipe(this,sizeof(*this));}} t;
  copy(t.check,p,n);wipe(t.check+81,16);
  if(!mic(t.check,n) || !equal(t.check+81,p+81,16))return Ignore;
  bool haveWPA=false;size_t at=99;
  while(at<n){
   if(n-at<2 || size_t(p[at+1])+2>n-at)return fail("Malformed WPA1 M3 IE.");
   const size_t bytes=size_t(p[at+1])+2;
   if(p[at]==221 && bytes>=6 && wpaSuiteType(p+at+2)==1){
    if(haveWPA || bytes!=rsnLength || !equal(p+at,apRSN,bytes))return fail("WPA1 M3 IE mismatch.");
    haveWPA=true;
   }
   at+=bytes;
  }
  if(!haveWPA)return fail("Missing WPA1 M3 IE.");
  m4Length=response(m4,p,false);if(!m4Length)return fail("WPA1 M4 MIC failed.");
  const bool retry=state==3,wasRekey=pairRekey;
  copy(savedM3,p,n);savedLength=n;replay3=replay;
  copy(output,m4,m4Length);outputLength=m4Length;
  if(retry)return Reply;
  copy(t.candidate,ptk+32,16);if(pairCipher==cipherTKIP)copy(t.candidate+56,ptk+48,16);
  copy(t.candidate+16,currentGTK,keyBytes);t.candidate[48]=groupCipher;t.candidate[49]=currentGTKIndex;
  copy(keys,t.candidate,sizeof(keys));keyChanges=PTKChanged;
  copy(establishedPTK,ptk,sizeof(ptk));copy(establishedANonce,anonce,32);copy(establishedSNonce,snonce,32);
  state=3;pairRekey=false;return wasRekey?PairKeys:InitialPairKeys;
 }
 // PMK is retained only for the live session to permit pairwise rekey.
 // reset()/destruction wipe every key, nonce and cached handshake frame.
};
}

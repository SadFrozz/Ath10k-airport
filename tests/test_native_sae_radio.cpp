#define ATH10K_NATIVE_KEY_STAGE_TEST
#define ATH10K_NATIVE_REAL_SAE
#include "test_native_pmf_receive.cpp"
#include "sae_eapol_vectors.inc"
#include "rsnxe_eapol_vectors.inc"
#include "p256_corecrypto_fixtures.hpp"
#include "h2e_password_vectors.inc"
#include "legacy_password_vectors.inc"
#include <dlfcn.h>
#include <cstdio>
using API=AthSecurity::P256CoreCryptoAPI;
static API api;
static uint8_t pwe[64]{},randomScalar[32]{},mask[32]{};
static AthSecurity::SAEGroup19AuthMessage request;
struct HMAC {static bool hmac256(const uint8_t *k,size_t kl,const uint8_t *d,size_t n,uint8_t *o){CCHmac(kCCHmacAlgSHA256,k,kl,d,n,o);return true;}};
static std::vector<uint8_t> apFrame(const AthSecurity::SAEGroup19AuthMessage &m){
 std::vector<uint8_t> f(1536);f[0]=0xb0;memcpy(f.data()+4,w_sta,6);memcpy(f.data()+10,w_ap,6);memcpy(f.data()+16,w_ap,6);
 size_t n=0;assert(AthSecurity::encodeSAEGroup19AuthBody(m,f.data()+24,f.size()-24,n));f.resize(n+24);return f;
}
static Ath10kPCIDevice *device(){
 nativeSAEClockMS=0;auto d=new Ath10kPCIDevice;auto &s=d->_connection;
 s.ssidLength=4;memcpy(s.ssid,"TEST",4);s.ap.ssidLength=4;memcpy(s.ap.ssid,s.ssid,4);
 s.ap.privacy=s.ap.rsnPresent=s.ap.ratesValid=true;s.ap.capabilities=0x11;s.ap.beaconInterval=100;
 s.ap.rateCount=4;const uint8_t rates[]={0x82,0x84,0x8b,0x96};memcpy(s.ap.rates,rates,4);
 s.ap.rxChannel=s.ap.advertisedChannel=s.operatingChannel=s.centerChannel=6;
 assert(!Ath10k::configureRegulatory(s.regulatory,0x64,2300,3000,4800,5925));
 s.stage=Ath10k::LinkStage::Auth;s.securityAKM=8;s.secure=s.pmfRequired=s.pmfQoSTransported=true;s.groupCipher=4;
 memcpy(s.local,w_sta,6);memcpy(s.bssid,w_ap,6);memcpy(s.ap.bssid,w_ap,6);memcpy(s.ap.rsn,w_rsn,sizeof(w_rsn));s.ap.rsnLength=sizeof(w_rsn);
 d->_nativeJoinPending=true;for(auto &q:d->_wmiRadio)q.completed=q.txConsumed=q.creditReturned=true;
 auto sec=d->_nativeSecurity=new Ath10kPCIDevice::NativeSecurity;assert(sec->prepareSAEWorker());
 sec->saeSession=new Ath10kSAESession;assert(sec->saeSession->initPrepared(api,randomScalar,32,pwe,64,request,w_sta,w_ap,301,0));
 sec->saeRadio=new Ath10kSAERadio;assert(sec->saeRadio->bind(sec->saeSession,sec->saeWorker,301,0));
 sec->pmfSession=new Ath10kPMFSession;assert(sec->pmfSession->initConnection(w_sta,w_ap,301));return d;
}
static const char *tick(Ath10kPCIDevice *d,uint64_t now){nativeSAEClockMS=now;ownerGate=true;const auto e=d->serviceNativeSAE(now);ownerGate=false;return e;}
static void retired(Ath10kPCIDevice *d){d->_connection.txOwned=false;d->_connection.txComplete=true;d->_connection.txStatus=0;}
static unsigned passwordRandomCalls=0;
static bool passwordRandom(uint8_t *out,size_t n){
 assert(!ownerGate && !heldLocks && n && n<=64);memset(out,0,n);out[n-1]=uint8_t(passwordRandomCalls++%2?3:7);return true;
}
static std::vector<uint8_t> unhex(const char *text){
 std::vector<uint8_t> out(strlen(text)/2);for(size_t i=0;i<out.size();++i){unsigned v=0;assert(sscanf(text+2*i,"%2x",&v)==1);out[i]=uint8_t(v);}return out;
}
static void passwordPreparationTests(const AthSecurity::P256FieldAPI &field){
 for(bool h2e:{false,true}){
  const auto &hv=H2EPasswordVectors::vectors[2];const auto &lv=LegacyPasswordVectors::vectors[1];
  auto name=h2e?unhex(hv.ssid):unhex("746573742d73736964");auto password=unhex(h2e?hv.password:lv.password);
  auto expectedPWE=unhex(h2e?hv.pwe:lv.pwe),expectedCommit=unhex(h2e?hv.commit:lv.commit);
  for(unsigned scenario=0;scenario<9;++scenario){auto d=device();auto sec=d->_nativeSecurity;auto &s=d->_connection;
   // An admitted join has PMF/worker ownership, but no radio or prepared session yet.
   sec->saeRadio->cancel();delete sec->saeRadio;sec->saeRadio=nullptr;sec->saeSession->release();sec->saeSession=nullptr;
   s.ssidLength=s.ap.ssidLength=uint8_t(name.size());memcpy(s.ssid,name.data(),name.size());memcpy(s.ap.ssid,name.data(),name.size());
   if(h2e){memcpy(s.ap.rsnxe,x_rsnxe,sizeof(x_rsnxe));s.ap.rsnxeLength=sizeof(x_rsnxe);}
   AirportWCL::JoinRequest join{};join.lowerAuth=1;join.upperAuth=1u<<12;join.keyCipher=10;
   join.ssidLength=s.ssidLength;memcpy(join.ssid,s.ssid,s.ssidLength);memcpy(join.bssid,s.bssid,6);
   join.keyLength=uint32_t(password.size());memcpy(join.key,password.data(),password.size());passwordRandomCalls=0;
   ownerGate=true;assert(sec->saePreparation.begin(sec->saeWorker,join,s.ap,api,field,passwordRandom,s.local,301,0));ownerGate=false;
   memset(&join,0,sizeof(join)); // Native progress must not retain the caller's request.
   ownerGate=true;assert(!d->advanceSAEAuth(0));ownerGate=false;
   assert(sec->saePreparation.active() && !sec->saeRadio && !sec->saeSession && d->transmitted.empty() && !s.authReply);
   if(scenario){
    if(scenario==1)s.ap.rsn[20]^=1;
    if(scenario==2)s.cancelRequested=true;
    if(scenario==3)d->_nativeRadioOn=false;
    if(scenario==4)s.bssid[5]^=1;
    if(scenario==5){sec->pmfSession->cancel();sec->pmfSession->release();sec->pmfSession=new Ath10kPMFSession;assert(sec->pmfSession->initConnection(w_sta,w_ap,302));}
    if(scenario==6)d->blocked=true;
    if(scenario==7){run(latest);s.ssid[0]^=1;} // Completed work cannot bypass current-profile validation.
    // Fail through the real common Auth caller, which resets retained owners.
    ownerGate=true;assert(!d->advanceSAEAuth(scenario==8?5000:1));ownerGate=false;assert(s.cancelRequested && d->saeDiscards==1);
    assert(!sec->saePreparation.active() && !sec->saeRadio && !sec->saeSession && d->transmitted.empty());stop(d);continue;
   }
   run(latest);assert(!tick(d,1));assert(!sec->saePreparation.active() && sec->saeRadio && sec->saeSession);
   assert(sec->saeSession->usingH2E()==h2e && d->transmitted.size()==1 && !s.authReply && !sec->ready);
   AthSecurity::SAEGroup19AuthMessage localCommit;auto &wire=d->transmitted[0];
   assert(AthSecurity::decodeSAEGroup19AuthBody(wire.data()+24,wire.size()-24,h2e,0,localCommit)==AthSecurity::SAEWireResult::Valid);
   assert(!memcmp(localCommit.commit,expectedCommit.data(),96));
   AthSecurity::P256CoreCryptoCandidate engine(api);AthSecurity::P256CoreCryptoWorkspace workspace;
   uint8_t peerRandom[32]{},peerMask[32]{};peerRandom[31]=11;peerMask[31]=5;auto remote=localCommit;
   assert(AthSecurity::saeGroup19Commit(engine,peerRandom,peerMask,32,expectedPWE.data(),64,remote.commit,96,workspace));
   AthSecurity::SAEGroup19Keys peerKeys{};
   assert(AthSecurity::saeGroup19ExchangeCandidate<HMAC>(engine,peerRandom,32,remote.commit,96,localCommit.commit,96,expectedPWE.data(),64,h2e,w_ap,w_sta,nullptr,0,nullptr,0,peerKeys,workspace));
   retired(d);nativeSAEClockMS=2;const auto peerWire=apFrame(remote);assert(deliver(d,peerWire.data(),peerWire.size()));
   assert(!tick(d,2));run(latest);assert(!tick(d,3));run(latest);assert(!tick(d,4) && d->transmitted.size()==2);
   AthSecurity::SAEGroup19AuthMessage remoteConfirm{};remoteConfirm.kind=AthSecurity::SAEAuthKind::Confirm;remoteConfirm.h2e=h2e;remoteConfirm.confirm[0]=1;
   assert(AthSecurity::saeGroup19Confirm<HMAC>(peerKeys.kck,32,1,remote.commit,96,localCommit.commit,96,remoteConfirm.confirm+2,32));
   const auto confirmWire=apFrame(remoteConfirm);nativeSAEClockMS=5;assert(deliver(d,confirmWire.data(),confirmWire.size()));
   assert(!tick(d,5));run(latest);assert(!tick(d,6) && !sec->ready && !s.authReply);retired(d);
   assert(!tick(d,7) && sec->ready && s.authReply);using S=AthSecurity::Supplicant<Ath10kKernelCrypto,true,true>;
   assert(sec->supplicant.receive(w_m1,sizeof(w_m1))==S::Reply);
   // The M2 MIC must use this freshly authenticated peer PMK, not the old fixture PMK.
   uint8_t context[76]{},ptk[48]{},mic[16]{};memcpy(context,w_sta,6);memcpy(context+6,w_ap,6);
   const uint8_t *nonce=sec->supplicant.output+31,*anonce=w_m1+31;
   const bool first=memcmp(nonce,anonce,32)<0;memcpy(context+12,first?nonce:anonce,32);memcpy(context+44,first?anonce:nonce,32);
   assert(AthSecurity::SHA256Personal<PersonalTestCrypto>::derive(peerKeys.pmk,context,ptk));
   auto eapol=std::vector<uint8_t>(sec->supplicant.output+14,sec->supplicant.output+sec->supplicant.outputLength);
   memset(eapol.data()+81,0,16);assert(AthSecurity::SHA256Personal<PersonalTestCrypto>::mic(ptk,eapol.data(),eapol.size(),mic));
   assert(!memcmp(mic,sec->supplicant.output+95,16));AthSecurity::wipe(ptk,sizeof(ptk));AthSecurity::wipe(&peerKeys,sizeof(peerKeys));stop(d);
  }
 }
}
int main(){
 void *lib=dlopen("/usr/lib/system/libcorecrypto.dylib",RTLD_NOW|RTLD_LOCAL);assert(lib);
#define LOAD(field,name) api.field=reinterpret_cast<decltype(api.field)>(dlsym(lib,name));assert(api.field)
 LOAD(curve,"ccec_cp_256");LOAD(importPoint,"ccec_x963_import_pub");LOAD(validatePoint,"ccec_validate_pub");LOAD(exportPoint,"ccec_x963_export");
 LOAD(project,"ccec_projectify");LOAD(affine,"ccec_affinify");LOAD(multiply,"ccec_mult_blinded");LOAD(add,"ccec_full_add");
 LOAD(subtract,"ccec_full_sub");LOAD(readScalar,"ccn_read_uint");LOAD(rng,"ccrng");
#undef LOAD
 for(unsigned i=0;i<64;++i){unsigned v=0;assert(sscanf(P256Fixtures::generator+2*i,"%2x",&v)==1);pwe[i]=uint8_t(v);}
 randomScalar[31]=7;mask[31]=3;AthSecurity::P256CoreCryptoCandidate engine(api);AthSecurity::P256CoreCryptoWorkspace workspace;
 request.kind=AthSecurity::SAEAuthKind::Commit;request.h2e=false;
 assert(AthSecurity::saeGroup19Commit(engine,randomScalar,mask,32,pwe,64,request.commit,96,workspace));
 uint8_t peerRandom[32]{},peerMask[32]{};peerRandom[31]=11;peerMask[31]=5;
 auto peer=request;assert(AthSecurity::saeGroup19Commit(engine,peerRandom,peerMask,32,pwe,64,peer.commit,96,workspace));
 AthSecurity::SAEGroup19Keys keys;assert(AthSecurity::saeGroup19ExchangeCandidate<HMAC>(engine,peerRandom,32,peer.commit,96,request.commit,96,pwe,64,true,w_ap,w_sta,nullptr,0,nullptr,0,keys,workspace));
 AthSecurity::SAEGroup19AuthMessage confirmation{};confirmation.kind=AthSecurity::SAEAuthKind::Confirm;confirmation.h2e=false;confirmation.confirm[0]=1;
 assert(AthSecurity::saeGroup19Confirm<HMAC>(keys.kck,32,1,peer.commit,96,request.commit,96,confirmation.confirm+2,32));
 const auto peerWire=apFrame(peer),confirmWire=apFrame(confirmation);
 {auto d=device();auto sec=d->_nativeSecurity;
  auto open=std::vector<uint8_t>(30);open[0]=0xb0;memcpy(open.data()+4,w_sta,6);memcpy(open.data()+10,w_ap,6);memcpy(open.data()+16,w_ap,6);open[26]=2;
  assert(deliver(d,open.data(),open.size()) && !d->_connection.authReply);
  ownerGate=true;assert(!d->advanceSAEAuth(0));ownerGate=false;
  assert(d->transmitted.size()==1 && d->transmitted[0][24]==3 && d->transmitted[0][26]==1);
  assert(!d->_connection.authReply && !sec->ready);retired(d);
  nativeSAEClockMS=1;assert(deliver(d,peerWire.data(),peerWire.size()));assert(!tick(d,1));run(latest);
  assert(!tick(d,2));run(latest);d->_wmiScan.completed=false;
  assert(!tick(d,3) && d->transmitted.size()==1);d->_wmiScan.completed=true;
  assert(!tick(d,4) && d->transmitted.size()==2 && d->transmitted[1][26]==2);
  nativeSAEClockMS=5;assert(deliver(d,confirmWire.data(),confirmWire.size()));assert(!tick(d,5));run(latest);
  assert(!tick(d,6) && !d->_connection.authReply && !sec->ready); // HTT/CE ownership remains live.
  d->_connection.txComplete=true;assert(!tick(d,7) && !d->_connection.authReply);
  retired(d);nativeSAEClockMS=8;ownerGate=true;assert(d->advanceSAEAuth(8));ownerGate=false;
  assert(d->_connection.authReply && sec->ready);
  uint8_t association[256]{};auto &s=d->_connection;
  assert(!Ath10k::buildStationManagement(association,sizeof(association),s));
  Ath10k::CandidateConfiguration candidate;assert(!Ath10k::prepareBSSCandidate(s,s.ap,candidate));
  auto transition=s.ap;std::vector<uint8_t> mixed(w_rsn,w_rsn+sizeof(w_rsn));
  mixed.insert(mixed.begin()+16,{0,15,172,2});mixed[14]=2;mixed[1]=uint8_t(mixed.size()-2);
  memcpy(transition.rsn,mixed.data(),mixed.size());transition.rsnLength=uint16_t(mixed.size());
  assert(!Ath10k::prepareBSSCandidate(s,transition,candidate) && s.securityAKM==8);
  s.pmfRequired=false;assert(Ath10k::prepareBSSCandidate(s,transition,candidate));s.pmfRequired=true;
  auto badAP=s.ap;memcpy(badAP.rsn,AthSecurity::stationRSN,sizeof(AthSecurity::stationRSN));badAP.rsnLength=sizeof(AthSecurity::stationRSN);
  assert(Ath10k::prepareBSSCandidate(s,badAP,candidate));
  s.stage=Ath10k::LinkStage::Assoc;assert(!Ath10k::buildStationManagement(association,sizeof(association),s));
  assert(d->buildNativeSAEAssociation(association,sizeof(association)));
  d->_nativeRadioOn=false;assert(!d->buildNativeSAEAssociation(association,sizeof(association)));d->_nativeRadioOn=true;
  d->_networkEnabled=false;assert(!d->buildNativeSAEAssociation(association,sizeof(association)));d->_networkEnabled=true;
  const auto associationBytes=d->buildNativeSAEAssociation(association,sizeof(association));
  size_t rsnAt=0;for(size_t at=28;at<associationBytes;at+=size_t(association[at+1])+2)if(association[at]==48)rsnAt=at;
  assert(rsnAt && association[rsnAt+1]==42 && AthSecurity::validSAEStationRSN(association+rsnAt,44));
  uint8_t station[44]{};size_t stationBytes=0;assert(sec->supplicant.copyAssociationRSN(station,sizeof(station),stationBytes));
  assert(stationBytes==44 && !memcmp(station,association+rsnAt,44) && !memcmp(station+24,w_pmkid,16));
  auto malformed=std::array<uint8_t,44>{};memcpy(malformed.data(),station,44);malformed[20]=0x80;
  assert(!Ath10k::buildStationManagement(association,sizeof(association),s,malformed.data(),malformed.size()));
  s.pmfRequired=false;assert(!d->buildNativeSAEAssociation(association,sizeof(association)));s.pmfRequired=true;
  std::vector<uint8_t> response(30);response[0]=0x10;memcpy(response.data()+4,w_sta,6);memcpy(response.data()+10,w_ap,6);memcpy(response.data()+16,w_ap,6);response[28]=1;
  auto invalid=response;invalid.insert(invalid.end(),AthSecurity::stationRSN,AthSecurity::stationRSN+sizeof(AthSecurity::stationRSN));
  Ath10k::receiveStationManagement(s,invalid.data(),invalid.size(),0,6);assert(!s.assocReply);
  response.insert(response.end(),w_rsn,w_rsn+sizeof(w_rsn));
  Ath10k::receiveStationManagement(s,response.data(),response.size(),0,6);assert(s.assocReply);
  // PSK-SHA256 response validation follows AKM6 instead of a hard-coded PSK2.
  auto sha=s;sha.securityAKM=6;sha.pmfRequired=false;sha.assocReply=false;
  auto shaResponse=std::vector<uint8_t>(response.begin(),response.begin()+30);
  auto pskResponse=shaResponse;pskResponse.insert(pskResponse.end(),AthSecurity::stationRSN,AthSecurity::stationRSN+sizeof(AthSecurity::stationRSN));
  Ath10k::receiveStationManagement(sha,pskResponse.data(),pskResponse.size(),0,6);assert(!sha.assocReply);
  shaResponse.insert(shaResponse.end(),AthSecurity::stationRSNSHA256,AthSecurity::stationRSNSHA256+sizeof(AthSecurity::stationRSNSHA256));
  Ath10k::receiveStationManagement(sha,shaResponse.data(),shaResponse.size(),0,6);assert(sha.assocReply);
  using S=AthSecurity::Supplicant<Ath10kKernelCrypto,true,true>;
  assert(sec->supplicant.receive(w_m1,sizeof(w_m1))==S::Reply);
  assert(sec->supplicant.outputLength==157 && !memcmp(sec->supplicant.output+113,station,44));
  assert(sec->supplicant.receive(w_m3,sizeof(w_m3))==S::Keys && !memcmp(sec->supplicant.keys,w_ptk+32,16));stop(d);
 }
 {auto d=device();d->_nativeJoinPending=false;ownerGate=true;assert(!d->advanceSAEAuth(0));ownerGate=false;
  assert(d->saeDiscards==1 && d->_connection.cancelRequested && !d->_nativeSecurity->saeRadio && !d->_nativeSecurity->saeSession);stop(d);}
 {auto d=device();d->_connection.securityAKM=2;ownerGate=true;assert(d->advanceSAEAuth(0));ownerGate=false;
  assert(d->transmitted.empty() && !d->saeDiscards);stop(d);}
 {auto d=device();d->blocked=true;assert(tick(d,0) && d->transmitted.empty() && !d->_connection.authReply);stop(d);}
 {auto d=device();auto sec=d->_nativeSecurity;sec->pmfSession->cancel();assert(tick(d,0) && d->transmitted.empty());stop(d);}
 {auto d=device();d->failSubmit=true;assert(tick(d,0) && d->transmitted.empty() && !d->_nativeSecurity->ready);stop(d);}
 {auto d=device();d->_connection.cancelRequested=true;assert(tick(d,0) && d->transmitted.empty());stop(d);}
 // Native H2E binds the accepted SAE mode to the scanned AP extension,
 // emits it in association/M2, and authenticates the AP's M3 snapshot.
 request.h2e=true;auto hPeer=peer;hPeer.h2e=true;auto hConfirm=confirmation;hConfirm.h2e=true;
 const auto hPeerWire=apFrame(hPeer),hConfirmWire=apFrame(hConfirm);
 {auto d=device();assert(tick(d,0) && d->transmitted.empty());stop(d);} // AP never advertised H2E.
 for(bool mismatch : {false,true}){auto d=device();auto sec=d->_nativeSecurity;auto &s=d->_connection;
  memcpy(s.ap.rsnxe,x_rsnxe,sizeof(x_rsnxe));s.ap.rsnxeLength=sizeof(x_rsnxe);
  assert(!tick(d,0) && d->transmitted[0][28]==126);retired(d);
  nativeSAEClockMS=1;assert(deliver(d,hPeerWire.data(),hPeerWire.size()));assert(!tick(d,1));run(latest);
  assert(!tick(d,2));run(latest);assert(!tick(d,3));
  nativeSAEClockMS=4;assert(deliver(d,hConfirmWire.data(),hConfirmWire.size()));assert(!tick(d,4));run(latest);
  retired(d);assert(!tick(d,5) && sec->ready && s.authReply);
  s.stage=Ath10k::LinkStage::Assoc;uint8_t assoc[256]{};const auto n=d->buildNativeSAEAssociation(assoc,sizeof(assoc));
  assert(n>3 && !memcmp(assoc+n-3,x_rsnxe,3));
  using S=AthSecurity::Supplicant<Ath10kKernelCrypto,true,true>;
  assert(sec->supplicant.receive(w_m1,sizeof(w_m1))==S::Reply && sec->supplicant.outputLength==160);
  assert(!memcmp(sec->supplicant.output,x_m2,sizeof(x_m2)));
  s.stage=Ath10k::LinkStage::Connected;ownerGate=true;assert(d->nativeAcceptSecurityResult(S::Reply));ownerGate=false;
  assert(sec->replyLength==160 && !memcmp(sec->reply,x_m2,160));sec->replyPending=false;
  const auto result=sec->supplicant.receive(mismatch?x_changed_m3:x_m3,mismatch?sizeof(x_changed_m3):sizeof(x_m3));
  assert(result==(mismatch?S::Fatal:S::Keys));
  if(!mismatch){ownerGate=true;assert(d->nativeAcceptSecurityResult(S::Keys));ownerGate=false;
   assert(sec->keysPending && sec->managementPending && !memcmp(sec->keys,w_ptk+32,16));}
  stop(d);
 }
 request.h2e=false;
 AthSecurity::P256FieldAPI field{};field.curve=api.curve;
#define FIELD(member,name) field.member=reinterpret_cast<decltype(field.member)>(dlsym(lib,name));assert(field.member)
 FIELD(units,"cczp_n");FIELD(prime,"cczp_prime");FIELD(multiply,"cczp_mul");FIELD(inverse,"cczp_inv");FIELD(add,"cczp_add");FIELD(subtract,"cczp_sub");
#undef FIELD
 passwordPreparationTests(field);
 AthSecurity::wipe(&keys,sizeof(keys));dlclose(lib);
}

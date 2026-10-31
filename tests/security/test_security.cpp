#include <cassert>
#include <cstring>
#include <vector>
#ifdef _WIN32
#include "../support/windows_security_backend.hpp"
#elif defined(__APPLE__)
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonCryptor.h>
#else
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif
#include "../../src/security/Ath10kSupplicant.hpp"
#include "../../src/security/Ath10kEAPOL.hpp"
#include "../../src/core/Ath10kControl.hpp"
#include "../fixtures/security_vectors.inc"
#include "../fixtures/eap_vectors.inc"
#include "../fixtures/eap_reauth_vectors.inc"
#include "../fixtures/rekey_vectors.inc"
#ifdef _WIN32
// The BCrypt-backed adapter is defined above; the same vectors run on each OS.
#elif defined(__APPLE__)
struct OpenSSLCrypto {
 static bool random(uint8_t *p,size_t n){for(size_t i=0;i<n;++i)p[i]=uint8_t(i+51);return true;}
 static bool hmac(const uint8_t *k,size_t kl,const uint8_t *p,size_t n,uint8_t *o){CCHmac(kCCHmacAlgSHA1,k,kl,p,n,o);return true;}
 static bool decrypt(const uint8_t *k,const uint8_t *p,uint8_t *o){size_t done=0;return CCCrypt(kCCDecrypt,kCCAlgorithmAES,kCCOptionECBMode,k,16,nullptr,p,16,o,16,&done)==kCCSuccess && done==16;}
 static bool encrypt(const uint8_t *k,const uint8_t *p,uint8_t *o){size_t done=0;return CCCrypt(kCCEncrypt,kCCAlgorithmAES,kCCOptionECBMode,k,16,nullptr,p,16,o,16,&done)==kCCSuccess && done==16;}
};
#else
struct OpenSSLCrypto {
 static bool random(uint8_t *p,size_t n){for(size_t i=0;i<n;++i)p[i]=uint8_t(i+51);return true;}
 static bool hmac(const uint8_t *k,size_t kl,const uint8_t *p,size_t n,uint8_t *o){unsigned len=0;return HMAC(EVP_sha1(),k,int(kl),p,n,o,&len)&&len==20;}
 static bool decrypt(const uint8_t *k,const uint8_t *p,uint8_t *o){
  EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new();assert(c);int n=0,last=0;
  bool ok=EVP_DecryptInit_ex(c,EVP_aes_128_ecb(),nullptr,k,nullptr)==1&&EVP_CIPHER_CTX_set_padding(c,0)==1&&EVP_DecryptUpdate(c,o,&n,p,16)==1&&EVP_DecryptFinal_ex(c,o+n,&last)==1&&n+last==16;
  EVP_CIPHER_CTX_free(c);return ok;
 }
 static bool encrypt(const uint8_t *k,const uint8_t *p,uint8_t *o){
  EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new();assert(c);int n=0,last=0;
  bool ok=EVP_EncryptInit_ex(c,EVP_aes_128_ecb(),nullptr,k,nullptr)==1&&EVP_CIPHER_CTX_set_padding(c,0)==1&&EVP_EncryptUpdate(c,o,&n,p,16)==1&&EVP_EncryptFinal_ex(c,o+n,&last)==1&&n+last==16;
  EVP_CIPHER_CTX_free(c);return ok;
 }
};
#endif
using S=AthSecurity::Supplicant<OpenSSLCrypto>;
static void start(S &s){assert(s.begin(v_pmk,v_snonce,v_sta,v_ap,v_rsn,sizeof(v_rsn)));}
static void putBE16(uint8_t *p,uint16_t n){p[0]=uint8_t(n>>8);p[1]=uint8_t(n);}
static std::vector<uint8_t> aesWrap(const uint8_t key[16],const uint8_t *plain,size_t bytes){
 assert(bytes>=16&&bytes%8==0);const size_t blocks=bytes/8;uint8_t a[8],work[16],encrypted[16];memset(a,0xa6,8);
 std::vector<uint8_t> r(plain,plain+bytes);
 for(unsigned j=0;j<6;++j)for(size_t i=1;i<=blocks;++i){
  memcpy(work,a,8);memcpy(work+8,r.data()+8*(i-1),8);assert(OpenSSLCrypto::encrypt(key,work,encrypted));
  const uint64_t t=uint64_t(blocks)*j+i;
  for(unsigned k=0;k<8;++k)a[k]=uint8_t(encrypted[k]^(t>>(56-8*k)));
  memcpy(r.data()+8*(i-1),encrypted+8,8);
 }
 std::vector<uint8_t> out(bytes+8);memcpy(out.data(),a,8);memcpy(out.data()+8,r.data(),bytes);return out;
}
static std::vector<uint8_t> tkipM3(const uint8_t *rsn,size_t rsnBytes,const uint8_t gtk[32],uint8_t index=1){
 constexpr size_t plainBytes=72,cipherBytes=80,keyBytes=99,eapolBytes=keyBytes+cipherBytes;
 std::vector<uint8_t> frame(v_m3,v_m3+14+keyBytes);frame.resize(14+eapolBytes,0);uint8_t *p=frame.data()+14;
 putBE16(p+2,uint16_t(eapolBytes-4));putBE16(p+97,uint16_t(cipherBytes));
 std::vector<uint8_t> plain(plainBytes,0);memcpy(plain.data(),rsn,rsnBytes);size_t at=rsnBytes;
 plain[at++]=221;plain[at++]=38;plain[at++]=0;plain[at++]=15;plain[at++]=172;plain[at++]=1;
 plain[at++]=index;plain[at++]=0;memcpy(plain.data()+at,gtk,32);at+=32;
 plain[at++]=221; // WPA key-data padding marker, followed by zeroes.
 assert(at<=plainBytes);auto wrapped=aesWrap(v_ptk+16,plain.data(),plainBytes);assert(wrapped.size()==cipherBytes);
 memcpy(p+99,wrapped.data(),cipherBytes);memset(p+81,0,16);uint8_t digest[20]{};
 assert(OpenSSLCrypto::hmac(v_ptk,16,p,eapolBytes,digest));memcpy(p+81,digest,16);return frame;
}
static void retainedGTKTests(){
 S s;assert(s.begin(v_pmk,v_snonce,v_sta,v_ap,AthSecurity::stationRSNTKIP,sizeof(AthSecurity::stationRSNTKIP)));
 assert(s.receive(v_m1,sizeof(v_m1))==S::Reply);
 uint8_t a[32],b[32];for(unsigned i=0;i<32;++i){a[i]=uint8_t(0x40+i);b[i]=uint8_t(0x80+i);}
 auto initial=tkipM3(AthSecurity::stationRSNTKIP,sizeof(AthSecurity::stationRSNTKIP),a);
 assert(s.receive(initial.data(),initial.size())==S::Keys);
 auto group=[&](const uint8_t *key,uint8_t index,uint8_t replay){
  auto f=tkipM3(AthSecurity::stationRSNTKIP,sizeof(AthSecurity::stationRSNTKIP),key,index);
  auto p=f.data()+14;putBE16(p+5,0x1382);p[16]=replay;memset(p+81,0,16);
  uint8_t digest[20];assert(OpenSSLCrypto::hmac(v_ptk,16,p,f.size()-14,digest));memcpy(p+81,digest,16);return f;
 };
 auto second=group(b,2,3);assert(s.receive(second.data(),second.size())==S::GroupKeys);
 auto retained=group(a,1,4);assert(s.receive(retained.data(),retained.size())==S::Reply);
 assert(s.receive(retained.data(),retained.size())==S::Reply);
 auto secondAgain=group(b,2,5);assert(s.receive(secondAgain.data(),secondAgain.size())==S::Reply);
 auto relocated=group(a,3,6);assert(s.receive(relocated.data(),relocated.size())==S::Fatal);
}
static void rekeyTests(){
 for(uint8_t index:{uint8_t(2),uint8_t(3)}){
  S trial;start(trial);assert(trial.receive(v_m1,sizeof(v_m1))==S::Reply);
  assert(trial.receive(v_m3,sizeof(v_m3))==S::Keys);
  assert(trial.receive(r_group_new,sizeof(r_group_new))==S::GroupKeys);
  assert(trial.receive(r_pair1,sizeof(r_pair1))==S::Reply);
  uint8_t plain[48]{};memcpy(plain,v_rsn,sizeof(v_rsn));size_t at=sizeof(v_rsn);
  const uint8_t kde[]={221,22,0,15,172,1,index,0};memcpy(plain+at,kde,sizeof(kde));
  memcpy(plain+at+8,r_new_gtk,16);plain[at+24]=221;
  auto wrapped=aesWrap(r_new_ptk+16,plain,sizeof(plain));
  std::vector<uint8_t> frame(r_pair3,r_pair3+sizeof(r_pair3));auto p=frame.data()+14;
  assert(wrapped.size()==AthSecurity::be16(p+97));memcpy(p+99,wrapped.data(),wrapped.size());
  memset(p+81,0,16);uint8_t digest[20]{};
  assert(OpenSSLCrypto::hmac(r_new_ptk,16,p,frame.size()-14,digest));memcpy(p+81,digest,16);
  uint8_t prior[S::keyPayloadLength];memcpy(prior,trial.keys,sizeof(prior));
  const auto result=trial.receive(frame.data(),frame.size());
  if(index==2)assert(result==S::PairKeys && trial.keyChanges==S::PTKChanged);
  else assert(result==S::Fatal && !trial.outputLength && !memcmp(prior,trial.keys,sizeof(prior)));
 }

 S s;start(s);assert(s.receive(v_m1,sizeof(v_m1))==S::Reply);assert(s.receive(v_m3,sizeof(v_m3))==S::Keys);
 assert(s.receive(r_group_new,sizeof(r_group_new))==S::GroupKeys);
 assert(!memcmp(s.keys+16,r_new_gtk,16) && s.keys[48]==AthSecurity::cipherCCMP && s.keys[49]==2 && s.keys[50]==9);
 assert(s.outputLength==sizeof(r_group_new_ack) && !memcmp(s.output,r_group_new_ack,sizeof(r_group_new_ack)));
 for(unsigned i=0;i<10;++i)assert(s.receive(r_group_new,sizeof(r_group_new))==S::Reply);
 assert(s.receive(v_group,sizeof(v_group))==S::Ignore);
 assert(s.receive(r_group_same,sizeof(r_group_same))==S::Reply);
 // Same replay with changed payload/MIC cannot cause a reinstall or an ACK.
 std::vector<uint8_t> changed(r_group_same,r_group_same+sizeof(r_group_same));changed.back()^=1;
 assert(s.receive(changed.data(),changed.size())==S::Ignore);
 assert(s.receive(r_group_other_index,sizeof(r_group_other_index))==S::Fatal);
 start(s);assert(s.receive(v_m1,sizeof(v_m1))==S::Reply);assert(s.receive(v_m3,sizeof(v_m3))==S::Keys);
 assert(s.receive(r_pair1,sizeof(r_pair1))==S::Reply && s.pairwisePending());
 assert(s.outputLength==sizeof(r_pair2) && !memcmp(s.output,r_pair2,sizeof(r_pair2)));
 assert(s.receive(r_pair1,sizeof(r_pair1))==S::Reply);
 changed.assign(r_pair3,r_pair3+sizeof(r_pair3));changed[95]^=1;
 assert(s.receive(changed.data(),changed.size())==S::Ignore && s.pairwisePending());
 s.cancelPairwiseAttempt();assert(!s.pairwisePending() && !s.outputLength);
 for(auto byte:s.output)assert(!byte);
 // Late candidate M3 is retired; established authenticated retries still work.
 assert(s.receive(r_pair3,sizeof(r_pair3))==S::Ignore);
 assert(s.receive(v_m3,sizeof(v_m3))==S::Reply);
 assert(s.outputLength==sizeof(v_m4) && !memcmp(s.output,v_m4,sizeof(v_m4)));
 // Forged M1 timeout restores established keys: an authentic GTK rekey still works.
 assert(s.receive(r_group_new,sizeof(r_group_new))==S::GroupKeys);
 assert(s.receive(r_pair1,sizeof(r_pair1))==S::Reply);
 assert(s.receive(r_pair3,sizeof(r_pair3))==S::PairKeys && !s.pairwisePending());
 assert(!memcmp(s.keys,r_new_ptk+32,16) && !memcmp(s.keys+16,r_new_gtk,16));
 assert(s.outputLength==sizeof(r_pair4) && !memcmp(s.output,r_pair4,sizeof(r_pair4)));
 for(unsigned i=0;i<10;++i)assert(s.receive(r_pair3,sizeof(r_pair3))==S::Reply);
 assert(s.receive(v_m3,sizeof(v_m3))==S::Ignore);
 assert(s.receive(r_group_after_pair,sizeof(r_group_after_pair))==S::GroupKeys);
 s.reset();assert(s.receive(r_pair1,sizeof(r_pair1))==S::Ignore);
}

static void eapEnvelopeChecks(){
 using namespace AthSecurity;
 uint8_t frame[160]{};frame[12]=0x88;frame[13]=0x8e;frame[14]=2;
 for(size_t n=0;n<18;++n)assert(classifyEAPOL(frame,n).kind==EAPOLKind::Invalid);
 assert(classifyEAPOL(nullptr,160).kind==EAPOLKind::Invalid);
 frame[15]=1;assert(classifyEAPOL(frame,60).kind==EAPOLKind::Start);
 assert(classifyEAPOL(frame,60).bytes==18);
 frame[17]=1;assert(classifyEAPOL(frame,60).kind==EAPOLKind::Invalid);
 frame[15]=0;frame[17]=5;frame[18]=1;frame[21]=5;frame[22]=1;
 assert(classifyEAPOL(frame,60).kind==EAPOLKind::EAP);
 assert(classifyEAPOL(frame,22).kind==EAPOLKind::Invalid);
 frame[21]=4;assert(classifyEAPOL(frame,60).kind==EAPOLKind::Invalid);
 frame[17]=frame[21]=4;frame[18]=3;
 assert(classifyEAPOL(frame,60).kind==EAPOLKind::EAP);
 frame[18]=5;assert(classifyEAPOL(frame,60).kind==EAPOLKind::Invalid);
 frame[15]=3;frame[17]=95;frame[18]=2;
 assert(classifyEAPOL(frame,113).kind==EAPOLKind::Key);
 assert(classifyEAPOL(frame,112).kind==EAPOLKind::Invalid);
 frame[112]=1;assert(classifyEAPOL(frame,160).kind==EAPOLKind::Invalid);
 frame[17]=96;assert(classifyEAPOL(frame,160).bytes==114);
 frame[18]=1;assert(classifyEAPOL(frame,160).kind==EAPOLKind::Invalid);
 frame[14]=4;assert(classifyEAPOL(frame,160).kind==EAPOLKind::Invalid);
}
static void enterpriseExchange(){
 using E=AthSecurity::Supplicant<OpenSSLCrypto,false,false,true>;
 S personal;assert(!personal.begin(e_pmk,e_snonce,e_sta,e_ap,e_rsn,sizeof(e_rsn),1));
 E e;assert(e.begin(e_pmk,e_snonce,e_sta,e_ap,e_rsn,sizeof(e_rsn),1));
 uint8_t association[64]{};size_t bytes=0;
 assert(e.copyAssociationRSN(association,sizeof(association),bytes));
 assert(bytes==sizeof(e_rsn) && !memcmp(association,e_rsn,bytes));
 assert(e.receive(e_m1,sizeof(e_m1))==E::Reply);
 assert(e.outputLength==sizeof(e_m2) && !memcmp(e.output,e_m2,sizeof(e_m2)));
 assert(e.receive(e_m3,sizeof(e_m3))==E::Keys);
 assert(e.outputLength==sizeof(e_m4) && !memcmp(e.output,e_m4,sizeof(e_m4)));
 assert(!memcmp(e.keys,e_ptk+32,16) && !memcmp(e.keys+16,e_gtk,16));
 assert(e.receive(e_m3,sizeof(e_m3))==E::Reply); // No key reinstallation.
 // Replacing PMK must not reset replay or installed-key history. The native
 // owner/firmware barriers are separate and are not emulated by this API test.
 uint8_t replacement[32];memcpy(replacement,e_pmk,32);replacement[0]^=0x80;
 uint8_t wrongPeer[6];memcpy(wrongPeer,e_ap,6);wrongPeer[5]^=1;
 assert(!e.replaceEAPMaster(nullptr,e_sta,e_ap));
 assert(!e.replaceEAPMaster(replacement,e_sta,wrongPeer));
 assert(e.replaceEAPMaster(replacement,e_sta,e_ap));
 assert(e.receive(e_m1,sizeof(e_m1))==E::Ignore);
 assert(e.receive(e_m3,sizeof(e_m3))==E::Reply);
 assert(!memcmp(e.keys,e_ptk+32,16) && !memcmp(e.keys+16,e_gtk,16));
 std::vector<uint8_t> fresh(e_m1,e_m1+sizeof(e_m1));
 const uint64_t replay=AthSecurity::be64(e_m3+14+9)+1;
 for(unsigned i=0;i<8;++i)fresh[14+9+i]=uint8_t(replay>>(56-8*i));
 fresh[14+17]^=1;
 assert(e.receive(fresh.data(),fresh.size())==E::Reply && e.pairwisePending());
 assert(!e.replaceEAPMaster(e_pmk,e_sta,e_ap));
 uint8_t nonce[32];assert(OpenSSLCrypto::random(nonce,sizeof(nonce)));
 E expected;assert(expected.begin(replacement,nonce,e_sta,e_ap,e_rsn,sizeof(e_rsn),1));
 assert(expected.receive(fresh.data(),fresh.size())==E::Reply);
 assert(e.outputLength==expected.outputLength && !memcmp(e.output,expected.output,e.outputLength));
 e.cancelPairwiseAttempt();assert(!e.pairwisePending());
 assert(e.receive(e_m3,sizeof(e_m3))==E::Reply); // Still the established M4, no install.
 assert(!memcmp(e.keys,e_ptk+32,16) && !memcmp(e.keys+16,e_gtk,16));
 assert(e.receive(er_m1,sizeof(er_m1))==E::Reply);
 assert(e.outputLength==sizeof(er_m2) && !memcmp(e.output,er_m2,sizeof(er_m2)));
 assert(e.receive(e_m3,sizeof(e_m3))==E::Ignore);
 auto forged=std::vector<uint8_t>(er_m3,er_m3+sizeof(er_m3));forged[14+81]^=1;
 assert(e.receive(forged.data(),forged.size())==E::Ignore && e.pairwisePending());
 assert(!memcmp(e.keys,e_ptk+32,16));
 assert(e.receive(er_m3,sizeof(er_m3))==E::PairKeys);
 assert(!e.pairwisePending() && !memcmp(e.keys,er_ptk+32,16));
 assert(e.outputLength==sizeof(er_m4) && !memcmp(e.output,er_m4,sizeof(er_m4)));
 assert(e.receive(er_m3,sizeof(er_m3))==E::Reply); // No second installation.
 assert(e.receive(e_m1,sizeof(e_m1))==E::Ignore);
 S psk;start(psk);assert(!psk.replaceEAPMaster(replacement,v_sta,v_ap));
 E empty;assert(!empty.replaceEAPMaster(replacement,e_sta,e_ap));
 e.reset();assert(e.receive(e_m3,sizeof(e_m3))==E::Ignore);
 assert(!e.begin(e_pmk,e_snonce,e_sta,e_ap,e_rsn,sizeof(e_rsn),5));
 assert(!e.begin(e_pmk,e_snonce,e_sta,e_ap,v_rsn,sizeof(v_rsn),1));
 uint8_t required[sizeof(e_rsn)];memcpy(required,e_rsn,sizeof(required));required[20]=0xc0;
 assert(!e.begin(e_pmk,e_snonce,e_sta,e_ap,required,sizeof(required),1));
}
static void eapolVersionTests(){
 for(uint8_t version:{1,2,3}){
  S s;start(s);std::vector<uint8_t> m1(v_m1,v_m1+sizeof(v_m1)),m3(v_m3,v_m3+sizeof(v_m3));
  m1[14]=m3[14]=version;uint8_t digest[20];memset(m3.data()+95,0,16);
  assert(OpenSSLCrypto::hmac(v_ptk,16,m3.data()+14,m3.size()-14,digest));memcpy(m3.data()+95,digest,16);
  assert(AthSecurity::classifyEAPOL(m1.data(),m1.size()).kind==AthSecurity::EAPOLKind::Key);
  assert(s.receive(m1.data(),m1.size())==S::Reply && s.output[14]==version);
  assert(s.receive(m3.data(),m3.size())==S::Keys && s.output[14]==version);
  uint8_t reply[99];memcpy(reply,s.output+14,sizeof(reply));memset(reply+81,0,16);
  assert(OpenSSLCrypto::hmac(v_ptk,16,reply,sizeof(reply),digest));assert(!memcmp(s.output+95,digest,16));
 }
 for(unsigned version=0;version<256;++version)if(version<1 || version>3){
  S s;start(s);std::vector<uint8_t> m1(v_m1,v_m1+sizeof(v_m1));m1[14]=uint8_t(version);
  assert(s.receive(m1.data(),m1.size())==S::Ignore && !s.outputLength);
 }
}
struct ReportFailureCrypto:OpenSSLCrypto {
 static inline bool fail=false;
 static bool hmac(const uint8_t *key,size_t keyBytes,const uint8_t *p,size_t bytes,uint8_t *out){
  if(fail){memset(out,0x77,20);return false;}
  return OpenSSLCrypto::hmac(key,keyBytes,p,bytes,out);
 }
};
static void micReportFailureOwnership(){
 using R=AthSecurity::Supplicant<ReportFailureCrypto>;
 R s;assert(s.begin(v_pmk,v_snonce,v_sta,v_ap,AthSecurity::stationRSNTKIP,sizeof(AthSecurity::stationRSNTKIP)));
 assert(s.receive(v_m1,sizeof(v_m1))==R::Reply);
 uint8_t key[32];for(unsigned i=0;i<32;++i)key[i]=uint8_t(i+32);
 auto m3=tkipM3(AthSecurity::stationRSNTKIP,sizeof(AthSecurity::stationRSNTKIP),key);
 assert(s.receive(m3.data(),m3.size())==R::Keys);
 uint8_t out[113];memset(out,0xa5,sizeof(out));size_t bytes=999;
 ReportFailureCrypto::fail=true;
 assert(!s.buildGroupMICFailureReport(out,sizeof(out),bytes) && !bytes);
 for(auto value:out)assert(value==0xa5);
 ReportFailureCrypto::fail=false;
 assert(s.buildGroupMICFailureReport(out,sizeof(out),bytes));
 assert(AthSecurity::be64(out+23)==0); // Failed signing cannot consume a request counter.
 assert(s.receive(m3.data(),m3.size())==R::Reply); // Cached handshake survives.
 s.reset();assert(!s.buildGroupMICFailureReport(out,sizeof(out),bytes));
}
static void groupMICFailureReportTests(){
 using namespace AthSecurity;
 S s;uint8_t report[114];memset(report,0xa5,sizeof(report));size_t bytes=999;
 assert(!s.buildGroupMICFailureReport(report,sizeof(report),bytes) && !bytes);
 assert(s.begin(v_pmk,v_snonce,v_sta,v_ap,stationRSNTKIP,sizeof(stationRSNTKIP)));
 assert(s.receive(v_m1,sizeof(v_m1))==S::Reply);
 assert(!s.buildGroupMICFailureReport(report,sizeof(report),bytes));
 uint8_t gtk[32];for(unsigned i=0;i<32;++i)gtk[i]=uint8_t(0x40+i);
 auto m3=tkipM3(stationRSNTKIP,sizeof(stationRSNTKIP),gtk);
 assert(s.receive(m3.data(),m3.size())==S::Keys);
 std::vector<uint8_t> reply(s.output,s.output+s.outputLength);
 for(unsigned i=0;i<2;++i){
  assert(s.buildGroupMICFailureReport(report,sizeof(report),bytes));assert(bytes==113 && report[113]==0xa5);
  assert(!memcmp(report,v_ap,6) && !memcmp(report+6,v_sta,6));
  assert(be16(report+19)==0x0f02 && be64(report+23)==i);
  uint8_t packet[99],digest[20];memcpy(packet,report+14,99);memset(packet+81,0,16);
  assert(OpenSSLCrypto::hmac(v_ptk,16,packet,99,digest));assert(!memcmp(digest,report+95,16));
  assert(s.outputLength==reply.size() && !memcmp(s.output,reply.data(),reply.size()));
 }
 assert(!s.buildGroupMICFailureReport(report,112,bytes));
 assert(!s.buildGroupMICFailureReport(report,sizeof(report),bytes,0));
 assert(!s.buildGroupMICFailureReport(report,sizeof(report),bytes,4));
 assert(s.buildGroupMICFailureReport(report,sizeof(report),bytes,3));assert(be64(report+23)==2);
 // Counter independence: a duplicate authenticated M3 still yields cached M4.
 assert(s.receive(m3.data(),m3.size())==S::Reply);
 assert(s.outputLength==reply.size() && !memcmp(s.output,reply.data(),reply.size()));
 // Unauthenticated replacement M1 must not change the report signing key.
 std::vector<uint8_t> next(v_m1,v_m1+sizeof(v_m1));next[30]=9;next[31]^=1;
 assert(s.receive(next.data(),next.size())==S::Reply && s.pairwisePending());
 assert(s.buildGroupMICFailureReport(report,sizeof(report),bytes));
 uint8_t packet[99],digest[20];memcpy(packet,report+14,99);memset(packet+81,0,16);
 assert(OpenSSLCrypto::hmac(v_ptk,16,packet,99,digest));assert(!memcmp(digest,report+95,16));
 s.reset();assert(!s.buildGroupMICFailureReport(report,sizeof(report),bytes));
 S ccmp;start(ccmp);assert(ccmp.receive(v_m1,sizeof(v_m1))==S::Reply);
 assert(ccmp.receive(v_m3,sizeof(v_m3))==S::Keys);
 assert(!ccmp.buildGroupMICFailureReport(report,sizeof(report),bytes));
}
struct FailingPTKCrypto {
 static inline unsigned calls=0,failAt=0;
 static bool hmac(const uint8_t *k,size_t kl,const uint8_t *p,size_t n,uint8_t *out){
  if(calls++==failAt){memset(out,0x77,20);return false;}
  return OpenSSLCrypto::hmac(k,kl,p,n,out);
 }
};
static void ptkExpansion(){
 uint8_t key[32],context[76],out[65];
 for(unsigned i=0;i<32;++i)key[i]=uint8_t(i);
 for(unsigned i=0;i<76;++i)context[i]=uint8_t(i);
 // Python hashlib/hmac SHA1 reference: label+NUL, context, counter 0..3.
 const uint8_t expected[]={228,73,142,115,117,128,70,73,190,230,63,62,137,99,149,104,226,228,60,234,18,40,41,228,202,249,160,217,3,167,193,237,74,122,43,229,134,70,189,10,117,48,245,179,204,206,14,102,82,232,139,135,71,71,140,245,120,82,96,200,195,231,221,42};
 for(size_t bytes:{size_t(48),size_t(64)}){
  memset(out,0xa5,sizeof(out));
  assert(AthSecurity::deriveSHA1PTK<OpenSSLCrypto>(key,context,out,bytes,bytes));
  assert(!memcmp(out,expected,bytes));assert(out[bytes]==0xa5);
  for(unsigned block=0;block<(bytes+19)/20;++block){
   memset(out,0xa5,sizeof(out));FailingPTKCrypto::calls=0;FailingPTKCrypto::failAt=block;
   assert(!AthSecurity::deriveSHA1PTK<FailingPTKCrypto>(key,context,out,bytes,sizeof(out)));
   for(auto byte:out)assert(byte==0xa5);
  }
 }
 for(size_t bytes=0;bytes<=65;++bytes)if(bytes!=48 && bytes!=64)
  assert(!AthSecurity::deriveSHA1PTK<OpenSSLCrypto>(key,context,out,bytes,sizeof(out)));
 assert(!AthSecurity::deriveSHA1PTK<OpenSSLCrypto>(key,context,out,64,63));
 assert(!AthSecurity::deriveSHA1PTK<OpenSSLCrypto>(nullptr,context,out,48,65));
 assert(!AthSecurity::deriveSHA1PTK<OpenSSLCrypto>(key,nullptr,out,48,65));
 assert(!AthSecurity::deriveSHA1PTK<OpenSSLCrypto>(key,context,nullptr,48,65));
 for(auto byte:out)assert(byte==0xa5);
}
int main(){
 micReportFailureOwnership();
 retainedGTKTests();
 eapolVersionTests();
 groupMICFailureReportTests();
 ptkExpansion();
 enterpriseExchange();
 eapEnvelopeChecks();
 { AthSecurity::PMFKeyEpochs state;AthSecurity::IGTKCMAC128 key{},snapshot{};
   key.keyID=4;key.ipn=3;key.key[0]=9;uint64_t epoch=0;
   assert(state.activate(key) && state.snapshot(4,snapshot,epoch));const auto first=epoch;
   assert(state.commitIPN(4,epoch,7));
   assert(state.activate(key) && state.snapshot(4,snapshot,epoch));
   assert(epoch==first && snapshot.ipn==7); // Redelivery never rolls back IPN.
   assert(!state.commitIPN(4,epoch,7));
   key.keyID=5;assert(!state.activate(key)); // Same key under another slot.
   key.keyID=4;key.key[0]=10;assert(state.activate(key));
   assert(!state.commitIPN(4,first,8));
   assert(state.snapshot(4,snapshot,epoch) && epoch>first && snapshot.ipn==3);
   const auto replacement=epoch;state.clear();assert(!state.commitIPN(4,epoch,9));
   assert(state.activate(key) && state.snapshot(4,snapshot,epoch) && epoch>replacement);
   assert(!state.commitIPN(4,epoch,0x1000000000000ull));
   AthSecurity::wipe(&snapshot,sizeof(snapshot));AthSecurity::wipe(&key,sizeof(key));
 }

    { const uint8_t malformed[]={192,4,0,0,255,255,255,255,255,255,2,1,2,3,4,5,2,1,2,3,4,5,0,0,3,0,76,16,4,0,7,0,0,0,0,0,184,5,201,77,143,136,128,204};
      uint64_t accepted=999;AthSecurity::IGTKCMAC128 key{};key.keyID=4;
      for(unsigned i=0;i<16;++i)key.key[i]=uint8_t(i);
      const uint8_t ap[]={2,1,2,3,4,5};
      assert(!AthSecurity::verifyBIPDisconnect<OpenSSLCrypto>(malformed,sizeof(malformed),ap,key,6,accepted));
      assert(accepted==999);
    }
    { const uint8_t malformed[]={192,0,0,0,255,255,255,255,255,255,2,1,2,3,4,5,2,1,2,3,4,5,1,0,3,0,76,16,4,0,7,0,0,0,0,0,219,152,59,137,57,155,205,49};
      uint64_t accepted=999;AthSecurity::IGTKCMAC128 key{};key.keyID=4;
      for(unsigned i=0;i<16;++i)key.key[i]=uint8_t(i);
      const uint8_t ap[]={2,1,2,3,4,5};
      assert(!AthSecurity::verifyBIPDisconnect<OpenSSLCrypto>(malformed,sizeof(malformed),ap,key,6,accepted));
      assert(accepted==999);
    }
    { const uint8_t malformed[]={192,128,0,0,255,255,255,255,255,255,2,1,2,3,4,5,2,1,2,3,4,5,0,0,3,0,76,16,4,0,7,0,0,0,0,0,254,188,127,208,82,108,16,170};
      uint64_t accepted=999;AthSecurity::IGTKCMAC128 key{};key.keyID=4;
      for(unsigned i=0;i<16;++i)key.key[i]=uint8_t(i);
      const uint8_t ap[]={2,1,2,3,4,5};
      assert(!AthSecurity::verifyBIPDisconnect<OpenSSLCrypto>(malformed,sizeof(malformed),ap,key,6,accepted));
      assert(accepted==999);
    }

 { uint8_t frame[]={192,0,0,0,255,255,255,255,255,255,2,1,2,3,4,5,2,1,2,3,4,5,0,0,3,0,76,16,4,0,7,0,0,0,0,0,219,152,59,137,57,155,205,49};
   uint8_t ap[]={2,1,2,3,4,5};AthSecurity::IGTKCMAC128 key{};key.keyID=4;
   for(unsigned i=0;i<16;++i)key.key[i]=uint8_t(i);
   uint64_t accepted=999;
   assert(AthSecurity::verifyBIPDisconnect<OpenSSLCrypto>(frame,sizeof(frame),ap,key,6,accepted) && accepted==7);
   accepted=999;
   assert(!AthSecurity::verifyBIPDisconnect<OpenSSLCrypto>(frame,sizeof(frame),ap,key,7,accepted) && accepted==999);
   for(unsigned i=4;i<sizeof(frame);++i){
     if(i==22 || i==23)continue; // Sequence control is outside BIP AAD.
     frame[i]^=2;
     assert(!AthSecurity::verifyBIPDisconnect<OpenSSLCrypto>(frame,sizeof(frame),ap,key,6,accepted));
     assert(accepted==999);frame[i]^=2;
   }
   frame[1]=0x38; // Retry, power-management and more-data bits are masked.
   assert(AthSecurity::verifyBIPDisconnect<OpenSSLCrypto>(frame,sizeof(frame),ap,key,6,accepted));
 }

 rekeyTests();
 S s;start(s);
 assert(s.receive(v_m1,sizeof(v_m1))==S::Reply);
 assert(s.outputLength==sizeof(v_m2)&&!memcmp(s.output,v_m2,sizeof(v_m2)));
 assert(s.receive(v_m1,sizeof(v_m1))==S::Reply); // retry M1, same SNonce
 assert(s.receive(v_m3,sizeof(v_m3))==S::Keys);
 assert(!memcmp(s.keys,v_ptk+32,16)&&!memcmp(s.keys+16,v_gtk,16)&&s.keys[48]==AthSecurity::cipherCCMP&&s.keys[49]==1);
 assert(s.outputLength==sizeof(v_m4)&&!memcmp(s.output,v_m4,sizeof(v_m4)));
 for(int i=0;i<10;++i)assert(s.receive(v_m3,sizeof(v_m3))==S::Reply); // no key reinstall
 assert(s.receive(v_retry,sizeof(v_retry))==S::Reply);
 assert(s.outputLength==sizeof(v_retry4) && !memcmp(s.output,v_retry4,sizeof(v_retry4)));
 assert(s.receive(v_m3,sizeof(v_m3))==S::Ignore); // older counter after valid retry
 assert(s.receive(v_group,sizeof(v_group))==S::Reply); // identical GTK acknowledged without reinstall
 start(s);assert(s.receive(v_m3,sizeof(v_m3))==S::Ignore);
 for(size_t n=0;n<sizeof(v_m1);++n)assert(s.receive(v_m1,n)==S::Ignore);
 for(size_t n=0;n<sizeof(v_rsn);++n)assert(!AthSecurity::supportsWPA2(v_rsn,n));
 uint8_t rsn[sizeof(v_rsn)];memcpy(rsn,v_rsn,sizeof(rsn));rsn[20]=0x40;assert(!AthSecurity::supportsWPA2(rsn,sizeof(rsn)));
 const uint8_t mixedRSN[]={48,24,1,0,0,15,172,2,2,0,0,15,172,2,0,15,172,4,1,0,0,15,172,2,0,0};
 assert(AthSecurity::supportsWPA2(mixedRSN,sizeof(mixedRSN)));
 assert(AthSecurity::wpa2GroupCipher(mixedRSN,sizeof(mixedRSN))==AthSecurity::cipherTKIP);
 size_t stationRSNLength=0;const uint8_t *stationRSN=AthSecurity::stationRSNForGroup(AthSecurity::cipherTKIP,stationRSNLength);
 assert(stationRSNLength==sizeof(AthSecurity::stationRSNTKIP) && !memcmp(stationRSN,AthSecurity::stationRSNTKIP,stationRSNLength));
 S mixed;assert(mixed.begin(v_pmk,v_snonce,v_sta,v_ap,mixedRSN,sizeof(mixedRSN)));
 assert(mixed.receive(v_m1,sizeof(v_m1))==S::Reply);
 assert(mixed.outputLength==sizeof(v_m2) && !memcmp(mixed.output+14+99,AthSecurity::stationRSNTKIP,stationRSNLength));
 uint8_t tkipGTK[32];for(unsigned i=0;i<sizeof(tkipGTK);++i)tkipGTK[i]=uint8_t(0xa0+i);
 S mixedHandshake;assert(mixedHandshake.begin(v_pmk,v_snonce,v_sta,v_ap,mixedRSN,sizeof(mixedRSN)));
 assert(mixedHandshake.receive(v_m1,sizeof(v_m1))==S::Reply);
 auto tkipFrame=tkipM3(mixedRSN,sizeof(mixedRSN),tkipGTK);
 assert(mixedHandshake.receive(tkipFrame.data(),tkipFrame.size())==S::Keys);
 assert(!memcmp(mixedHandshake.keys,v_ptk+32,16) && !memcmp(mixedHandshake.keys+16,tkipGTK,32));
 assert(mixedHandshake.keys[48]==AthSecurity::cipherTKIP && mixedHandshake.keys[49]==1);
 uint8_t tkipOnly[sizeof(mixedRSN)];memcpy(tkipOnly,mixedRSN,sizeof(tkipOnly));tkipOnly[17]=AthSecurity::cipherTKIP;
 assert(!AthSecurity::supportsWPA2(tkipOnly,sizeof(tkipOnly)));
 assert(!AthSecurity::stationRSNForGroup(0,stationRSNLength) && stationRSNLength==0);
 for(unsigned offset:{19u,31u,95u,125u}){
  start(s);assert(s.receive(v_m1,sizeof(v_m1))==S::Reply);
  std::vector<uint8_t> p(v_m3,v_m3+sizeof(v_m3));p[offset]^=1;
  auto result=s.receive(p.data(),p.size());assert(result==S::Ignore||result==S::Fatal);
 }
 start(s);assert(s.receive(v_m1,sizeof(v_m1))==S::Reply);assert(s.receive(v_bad_rsn,sizeof(v_bad_rsn))==S::Fatal);
 uint8_t badPMK[32]{};assert(s.begin(badPMK,v_snonce,v_sta,v_ap,v_rsn,sizeof(v_rsn)));
 assert(s.receive(v_m1,sizeof(v_m1))==S::Reply);assert(s.receive(v_m3,sizeof(v_m3))==S::Fatal);
 s.reset();assert(s.receive(v_m1,sizeof(v_m1))==S::Ignore);
}

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
static std::vector<uint8_t> tkipM3(const uint8_t *rsn,size_t rsnBytes,const uint8_t gtk[32]){
 constexpr size_t plainBytes=72,cipherBytes=80,keyBytes=99,eapolBytes=keyBytes+cipherBytes;
 std::vector<uint8_t> frame(v_m3,v_m3+14+keyBytes);frame.resize(14+eapolBytes,0);uint8_t *p=frame.data()+14;
 putBE16(p+2,uint16_t(eapolBytes-4));putBE16(p+97,uint16_t(cipherBytes));
 std::vector<uint8_t> plain(plainBytes,0);memcpy(plain.data(),rsn,rsnBytes);size_t at=rsnBytes;
 plain[at++]=221;plain[at++]=38;plain[at++]=0;plain[at++]=15;plain[at++]=172;plain[at++]=1;
 plain[at++]=1;plain[at++]=0;memcpy(plain.data()+at,gtk,32);at+=32;
 plain[at++]=221; // WPA key-data padding marker, followed by zeroes.
 assert(at<=plainBytes);auto wrapped=aesWrap(v_ptk+16,plain.data(),plainBytes);assert(wrapped.size()==cipherBytes);
 memcpy(p+99,wrapped.data(),cipherBytes);memset(p+81,0,16);uint8_t digest[20]{};
 assert(OpenSSLCrypto::hmac(v_ptk,16,p,eapolBytes,digest));memcpy(p+81,digest,16);return frame;
}
static void rekeyTests(){
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
 e.reset();assert(e.receive(e_m3,sizeof(e_m3))==E::Ignore);
 assert(!e.begin(e_pmk,e_snonce,e_sta,e_ap,e_rsn,sizeof(e_rsn),5));
 assert(!e.begin(e_pmk,e_snonce,e_sta,e_ap,v_rsn,sizeof(v_rsn),1));
 uint8_t required[sizeof(e_rsn)];memcpy(required,e_rsn,sizeof(required));required[20]=0xc0;
 assert(!e.begin(e_pmk,e_snonce,e_sta,e_ap,required,sizeof(required),1));
}
int main(){
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

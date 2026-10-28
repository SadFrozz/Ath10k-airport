#include <cassert>
#include <cstring>
#include <initializer_list>
#include <new>
#include <type_traits>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonCryptor.h>
#include "../src/shared/Ath10kSupplicant.hpp"
#include "../src/shared/Ath10kSAE.hpp"
#include "sha256_vectors.inc"
struct Crypto {
 static bool random(uint8_t *out,size_t n){for(size_t i=0;i<n;++i)out[i]=uint8_t(i);return true;}
 static bool hmac(const uint8_t *k,size_t kl,const uint8_t *p,size_t n,uint8_t *o){CCHmac(kCCHmacAlgSHA1,k,kl,p,n,o);return true;}
 static bool hmac256(const uint8_t *k,size_t kl,const uint8_t *p,size_t n,uint8_t *o){CCHmac(kCCHmacAlgSHA256,k,kl,p,n,o);return true;}
 static bool encrypt(const uint8_t *k,const uint8_t *p,uint8_t *o){size_t done=0;return CCCrypt(kCCEncrypt,kCCAlgorithmAES,kCCOptionECBMode,k,16,nullptr,p,16,o,16,&done)==kCCSuccess && done==16;}
 static bool decrypt(const uint8_t *k,const uint8_t *p,uint8_t *o){size_t done=0;return CCCrypt(kCCDecrypt,kCCAlgorithmAES,kCCOptionECBMode,k,16,nullptr,p,16,o,16,&done)==kCCSuccess && done==16;}
};
struct FailedHMAC:Crypto {
 static bool hmac256(const uint8_t *,size_t,const uint8_t *,size_t,uint8_t *out){memset(out,0x77,32);return false;}
};
struct FailSelectedHMAC:Crypto {
 static inline unsigned calls=0,failAt=0;
 static bool hmac256(const uint8_t *k,size_t kl,const uint8_t *p,size_t n,uint8_t *out){
  if(++calls==failAt){memset(out,0x77,32);return false;}
  return Crypto::hmac256(k,kl,p,n,out);
 }
};
static void checkSAEConfirmationFence(){
 using Owner=AthSecurity::SAEGroup19Confirmation;using Job=AthSecurity::SAEGroup19ConfirmWork;
 static_assert(!std::is_copy_constructible<Owner>::value && !std::is_copy_constructible<Job>::value);
 static_assert(sizeof(Owner)<=512 && sizeof(Job)<=512);
 Owner owner;Job local,peer,older,newer;uint64_t token=0;
 uint8_t a[96]{},b[96]{},pmk[40],id[24],body[34]{},confirm[40];
 for(unsigned i=0;i<96;++i){a[i]=uint8_t(i);b[i]=uint8_t(255-i);}
 AthSecurity::SAEGroup19Keys keys{};for(unsigned i=0;i<32;++i){keys.kck[i]=uint8_t(i+1);keys.pmk[i]=uint8_t(i+33);}
 for(unsigned i=0;i<16;++i)keys.pmkid[i]=uint8_t(i+77);
 const auto expected=keys;
 auto noPMK=[&](uint64_t generation){
  memset(pmk,0xa5,sizeof(pmk));memset(id,0xa5,sizeof(id));
  assert(!owner.copyPMK(generation,pmk,sizeof(pmk),id,sizeof(id)));
  for(auto x:pmk)assert(x==0xa5);for(auto x:id)assert(x==0xa5);
 };
 auto consumed=[&](){const auto *p=reinterpret_cast<const uint8_t *>(&keys);for(size_t i=0;i<sizeof(keys);++i)assert(p[i]==0);};
 auto peerBody=[&](uint16_t counter){body[0]=uint8_t(counter);body[1]=uint8_t(counter>>8);
  assert(AthSecurity::saeGroup19Confirm<Crypto>(expected.kck,32,counter,b,96,a,96,body+2,32));};
 noPMK(0);assert(!owner.snapshotLocal(0,local));assert(!owner.snapshotPeer(0,peer));
 assert(owner.begin(a,96,b,96,token));const uint64_t first=token;noPMK(token);
 assert(!owner.snapshotLocal(token,local));
 assert(owner.completeKeys(token,true,keys));consumed();noPMK(token);
 // Neither a generated local confirm nor a verified peer confirm alone releases PMK.
 assert(owner.snapshotLocal(token,local));memset(confirm,0xa5,sizeof(confirm));
 assert(local.makeLocal<Crypto>(confirm,sizeof(confirm)));assert(owner.localReadyToTransmit(local));assert(confirm[0]==1 && confirm[1]==0);
 for(unsigned i=34;i<40;++i)assert(confirm[i]==0xa5);noPMK(token);
 assert(!owner.completeLocal(local,false));noPMK(token);
 peerBody(1);assert(owner.snapshotPeer(token,peer));assert(peer.verifyPeer<Crypto>(body,34));
 assert(owner.completePeer(peer));noPMK(token);
 assert(owner.completeLocal(local,true));
 { Owner other;uint64_t sameToken=0;assert(other.begin(a,96,b,96,sameToken) && sameToken==token);
   keys=expected;assert(other.completeKeys(sameToken,true,keys));consumed();
   assert(!other.completeLocal(local,true));assert(!other.completePeer(peer));
   assert(!other.copyPMK(sameToken,pmk,sizeof(pmk),id,sizeof(id)));
 }
 assert(owner.copyPMK(token,pmk,sizeof(pmk),id,sizeof(id)));
 assert(!memcmp(pmk,expected.pmk,32) && !memcmp(id,expected.pmkid,16));
 for(unsigned i=32;i<40;++i)assert(pmk[i]==0xa5);for(unsigned i=16;i<24;++i)assert(id[i]==0xa5);
 assert(!owner.copyPMK(token,pmk,31,id,16));assert(!owner.copyPMK(token,pmk,32,id,15));
 assert(!owner.copyPMK(token,nullptr,32,id,16));assert(!owner.copyPMK(token,pmk,32,nullptr,16));
 // Already accepted replay and repeated completion cannot advance replay state.
 assert(!owner.completePeer(peer));assert(owner.snapshotPeer(token,newer));
 assert(!newer.verifyPeer<Crypto>(body,34));assert(!owner.completePeer(newer));
 // Verified jobs may finish after cancellation and even after a new join starts.
 assert(owner.snapshotPeer(token,older));
 owner.cancel();noPMK(first);assert(!owner.localReadyToTransmit(local));
 assert(owner.begin(a,96,b,96,token) && token>first);noPMK(token);
 peerBody(2);assert(older.verifyPeer<Crypto>(body,34));assert(!owner.completePeer(older));
 assert(!owner.localReadyToTransmit(local));
 assert(!owner.completeLocal(local,true));assert(!owner.completePeer(peer));
 keys=expected;assert(!owner.completeKeys(first,true,keys));consumed();
 keys=expected;assert(owner.completeKeys(token,true,keys));consumed();
 assert(!owner.completeLocal(local,true));assert(!owner.completePeer(peer));noPMK(token);
 // A provider failure must not turn a successful prior job into a valid result.
 assert(owner.snapshotLocal(token,local));memset(confirm,0xa5,sizeof(confirm));
 assert(!local.makeLocal<FailedHMAC>(confirm,sizeof(confirm)));
 for(auto x:confirm)assert(x==0xa5);assert(!owner.completeLocal(local,true));
 assert(local.makeLocal<Crypto>(confirm,sizeof(confirm)));assert(owner.completeLocal(local,true));noPMK(token);
 peerBody(1);assert(owner.snapshotPeer(token,peer));
 assert(!peer.verifyPeer<FailedHMAC>(body,34));assert(!owner.completePeer(peer));noPMK(token);
 // Concurrent snapshots verified against old replay state are rechecked at publication.
 assert(owner.snapshotPeer(token,older));assert(owner.snapshotPeer(token,newer));
 peerBody(9);assert(older.verifyPeer<Crypto>(body,34));
 peerBody(10);assert(newer.verifyPeer<Crypto>(body,34));
 assert(owner.completePeer(newer));assert(!owner.completePeer(older));
 assert(owner.copyPMK(token,pmk,32,id,16) && !memcmp(pmk,expected.pmk,32));
 const auto oldToken=token;
 // Failed crypto and malformed replacement join invalidate previous accepted keys.
 assert(owner.begin(a,96,b,96,token));keys=expected;
 assert(!owner.completeKeys(token,false,keys));consumed();noPMK(token);
 assert(!owner.completeKeys(oldToken,true,keys));noPMK(oldToken);
 assert(owner.begin(a,96,b,96,token));keys=expected;assert(owner.completeKeys(token,true,keys));
 uint64_t unchanged=123;assert(!owner.begin(a,95,b,96,unchanged) && unchanged==123);noPMK(token);
 assert(!owner.begin(a,96,a,96,unchanged));assert(!owner.begin(nullptr,96,b,96,unchanged));
 // Local reservation counters never wrap or emit the accepted-state sentinel.
 assert(owner.begin(a,96,b,96,token));keys=expected;assert(owner.completeKeys(token,true,keys));
 for(unsigned i=0;i<0xfffe;++i)assert(owner.snapshotLocal(token,local));
 assert(!owner.snapshotLocal(token,local));assert(!local.makeLocal<Crypto>(confirm,sizeof(confirm)));
 // Destruction wipes even snapshots which outlive a cancelled exchange.
 alignas(Job) uint8_t jobStorage[sizeof(Job)];auto *held=new(jobStorage) Job;
 assert(owner.snapshotPeer(token,*held));owner.cancel();held->~Job();
 for(auto x:jobStorage)assert(x==0);
 alignas(Owner) uint8_t ownerStorage[sizeof(Owner)];auto *destroyed=new(ownerStorage) Owner;
 assert(destroyed->begin(a,96,b,96,token));keys=expected;assert(destroyed->completeKeys(token,true,keys));
 destroyed->~Owner();for(auto x:ownerStorage)assert(x==0);
}
int main(){
 checkSAEConfirmationFence();
 { uint8_t identifier[255]{},out[96];const uint8_t password[]={1},ssid[]={2};
   assert(AthSecurity::saeGroup19H2EValues<Crypto>(ssid,1,password,1,identifier,254,out,sizeof(out)));
   memset(out,0xa5,sizeof(out));
   assert(!AthSecurity::saeGroup19H2EValues<Crypto>(ssid,1,password,1,identifier,255,out,sizeof(out)));
   for(auto v:out)assert(v==0xa5);
 }
 { const uint8_t ssid[]="test-ssid",password[]="test-password",identifier[]="test-id";
   const uint8_t expected[]={249,239,103,234,204,133,139,5,13,32,186,157,203,224,93,10,220,76,193,147,96,119,105,182,73,35,87,23,97,206,85,112,99,126,163,154,183,174,116,36,195,96,182,24,61,196,224,15,143,143,121,0,176,36,28,161,23,203,147,154,176,212,168,196,232,83,250,14,196,44,227,225,81,240,25,92,61,103,133,245,136,22,105,167,192,115,215,103,166,194,255,85,199,96,166,211};uint8_t out[104];memset(out,0xa5,sizeof(out));
   assert(AthSecurity::saeGroup19H2EValues<Crypto>(ssid,9,password,13,identifier,7,out,sizeof(out)));
   assert(!memcmp(out,expected,96));for(unsigned i=96;i<104;++i)assert(out[i]==0xa5);
   for(unsigned failure=1;failure<=5;++failure){
     FailSelectedHMAC::calls=0;FailSelectedHMAC::failAt=failure;memset(out,0xa5,sizeof(out));
     assert(!AthSecurity::saeGroup19H2EValues<FailSelectedHMAC>(ssid,9,password,13,identifier,7,out,sizeof(out)));
     for(auto b:out)assert(b==0xa5);
   }
 }

 { uint8_t kck[32],sender[96],receiver[96],out[40];
   for(unsigned i=0;i<32;++i)kck[i]=uint8_t(i);
   for(unsigned i=0;i<96;++i){sender[i]=uint8_t(i);receiver[i]=uint8_t(i+96);}
   const uint8_t expected[]={184,126,183,216,119,3,244,86,114,117,139,71,138,205,83,101,76,8,242,28,124,67,73,92,60,177,170,22,221,172,109,193};
   memset(out,0xa5,sizeof(out));
   assert(AthSecurity::saeGroup19Confirm<Crypto>(kck,32,0x1234,sender,96,receiver,96,out,sizeof(out)));
   assert(!memcmp(out,expected,32));for(unsigned i=32;i<40;++i)assert(out[i]==0xa5);
   assert(AthSecurity::saeGroup19Confirm<Crypto>(kck,32,0x1234,receiver,96,sender,96,out,sizeof(out)));
   assert(memcmp(out,expected,32)); // Receive verification must reverse sender order.
   uint8_t body[34]={0x34,0x12};memcpy(body+2,out,32);uint16_t accepted=999;
   assert(AthSecurity::verifySAEGroup19PeerConfirm<Crypto>(kck,32,sender,96,receiver,96,body,34,false,0,accepted));
   assert(accepted==0x1234);accepted=999;
   assert(!AthSecurity::verifySAEGroup19PeerConfirm<Crypto>(kck,32,sender,96,receiver,96,body,34,true,0x1234,accepted));
   assert(accepted==999);
   for(unsigned i=0;i<34;++i){
     body[i]^=1;
     assert(!AthSecurity::verifySAEGroup19PeerConfirm<Crypto>(kck,32,sender,96,receiver,96,body,34,false,0,accepted));
     assert(accepted==999);body[i]^=1;
   }
   for(unsigned n=0;n<34;++n)assert(!AthSecurity::verifySAEGroup19PeerConfirm<Crypto>(kck,32,sender,96,receiver,96,body,n,false,0,accepted));
   assert(!AthSecurity::verifySAEGroup19PeerConfirm<FailedHMAC>(kck,32,sender,96,receiver,96,body,34,false,0,accepted));
   assert(accepted==999);

   memset(out,0xa5,sizeof(out));
   assert(!AthSecurity::saeGroup19Confirm<FailedHMAC>(kck,32,0x1234,sender,96,receiver,96,out,sizeof(out)));
   for(auto v:out)assert(v==0xa5);
   assert(!AthSecurity::saeGroup19Confirm<Crypto>(kck,32,0x1234,sender,95,receiver,96,out,sizeof(out)));
   for(auto v:out)assert(v==0xa5);
   AthSecurity::SAEGroup19Keys keys{};memset(&keys,0xa5,sizeof(keys));
   assert(!AthSecurity::deriveSAEGroup19Keys<FailedHMAC>(kck,32,sender,32,keys));
   for(auto v:keys.kck)assert(v==0xa5);for(auto v:keys.pmk)assert(v==0xa5);
 }

 { const uint8_t seed[]={70,189,50,6,5,197,166,182,22,58,183,11,198,52,91,146,165,249,8,231,159,229,137,121,194,62,187,71,209,165,227,7},sum[]={31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0},expected[]={102,163,87,175,244,25,116,240,42,253,178,34,5,192,113,147,77,155,22,246,64,223,237,0,85,246,163,236,26,229,218,71,88,192,240,166,231,118,241,109,25,74,4,248,23,170,117,172,218,37,25,197,199,64,145,30,122,227,221,161,84,255,70,234};
   AthSecurity::SAEGroup19Keys keys{};
   assert(AthSecurity::deriveSAEGroup19Keys<Crypto>(seed,32,sum,32,keys));
   assert(!memcmp(keys.kck,expected,32) && !memcmp(keys.pmk,expected+32,32) && !memcmp(keys.pmkid,sum,16));
   const auto previous=keys;
   for(unsigned failure:{1u,2u}){
     FailSelectedHMAC::calls=0;FailSelectedHMAC::failAt=failure;
     assert(!AthSecurity::deriveSAEGroup19Keys<FailSelectedHMAC>(seed,32,sum,32,keys));
     assert(!memcmp(&keys,&previous,sizeof(keys)));
   }

   assert(!AthSecurity::deriveSAEGroup19Keys<Crypto>(seed,31,sum,32,keys));
   assert(!memcmp(&keys,&previous,sizeof(keys)));
   AthSecurity::wipe(&keys,sizeof(keys));
 }

 { // Python hashlib/hmac fixture, shared x=77*G; no rejected-group salt.
   const uint8_t secret[]={0x58,0x21,0xb0,0x02,0xdb,0xa2,0x77,0x25,0x1a,0x9d,0x18,0xeb,0x72,0xd5,0xc7,0x20,0xf4,0xef,0xe0,0x21,0xb3,0x80,0x29,0xc0,0x17,0xd8,0x71,0x34,0x08,0x93,0xbe,0x7b};
   const uint8_t expected[]={0xa2,0x67,0x91,0x55,0x87,0xb5,0x90,0x1f,0x3d,0x9d,0xdc,0xf0,0xb8,0x9e,0xda,0x0b,0x4a,0x9c,0x21,0x22,0x10,0xf6,0x89,0x56,0xe1,0x0d,0x04,0xd0,0x66,0x16,0xe8,0xda,0x82,0xb9,0x39,0x1b,0x7d,0x38,0x22,0x8f,0xdb,0x91,0x3b,0x2d,0x58,0x75,0x47,0x38,0x0b,0xfc,0x13,0x10,0xfb,0x5c,0x63,0xb9,0xb8,0xe1,0xba,0xa2,0xd5,0x68,0xd7,0x15};
   uint8_t sum[32]{};sum[31]=26;
   uint8_t a[6]={2,0,0,0,0,2},b[6]={2,0,0,0,0,1},groups[256]{};
   AthSecurity::SAEGroup19Keys keys{};
   for(bool h2e:{false,true}){
     assert(AthSecurity::deriveSAEGroup19ExchangeKeys<Crypto>(secret,32,sum,32,h2e,a,b,nullptr,0,nullptr,0,keys));
     assert(!memcmp(keys.kck,expected,32) && !memcmp(keys.pmk,expected+32,32) && !memcmp(keys.pmkid,sum,16));
   }
   const auto previous=keys;
   for(unsigned failure:{1u,2u,3u}){
     FailSelectedHMAC::calls=0;FailSelectedHMAC::failAt=failure;
     assert(!AthSecurity::deriveSAEGroup19ExchangeKeys<FailSelectedHMAC>(secret,32,sum,32,true,a,b,nullptr,0,nullptr,0,keys));
     assert(!memcmp(&keys,&previous,sizeof(keys)));
   }
   for(size_t length:{1u,3u,255u,256u}){
     assert(!AthSecurity::deriveSAEGroup19ExchangeKeys<Crypto>(secret,32,sum,32,true,a,b,groups,length,nullptr,0,keys));
     assert(!AthSecurity::deriveSAEGroup19ExchangeKeys<Crypto>(secret,32,sum,32,true,a,b,nullptr,0,groups,length,keys));
     assert(!memcmp(&keys,&previous,sizeof(keys)));
   }
   assert(!AthSecurity::deriveSAEGroup19ExchangeKeys<Crypto>(secret,32,sum,32,false,a,b,groups,2,nullptr,0,keys));
   assert(!AthSecurity::deriveSAEGroup19ExchangeKeys<Crypto>(secret,32,sum,32,true,a,b,nullptr,2,nullptr,0,keys));
   assert(!AthSecurity::deriveSAEGroup19ExchangeKeys<Crypto>(secret,32,sum,32,true,a,a,nullptr,0,nullptr,0,keys));
   a[0]=1;assert(!AthSecurity::deriveSAEGroup19ExchangeKeys<Crypto>(secret,32,sum,32,true,a,b,nullptr,0,nullptr,0,keys));
   memset(a,0,6);assert(!AthSecurity::deriveSAEGroup19ExchangeKeys<Crypto>(secret,32,sum,32,true,a,b,nullptr,0,nullptr,0,keys));
   assert(!memcmp(&keys,&previous,sizeof(keys)));AthSecurity::wipe(&keys,sizeof(keys));
 }

 using S=AthSecurity::Supplicant<Crypto,true>;S s;
 assert(!s.begin(nullptr,s_snonce,s_sta,s_ap,s_rsn,sizeof(s_rsn),6));
 assert(s.begin(s_pmk,s_snonce,s_sta,s_ap,s_rsn,sizeof(s_rsn),6));
 uint8_t wrong[sizeof(s_m1)];memcpy(wrong,s_m1,sizeof(wrong));wrong[20]^=1;
 assert(s.receive(wrong,sizeof(wrong))==S::Ignore);
 assert(s.receive(s_m1,sizeof(s_m1))==S::Reply);
 assert(s.outputLength==sizeof(s_m2) && !memcmp(s.output,s_m2,sizeof(s_m2)));
 assert(s.receive(s_m3,sizeof(s_m3))==S::Keys);
 assert(s.outputLength==sizeof(s_m4) && !memcmp(s.output,s_m4,sizeof(s_m4)));
 assert(!memcmp(s.keys,s_ptk+32,16) && !memcmp(s.keys+16,s_gtk,16));
 assert(s.receive(s_m3,sizeof(s_m3))==S::Reply); // no reinstallation
 assert(s.receive(s_group,sizeof(s_group))==S::GroupKeys);
 assert(!memcmp(s.keys+16,s_newgtk,16));
 assert(s.outputLength==sizeof(s_groupAck) && !memcmp(s.output,s_groupAck,sizeof(s_groupAck)));
 assert(s.receive(s_group,sizeof(s_group))==S::Reply);
 assert(s.receive(s_rekey1,sizeof(s_rekey1))==S::Reply);
 assert(s.pairwisePending());
 assert(s.outputLength==sizeof(s_rekey2) && !memcmp(s.output,s_rekey2,sizeof(s_rekey2)));
 assert(s.receive(s_rekey3,sizeof(s_rekey3))==S::PairKeys);
 assert(!memcmp(s.keys,s_nextPTK+32,16));
 assert(s.outputLength==sizeof(s_rekey4) && !memcmp(s.output,s_rekey4,sizeof(s_rekey4)));
 assert(s.receive(s_rekey3,sizeof(s_rekey3))==S::Reply);
 assert(s.receive(s_m3,sizeof(s_m3))==S::Ignore);
 S bad;assert(bad.begin(s_pmk,s_snonce,s_sta,s_ap,s_rsn,sizeof(s_rsn),6));
 assert(bad.receive(s_m1,sizeof(s_m1))==S::Reply);
 uint8_t corrupt[sizeof(s_m3)];memcpy(corrupt,s_m3,sizeof(corrupt));corrupt[14+81]^=1;
 assert(bad.receive(corrupt,sizeof(corrupt))==S::Fatal);
 uint8_t mandatory[sizeof(s_rsn)];memcpy(mandatory,s_rsn,sizeof(mandatory));mandatory[20]|=0x40;
 assert(!bad.begin(s_pmk,s_snonce,s_sta,s_ap,mandatory,sizeof(mandatory),6));
 assert(!bad.begin(s_pmk,s_snonce,s_sta,s_ap,s_rsn,sizeof(s_rsn),2));
 AthSecurity::Supplicant<Crypto> legacy;assert(!legacy.begin(s_pmk,s_snonce,s_sta,s_ap,s_rsn,sizeof(s_rsn),6));
 // RFC 4493 AES-CMAC example 1 (empty message).
 const uint8_t key[]={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
 const uint8_t expected[]={0xbb,0x1d,0x69,0x29,0xe9,0x59,0x37,0x28,0x7f,0xa3,0x7d,0x12,0x9b,0x75,0x67,0x46};
 uint8_t tag[16];
 assert(!AthSecurity::SHA256Personal<Crypto>::derive(nullptr,s_snonce,tag));
 assert(!AthSecurity::SHA256Personal<Crypto>::mic(key,key,513,tag));
 assert(AthSecurity::SHA256Personal<Crypto>::mic(key,nullptr,0,tag));assert(!memcmp(tag,expected,16));
 const uint8_t block[]={0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
 const uint8_t fullTag[]={0x07,0x0a,0x16,0xb4,0x6b,0x4d,0x41,0x44,0xf7,0x9b,0xdd,0x9d,0xd0,0x4a,0x28,0x7c};
 assert(AthSecurity::SHA256Personal<Crypto>::mic(key,block,sizeof(block),tag));assert(!memcmp(tag,fullTag,16));

}

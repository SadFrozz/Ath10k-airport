#include <cassert>
#include <cstring>
#include <initializer_list>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonCryptor.h>
#include <vector>
#include "../../src/security/Ath10kWPA1KeyData.hpp"
#include "../../src/security/Ath10kSupplicant.hpp"
#include "../../src/macos/native/Ath10kNativeKeyStart.hpp"
#include "../fixtures/security_vectors.inc"
struct Crypto {
 static bool random(uint8_t *p,size_t n){for(size_t i=0;i<n;++i)p[i]=uint8_t(i+51);return true;}
 static bool hmac(const uint8_t *k,size_t kl,const uint8_t *p,size_t n,uint8_t *out){CCHmac(kCCHmacAlgSHA1,k,kl,p,n,out);return true;}
 static bool decrypt(const uint8_t *k,const uint8_t *p,uint8_t *o){size_t done=0;return CCCrypt(kCCDecrypt,kCCAlgorithmAES,kCCOptionECBMode,k,16,nullptr,p,16,o,16,&done)==kCCSuccess && done==16;}

 static bool hmacMD5(const uint8_t *k,size_t kl,const uint8_t *p,size_t n,uint8_t *out){
  CCHmac(kCCHmacAlgMD5,k,kl,p,n,out);return true;
 }
};
struct FailedCrypto:Crypto {
 static bool hmacMD5(const uint8_t *,size_t,const uint8_t *,size_t,uint8_t *out){memset(out,0x77,16);return false;}
};
struct CorruptCrypto:Crypto {
 static bool hmacMD5(const uint8_t *,size_t,const uint8_t *,size_t,uint8_t *out){memset(out,0,16);return true;}
};
// Extract the production provider wrapper; simulate binding metadata and
// delegate the primitive to CommonCrypto. This is not kernel execution evidence.
namespace ProviderFixture {
 using UInt8=uint8_t;
 struct Descriptor {size_t output_size=16,state_size=16,block_size=64;const void *initial_state=this,*compress=this,*final=this;};
 static Descriptor descriptor;static bool missing=false;static unsigned calls=0;
 static const Descriptor *ccmd5_di(){return missing?nullptr:&descriptor;}
 static void cchmac(const Descriptor *,size_t klen,const void *key,size_t length,const void *data,void *out){
  ++calls;CCHmac(kCCHmacAlgMD5,key,klen,data,length,out);
 }
 struct Production {
#include "native_hmac_md5_provider.inc"
 };
 static void test(){
  assert(AthSecurity::legacyHMACReady<Production>() && calls==1);
  uint8_t key[16]{},data[513]{},out[16];
  for(unsigned failure=0;failure<12;++failure){
   descriptor=Descriptor{};missing=failure==0;calls=0;memset(out,0xa5,sizeof(out));
   if(failure==1)descriptor.output_size=32;
   if(failure==2)descriptor.state_size=128;
   if(failure==3)descriptor.block_size=128;
   if(failure==4)descriptor.initial_state=nullptr;
   if(failure==5)descriptor.compress=nullptr;
   if(failure==6)descriptor.final=nullptr;
   assert(!Production::hmacMD5(failure==7?nullptr:key,failure==8?15:16,failure==9?nullptr:data,
      failure==10?0:failure==11?513:8,out));
   assert(!calls);for(auto c:out)assert(c==0xa5);
  }
  descriptor=Descriptor{};missing=false;assert(AthSecurity::legacyHMACReady<Production>());
 }
}
static std::vector<uint8_t> wrapGTK(const uint8_t *k,const uint8_t *key,size_t bytes){
 using namespace AthSecurity;std::vector<uint8_t> out(bytes+8);memset(out.data(),0xa6,8);memcpy(out.data()+8,key,bytes);
 for(unsigned j=0;j<6;++j)for(size_t i=1;i<=bytes/8;++i){uint8_t block[16],encrypted[16];size_t done=0;
  memcpy(block,out.data(),8);memcpy(block+8,out.data()+8*i,8);
  assert(CCCrypt(kCCEncrypt,kCCAlgorithmAES,kCCOptionECBMode,k,16,nullptr,block,16,encrypted,16,&done)==kCCSuccess && done==16);
  const uint64_t t=(bytes/8)*j+i;for(unsigned n=0;n<8;++n)out[n]=encrypted[n]^uint8_t(t>>(56-8*n));memcpy(out.data()+8*i,encrypted+8,8);
 }return out;
}
static void wpa1Handshake(){
 using namespace AthSecurity;using S=Supplicant<Crypto,false,false,true,true,true>;
 for(uint8_t akm:{1,2})for(uint8_t pair:{2,4})for(uint8_t group:{2,4})for(unsigned compatibility=0;compatibility<2;++compatibility){
  if(compatibility && !(pair==4 && group==2))continue;
  uint8_t ie[]={221,22,0,0x50,0xf2,1,1,0,0,0x50,0xf2,group,1,0,0,0x50,0xf2,pair,1,0,0,0x50,0xf2,akm};
  assert(legacyHMACReady<Crypto>() && !legacyHMACReady<FailedCrypto>() && !legacyHMACReady<CorruptCrypto>());
  Supplicant<FailedCrypto,false,false,true,true,true> failed;
  Supplicant<CorruptCrypto,false,false,true,true,true> corrupt;
  assert(!failed.beginWPA1(v_pmk,v_snonce,v_sta,v_ap,ie,sizeof(ie),akm,pair));
  assert(!corrupt.beginWPA1(v_pmk,v_snonce,v_sta,v_ap,ie,sizeof(ie),akm,pair));
  S s;Supplicant<Crypto> disabled;assert(!disabled.beginWPA1(v_pmk,v_snonce,v_sta,v_ap,ie,sizeof(ie),2,pair));
  struct State {bool secure=true,pmfRequired=false,wpa1Selected=true;uint8_t securityAKM=2,pairCipher=0,groupCipher=0;
   uint8_t local[6]{},bssid[6]{};struct {uint8_t wpa[24]{},rsn[22]{},rsnxe[18]{};size_t wpaLength=24,rsnLength=0,rsnxeLength=0;} ap;} selected;
  selected.securityAKM=akm;selected.pairCipher=pair;selected.groupCipher=group;memcpy(selected.local,v_sta,6);memcpy(selected.bssid,v_ap,6);memcpy(selected.ap.wpa,ie,24);
  selected.groupCipher=group==2?4:2;assert(!AthNative::beginMasterKey(s,selected,v_pmk,v_snonce));selected.groupCipher=group;
  selected.pmfRequired=true;assert(!AthNative::beginMasterKey(s,selected,v_pmk,v_snonce));selected.pmfRequired=false;
  assert(AthNative::beginMasterKey(s,selected,v_pmk,v_snonce));assert(s.awaitingInitialGroup());
  const uint8_t rsnxe[]={244,1,0x20};
  assert(!s.bindRSNXE(nullptr,0,false));assert(!s.bindRSNXE(rsnxe,sizeof(rsnxe),false));
  assert(!s.bindRSNXE(rsnxe,sizeof(rsnxe),true));
  uint8_t association[24];size_t associationBytes=0;assert(s.copyAssociationRSN(association,24,associationBytes));assert(associationBytes==24 && !memcmp(association,ie,24));
  const uint8_t version=pair==2?1:2,groupVersion=compatibility?1:version;const size_t pairBytes=pair==2?32:16,groupBytes=group==2?32:16;
  uint8_t m1[113];memcpy(m1,v_m1,113);m1[18]=254;put16(m1+19,0x88|version);put16(m1+21,pairBytes);
  assert(s.receive(m1,113)==S::Reply);assert(s.output[18]==254 && be16(s.output+19)==(0x108|version) && be16(s.output+21)==pairBytes);
  assert(!memcmp(s.output+113,ie,24));
  uint8_t context[76],ptk[64];memcpy(context,v_sta,6);memcpy(context+6,v_ap,6);memcpy(context+12,v_snonce,32);memcpy(context+44,m1+31,32);
  assert(deriveSHA1PTK<Crypto>(v_pmk,context,ptk,pair==2?64:48,64));assert(!memcmp(ptk,v_ptk,48));
  auto sign=[&](uint8_t *p,size_t n){uint8_t digest[20]{};memset(p+81,0,16);
   assert((be16(p+5)&7)==1?Crypto::hmacMD5(ptk,16,p,n,digest):Crypto::hmac(ptk,16,p,n,digest));memcpy(p+81,digest,16);};
  auto verify=[&](){uint8_t packet[160];const size_t n=s.outputLength-14;memcpy(packet,s.output+14,n);sign(packet,n);assert(!memcmp(packet+81,s.output+95,16));};verify();
  uint8_t gtk[32];for(unsigned i=0;i<32;++i)gtk[i]=uint8_t(80+i);
  auto groupFrame=[&](uint64_t replay,unsigned index){std::vector<uint8_t> f(113+(groupVersion==1?groupBytes:groupBytes+8));memcpy(f.data(),m1,14);auto p=f.data()+14;
   p[0]=2;p[1]=3;p[4]=254;put16(p+2,f.size()-18);put16(p+5,uint16_t(0x380|(index<<4)|groupVersion));put16(p+7,groupBytes);
   for(unsigned i=0;i<8;++i)p[16-i]=uint8_t(replay>>(8*i));for(unsigned i=0;i<16;++i)p[49+i]=uint8_t(i+1);p[65]=9;
   put16(p+97,f.size()-113);
   if(groupVersion==1)assert(decryptWPA1KeyData(p+49,ptk+16,gtk,groupBytes,p+99,groupBytes));
   else {auto wrapped=wrapGTK(ptk+16,gtk,groupBytes);memcpy(p+99,wrapped.data(),wrapped.size());}
   sign(p,f.size()-14);return f;};
  auto initial=groupFrame(3,2);assert(s.receive(initial.data(),initial.size())==S::Ignore);
  uint8_t m3[137]{};memcpy(m3,m1,113);auto p=m3+14;put16(p+2,119);put16(p+5,0x1c8|version);p[16]=2;put16(p+97,24);memcpy(p+99,ie,24);sign(p,123);
  p[81]^=1;assert(s.receive(m3,sizeof(m3))==S::Ignore && s.awaitingInitialGroup());p[81]^=1;
  assert(s.receive(m3,sizeof(m3))==S::InitialPairKeys && s.keyChanges==S::PTKChanged && s.awaitingInitialGroup());verify();
  assert(be16(s.output+19)==(0x108|version) && be16(s.output+21)==pairBytes);
  assert(!memcmp(s.keys,ptk+32,16));if(pair==2)assert(!memcmp(s.keys+56,ptk+48,16));
  assert(s.receive(m3,sizeof(m3))==S::Reply && s.awaitingInitialGroup());
  initial[95]^=1;assert(s.receive(initial.data(),initial.size())==S::Ignore && s.awaitingInitialGroup());initial[95]^=1;
  assert(s.receive(initial.data(),initial.size())==S::InitialGroupKeys && !s.awaitingInitialGroup() && s.keyChanges==S::GTKChanged);verify();
  assert(be16(s.output+19)==(0x320|groupVersion) && be16(s.output+21)==groupBytes);
  assert(!memcmp(s.keys+16,gtk,groupBytes) && s.keys[49]==2 && s.keys[50]==9);
  assert(s.receive(initial.data(),initial.size())==S::Reply);auto same=groupFrame(4,2);assert(s.receive(same.data(),same.size())==S::Reply);
  gtk[0]^=1;auto next=groupFrame(5,3);assert(s.receive(next.data(),next.size())==S::GroupKeys);verify();
  m1[30]=6;m1[31]^=1;assert(s.receive(m1,sizeof(m1))==S::Reply && s.pairwisePending());s.cancelPairwiseAttempt();
  assert(s.receive(next.data(),next.size())==S::Reply);verify();
  // A completed pairwise renewal retains the already installed GTK.
  m1[30]=7;assert(s.receive(m1,sizeof(m1))==S::Reply && s.pairwisePending());
  uint8_t renewedNonce[32];assert(Crypto::random(renewedNonce,32));
  const bool first=memcmp(renewedNonce,m1+31,32)<0;
  memcpy(context+12,first?renewedNonce:m1+31,32);memcpy(context+44,first?m1+31:renewedNonce,32);
  assert(deriveSHA1PTK<Crypto>(v_pmk,context,ptk,pair==2?64:48,64));
  memcpy(p+17,m1+31,32);p[16]=8;sign(p,123);
  assert(s.receive(m3,sizeof(m3))==S::PairKeys && s.keyChanges==S::PTKChanged && !s.awaitingInitialGroup());verify();
  assert(!memcmp(s.keys,ptk+32,16));if(pair==2)assert(!memcmp(s.keys+56,ptk+48,16));
  assert(s.keys[49]==3 && !memcmp(s.keys+16,gtk,groupBytes));
  p[16]=9;sign(p,123);assert(s.receive(m3,sizeof(m3))==S::Reply);verify();
  auto retained=groupFrame(10,3);assert(s.receive(retained.data(),retained.size())==S::Reply);
  auto moved=groupFrame(11,2);assert(s.receive(moved.data(),moved.size())==S::Fatal);
  s.reset();assert(s.receive(next.data(),next.size())==S::Ignore);
  selected.ap.wpa[23]=1;selected.securityAKM=1;assert(AthNative::beginMasterKey(s,selected,v_pmk,v_snonce));
 }
}
static void pairwiseTKIP(){
 using namespace AthSecurity;
 using S=Supplicant<Crypto,false,false,true,true>;
 uint8_t rsn[22];memcpy(rsn,v_rsn,22);rsn[7]=2;rsn[13]=2;
 Supplicant<Crypto> closed;
 assert(!closed.begin(v_pmk,v_snonce,v_sta,v_ap,rsn,22,2,nullptr,0,2));
 S s;assert(s.begin(v_pmk,v_snonce,v_sta,v_ap,rsn,22,2,nullptr,0,2));
 uint8_t assoc[22];size_t assocBytes=0;assert(s.copyAssociationRSN(assoc,22,assocBytes));
 assert(assocBytes==22 && !memcmp(assoc,rsn,22));
 uint8_t m1[sizeof(v_m1)];memcpy(m1,v_m1,sizeof(m1));put16(m1+19,0x89);put16(m1+21,32);
 assert(s.receive(m1,sizeof(m1))==S::Reply);
 uint8_t context[76],ptk[64];memcpy(context,v_sta,6);memcpy(context+6,v_ap,6);
 memcpy(context+12,v_snonce,32);memcpy(context+44,m1+31,32);
 assert(deriveSHA1PTK<Crypto>(v_pmk,context,ptk,64,64));assert(!memcmp(ptk,v_ptk,48));
 auto verify=[&](){uint8_t packet[160],mic[16];size_t n=s.outputLength-14;
  memcpy(packet,s.output+14,n);memset(packet+81,0,16);assert(Crypto::hmacMD5(ptk,16,packet,n,mic));
  assert(!memcmp(mic,s.output+95,16));};verify();
 uint8_t plain[62]{};memcpy(plain,rsn,22);
 const uint8_t kde[]={221,38,0,15,172,1,1,0};memcpy(plain+22,kde,8);
 for(unsigned i=0;i<32;++i)plain[30+i]=uint8_t(80+i);
 uint8_t frame[175]{};memcpy(frame,m1,14);auto p=frame+14;
 p[0]=2;p[1]=3;p[4]=2;put16(p+2,157);put16(p+5,0x13c9);put16(p+7,32);p[16]=2;
 memcpy(p+17,m1+31,32);put16(p+97,62);
 for(unsigned i=0;i<16;++i)p[49+i]=uint8_t(i+1);
 assert(decryptWPA1KeyData(p+49,ptk+16,plain,62,p+99,62));
 auto sign=[&](){memset(p+81,0,16);assert(Crypto::hmacMD5(ptk,16,p,161,p+81));};sign();
 p[81]^=1;assert(s.receive(frame,sizeof(frame))==S::Fatal);p[81]^=1;
 assert(s.receive(frame,sizeof(frame))==S::Keys);verify();
 assert(!memcmp(s.keys,ptk+32,16) && !memcmp(s.keys+56,ptk+48,16));
 assert(!memcmp(s.keys+16,plain+30,32));assert(s.keys[48]==2 && s.keys[49]==1);
 assert(s.receive(frame,sizeof(frame))==S::Reply);verify();
 for(bool pairwise:{false,true}){
  uint8_t report[113],packet[99],mic[16];size_t bytes=0;
  assert(s.buildMICFailureReport(report,sizeof(report),bytes,pairwise) && bytes==113);
  assert(be16(report+19)==(pairwise?0xf09:0xf01));
  memcpy(packet,report+14,99);memset(packet+81,0,16);
  assert(Crypto::hmacMD5(ptk,16,packet,99,mic) && !memcmp(mic,report+95,16));
 }
 // A candidate pairwise exchange cannot truncate the retained 64-byte PTK.
 m1[30]=3;m1[31]^=1;assert(s.receive(m1,sizeof(m1))==S::Reply);assert(s.pairwisePending());
 s.cancelPairwiseAttempt();assert(!s.pairwisePending());
 assert(s.receive(frame,sizeof(frame))==S::Reply);verify();
 p[16]=4;sign();assert(s.receive(frame,sizeof(frame))==S::Reply);verify();
 // Complete the next pairwise exchange and export both Michael subkeys.
 m1[30]=5;assert(s.receive(m1,sizeof(m1))==S::Reply);
 uint8_t nextNonce[32];assert(Crypto::random(nextNonce,32));
 const bool nonceFirst=memcmp(nextNonce,m1+31,32)<0;
 memcpy(context+12,nonceFirst?nextNonce:m1+31,32);memcpy(context+44,nonceFirst?m1+31:nextNonce,32);
 assert(deriveSHA1PTK<Crypto>(v_pmk,context,ptk,64,64));
 p[16]=6;memcpy(p+17,m1+31,32);
 assert(decryptWPA1KeyData(p+49,ptk+16,plain,62,p+99,62));sign();
 assert(s.receive(frame,sizeof(frame))==S::PairKeys);verify();
 assert(!memcmp(s.keys,ptk+32,16) && !memcmp(s.keys+56,ptk+48,16));
 assert(s.keyChanges==S::PTKChanged); // Retained GTK must not be reinstalled.
 uint8_t groupFrame[153]{};memcpy(groupFrame,frame,113);auto gp=groupFrame+14;
 put16(gp+2,135);put16(gp+5,0x1381);put16(gp+97,40);gp[16]=7;
 plain[28]=2;plain[30]^=1;
 assert(decryptWPA1KeyData(gp+49,ptk+16,plain+22,40,gp+99,40));
 memset(gp+81,0,16);assert(Crypto::hmacMD5(ptk,16,gp,139,gp+81));
 assert(s.receive(groupFrame,sizeof(groupFrame))==S::GroupKeys);verify();
 assert(s.keys[49]==2 && !memcmp(s.keys+16,plain+30,32));
 assert(s.receive(groupFrame,sizeof(groupFrame))==S::Reply);verify();
 s.reset();assert(s.receive(frame,sizeof(frame))==S::Ignore);
 rsn[19]=1;assert(s.begin(v_pmk,v_snonce,v_sta,v_ap,rsn,22,1,nullptr,0,2));
 rsn[20]=0xc0;assert(!s.begin(v_pmk,v_snonce,v_sta,v_ap,rsn,22,1,nullptr,0,2));
}
int main(){
 ProviderFixture::test();
 wpa1Handshake();
 pairwiseTKIP();
 using namespace AthSecurity;
 uint8_t kck[16],kek[16],p[131]{},out[33];memset(kck,0x0b,16);memset(kek,0x55,16);
 // RFC2202 case1 independently checks the provider selected for these fixtures.
 const uint8_t answer[]={0x92,0x94,0x72,0x7a,0x36,0x38,0xbb,0x1c,0x13,0xf4,0x8e,0xf8,0x15,0x8b,0xfc,0x9d};
 assert(Crypto::hmacMD5(kck,16,reinterpret_cast<const uint8_t *>("Hi There"),8,out));assert(!memcmp(out,answer,16));
 p[0]=1;p[1]=3;p[4]=254;put16(p+2,sizeof(p)-4);put16(p+5,0x301);put16(p+97,32);
 for(unsigned i=0;i<16;++i)p[49+i]=uint8_t(i);
 uint8_t plaintext[32];for(unsigned i=0;i<32;++i)plaintext[i]=uint8_t(0x80+i);
 assert(decryptWPA1KeyData(p+49,kek,plaintext,32,p+99,32));
 assert(Crypto::hmacMD5(kck,16,p,sizeof(p),p+81));
 memset(out,0x5a,sizeof(out));assert(authenticateWPA1KeyData<Crypto>(kck,kek,p,sizeof(p),out,32));
 assert(!memcmp(out,plaintext,32) && out[32]==0x5a);
 // Every authenticated octet matters, including IV and ciphertext. Failures
 // must leave output untouched, even if the crypto provider dirties its buffer.
 for(unsigned i=0;i<sizeof(p);++i){
  p[i]^=1;memset(out,0x5a,sizeof(out));
  assert(!authenticateWPA1KeyData<Crypto>(kck,kek,p,sizeof(p),out,32));
  for(auto b:out)assert(b==0x5a);p[i]^=1;
 }
 assert(!authenticateWPA1KeyData<FailedCrypto>(kck,kek,p,sizeof(p),out,32));
 assert(!authenticateWPA1KeyData<Crypto>(kck,kek,p,sizeof(p),out,31));
 for(auto b:out)assert(b==0x5a);
 for(size_t n=0;n<sizeof(p);++n)assert(!authenticateWPA1KeyData<Crypto>(kck,kek,p,n,out,32));
 // Raw WPA1 GTK decoding is transactional and distinct from an RSN KDE.
 auto sign=[&](){memset(p+81,0,16);assert(Crypto::hmacMD5(kck,16,p,sizeof(p),p+81));};
 put16(p+5,0x3b1);put16(p+7,32);p[16]=7;p[65]=0x42;sign();
 WPA1GroupKey group;
 assert(decodeWPA1GroupKey<Crypto>(kck,kek,p,sizeof(p),cipherTKIP,6,group));
 assert(group.index==3 && group.replay==7 && group.rsc[0]==0x42 && !group.transmit);
 assert(!memcmp(group.key,plaintext,32));
 uint8_t snapshot[sizeof(group)];memcpy(snapshot,&group,sizeof(group));
 assert(!decodeWPA1GroupKey<Crypto>(kck,kek,p,sizeof(p),cipherTKIP,7,group));
 assert(!decodeWPA1GroupKey<FailedCrypto>(kck,kek,p,sizeof(p),cipherTKIP,6,group));
 assert(!decodeWPA1GroupKey<Crypto>(kck,kek,p,sizeof(p),cipherCCMP,6,group));
 for(unsigned bit:{3u,10u,11u,12u,13u,14u,15u}){
  put16(p+5,uint16_t(0x3b1|(1u<<bit)));sign();
  assert(!decodeWPA1GroupKey<Crypto>(kck,kek,p,sizeof(p),cipherTKIP,6,group));
 }
 put16(p+5,0x3b1);p[71]=1;sign();
 assert(!decodeWPA1GroupKey<Crypto>(kck,kek,p,sizeof(p),cipherTKIP,6,group));
 p[71]=0;sign();
 for(size_t n=0;n<sizeof(p);++n)
  assert(!decodeWPA1GroupKey<Crypto>(kck,kek,p,n,cipherTKIP,6,group));
 assert(!memcmp(&group,snapshot,sizeof(group)));
 // Exercise every legal index/optional flag combination with a CCMP GTK
 // transported using the WPA1 version-1 group descriptor.
 uint8_t shortFrame[115]{};memcpy(shortFrame,p,99);
 put16(shortFrame+2,111);put16(shortFrame+7,16);put16(shortFrame+97,16);
 assert(decryptWPA1KeyData(shortFrame+49,kek,plaintext,16,shortFrame+99,16));
 for(unsigned flags=0;flags<16;++flags){
  put16(shortFrame+5,uint16_t(0x181|((flags&3)<<4)|((flags&4)?0x40:0)|((flags&8)?0x200:0)));
  memset(shortFrame+81,0,16);assert(Crypto::hmacMD5(kck,16,shortFrame,sizeof(shortFrame),shortFrame+81));
  assert(decodeWPA1GroupKey<Crypto>(kck,kek,shortFrame,sizeof(shortFrame),cipherCCMP,6,group));
  assert(group.index==(flags&3) && group.transmit==bool(flags&4));
  assert(!memcmp(group.key,plaintext,16));for(unsigned i=16;i<32;++i)assert(group.key[i]==0);
 }
 for(unsigned required:{0x80u,0x100u}){
  put16(shortFrame+5,uint16_t(0x181&~required));
  memset(shortFrame+81,0,16);assert(Crypto::hmacMD5(kck,16,shortFrame,sizeof(shortFrame),shortFrame+81));
  assert(!decodeWPA1GroupKey<Crypto>(kck,kek,shortFrame,sizeof(shortFrame),cipherCCMP,6,group));
 }
 assert(!decodeWPA1GroupKey<Crypto>(kck,kek,nullptr,131,cipherTKIP,6,group));
 uint8_t saved[sizeof(p)];memcpy(saved,p,sizeof(p));
 assert(authenticateWPA1KeyData<Crypto>(kck,kek,p,sizeof(p),p+99,32));
 assert(!memcmp(p+99,plaintext,32) && !memcmp(p,saved,99));
}

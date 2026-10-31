#include <cassert>
#include <cstring>
#include <initializer_list>
#include <CommonCrypto/CommonCryptor.h>
#include "../../src/security/Ath10kWEPAuth.hpp"
static void lifecycle(){
 using A=AthSecurity::WEPSharedAuthentication;
 uint8_t station[6]={2,0,0,0,0,1},peer[6]={2,0,0,0,0,2},key[13]{},iv[3]={1,2,3};
 uint8_t challenge[9]={1,0,2,0,0,0,16,1,0x42},done[6]={1,0,4,0,0,0};
 A a;assert(a.begin(7,station,peer,key,13,2,iv,100,1000));
 assert(!a.receive(7,station,peer,challenge,9,101));assert(a.requestSubmitted());
 assert(!a.receive(8,station,peer,challenge,9,101));
 assert(!a.receive(7,peer,station,challenge,9,101));
 assert(!a.receive(7,station,peer,done,6,101));
 assert(a.receive(7,station,peer,challenge,9,101));
 size_t bytes=0;const auto *r=a.response(7,station,peer,102,bytes);assert(r && bytes==17);
 uint8_t saved[17];memcpy(saved,r,17);
 assert(a.receive(7,station,peer,challenge,9,103));assert(!memcmp(r,saved,17));
 challenge[8]^=1;assert(!a.receive(7,station,peer,challenge,9,104));assert(!memcmp(r,saved,17));
 assert(!a.receive(7,station,peer,done,6,105));assert(a.responseSubmitted());
 assert(a.receive(7,station,peer,done,6,105));assert(a.state()==A::State::Complete);
 assert(!a.response(7,station,peer,106,bytes) && !bytes);
 assert(a.begin(8,station,peer,key,5,0,iv,200,300));assert(a.requestSubmitted());
 assert(!a.poll(199) && a.state()==A::State::Failed);
 assert(!a.receive(8,station,peer,challenge,9,210));
 assert(a.begin(9,station,peer,key,5,0,iv,200,300));assert(!a.poll(300));
 iv[0]=3;iv[1]=255;assert(!a.begin(10,station,peer,key,5,0,iv,200,300));
}
int main(){
 lifecycle();
 uint8_t key[13],iv[3]={1,2,3},body[263]{1,0,3,0,0,0,16,0},out[272],decoded[267],seed[16];
 for(unsigned n=0;n<13;++n)key[n]=uint8_t(n+4);
 for(size_t keyBytes:{size_t(5),size_t(13)})for(unsigned challenge:{1u,128u,255u})for(unsigned index=0;index<4;++index){
  body[7]=challenge;for(unsigned n=0;n<challenge;++n)body[8+n]=uint8_t(n^0xa5);
  const size_t bytes=challenge+8;memset(out,0x5a,sizeof(out));
  assert(AthSecurity::encryptWEPAuthentication(key,keyBytes,iv,index,body,bytes,out,sizeof(out))==bytes+8);
  assert(!memcmp(out,iv,3) && out[3]==index<<6 && out[bytes+8]==0x5a);
  memcpy(seed,iv,3);memcpy(seed+3,key,keyBytes);size_t written=0;
  assert(CCCrypt(kCCDecrypt,kCCAlgorithmRC4,0,seed,keyBytes+3,nullptr,out+4,bytes+4,decoded,sizeof(decoded),&written)==kCCSuccess);
  assert(written==bytes+4 && !memcmp(decoded,body,bytes));
  // Independent bitwise polynomial division, MSB-first reflected octets.
  uint32_t crc=0xffffffff;
  for(size_t n=0;n<bytes;++n){uint8_t v=body[n];for(unsigned b=0;b<8;++b){
   const bool high=bool(crc>>31)^bool(v&1);crc<<=1;if(high)crc^=0x04c11db7;v>>=1;
  }}
  uint32_t reflected=0;for(unsigned n=0;n<32;++n)reflected|=((~crc>>n)&1)<<(31-n);
  for(unsigned n=0;n<4;++n)assert(decoded[bytes+n]==uint8_t(reflected>>(8*n)));
  memset(out,0x5a,sizeof(out));
  for(size_t cap=0;cap<bytes+8;++cap)assert(!AthSecurity::encryptWEPAuthentication(key,keyBytes,iv,index,body,bytes,out,cap));
  for(unsigned at:{0u,1u,2u,3u,4u,5u,6u,7u}){body[at]^=0xff;
   assert(!AthSecurity::encryptWEPAuthentication(key,keyBytes,iv,index,body,bytes,out,sizeof(out)));body[at]^=0xff;
  }
  for(auto byte:out)assert(byte==0x5a);
  assert(!AthSecurity::encryptWEPAuthentication(key,keyBytes,iv,4,body,bytes,out,sizeof(out)));
  assert(!AthSecurity::encryptWEPAuthentication(key,keyBytes,iv,index,body,bytes,body,sizeof(body)));
  assert(!AthSecurity::encryptWEPAuthentication(key,7,iv,index,body,bytes,out,sizeof(out)));
 }
}

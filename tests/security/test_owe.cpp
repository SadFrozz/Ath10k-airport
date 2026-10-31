#include <cassert>
#include <initializer_list>
#include <cstring>
#include <CommonCrypto/CommonDigest.h>
#include "../support/common_crypto_personal.hpp"
#include "../../src/security/Ath10kOWE.hpp"
struct Crypto:PersonalTestCrypto {
 static inline unsigned calls=0,fail=0;
 static bool hmac256(const uint8_t *k,size_t n,const uint8_t *d,size_t l,uint8_t *o){
  if(++calls==fail){memset(o,0xaa,32);return false;}return PersonalTestCrypto::hmac256(k,n,d,l,o);
 }
 static bool hash256(const uint8_t *d,size_t n,uint8_t *o){
  if(++calls==fail){memset(o,0xaa,32);return false;}return CC_SHA256(d,CC_LONG(n),o)!=nullptr;
 }
};
int main(){
 uint8_t c[32],a[32],z[32];for(unsigned i=0;i<32;++i){c[i]=i;a[i]=i+32;z[i]=i+64;}
 // Independent Python hashlib/HMAC calculation, not an ECDH test vector.
 const uint8_t expectedPMK[32]={0xe5,0xb9,0x3a,0x86,0xd0,0x73,0xf4,0x2e,0xf8,0x9a,0x2b,0x54,0x1b,0xd8,0xce,0x4a,0xe9,0x33,0x6a,0x50,0x86,0xd1,0xac,0xce,0xc6,0xb9,0x1c,0x8e,0x8f,0x1f,0x8d,0x0d};
 const uint8_t expectedID[16]={0xfd,0xea,0xb9,0xac,0xf3,0x71,0x03,0x62,0xbd,0x26,0x58,0xcd,0xc9,0xa2,0x9e,0x8f};
 AthSecurity::OWEGroup19Keys keys{};
 assert(AthSecurity::deriveOWEGroup19Keys<Crypto>(c,32,a,32,z,32,keys));
 assert(!memcmp(keys.pmk,expectedPMK,32) && !memcmp(keys.pmkid,expectedID,16));
 auto original=keys;
 for(unsigned fault=1;fault<=3;++fault){Crypto::calls=0;Crypto::fail=fault;
  assert(!AthSecurity::deriveOWEGroup19Keys<Crypto>(c,32,a,32,z,32,keys));assert(!memcmp(&keys,&original,sizeof(keys)));}
 Crypto::fail=0;
 assert(AthSecurity::deriveOWEGroup19Keys<Crypto>(a,32,c,32,z,32,keys));
 assert(memcmp(keys.pmk,expectedPMK,32) && memcmp(keys.pmkid,expectedID,16));
 keys=original;
 for(unsigned size:{0u,31u,33u}){
  assert(!AthSecurity::deriveOWEGroup19Keys<Crypto>(c,size,a,32,z,32,keys));
  assert(!AthSecurity::deriveOWEGroup19Keys<Crypto>(c,32,a,size,z,32,keys));
  assert(!AthSecurity::deriveOWEGroup19Keys<Crypto>(c,32,a,32,z,size,keys));
  assert(!memcmp(&keys,&original,sizeof(keys)));
 }
 uint8_t ie[38]{};assert(AthSecurity::encodeOWEGroup19Parameter(c,32,ie,sizeof(ie)));
 AthSecurity::OWEGroup19Parameter view{};assert(AthSecurity::decodeOWEGroup19Parameter(ie,37,view));
 assert(view.x==ie+5 && !memcmp(view.x,c,32));
 for(unsigned n=0;n<37;++n)assert(!AthSecurity::decodeOWEGroup19Parameter(ie,n,view) && !view.x);
 assert(!AthSecurity::decodeOWEGroup19Parameter(ie,38,view));
 for(unsigned field=0;field<5;++field){ie[field]^=1;assert(!AthSecurity::decodeOWEGroup19Parameter(ie,37,view) && !view.x);ie[field]^=1;}
 uint8_t before[38];memcpy(before,ie,38);assert(!AthSecurity::encodeOWEGroup19Parameter(c,32,ie,36));assert(!memcmp(ie,before,38));
 // Encoder supports overlap without corrupting the borrowed public value.
 memcpy(ie,c,32);assert(AthSecurity::encodeOWEGroup19Parameter(ie,32,ie,38));assert(!memcmp(ie+5,c,32));
}

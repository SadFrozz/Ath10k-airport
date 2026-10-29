#include <cassert>
#include <cstring>
#include <vector>
#include "common_crypto_personal.hpp"
#include "../src/shared/Ath10kPSKPassword.hpp"
struct Crypto : PersonalTestCrypto {
 static inline unsigned calls=0,fail=0;
 static bool hmac(const uint8_t *k,size_t n,const uint8_t *d,size_t bytes,uint8_t *out){++calls;return calls!=fail && PersonalTestCrypto::hmac(k,n,d,bytes,out);}
};
static std::vector<uint8_t> unhex(const char *p){std::vector<uint8_t> v(strlen(p)/2);for(size_t i=0;i<v.size();++i)v[i]=uint8_t(AthSecurity::pskHex(p[2*i])*16+AthSecurity::pskHex(p[2*i+1]));return v;}
int main(){
 // Independent Python hashlib/OpenSSL PBKDF2 vectors; public synthetic inputs.
 const char *vectors[][3]={
 {"70617373776f7264","49454545","f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"},
 {"5468697349734150617373776f7264","5468697349734153534944","0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af"},
 {"616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161","000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","3a2e67a2d5bf4c1c1e6aafe849e2e8f31a0f570f5c60cc8e6846cbba2793d0e3"},
 {"0061626300646566","006162630078797a","17f1d95bf96e386b05e1990e042677888551119004c9aaf754b32233a1d4aa87"},
 };
 for(const auto &v:vectors){auto password=unhex(v[0]),name=unhex(v[1]),expected=unhex(v[2]);uint8_t result[32]{};
  Crypto::calls=0;assert(AthSecurity::pskFromPassword<Crypto>(password.data(),password.size(),name.data(),name.size(),result));
  assert(!memcmp(result,expected.data(),32) && Crypto::calls==8192);
  for(unsigned fail:{1u,4096u,4097u,8192u}){Crypto::calls=0;Crypto::fail=fail;memset(result,0xa5,32);
   assert(!AthSecurity::pskFromPassword<Crypto>(password.data(),password.size(),name.data(),name.size(),result));
   assert(Crypto::calls==fail);for(auto c:result)assert(c==0xa5);
  }Crypto::fail=0;
 }
 const auto key=unhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
 const uint8_t hex[]="0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef",name[]="test";uint8_t result[32]{};
 Crypto::calls=0;assert(AthSecurity::pskFromPassword<Crypto>(hex,64,name,4,result) && !memcmp(result,key.data(),32) && !Crypto::calls);
 for(size_t bytes:{0u,7u,65u}){memset(result,0xa5,32);assert(!AthSecurity::pskFromPassword<Crypto>(hex,bytes,name,4,result));for(auto c:result)assert(c==0xa5);}
 uint8_t bad[64]{};memcpy(bad,hex,64);bad[63]='g';assert(!AthSecurity::pskFromPassword<Crypto>(bad,64,name,4,result));
 assert(!AthSecurity::pskFromPassword<Crypto>(hex,8,name,0,result));assert(!AthSecurity::pskFromPassword<Crypto>(hex,8,name,33,result));
}

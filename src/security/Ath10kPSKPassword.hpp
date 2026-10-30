#pragma once
#include "Ath10kSecurity.hpp"
namespace AthSecurity {
inline int pskHex(uint8_t c){return c>='0' && c<='9'?c-'0':c>='a' && c<='f'?c-'a'+10:c>='A' && c<='F'?c-'A'+10:-1;}
inline bool validPSKPassword(const uint8_t *password,size_t bytes){
 if(!password || bytes<8 || bytes>64)return false;
 if(bytes==64){for(size_t i=0;i<bytes;++i)if(pskHex(password[i])<0)return false;}
 return true;
}
// WPA/WPA2 PSK uses PBKDF2-HMAC-SHA1 even when the negotiated AKM uses SHA256.
// Run on the retained crypto worker. Failure leaves the caller's output intact.
template<class Crypto> bool pskFromPassword(const uint8_t *password,size_t bytes,
 const uint8_t *ssid,size_t ssidBytes,uint8_t *out){
 if(!out || !ssid || !ssidBytes || ssidBytes>32 || !validPSKPassword(password,bytes))return false;
 uint8_t key[32]{},salt[36]{},u[20]{},next[20]{},block[20]{};bool ok=true;
 if(bytes==64){for(unsigned i=0;i<32;++i)key[i]=uint8_t(pskHex(password[2*i])*16+pskHex(password[2*i+1]));}
 else {
  copy(salt,ssid,ssidBytes);
  for(unsigned number=1;number<=2 && ok;++number){
   salt[ssidBytes+3]=uint8_t(number);ok=Crypto::hmac(password,bytes,salt,ssidBytes+4,u);
   if(!ok)break;copy(block,u,20);
   for(unsigned iteration=1;iteration<4096;++iteration){
    if(!Crypto::hmac(password,bytes,u,20,next)){ok=false;break;}
    copy(u,next,20);for(unsigned i=0;i<20;++i)block[i]^=u[i];
   }
   if(ok)copy(key+(number-1)*20,block,number==1?20:12);
  }
 }
 if(ok)copy(out,key,32);
 wipe(key,sizeof(key));wipe(salt,sizeof(salt));wipe(u,sizeof(u));wipe(next,sizeof(next));wipe(block,sizeof(block));return ok;
}
}

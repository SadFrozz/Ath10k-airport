#pragma once
#include "Ath10kSecurity.hpp"
namespace AthSecurity {
// IEEE 802.11 SHA256 KDF and RFC 4493 AES-CMAC. The provider supplies
// HMAC-SHA256 and single-block AES encryption; no keys leave the provider.
template<class Crypto> struct SHA256Personal {
 static bool derive(const uint8_t *pmk,const uint8_t *context,uint8_t *ptk){
  if(!pmk || !context || !ptk)return false;
  static constexpr char label[]="Pairwise key expansion";
  uint8_t input[2+sizeof(label)-1+76+2]{},digest[32]{};
  copy(input+2,reinterpret_cast<const uint8_t *>(label),sizeof(label)-1);
  copy(input+2+sizeof(label)-1,context,76);
  input[sizeof(input)-2]=0x80;input[sizeof(input)-1]=1; // 384 bits LE
  bool ok=true;
  for(unsigned block=1;block<=2;++block){input[0]=uint8_t(block);
   if(!Crypto::hmac256(pmk,32,input,sizeof(input),digest)){ok=false;break;}
   copy(ptk+(block-1)*32,digest,block==1?32:16);
  }
  wipe(input,sizeof(input));wipe(digest,sizeof(digest));if(!ok)wipe(ptk,48);return ok;
 }
 static void doubleBlock(uint8_t *p){
  const uint8_t carry=p[0]>>7;
  for(unsigned i=0;i<15;++i)p[i]=uint8_t((p[i]<<1)|(p[i+1]>>7));
  p[15]=uint8_t(p[15]<<1);p[15]^=uint8_t(0x87 & uint8_t(0-carry));
 }
 static bool mic(const uint8_t *key,const uint8_t *data,size_t length,uint8_t *out){
  if(!key || !out || (!data && length) || length>512)return false;
  uint8_t sub[16]{},state[16]{},block[16]{};
  bool ok=Crypto::encrypt(key,state,sub);doubleBlock(sub);
  const size_t blocks=length?(length+15)/16:1;
  for(size_t i=0;i+1<blocks && ok;++i){
   for(unsigned j=0;j<16;++j)block[j]=state[j]^data[16*i+j];
   ok=Crypto::encrypt(key,block,state);
  }
  if(ok){
   const size_t tail=length-16*(blocks-1);wipe(block,16);
   if(tail)copy(block,data+16*(blocks-1),tail);
   if(tail!=16){doubleBlock(sub);block[tail]=0x80;}
   for(unsigned j=0;j<16;++j)block[j]^=state[j]^sub[j];
   ok=Crypto::encrypt(key,block,out);
  }
  wipe(sub,16);wipe(state,16);wipe(block,16);if(!ok)wipe(out,16);return ok;
 }
};
}

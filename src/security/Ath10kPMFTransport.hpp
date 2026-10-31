#pragma once
#include "Ath10kPMFCCMP.hpp"
namespace AthSecurity {
// Explicit representation: hardware PMF carries plaintext plus an eight-byte
// MIC slot, whereas software PMF already carries ciphertext and a valid tag.
enum class ManagementTX : uint8_t {Plain,HardwareCCMP,SoftwareCCMP,SoftwareWEPAuthentication};
struct PMFHardwareCCMP {
private:
 static bool overlap(const void *a,size_t n,const void *b,size_t m){
  const uintptr_t x=reinterpret_cast<uintptr_t>(a),y=reinterpret_cast<uintptr_t>(b);
  return x<=y?y-x<n:x-y<m;
 }
 static uint64_t packetNumber(const uint8_t *frame){
  return uint64_t(frame[24])|(uint64_t(frame[25])<<8)|(uint64_t(frame[28])<<16)|
   (uint64_t(frame[29])<<24)|(uint64_t(frame[30])<<32)|(uint64_t(frame[31])<<40);
 }
public:
 static bool prepare(const uint8_t *frame,size_t bytes,const uint8_t *local,const uint8_t *ap,uint64_t pn,PMFCCMPResult &out){
  if(!frame || !local || !ap || bytes<26 || bytes>496 || !pn || pn>0xffffffffffffull ||
     overlap(frame,bytes,&out,sizeof(out)) || overlap(local,6,&out,sizeof(out)) || overlap(ap,6,&out,sizeof(out)) ||
     !pmfCCMPHeader(frame,bytes,local,ap,false) || !pmfRobustBody(frame,bytes))return false;
  // All validation precedes output mutation. No crypto or fallible work follows.
  wipe(out.frame,sizeof(out.frame));copy(out.frame,frame,24);
  out.frame[24]=uint8_t(pn);out.frame[25]=uint8_t(pn>>8);out.frame[27]=0x20;
  for(unsigned i=0;i<4;++i)out.frame[28+i]=uint8_t(pn>>(16+8*i));
  copy(out.frame+32,frame+24,bytes-24);out.bytes=bytes+16;out.pn=pn;return true;
 }
 static bool valid(const uint8_t *frame,size_t bytes,const uint8_t *local,const uint8_t *ap){
  if(!frame || bytes<42 || bytes>512 || !pmfCCMPHeader(frame,bytes,local,ap,false) ||
     frame[26] || frame[27]!=0x20 || !packetNumber(frame))return false;
  if((frame[0]&0xf0)==0xd0 && !robustManagementActionCategory(frame[32]))return false;
  for(unsigned i=0;i<8;++i)if(frame[bytes-8+i])return false;
  return true;
 }
};
}

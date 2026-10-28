#pragma once
#include "Ath10kSAQuery.hpp"
namespace AthSecurity {
// Supported nonfragmented 24-byte-header unicast robust management profile.
// No FCS, HT Control, CCMP-256, GCMP, group protection or extended key IDs.
inline bool pmfCCMPHeader(const uint8_t *f,size_t n,const uint8_t *local,const uint8_t *ap,bool fromAP){
 if(!f || n<26 || !saQueryIdentities(local,ap))return false;
 const uint16_t fc=le16(f),kind=fc&0xc7ff;
 return (kind==0x40c0 || kind==0x40a0 || kind==0x40d0) && !(le16(f+22)&15) &&
  equal(f+4,fromAP?local:ap,6) && equal(f+10,fromAP?ap:local,6) && equal(f+16,ap,6);
}
inline bool pmfRobustBody(const uint8_t *f,size_t n){
 if(n<26)return false;
 if((f[0]&0xf0)!=0xd0)return true;
 switch(f[24]){case 4:case 7:case 11:case 15:case 20:case 21:case 22:case 127:return false;default:return true;}
}
struct PMFCCMPResult {
 uint8_t frame[512]{};size_t bytes=0;uint64_t pn=0;
 ~PMFCCMPResult(){wipe(this,sizeof(*this));}
};
struct PMFCCMPWorkspace {
 uint8_t candidate[512]{},block[16]{},state[16]{},counter[16]{},stream[16]{},aad[32]{};
 PMFCCMPWorkspace()=default;
 PMFCCMPWorkspace(const PMFCCMPWorkspace &)=delete;
 PMFCCMPWorkspace &operator=(const PMFCCMPWorkspace &)=delete;
 void clear(){wipe(this,sizeof(*this));}
 ~PMFCCMPWorkspace(){clear();}
};
// Crypto supplies AES-128 single-block encrypt, supporting distinct in/out.
// All buffers, output and workspace must be disjoint. This does not perform I/O
// or commit replay state. Caller snapshots an acknowledged PTK epoch off-gate,
// then rechecks/commits that epoch and PN under its owner gate after success.
template<class Crypto> struct PMFCCMP128 {
 enum class RXLayout : uint8_t {Ciphertext,PlaintextWithEncryptedTag};
private:
 struct Clear {PMFCCMPWorkspace &w;~Clear(){w.clear();}};
 static bool overlaps(const void *a,size_t n,const void *b,size_t m){
  const uintptr_t x=reinterpret_cast<uintptr_t>(a),y=reinterpret_cast<uintptr_t>(b);
  return x<=y?y-x<n:x-y<m;
 }
 static bool disjoint(const uint8_t *frame,size_t bytes,const uint8_t *key,const uint8_t *local,const uint8_t *ap,
    const PMFCCMPResult &out,const PMFCCMPWorkspace &w){
  const void *inputs[]={frame,key,local,ap};const size_t lengths[]={bytes,16,6,6};
  if(overlaps(&out,sizeof(out),&w,sizeof(w)))return false;
  for(unsigned i=0;i<4;++i)if(overlaps(inputs[i],lengths[i],&out,sizeof(out)) || overlaps(inputs[i],lengths[i],&w,sizeof(w)))return false;
  return true;
 }
 static void init(PMFCCMPWorkspace &w,const uint8_t *header,uint64_t pn,size_t body){
  w.block[0]=0x59;w.block[1]=0x10;copy(w.block+2,header+10,6);
  for(unsigned i=0;i<6;++i)w.block[8+i]=uint8_t(pn>>(8*(5-i)));
  w.block[14]=uint8_t(body>>8);w.block[15]=uint8_t(body);
  w.counter[0]=1;copy(w.counter+1,w.block+1,13);
  w.aad[1]=22;const uint16_t masked=uint16_t(le16(header)&~0x3800u);
  w.aad[2]=uint8_t(masked);w.aad[3]=uint8_t(masked>>8);copy(w.aad+4,header+4,18);
  // Sequence number is masked; fragmentation was rejected at admission.
 }
 static bool mac(PMFCCMPWorkspace &w,const uint8_t *key,const uint8_t *plain,size_t bytes){
  if(!Crypto::encrypt(key,w.block,w.state))return false;
  for(unsigned i=0;i<2;++i){
   for(unsigned j=0;j<16;++j)w.block[j]=w.state[j]^w.aad[16*i+j];
   if(!Crypto::encrypt(key,w.block,w.state))return false;
  }
  for(size_t at=0;at<bytes;at+=16){
   for(unsigned j=0;j<16;++j)w.block[j]=w.state[j]^(at+j<bytes?plain[at+j]:0);
   if(!Crypto::encrypt(key,w.block,w.state))return false;
  }
  w.counter[14]=w.counter[15]=0;
  if(!Crypto::encrypt(key,w.counter,w.stream))return false;
  for(unsigned i=0;i<8;++i)w.state[i]^=w.stream[i];
  return true;
 }
 static bool crypt(PMFCCMPWorkspace &w,const uint8_t *key,const uint8_t *in,uint8_t *out,size_t bytes){
  for(size_t at=0;at<bytes;at+=16){
   const unsigned count=unsigned(at/16)+1;w.counter[14]=uint8_t(count>>8);w.counter[15]=uint8_t(count);
   if(!Crypto::encrypt(key,w.counter,w.stream))return false;
   for(unsigned j=0;j<16 && at+j<bytes;++j)out[at+j]=in[at+j]^w.stream[j];
  }
  return true;
 }
 static void publish(PMFCCMPResult &out,const PMFCCMPWorkspace &w,size_t bytes,uint64_t pn){
  wipe(out.frame,sizeof(out.frame));copy(out.frame,w.candidate,bytes);out.bytes=bytes;out.pn=pn;
 }
public:
 static constexpr uint64_t MaxPN=0xffffffffffffull;
 // Verify either wire ciphertext or an explicitly normalized firmware layout
 // with plaintext payload and the ORIGINAL encrypted CCMP tag still retained.
 // The latter layout must be established experimentally before native use.
 static bool receive(const uint8_t *frame,size_t bytes,const uint8_t *key,const uint8_t *local,const uint8_t *ap,
    uint64_t lastPN,RXLayout layout,PMFCCMPResult &out,PMFCCMPWorkspace &w){
  if(!frame || !key || !local || !ap || bytes<42 || bytes>512 || lastPN>MaxPN ||
     (layout!=RXLayout::Ciphertext && layout!=RXLayout::PlaintextWithEncryptedTag) ||
     !disjoint(frame,bytes,key,local,ap,out,w))return false;
  w.clear();Clear clear{w};
  if(!pmfCCMPHeader(frame,bytes,local,ap,true) || frame[26] || frame[27]!=0x20)return false;
  const uint64_t pn=uint64_t(frame[24])|(uint64_t(frame[25])<<8)|(uint64_t(frame[28])<<16)|
   (uint64_t(frame[29])<<24)|(uint64_t(frame[30])<<32)|(uint64_t(frame[31])<<40);
  if(pn<=lastPN)return false;
  const size_t body=bytes-40;copy(w.candidate,frame,24);init(w,frame,pn,body);
  if(layout==RXLayout::Ciphertext){if(!crypt(w,key,frame+32,w.candidate+24,body))return false;}
  else copy(w.candidate+24,frame+32,body);
  if(!mac(w,key,w.candidate+24,body) || !equal(w.state,frame+bytes-8,8) || !pmfRobustBody(w.candidate,body+24))return false;
  publish(out,w,body+24,pn);return true;
 }
 // Caller must reserve an UNUSED nonzero PN for this PTK before encryption.
 // Failed construction/submission consumes the PN; never roll it back/reuse it.
 // TX transport must send these encrypted bytes unchanged, without a second
 // hardware encryption pass. It is not yet connected to the native HTT path.
 static bool protect(const uint8_t *frame,size_t bytes,const uint8_t *key,const uint8_t *local,const uint8_t *ap,
    uint64_t pn,PMFCCMPResult &out,PMFCCMPWorkspace &w){
  if(!frame || !key || !local || !ap || bytes<26 || bytes>496 || !pn || pn>MaxPN ||
     !disjoint(frame,bytes,key,local,ap,out,w))return false;
  w.clear();Clear clear{w};
  if(!pmfCCMPHeader(frame,bytes,local,ap,false) || !pmfRobustBody(frame,bytes))return false;
  const size_t body=bytes-24;copy(w.candidate,frame,24);
  w.candidate[24]=uint8_t(pn);w.candidate[25]=uint8_t(pn>>8);w.candidate[27]=0x20;
  for(unsigned i=0;i<4;++i)w.candidate[28+i]=uint8_t(pn>>(16+8*i));
  init(w,frame,pn,body);
  if(!mac(w,key,frame+24,body))return false;
  copy(w.candidate+bytes+8,w.state,8);
  if(!crypt(w,key,frame+24,w.candidate+32,body))return false;
  publish(out,w,bytes+16,pn);return true;
 }
};
// Separate management RX replay domain. Activation is called only after PTK
// installation acknowledgement. Same-key redelivery preserves the epoch/PN.
class PMFPairwiseEpoch {
 uint8_t key[16]{},local[6]{},ap[6]{};uint64_t connection=0,epoch=0,nextEpoch=0,rxPN=0;bool active=false;
public:
 struct Snapshot {
  uint8_t key[16]{},local[6]{},ap[6]{};uint64_t connection=0,epoch=0,rxPN=0;
  ~Snapshot(){wipe(this,sizeof(*this));}
 };
 PMFPairwiseEpoch()=default;
 PMFPairwiseEpoch(const PMFPairwiseEpoch &)=delete;
 PMFPairwiseEpoch &operator=(const PMFPairwiseEpoch &)=delete;
 ~PMFPairwiseEpoch(){wipe(this,sizeof(*this));}
 void clear(){const uint64_t saved=nextEpoch;wipe(this,sizeof(*this));nextEpoch=saved;}
 bool activate(const uint8_t *tk,const uint8_t *station,const uint8_t *bssid,uint64_t generation){
  if(!tk || !generation || !saQueryIdentities(station,bssid))return false;
  if(active && equal(key,tk,16))return connection==generation && equal(local,station,6) && equal(ap,bssid,6);
  if(nextEpoch==~uint64_t(0))return false;
  copy(key,tk,16);copy(local,station,6);copy(ap,bssid,6);connection=generation;epoch=++nextEpoch;rxPN=0;active=true;return true;
 }
 bool snapshot(Snapshot &out) const {
  if(!active)return false;
  copy(out.key,key,16);copy(out.local,local,6);copy(out.ap,ap,6);out.connection=connection;out.epoch=epoch;out.rxPN=rxPN;return true;
 }
 // Invoke only after successful CCMP verification with this immutable snapshot.
 // Check the live PN again: another worker may already have committed a packet.
 bool commit(const Snapshot &snapshot,uint64_t pn,PMFVerifiedRX &out){
  if(!active || snapshot.connection!=connection || snapshot.epoch!=epoch || !pn || pn>0xffffffffffffull || pn<=rxPN)return false;
  rxPN=pn;out={connection,epoch,true,true};return true;
 }
};
}

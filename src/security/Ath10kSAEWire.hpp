#pragma once
#include "Ath10kSecurity.hpp"

namespace AthSecurity {
// Group-19 AKM-8 framing only. This performs no curve validation or SAE state
// transition. Bind decoded identity/mode/IEs to the retained exchange before
// queuing cryptography. Input/output buffers must not overlap.
enum class SAEAuthKind : uint8_t { Empty, Commit, Confirm, TokenRequest, GroupRejected, Rejected };
enum class SAEWireResult : uint8_t { Valid, Malformed, Unsupported, WrongPeer, ModeMismatch };
struct SAEGroup19AuthMessage {
 SAEAuthKind kind=SAEAuthKind::Empty;
 bool h2e=false,identifierPresent=false;
 uint16_t status=0,group=19,identifierBytes=0,rejectedBytes=0,tokenBytes=0;
 uint8_t commit[96]{},confirm[34]{},identifier[254]{},rejected[254]{},token[1024]{};
};
static_assert(sizeof(SAEGroup19AuthMessage)<=2048,"Bounded SAE message");
inline bool saeUnicastIdentity(const uint8_t *mac){
 if(!mac || (mac[0]&1))return false;
 uint8_t nonzero=0;for(unsigned i=0;i<6;++i)nonzero|=mac[i];return nonzero!=0;
}
inline bool saeRejectedGroupsValid(const uint8_t *groups,size_t bytes){
 if(!groups || !bytes || bytes>254 || (bytes&1))return false;
 for(size_t i=0;i<bytes;i+=2){const uint16_t group=rsnLE16(groups+i);if(!group || group==19)return false;}
 return true;
}
// Authentication body includes algorithm/transaction/status (six bytes).
// Legacy token prefix length is explicit exchange context, never inferred from
// arbitrary trailing bytes. From-AP client reception always expects zero.
inline SAEWireResult decodeSAEGroup19AuthBody(const uint8_t *body,size_t bytes,bool expectedH2E,
 size_t legacyTokenBytes,SAEGroup19AuthMessage &out){
 if(!body || bytes<6 || bytes>1512 || legacyTokenBytes>1024 || (expectedH2E && legacyTokenBytes))return SAEWireResult::Malformed;
 if(rsnLE16(body)!=3)return SAEWireResult::Unsupported;
 const uint16_t transaction=rsnLE16(body+2),status=rsnLE16(body+4);
 if(transaction!=1 && transaction!=2)return SAEWireResult::Malformed;
 struct Scratch {SAEGroup19AuthMessage message{};~Scratch(){wipe(&message,sizeof(message));}} scratch;
 auto &m=scratch.message;m.h2e=expectedH2E;m.status=status;
 const uint8_t *p=body+6;size_t remaining=bytes-6;
 if(status!=0 && status!=126 && status!=76 && status!=77){
  m.kind=SAEAuthKind::Rejected;out=m;return SAEWireResult::Valid;
 }
 if(transaction==2){
  if(status || remaining!=34 || legacyTokenBytes)return SAEWireResult::Malformed;
  m.kind=SAEAuthKind::Confirm;copy(m.confirm,p,34);out=m;return SAEWireResult::Valid;
 }
 if(remaining<2)return SAEWireResult::Malformed;
 m.group=rsnLE16(p);if(m.group!=19)return SAEWireResult::Unsupported;
 p+=2;remaining-=2;
 if(status==77){
  if(remaining || legacyTokenBytes)return SAEWireResult::Malformed;
  m.kind=SAEAuthKind::GroupRejected;out=m;return SAEWireResult::Valid;
 }
 if(status==76){
  if(legacyTokenBytes)return SAEWireResult::Malformed;
  if(expectedH2E){
   if(remaining<4 || p[0]!=255 || p[1]<2 || p[2]!=93 || size_t(p[1])+2!=remaining)return SAEWireResult::Malformed;
   m.tokenBytes=uint16_t(p[1]-1);copy(m.token,p+3,m.tokenBytes);
  }else{
   if(!remaining || remaining>sizeof(m.token))return SAEWireResult::Malformed;
   m.tokenBytes=uint16_t(remaining);copy(m.token,p,remaining);
  }
  m.kind=SAEAuthKind::TokenRequest;out=m;return SAEWireResult::Valid;
 }
 if((status==126)!=expectedH2E)return SAEWireResult::ModeMismatch;
 if(remaining<legacyTokenBytes+96)return SAEWireResult::Malformed;
 if(legacyTokenBytes){m.tokenBytes=uint16_t(legacyTokenBytes);copy(m.token,p,legacyTokenBytes);p+=legacyTokenBytes;remaining-=legacyTokenBytes;}
 copy(m.commit,p,96);p+=96;remaining-=96;
 unsigned previousRank=0;
 while(remaining){
  if(remaining<3 || p[0]!=255 || p[1]<1 || size_t(p[1])+2>remaining)return SAEWireResult::Malformed;
  const uint8_t id=p[2];const size_t n=p[1]-1;unsigned rank=0;
  if(id==33)rank=1;else if(id==92 && expectedH2E)rank=2;else if(id==93 && expectedH2E)rank=3;
  else return SAEWireResult::Unsupported; // Includes unsupported extended-key AKMs.
  if(rank<=previousRank)return SAEWireResult::Malformed;
  if(rank==1){m.identifierPresent=true;m.identifierBytes=uint16_t(n);if(n)copy(m.identifier,p+3,n);}
  else if(rank==2){
   if(!saeRejectedGroupsValid(p+3,n))return SAEWireResult::Malformed;
   m.rejectedBytes=uint16_t(n);copy(m.rejected,p+3,n);
  }else{
   if(!n)return SAEWireResult::Malformed;
   m.tokenBytes=uint16_t(n);copy(m.token,p+3,n);
  }
  previousRank=rank;p+=size_t(p[1])+2;remaining-=n+3;
 }
 m.kind=SAEAuthKind::Commit;out=m;return SAEWireResult::Valid;
}
inline SAEWireResult decodeSAEGroup19FromAP(const uint8_t *frame,size_t bytes,const uint8_t *local,
 const uint8_t *ap,bool expectedH2E,SAEGroup19AuthMessage &out){
 if(!frame || bytes<30 || bytes>1536)return SAEWireResult::Malformed;
 if(!saeUnicastIdentity(local) || !saeUnicastIdentity(ap) || equal(local,ap,6))return SAEWireResult::WrongPeer;
 const uint16_t fc=rsnLE16(frame);
 if((fc&0xff)!=0xb0 || (fc&0xc700) || (rsnLE16(frame+22)&15))return SAEWireResult::Malformed;
 if(!equal(frame+4,local,6) || !equal(frame+10,ap,6) || !equal(frame+16,ap,6))return SAEWireResult::WrongPeer;
 return decodeSAEGroup19AuthBody(frame+24,bytes-24,expectedH2E,0,out);
}
inline bool saeGroup19AuthBodySize(const SAEGroup19AuthMessage &m,size_t &bytes){
 if(m.group!=19 || m.identifierBytes>254 || m.rejectedBytes>254 || m.tokenBytes>1024 ||
    (!m.identifierPresent && m.identifierBytes) || (m.h2e && m.tokenBytes>254) ||
    (!m.h2e && m.rejectedBytes) || (m.rejectedBytes && !saeRejectedGroupsValid(m.rejected,m.rejectedBytes)))return false;
 size_t n=0;
 if(m.kind==SAEAuthKind::Commit){
  n=104+m.tokenBytes+(m.identifierPresent?3+m.identifierBytes:0)+(m.rejectedBytes?3+m.rejectedBytes:0);
  if(m.h2e && m.tokenBytes)n+=3;
 }else if(m.kind==SAEAuthKind::Confirm)n=40;
 else if(m.kind==SAEAuthKind::TokenRequest){if(!m.tokenBytes)return false;n=8+m.tokenBytes+(m.h2e?3:0);}
 else if(m.kind==SAEAuthKind::GroupRejected)n=8;
 else return false;
 if(m.kind!=SAEAuthKind::Commit && (m.identifierPresent || m.rejectedBytes || (m.kind!=SAEAuthKind::TokenRequest && m.tokenBytes)))return false;
 if(n>1512)return false;
 bytes=n;return true;
}
// Call only after the shared size/shape validation succeeds.
inline void writeSAEGroup19AuthBody(const SAEGroup19AuthMessage &m,uint8_t *out){
 auto put=[](uint8_t *p,uint16_t value){p[0]=uint8_t(value);p[1]=uint8_t(value>>8);};
 put(out,3);put(out+2,m.kind==SAEAuthKind::Confirm?2:1);
 const uint16_t status=m.kind==SAEAuthKind::TokenRequest?76:(m.kind==SAEAuthKind::GroupRejected?77:(m.kind==SAEAuthKind::Commit && m.h2e?126:0));
 put(out+4,status);
 if(m.kind==SAEAuthKind::Confirm){copy(out+6,m.confirm,34);return;}
 put(out+6,19);size_t at=8;
 auto element=[&](uint8_t id,const uint8_t *data,size_t n){out[at++]=255;out[at++]=uint8_t(n+1);out[at++]=id;if(n)copy(out+at,data,n);at+=n;};
 if(m.kind==SAEAuthKind::GroupRejected)return;
 if(!m.h2e && m.tokenBytes){copy(out+at,m.token,m.tokenBytes);at+=m.tokenBytes;}
 if(m.kind==SAEAuthKind::Commit){
  copy(out+at,m.commit,96);at+=96;
  if(m.identifierPresent)element(33,m.identifier,m.identifierBytes);
  if(m.rejectedBytes)element(92,m.rejected,m.rejectedBytes);
 }
 if(m.h2e && m.tokenBytes)element(93,m.token,m.tokenBytes);
}
inline bool encodeSAEGroup19AuthBody(const SAEGroup19AuthMessage &m,uint8_t *out,size_t capacity,size_t &bytes){
 size_t n=0;if(!out || !saeGroup19AuthBodySize(m,n) || capacity<n)return false;
 writeSAEGroup19AuthBody(m,out);bytes=n;return true;
}
inline bool encodeSAEGroup19ToAP(const SAEGroup19AuthMessage &m,const uint8_t *local,const uint8_t *ap,
 uint16_t sequence,uint8_t *out,size_t capacity,size_t &bytes){
 size_t n=0;
 if(!out || !saeUnicastIdentity(local) || !saeUnicastIdentity(ap) || equal(local,ap,6) || sequence>4095 ||
    !saeGroup19AuthBodySize(m,n) || capacity<n+24)return false;
 wipe(out,24);out[0]=0xb0;copy(out+4,ap,6);copy(out+10,local,6);copy(out+16,ap,6);
 const uint16_t sc=uint16_t(sequence<<4);out[22]=uint8_t(sc);out[23]=uint8_t(sc>>8);
 writeSAEGroup19AuthBody(m,out+24);bytes=n+24;return true;
}
}

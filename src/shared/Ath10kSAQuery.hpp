#pragma once
#include "Ath10kSecurity.hpp"
namespace AthSecurity {
// Plaintext management payloads, excluding FCS and crypto IV/MIC. The caller
// must authenticate/decrypt RX and verify replay under this exact PTK epoch.
// Protected-bit presence alone is never evidence of authentication.
struct PMFVerifiedRX {
 uint64_t connection=0,ptkEpoch=0;
 bool integrity=false,replay=false;
};
struct SAQueryMessage {uint8_t action=0,id[2]{};};
inline bool saQueryIdentities(const uint8_t *local,const uint8_t *ap){
 if(!local || !ap || (local[0]&1) || (ap[0]&1) || equal(local,ap,6))return false;
 uint8_t a=0,b=0;for(unsigned i=0;i<6;++i){a|=local[i];b|=ap[i];}return a && b;
}
// A trigger is deliberately unauthenticated: it may request a bounded query,
// never authorize disconnect. Other unprotected robust frames are dropped.
inline bool saQueryDisconnectTrigger(const uint8_t *frame,size_t bytes,bool pmf,bool authorized,
 const uint8_t *local,const uint8_t *ap){
 if(!pmf || !authorized || !frame || bytes<26 || bytes>512 || !saQueryIdentities(local,ap))return false;
 const uint16_t fc=le16(frame);
 if(((fc&0xc7ff)!=0x00c0 && (fc&0xc7ff)!=0x00a0) || (le16(frame+22)&15) ||
    !equal(frame+4,local,6) || !equal(frame+10,ap,6) || !equal(frame+16,ap,6))return false;
 const uint16_t reason=le16(frame+24);return reason==6 || reason==7;
}
inline bool parseSAQuery(const uint8_t *frame,size_t bytes,const uint8_t *local,const uint8_t *ap,
 const PMFVerifiedRX &verified,uint64_t connection,uint64_t ptkEpoch,SAQueryMessage &out){
 if(!frame || bytes!=28 || !saQueryIdentities(local,ap) || !connection || !ptkEpoch ||
    !verified.integrity || !verified.replay || verified.connection!=connection || verified.ptkEpoch!=ptkEpoch)return false;
 const uint16_t fc=le16(frame);
 if((fc&0xc7ff)!=0x40d0 || (le16(frame+22)&15) || !equal(frame+4,local,6) ||
    !equal(frame+10,ap,6) || !equal(frame+16,ap,6) || frame[24]!=8 || frame[25]>1)return false;
 SAQueryMessage message{};message.action=frame[25];copy(message.id,frame+26,2);out=message;return true;
}
// Output still needs PTK protection and sequence/PN assignment at actual TX.
// OCV/OCI extensions are deliberately unsupported, not silently discarded.
inline bool buildSAQuery(uint8_t action,const uint8_t *id,const uint8_t *local,const uint8_t *ap,
 uint8_t *out,size_t capacity){
 if(action>1 || !id || !out || capacity<28 || !saQueryIdentities(local,ap))return false;
 uint8_t frame[28]{};frame[0]=0xd0;frame[1]=0x40;
 copy(frame+4,ap,6);copy(frame+10,local,6);copy(frame+16,ap,6);
 frame[24]=8;frame[25]=action;copy(frame+26,id,2);copy(out,frame,sizeof(frame));return true;
}
// Serialized owner-context coordinator; no crypto, allocation, timers or I/O.
// Bind once per association/PTK epoch; cancel on leave, reset, sleep or rekey.
// All timestamps are monotonic microseconds. Late timers never extend timeout.
class SAQueryExchange {
public:
 enum class State : uint8_t {Idle,Waiting,Succeeded,TimedOut,Failed};
 static constexpr uint64_t RetryUS=201*1024,TimeoutUS=1000*1024,RateLimitUS=10000000;
 static constexpr unsigned MaxAttempts=5;
 struct TX {const SAQueryExchange *owner=nullptr;uint64_t serial=0,connection=0,ptkEpoch=0;uint8_t frame[28]{};};
private:
 uint8_t local[6]{},ap[6]{},sent[MaxAttempts][2]{};
 uint64_t connection=0,ptkEpoch=0,serial=0,deadline=0,nextRetry=0,lastNow=0,lastStart=0;
 unsigned attempts=0,sentCount=0;
 State phase=State::Idle;bool bound=false,started=false,pending=false;
 TX reservation{};
 void retire(State result){wipe(sent,sizeof(sent));wipe(&reservation,sizeof(reservation));pending=false;attempts=sentCount=0;deadline=nextRetry=0;phase=result;}
 bool clock(uint64_t now){
  if(!bound)return false;
  if(now<lastNow){retire(State::Failed);return false;}
  lastNow=now;
  if(phase==State::Waiting && now>=deadline){retire(State::TimedOut);return false;}
  return true;
 }
 bool matches(const TX &tx) const {
  return pending && tx.owner==this && tx.serial==reservation.serial && tx.connection==connection &&
   tx.ptkEpoch==ptkEpoch && equal(tx.frame,reservation.frame,sizeof(tx.frame));
 }
public:
 SAQueryExchange()=default;
 SAQueryExchange(const SAQueryExchange &)=delete;
 SAQueryExchange &operator=(const SAQueryExchange &)=delete;
 ~SAQueryExchange(){wipe(this,sizeof(*this));}
 // Preserve the monotonic ticket serial across association reuse.
 void clear(){const uint64_t saved=serial;wipe(this,sizeof(*this));serial=saved;}
 bool bind(const uint8_t *station,const uint8_t *bssid,uint64_t generation,uint64_t epoch,uint64_t now){
  clear();if(!generation || !epoch || !saQueryIdentities(station,bssid))return false;
  copy(local,station,6);copy(ap,bssid,6);connection=generation;ptkEpoch=epoch;lastNow=now;bound=true;return true;
 }
 State state() const {return phase;}
 bool start(uint64_t now){
  if(!clock(now) || phase==State::Waiting || (started && now-lastStart<RateLimitUS) || now>~uint64_t(0)-TimeoutUS)return false;
  retire(State::Waiting);deadline=now+TimeoutUS;nextRetry=now;lastStart=now;started=true;return true;
 }
 State poll(uint64_t now){clock(now);return phase;}
 bool reserve(const uint8_t *randomID,uint64_t now,TX &out){
  if(!clock(now) || phase!=State::Waiting || pending || now<nextRetry || attempts==MaxAttempts || !randomID || serial==~uint64_t(0))return false;
  for(unsigned i=0;i<sentCount;++i)if(equal(sent[i],randomID,2))return false;
  TX tx{};tx.owner=this;tx.serial=++serial;tx.connection=connection;tx.ptkEpoch=ptkEpoch;
  if(!buildSAQuery(0,randomID,local,ap,tx.frame,sizeof(tx.frame)))return false;
  reservation=tx;pending=true;++attempts;nextRetry=now+(deadline-now<RetryUS?deadline-now:RetryUS);out=tx;return true;
 }
 // Recheck under the owner gate immediately before handing bytes to transport.
 bool ready(const TX &tx,uint64_t now){return clock(now) && phase==State::Waiting && matches(tx);}
 // 'submitted' means accepted by the protected TX path, not a later MAC ACK.
 // Consume before RX dispatch can run. A failed handoff never admits its ID.
 bool submitted(const TX &tx,bool accepted,uint64_t now){
  if(!ready(tx,now))return false;
  if(accepted){copy(sent[sentCount++],reservation.frame+26,2);}
  wipe(&reservation,sizeof(reservation));pending=false;return true;
 }
 bool response(const uint8_t *frame,size_t bytes,const PMFVerifiedRX &verified,uint64_t now){
  if(!clock(now) || phase!=State::Waiting)return false;
  SAQueryMessage message{};if(!parseSAQuery(frame,bytes,local,ap,verified,connection,ptkEpoch,message) || message.action!=1)return false;
  for(unsigned i=0;i<sentCount;++i)if(equal(sent[i],message.id,2)){retire(State::Succeeded);return true;}
  return false;
 }
 // Repeated unauthenticated triggers cannot extend an active query or bypass
 // the per-association ten-second start limit. Clear is association teardown.
};
}

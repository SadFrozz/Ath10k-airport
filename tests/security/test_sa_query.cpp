#include "../../src/security/Ath10kSAQuery.hpp"
#include <cassert>
#include <cstring>
#include <limits>
#include <array>
using Q=AthSecurity::SAQueryExchange;using RX=AthSecurity::PMFVerifiedRX;
static constexpr uint8_t station[]={2,1,2,3,4,5},ap[]={2,6,7,8,9,10};
static constexpr uint8_t expectedTX[]={0xd0,0x40,0,0,2,6,7,8,9,10,2,1,2,3,4,5,2,6,7,8,9,10,0,0,8,0,0x12,0x34};
static constexpr uint8_t expectedRX[]={0xd0,0x40,0,0,2,1,2,3,4,5,2,6,7,8,9,10,2,6,7,8,9,10,0,0,8,1,0x12,0x34};
static constexpr RX verified{9,11,true,true};
static std::array<uint8_t,28> reply(const uint8_t *id){std::array<uint8_t,28> f{};memcpy(f.data(),expectedRX,28);memcpy(f.data()+26,id,2);return f;}
static void bind(Q &q,uint64_t now=0){assert(q.bind(station,ap,9,11,now));}
static void wire(){
 uint8_t frame[29];memset(frame,0xa5,sizeof(frame));const uint8_t id[]={0x12,0x34};
 assert(AthSecurity::buildSAQuery(0,id,station,ap,frame,28));assert(!memcmp(frame,expectedTX,28) && frame[28]==0xa5);
 uint8_t unchanged[29];memcpy(unchanged,frame,sizeof(frame));
 for(unsigned failure=0;failure<7;++failure){
  assert(!AthSecurity::buildSAQuery(failure==0?2:0,failure==1?nullptr:id,failure==2?nullptr:station,
    failure==3?nullptr:(failure==6?station:ap),failure==4?nullptr:frame,failure==5?27:28));
  assert(!memcmp(frame,unchanged,sizeof(frame)));
 }
 assert(AthSecurity::buildSAQuery(1,id,station,ap,frame,28) && frame[25]==1);
 AthSecurity::SAQueryMessage out{};assert(AthSecurity::parseSAQuery(expectedRX,28,station,ap,verified,9,11,out));
 assert(out.action==1 && !memcmp(out.id,id,2));
 auto bad=reply(id);bad[25]=0;assert(AthSecurity::parseSAQuery(bad.data(),28,station,ap,verified,9,11,out) && !out.action);
 // Each protected/authenticated field must be independently admitted.
 for(unsigned i=0;i<28;++i){
  if(i==2 || i==3 || i==22 || i==23 || i==26 || i==27)continue;
  bad=reply(id);bad[i]^=i==25?2:1;out.action=0xa5;
  assert(!AthSecurity::parseSAQuery(bad.data(),28,station,ap,verified,9,11,out) && out.action==0xa5);
 }
 for(uint16_t forbidden:{uint16_t(1),uint16_t(0x100),uint16_t(0x200),uint16_t(0x400),uint16_t(0x8000),uint16_t(0x4000)}){
  bad=reply(id);bad[0]^=uint8_t(forbidden);bad[1]^=uint8_t(forbidden>>8);
  assert(!AthSecurity::parseSAQuery(bad.data(),28,station,ap,verified,9,11,out));
 }
 bad=reply(id);bad[22]=1;assert(!AthSecurity::parseSAQuery(bad.data(),28,station,ap,verified,9,11,out));
 bad=reply(id);bad[1]|=0x38;bad[22]=0xf0;bad[23]=0xff;
 assert(AthSecurity::parseSAQuery(bad.data(),28,station,ap,verified,9,11,out)); // Retry/power/sequence outside this admission.
 for(unsigned i=0;i<6;++i){RX stamp=verified;if(i==0)stamp.connection++;if(i==1)stamp.ptkEpoch++;
  if(i==2)stamp.integrity=false;if(i==3)stamp.replay=false;
  assert(!AthSecurity::parseSAQuery(expectedRX,28,station,ap,stamp,i==4?0:9,i==5?0:11,out));}
 assert(!AthSecurity::parseSAQuery(nullptr,28,station,ap,verified,9,11,out));
 assert(!AthSecurity::parseSAQuery(expectedRX,27,station,ap,verified,9,11,out));
 assert(!AthSecurity::parseSAQuery(frame,29,station,ap,verified,9,11,out)); // OCV extension unsupported.
 uint8_t zero[6]{};assert(!AthSecurity::saQueryIdentities(zero,ap));zero[0]=1;assert(!AthSecurity::saQueryIdentities(zero,ap));
}
static void triggers(){
 uint8_t frame[28];memcpy(frame,expectedRX,28);frame[0]=0xc0;frame[1]=0;frame[24]=6;frame[25]=0;
 auto trigger=[&](bool pmf=true,bool authorized=true){return AthSecurity::saQueryDisconnectTrigger(frame,26,pmf,authorized,station,ap);};
 assert(trigger() && !trigger(false,true) && !trigger(true,false));
 frame[24]=7;assert(trigger());frame[0]=0xa0;assert(trigger());
 for(unsigned reason=0;reason<256;++reason){frame[24]=uint8_t(reason);assert(trigger()==(reason==6 || reason==7));}
 frame[24]=6;frame[1]=0x40;assert(!trigger());frame[1]=0;frame[4]|=1;assert(!trigger());
 frame[4]&=~1;frame[10]^=1;assert(!trigger());frame[10]^=1;frame[22]=1;assert(!trigger());
 assert(!AthSecurity::saQueryDisconnectTrigger(nullptr,26,true,true,station,ap));
 assert(!AthSecurity::saQueryDisconnectTrigger(frame,25,true,true,station,ap));
}
static void handshake(){
 Q q;Q::TX tx{};const uint8_t id[]={0x12,0x34};assert(!q.start(0) && !q.reserve(id,0,tx));
 bind(q);assert(q.start(0));assert(q.reserve(id,0,tx));assert(!memcmp(tx.frame,expectedTX,28));
 Q::TX other{};assert(!q.reserve(id,0,other) && !other.serial);
 assert(!q.response(expectedRX,28,verified,0)); // Reserved bytes have not reached transport.
 auto corrupt=tx;corrupt.frame[27]^=1;assert(!q.ready(corrupt,0));corrupt=tx;corrupt.serial++;
 assert(!q.submitted(corrupt,true,0));
 assert(q.ready(tx,0) && q.submitted(tx,true,0) && !q.submitted(tx,true,0));
 RX stale=verified;stale.ptkEpoch++;assert(!q.response(expectedRX,28,stale,1));
 auto wrong=reply(id);wrong[27]++;assert(!q.response(wrong.data(),28,verified,1));
 assert(q.response(expectedRX,28,verified,1) && q.state()==Q::State::Succeeded);
 assert(!q.ready(tx,1) && !q.response(expectedRX,28,verified,1));
 assert(!q.start(Q::RateLimitUS-1) && q.start(Q::RateLimitUS));
 assert(q.reserve(id,Q::RateLimitUS,other) && other.serial>tx.serial);
 assert(!q.ready(tx,Q::RateLimitUS));q.clear();assert(!q.ready(other,Q::RateLimitUS));
 bind(q,Q::RateLimitUS);assert(q.start(Q::RateLimitUS));Q::TX newer{};
 assert(q.reserve(id,Q::RateLimitUS,newer) && newer.serial>other.serial && !q.ready(other,Q::RateLimitUS));
}
static void deadlines(){
 Q q;bind(q);assert(q.start(100));
 for(unsigned i=0;i<Q::MaxAttempts;++i){const uint64_t now=100+i*Q::RetryUS;
  uint8_t id[]={uint8_t(i),0};Q::TX tx{};
  if(i)assert(!q.reserve(id,now-1,tx));
  assert(q.reserve(id,now,tx));assert(!q.start(now));assert(q.submitted(tx,true,now));
  Q::TX duplicate{};assert(!q.reserve(id,now,duplicate));
 }
 assert(q.poll(100+Q::TimeoutUS-1)==Q::State::Waiting);
 assert(q.poll(100+Q::TimeoutUS)==Q::State::TimedOut);
 const uint8_t id[]={0,0};auto late=reply(id);assert(!q.response(late.data(),28,verified,100+Q::TimeoutUS));
 assert(!q.start(100+Q::TimeoutUS));
 assert(q.start(100+Q::RateLimitUS));Q::TX tx{};assert(q.reserve(id,100+Q::RateLimitUS,tx));
 assert(!q.ready(tx,100+Q::RateLimitUS+Q::TimeoutUS) && q.state()==Q::State::TimedOut);
 bind(q,50);assert(!q.start(49) && q.state()==Q::State::Failed);
 bind(q);assert(q.start(0) && q.reserve(id,0,tx));assert(!q.ready(tx,Q::TimeoutUS));
 bind(q);assert(q.start(0) && q.reserve(id,0,tx));assert(q.poll(1)==Q::State::Waiting);
 assert(!q.ready(tx,0) && q.state()==Q::State::Failed);
 const uint64_t max=std::numeric_limits<uint64_t>::max();bind(q,max-Q::TimeoutUS+1);assert(!q.start(max-Q::TimeoutUS+1));
 bind(q,max-Q::TimeoutUS);assert(q.start(max-Q::TimeoutUS));assert(q.reserve(id,max-1,tx));
 assert(q.submitted(tx,true,max-1));assert(q.poll(max)==Q::State::TimedOut); // Retry arithmetic cannot wrap.
}
static void failedHandoff(){
 Q q;bind(q);assert(q.start(0));const uint8_t id[]={0,0};auto frame=reply(id);Q::TX tx{};
 assert(q.reserve(id,0,tx) && q.submitted(tx,false,0));assert(!q.response(frame.data(),28,verified,0));
 assert(q.reserve(id,Q::RetryUS,tx) && q.submitted(tx,true,Q::RetryUS));
 Q::TX dup{};assert(!q.reserve(id,2*Q::RetryUS,dup));
 const uint8_t other[]={1,0};assert(q.reserve(other,2*Q::RetryUS,dup) && q.submitted(dup,true,2*Q::RetryUS));
 assert(q.response(frame.data(),28,verified,2*Q::RetryUS)); // Any actually submitted transaction may complete.
 Q peer;bind(peer);assert(peer.start(0));assert(!peer.ready(tx,0));
 assert(!peer.bind(station,ap,0,11,0));assert(!peer.start(0));
 assert(!peer.bind(station,station,9,11,0));assert(!peer.bind(nullptr,ap,9,11,0));
}
int main(){wire();triggers();handshake();deadlines();failedHandoff();}

#include <cassert>
#include <initializer_list>
#include <cstring>
#include "../../src/macos/native/Ath10kNativeEAPOwner.hpp"
int main(){
 using Owner=AthNative::EAPOwner;using K=Owner::KeyResult;using P=Owner::PacketOwner;
 Owner owner;uint8_t sta[6]={2,1,2,3,4,5},ap[6]={2,6,7,8,9,10},other[6]={2,3,3,3,3,3};
 uint8_t key[64]{},output[32];key[0]=7;memset(output,0xa5,sizeof(output));
 assert(owner.begin(sta,ap,100,1000));const auto first=owner.generation();
 assert(owner.setMSK(first,sta,other,9,key,32,110)==K::Stale);
 assert(owner.setMSK(first,sta,ap,10,key,32,110)==K::Invalid);
 assert(owner.setMSK(first,sta,ap,9,key,64,110)==K::Invalid);
 assert(owner.setMSK(first,sta,ap,9,nullptr,32,110)==K::Invalid);
 assert(!owner.takePMK(first,sta,ap,110,output) && output[0]==0xa5);
 assert(owner.setMSK(first,sta,ap,9,key,32,120)==K::Accepted);
 assert(owner.setMSK(first,sta,ap,9,key,32,130)==K::Duplicate);
 key[1]=1;assert(owner.setMSK(first,sta,ap,9,key,32,140)==K::Conflict);key[1]=0;
 assert(owner.takePMK(first,sta,ap,150,output) && !memcmp(output,key,32));
 assert(!owner.takePMK(first,sta,ap,151,output));assert(!owner.expire(2000));
 assert(owner.setMSK(first,sta,ap,9,key,32,2000)==K::Duplicate);
 uint8_t frame[160]{};memcpy(frame,sta,6);memcpy(frame+6,ap,6);
 frame[12]=0x88;frame[13]=0x8e;frame[14]=2;frame[17]=5;frame[18]=1;frame[21]=5;frame[22]=1;
 assert(owner.route(first,sta,ap,frame,60,false)==P::SystemEAP);
 frame[6]^=2;assert(owner.route(first,sta,ap,frame,60,false)==P::Reject);frame[6]^=2;
 frame[15]=3;frame[17]=95;frame[18]=2;
 assert(owner.route(first,sta,ap,frame,113,false)==P::InternalKey);
 memcpy(frame,ap,6);memcpy(frame+6,sta,6);
 assert(owner.route(first,sta,ap,frame,113,true)==P::Reject);
 frame[15]=1;frame[17]=0;assert(owner.route(first,sta,ap,frame,60,true)==P::SystemEAP);
 // Padding is not queued; queue pressure must retain caller ownership.
 for(unsigned i=0;i<4;++i)assert(owner.enqueuePacket(first,sta,ap,frame,60,2000+i)==Owner::Enqueue::Queued);
 assert(owner.enqueuePacket(first,sta,ap,frame,60,2004)==Owner::Enqueue::Full);
 size_t length=0;uint64_t since=0;const auto queued=owner.front(length,since);
 assert(queued && length==18 && since==2000);frame[0]^=2;
 assert(queued[0]!=frame[0]);frame[0]^=2;owner.pop();
 assert(owner.enqueuePacket(first,sta,ap,frame,60,2005)==Owner::Enqueue::Queued);
 assert(owner.setMSK(first,sta,ap,9,nullptr,0,2006)==K::Cleared);
 assert(!owner.pending() && !owner.front(length,since) && !length);
 assert(!owner.generation() && owner.route(first,sta,ap,frame,60,true)==P::Reject);
 assert(owner.begin(sta,ap,2000,3000));auto second=owner.generation();assert(second!=first);
 assert(owner.setMSK(first,sta,ap,9,key,32,2100)==K::Stale);
 assert(!owner.expire(2999) && owner.expire(3000) && !owner.generation());
 assert(owner.begin(sta,ap,3000,4000));auto third=owner.generation();
 assert(owner.setMSK(third,sta,ap,9,key,32,4000)==K::Stale);
 assert(owner.begin(sta,ap,5000,6000));assert(owner.expire(4999));
 assert(!owner.begin(sta,sta,1,2));assert(!owner.begin(sta,ap,2,2));
 // An expired queue must reject even when full; a stalled caller must not
 // wait for space in an association whose authentication budget has elapsed.
 assert(owner.begin(sta,ap,100,200));auto last=owner.generation();
 assert(owner.validAt(199) && !owner.validAt(200) && !owner.validAt(99));
 for(unsigned i=0;i<4;++i)assert(owner.enqueuePacket(last,sta,ap,frame,60,199)==Owner::Enqueue::Queued);
 assert(owner.enqueuePacket(last,sta,ap,frame,60,200)==Owner::Enqueue::Invalid);
 assert(owner.enqueuePacket(last,sta,ap,frame,60,99)==Owner::Enqueue::Invalid);
 assert(owner.setMSK(last,sta,ap,9,nullptr,0,199)==K::Empty);
 assert(owner.generation()==last && owner.pending());
 assert(owner.expire(200) && !owner.pending());
 assert(owner.begin(sta,ap,100,200));last=owner.generation();
 assert(owner.setMSK(last,sta,ap,9,nullptr,0,200)==K::Stale && !owner.generation());
 assert(owner.begin(sta,ap,100,200));last=owner.generation();
 assert(owner.setMSK(last,sta,ap,9,key,32,150)==K::Accepted);
 assert(owner.setMSK(last,sta,ap,9,nullptr,0,151)==K::Cleared && !owner.generation());
 // Replacement spans MSK plus firmware/receipt completion, unlike initial
 // MSK wait. Consumption must not disable its terminal deadline.
 for(bool complete:{false,true}){
  Owner r;assert(r.begin(sta,ap,100,200));auto old=r.generation();
  assert(!r.beginReplacement(old,sta,ap,101,300));
  assert(r.setMSK(old,sta,ap,9,key,32,110)==K::Accepted);
  assert(r.takePMK(old,sta,ap,120,output));
  assert(r.enqueuePacket(old,sta,ap,frame,60,121)==Owner::Enqueue::Queued);
  assert(!r.beginReplacement(old,sta,other,122,300));
  assert(r.beginReplacement(old,sta,ap,122,300) && r.pending());
  size_t queuedLength=0;uint64_t queuedSince=0;assert(r.front(queuedLength,queuedSince) && queuedLength==18 && queuedSince==121);r.pop();
  auto next=r.generation();
  assert(next!=old && r.replacementPending() && !r.replacementKeyReady());
  assert(!r.finishReplacement(next,sta,ap,123));
  assert(r.setMSK(old,sta,ap,9,key,32,124)==K::Stale);
  assert(r.setMSK(next,sta,ap,9,key,32,125)==K::Accepted);
  assert(r.takePMK(next,sta,ap,126,output) && r.replacementKeyReady());
  assert(!r.beginReplacement(next,sta,ap,127,400));
  assert(!r.finishReplacement(old,sta,ap,128));
  if(complete){assert(r.finishReplacement(next,sta,ap,299));assert(!r.replacementPending() && !r.expire(300));}
  else {assert(!r.finishReplacement(next,sta,ap,300));assert(r.expire(300) && !r.generation());}
 }
 AthSecurity::wipe(output,sizeof(output));AthSecurity::wipe(key,sizeof(key));
}

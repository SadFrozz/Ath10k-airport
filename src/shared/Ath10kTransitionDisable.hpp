#pragma once
#include "Ath10kSecurity.hpp"
namespace AthSecurity {
// Authenticated WFA Transition Disable bitmap. Unknown bits are preserved;
// interpreting/persisting them is the profile owner's responsibility.
struct TransitionDisableUpdate {
 uint8_t bitmap[251]{},length=0,station[6]{},bssid[6]{};
 uint64_t replay=0;
};
static_assert(sizeof(TransitionDisableUpdate)<=280,"Bounded policy export");
inline bool transitionDisableSelector(const uint8_t *element,size_t bytes){
 return element && bytes>=6 && element[0]==221 && element[2]==0x50 &&
     element[3]==0x6f && element[4]==0x9a && element[5]==0x20;
}
// Serialized association owner. Only authenticated supplicant exports enter
// this accumulator; an enqueue failure must not consume the pending policy.
// Sequoia's stock producer forwards bitmap octet0. Higher bitmap octets have
// no established native representation; no meaning is assigned to them here.
class TransitionDisableDelivery {
 uint8_t station[6]{},bssid[6]{},flags=0;
 uint64_t generation=0,serial=0,lastReplay=0;
 bool pending=false;
 static bool identities(const uint8_t *a,const uint8_t *b){
  if(!a || !b || (a[0]&1) || (b[0]&1) || equal(a,b,6))return false;
  uint8_t x=0,y=0;for(unsigned i=0;i<6;++i){x|=a[i];y|=b[i];}return x && y;
 }
public:
 struct Ticket {const TransitionDisableDelivery *owner=nullptr;uint64_t generation=0,serial=0;uint8_t flags=0;};
 TransitionDisableDelivery()=default;
 TransitionDisableDelivery(const TransitionDisableDelivery &)=delete;
 TransitionDisableDelivery &operator=(const TransitionDisableDelivery &)=delete;
 ~TransitionDisableDelivery(){wipe(this,sizeof(*this));}
 void clear(){const uint64_t saved=serial;wipe(this,sizeof(*this));serial=saved;}
 bool bind(const uint8_t *local,const uint8_t *ap,uint64_t epoch,uint8_t existing){
  if(generation || !epoch || !identities(local,ap))return false;
  copy(station,local,6);copy(bssid,ap,6);generation=epoch;flags=existing;return true;
 }
 bool matches(const uint8_t *local,const uint8_t *ap,uint64_t epoch) const {
  return generation && epoch==generation && local && ap && equal(station,local,6) && equal(bssid,ap,6);
 }
 bool observe(const TransitionDisableUpdate &update,uint64_t epoch){
  if(!matches(update.station,update.bssid,epoch) || !update.length ||
     update.length>sizeof(update.bitmap) || !update.replay || update.replay<=lastReplay)return false;
  const uint8_t next=uint8_t(flags|update.bitmap[0]);
  if(next!=flags && serial==~uint64_t(0))return false;
  lastReplay=update.replay;
  if(next!=flags){flags=next;++serial;pending=true;}return true;
 }
 bool snapshot(const uint8_t *local,const uint8_t *ap,uint64_t epoch,Ticket &out) const {
  if(!pending || !matches(local,ap,epoch))return false;
  out={this,generation,serial,flags};return true;
 }
 bool delivered(const Ticket &ticket){
  if(!pending || ticket.owner!=this || ticket.generation!=generation || ticket.serial!=serial || ticket.flags!=flags)return false;
  pending=false;return true;
 }
};
}

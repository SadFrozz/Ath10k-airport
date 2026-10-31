#pragma once
#include <stdint.h>
namespace AthSecurity {
// Radio-gate-owned report lifecycle. No packet transmission or authorization.
// Keep this owner outside association reset so countermeasures survive leave.
class TKIPMICOwner {
public:
 enum class Detection { Invalid, Duplicate, Report, Countermeasures };
 struct Evidence {uint64_t association=0,keyEpoch=0,tsc=0;uint8_t slot=0,tid=0;bool pairwise=false;};
 struct Ticket {uint64_t serial=0,association=0;};
private:
 struct Seen {uint64_t epoch=0,tsc[17]{};} seen[5]{};
 struct Report {Evidence evidence{};uint64_t deadline=0,serial=0;} reports[2]{};
 uint64_t association=0,serial=0,lastFailure=0,blockedUntil=0;
 unsigned count=0;bool haveFailure=false,inFlight=false,failed=false;
 static constexpr uint64_t window=60000,reportWait=5000;
 bool match(Ticket t) const {return count && t.serial && t.serial==reports[0].serial && t.association==association;}
public:
 struct Window {uint64_t last=0,until=0;bool present=false;};
 Window windowState()const{return {lastFailure,blockedUntil>lastFailure?blockedUntil:0,haveFailure};}
 bool restoreWindow(Window w,uint64_t now){
  if(association || count || inFlight || failed || haveFailure || blockedUntil)return false;
  if((!w.present && (w.last || w.until)) || (w.present && w.last>now) ||
     (w.until && (!w.present || w.last>UINT64_MAX-window || w.until!=w.last+window)))return false;
  haveFailure=w.present;lastFailure=w.last;blockedUntil=w.until;return true;
 }
 uint64_t generation() const {return association;}
 bool blocked(uint64_t now) const {return now<blockedUntil;}
 // Caller must drain/cancel transport ownership before retiring an association.
 // This clears host tickets; it is not proof that firmware DMA has stopped.
 void retire(){
  association=0;count=0;inFlight=false;failed=false;
  for(auto &s:seen)s={};for(auto &r:reports)r={};
  // Serial, first-failure window and exclusion survive leave/reassociation.
  // Otherwise reconnecting between two failures would evade countermeasures.
 }
 bool begin(uint64_t owner,uint64_t now){
  if(!owner || association || blocked(now))return false;
  retire();association=owner;return true;
 }
 Detection detect(Evidence e,uint64_t now){
  if(!association || e.association!=association || !e.keyEpoch || !e.tsc ||
     e.tsc>0xffffffffffffull || e.slot>3 || (e.pairwise && e.slot) || e.tid>16 || failed || blocked(now) ||
     now>UINT64_MAX-window || (haveFailure && now<lastFailure))return Detection::Invalid;
  auto &s=seen[e.pairwise?4:e.slot];
  if(e.keyEpoch<s.epoch)return Detection::Invalid;
  if(e.keyEpoch==s.epoch && e.tsc<=s.tsc[e.tid])return Detection::Duplicate;
  if(count==2 || serial==UINT64_MAX){failed=true;return Detection::Invalid;}
  if(e.keyEpoch!=s.epoch){s={};s.epoch=e.keyEpoch;}
  s.tsc[e.tid]=e.tsc;
  const bool second=haveFailure && now-lastFailure<=window;
  reports[count++]={e,now+reportWait,++serial};lastFailure=now;haveFailure=true;
  if(second)blockedUntil=now+window;
  return second?Detection::Countermeasures:Detection::Report;
 }
 bool next(uint64_t now,Evidence &e,Ticket &ticket){
  if(failed || !count || inFlight)return false;
  if(now<reports[0].deadline-reportWait || now>=reports[0].deadline){failed=true;return false;}
  e=reports[0].evidence;ticket={reports[0].serial,association};return true;
 }
 bool submitted(Ticket t){if(failed || inFlight || !match(t))return false;inFlight=true;return true;}
 bool complete(Ticket t,uint32_t status,uint64_t now){
  if(failed || !inFlight || !match(t))return false;
  if(status || now<reports[0].deadline-reportWait || now>=reports[0].deadline){failed=true;return false;}
  reports[0]=reports[1];reports[1]={};--count;inFlight=false;return true;
 }
 bool poll(uint64_t now){if(count && (now<reports[0].deadline-reportWait || now>=reports[0].deadline))failed=true;return !failed;}
 bool needsTeardown() const {return failed;}
 unsigned pending() const {return count;}
};
}

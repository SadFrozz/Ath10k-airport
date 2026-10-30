#include <cassert>
#include <cstring>
#include "../src/shared/Ath10kTransitionDisable.hpp"
#include "../vendor/itlwm/WCL.hpp"
using Policy=AthSecurity::TransitionDisableDelivery;
static const uint8_t sta[]={2,0,0,0,0,1},ap[]={2,0,0,0,0,2};
static AthSecurity::TransitionDisableUpdate update(uint8_t flags,uint64_t replay){
 AthSecurity::TransitionDisableUpdate u{};memcpy(u.station,sta,6);memcpy(u.bssid,ap,6);
 u.bitmap[0]=flags;u.length=1;u.replay=replay;return u;
}
int main(){
 Policy p;Policy::Ticket ticket{};ticket.flags=77;
 assert(!p.bind(nullptr,ap,1,0) && !p.bind(sta,sta,1,0) && !p.bind(sta,ap,0,0));
 assert(!p.snapshot(sta,ap,1,ticket) && ticket.flags==77);
 assert(p.bind(sta,ap,9,16) && !p.bind(sta,ap,10,0));
 auto u=update(1,2);assert(!p.observe(u,10));u.station[5]^=4;assert(!p.observe(u,9));u.station[5]^=4;
 u.length=0;assert(!p.observe(u,9));u.length=252;assert(!p.observe(u,9));u.length=1;
 u.replay=0;assert(!p.observe(u,9));u.replay=2;assert(p.observe(u,9));
 assert(p.snapshot(sta,ap,9,ticket) && ticket.flags==17);
 assert(!p.observe(u,9));u.replay=1;assert(!p.observe(u,9));
 const auto first=ticket;u=update(2,3);assert(p.observe(u,9));
 assert(!p.delivered(first) && p.snapshot(sta,ap,9,ticket) && ticket.flags==19);
 Policy other;assert(other.bind(sta,ap,9,16) && other.observe(update(3,3),9));
 assert(!other.delivered(ticket));auto bad=ticket;bad.flags=0;assert(!p.delivered(bad));
 // No acknowledgement is made for a failed enqueue; a retry gets the same ticket.
 Policy::Ticket retry{};assert(p.snapshot(sta,ap,9,retry) && retry.serial==ticket.serial && retry.flags==19);
 assert(p.delivered(ticket) && !p.delivered(ticket) && !p.snapshot(sta,ap,9,retry));
 assert(p.observe(update(0,4),9) && !p.snapshot(sta,ap,9,retry));
 assert(p.observe(update(3,5),9) && !p.snapshot(sta,ap,9,retry));
 p.clear();assert(!p.matches(sta,ap,9) && !p.observe(update(4,6),9));
 assert(p.bind(sta,ap,9,16) && p.observe(update(3,2),9));
 assert(!p.delivered(ticket) && p.snapshot(sta,ap,9,retry) && retry.serial>ticket.serial);
 // Unknown bits within the stock octet are preserved, never mapped to a weaker mode.
 assert(p.observe(update(128,3),9));assert(p.snapshot(sta,ap,9,retry) && retry.flags==147);
 assert(p.delivered(retry));
 // Stock Sequoia publication carries octet0; no invented mapping of extra octets.
 u=update(0,4);u.length=2;u.bitmap[1]=0xff;assert(p.observe(u,9) && !p.snapshot(sta,ap,9,retry));
 Policy zero;assert(zero.bind(sta,ap,1,0) && zero.observe(update(0,1),1) && !zero.snapshot(sta,ap,1,retry));
 // Independent expected bytes from the stock successful status6/reason0 producer.
 const uint8_t golden[40]={6,4,0x82,0xe0,0,0x2c,0x82,0xe0,0,0,0,0,0x13};
 const auto event=AirportWCL::completedSupplicantPolicy(0x13);
 assert(AirportWCL::SupplicantEvent==76 && !memcmp(&event,golden,sizeof(golden)));
}

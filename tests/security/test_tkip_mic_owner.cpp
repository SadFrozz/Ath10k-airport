#include <cassert>
#include "../../src/security/Ath10kTKIPMICOwner.hpp"
using O=AthSecurity::TKIPMICOwner;
int main(){
 // PTK and GTK index zero have independent replay histories but share the
 // two-failure countermeasure window.
 {O mixed;assert(mixed.begin(1,0));
  assert(mixed.detect({1,5,10,0,16,false},1)==O::Detection::Report);
  assert(mixed.detect({1,5,10,0,16,true},2)==O::Detection::Countermeasures);
  assert(mixed.pending()==2 && mixed.blocked(60001));
 }
 {O pair;assert(pair.begin(1,0));
  assert(pair.detect({1,5,10,1,16,true},1)==O::Detection::Invalid);
  assert(pair.detect({1,5,10,0,16,true},1)==O::Detection::Report);
  assert(pair.detect({1,5,10,0,16,true},2)==O::Detection::Duplicate);
 }
 O o;O::Evidence e{7,1,10,2,16},out{};O::Ticket a{},b{};
 assert(o.begin(7,0));assert(o.detect(e,0)==O::Detection::Report);
 assert(o.detect(e,1)==O::Detection::Duplicate && o.pending()==1);
 assert(o.next(1,out,a) && out.tsc==10);
 assert(!o.complete(a,0,2));assert(o.submitted(a));assert(!o.next(2,out,b));
 ++e.tsc;assert(o.detect(e,2)==O::Detection::Countermeasures && o.blocked(60001));
 assert(o.complete(a,0,3));assert(!o.complete(a,0,4));
 assert(o.next(4,out,b) && b.serial!=a.serial && o.submitted(b));
 assert(o.complete(b,0,5) && !o.pending());o.retire();
 assert(!o.begin(8,60001));assert(o.begin(8,60002));
 assert(!o.complete(b,0,60003));e.association=8;e.keyEpoch=2;e.tsc=1;
 assert(o.detect(e,60003)==O::Detection::Report);
 assert(o.detect({7,2,2,2,16},60004)==O::Detection::Invalid);
 assert(o.detect({8,1,50,2,16},60004)==O::Detection::Invalid);
 assert(o.next(60004,out,b) && o.submitted(b));assert(!o.complete(b,1,60005) && o.needsTeardown());
 O timeout;assert(timeout.begin(9,70000));e.association=9;
 assert(timeout.detect(e,70000)==O::Detection::Report);assert(!timeout.poll(75000) && timeout.needsTeardown());
 O boundary;assert(boundary.begin(1,0));e={1,1,1,0,0};assert(boundary.detect(e,0)==O::Detection::Report);
 assert(boundary.next(1,out,a) && boundary.submitted(a) && boundary.complete(a,0,2));
 ++e.tsc;assert(boundary.detect(e,60001)==O::Detection::Report && !boundary.blocked(60001));
 assert(boundary.detect(e,60000)==O::Detection::Invalid);
 assert(boundary.detect({1,1,3,4,0},60002)==O::Detection::Invalid);
 assert(boundary.detect({1,1,3,0,17},60002)==O::Detection::Invalid);
 assert(boundary.detect({1,1,3,0,0},UINT64_MAX)==O::Detection::Invalid);
 O rollback;assert(rollback.begin(3,100));e={3,1,1,1,16};
 assert(rollback.detect(e,100)==O::Detection::Report);
 assert(!rollback.next(99,out,a) && rollback.needsTeardown());
 O edge;assert(edge.begin(4,0));e={4,1,1,1,16};
 assert(edge.detect(e,0)==O::Detection::Report);
 assert(edge.next(1,out,a) && edge.submitted(a) && edge.complete(a,0,2));
 e.keyEpoch=2; // A newly installed key can legitimately restart its TSC.
 assert(edge.detect(e,60000)==O::Detection::Countermeasures);
 edge.retire();assert(edge.blocked(119999) && !edge.blocked(120000));

 // Association changes cannot erase the first MIC failure's 60-second window.
 O reconnect;assert(reconnect.begin(10,0));e={10,1,1,0,16};
 assert(reconnect.detect(e,10)==O::Detection::Report);
 assert(reconnect.next(11,out,a) && reconnect.submitted(a) && reconnect.complete(a,0,12));
 reconnect.retire();assert(reconnect.begin(11,20));e.association=11;e.keyEpoch=2;
 assert(reconnect.detect(e,21)==O::Detection::Countermeasures && reconnect.blocked(60020));
 // Failure is terminal for this owner: a contradictory later success cannot
 // remove a report after timeout or failed transmission.
 for(unsigned reason=0;reason<2;++reason){
  O terminal;assert(terminal.begin(20,0));e={20,1,1,0,16};
  assert(terminal.detect(e,100)==O::Detection::Report);
  assert(terminal.next(101,out,a) && terminal.submitted(a));
  if(reason)assert(!terminal.complete(a,1,102));else assert(!terminal.poll(5100));
  assert(!terminal.complete(a,0,103) && terminal.pending()==1 && terminal.needsTeardown());
 }
 O restored;auto saved=reconnect.windowState();
 assert(restored.restoreWindow(saved,30) && restored.blocked(60020));
 assert(!restored.pending() && !restored.generation() && !restored.begin(99,30));
 assert(restored.begin(99,60021));
 O firstOnly;assert(firstOnly.begin(1,0));assert(firstOnly.detect({1,1,1,0,16},100)==O::Detection::Report);
 O recovered;assert(recovered.restoreWindow(firstOnly.windowState(),101));assert(recovered.begin(2,102));
 assert(recovered.detect({2,2,1,0,16},103)==O::Detection::Countermeasures);
 O invalid;assert(!invalid.restoreWindow({100,60100,false},101));
 assert(!invalid.restoreWindow({102,0,true},101));assert(!invalid.restoreWindow({100,60099,true},101));
 assert(!invalid.restoreWindow({UINT64_MAX,1,true},UINT64_MAX));
 assert(invalid.restoreWindow({},101));
 recovered.retire();assert(recovered.begin(3,120000));
 assert(recovered.detect({3,3,1,0,16},120001)==O::Detection::Report);
 O later;assert(later.restoreWindow(recovered.windowState(),120002));
 assert(later.begin(4,120003) && later.detect({4,4,1,0,16},120004)==O::Detection::Countermeasures);
}

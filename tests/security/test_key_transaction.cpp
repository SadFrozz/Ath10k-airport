#include <cassert>
#include "../../src/security/Ath10kKeyTransaction.hpp"
using K=AthSecurity::KeyTransaction;
int main(){
 K k;K::Ticket a{},b{};
 assert(k.reserve(1,7,3,0x81,100,50,a));
 assert(!k.reserve(2,7,2,0x81,100,50,b));
 assert(!k.acknowledge(a,7,0x81,101));
 assert(k.submitted(a,101));
 assert(!k.acknowledge(a,8,0x81,102));
 assert(!k.acknowledge(a,7,1,102));
 assert(k.acknowledge(a,7,0x81,149));
 assert(!k.acknowledge(a,7,0x81,149));
 assert(k.state()==K::State::Acknowledged);
 assert(!k.reserve(1,7,2,0x81,149,50,b));
 assert(!k.completeAfterFence(b,149));
 assert(k.completeAfterFence(a,149));
 assert(k.reserve(1,7,2,1,150,50,b) && b.serial!=a.serial);
 assert(!k.submitted(a,151) && k.submitted(b,151));
 assert(!k.acknowledge(b,7,1,200) && k.state()==K::State::Uncertain);
 k.cancel();assert(!k.reserve(2,7,0,1,201,50,a));
 k.firmwareRetired();assert(k.reserve(2,7,0,1,201,50,a));
 assert(!k.acknowledge(b,7,1,202));
 assert(k.rejectBeforeSubmission(a));
 assert(k.reserve(3,7,1,1,300,50,a) && k.submitted(a,301));
 k.cancel();assert(!k.acknowledge(a,7,1,301));
 assert(!k.reserve(4,7,1,1,302,50,b));
 k.firmwareRetired();assert(!k.reserve(4,7,1,1,UINT64_MAX,1,b));
 assert(!k.reserve(4,7,4,1,400,50,b));
 assert(k.reserve(4,7,1,1,400,50,b));assert(!k.poll(450));
 assert(k.reserve(4,7,1,1,451,50,a));k.cancel();assert(k.state()==K::State::Idle);

 // Deadline includes fence retirement; late submission/clock rollback cannot
 // silently turn an old reservation into a new firmware operation.
 assert(k.reserve(5,7,0,0x83,500,50,a));assert(!k.submitted(a,550));
 assert(k.state()==K::State::Idle);
 assert(k.reserve(5,7,0,0x83,600,50,a));assert(!k.submitted(a,599));
 assert(k.state()==K::State::Idle);
 assert(k.reserve(5,7,0,0x83,700,50,a) && k.submitted(a,701));
 assert(k.acknowledge(a,7,0x83,702));
 assert(!k.completeAfterFence(a,750) && k.state()==K::State::Uncertain);
 assert(!k.reserve(6,7,1,0x83,751,50,b));k.firmwareRetired();
 assert(k.reserve(6,7,1,0x82,800,50,b) && k.submitted(b,801));
 assert(!k.acknowledge(a,7,0x82,802));
 assert(k.acknowledge(b,7,0x82,802));k.cancel();
 assert(!k.completeAfterFence(b,803) && k.state()==K::State::Uncertain);
 k.firmwareRetired();
 assert(k.reserve(7,7,1,0x82,900,50,a) && k.submitted(a,901));
 assert(!k.acknowledge(a,7,0x82,899) && k.state()==K::State::Uncertain);
}

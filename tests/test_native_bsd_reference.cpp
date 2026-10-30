#include <cassert>
#include <cstdint>
#include <vector>
using IOReturn=int;
constexpr IOReturn kIOReturnSuccess=0,kIOReturnBadArgument=1,kIOReturnBusy=2,kIOReturnError=3,kIOReturnNotAttached=4;
struct Owner;
struct Ifnet {unsigned references=1;bool deny=false;Owner *softc=nullptr;};
using ifnet_t=Ifnet *;
static std::vector<unsigned> order;
static int ifnet_reference(ifnet_t net){if(net->deny)return 1;assert(net->references);++net->references;return 0;}
static void ifnet_release(ifnet_t net){assert(net->references);--net->references;order.push_back(4);}
struct Owner {
 unsigned references=1;Ifnet net;
 Owner(){net.softc=this;}
 ifnet_t getIfnet(){return &net;}
 void retain(){assert(references);++references;}
 void release(){assert(references);--references;order.push_back(5);if(!references)ifnet_release(&net);}
};
struct Controller {Owner *_networkInterface=nullptr;};
struct IO80211InfraProtocol {
 ifnet_t borrowed=nullptr;bool fail=false;unsigned calls=0,frees=0;
 IOReturn prepareBSDInterface(ifnet_t net,unsigned int options){
  assert(net->references==2 && net->softc->references==2 && options==17);borrowed=net;++calls;
  return fail?kIOReturnError:kIOReturnSuccess;
 }
 void free(){
  assert(!borrowed || (borrowed->references && borrowed->softc->references));
  ++frees;order.push_back(3);borrowed=nullptr;
 }
};
struct Ath10kNativeInterface:IO80211InfraProtocol {
 Controller *controller=nullptr;
 ifnet_t _nativeBSDReference=nullptr;Owner *_nativeBSDOwner=nullptr;
 IOReturn prepareBSDInterface(ifnet_t,unsigned int);
 void releaseTerminationNotification(){order.push_back(1);}
 void detachRegistrationLoan(){order.push_back(2);}
 void free();
};
#include "native_bsd_reference.inc"
#include "native_termination_free.inc"
int main(){
 for(bool failed:{false,true}){
  Owner owner;auto &net=owner.net;Controller controller{&owner};Ath10kNativeInterface native;
  native.controller=&controller;native.fail=failed;order.clear();
  assert(native.prepareBSDInterface(&net,17)==(failed?kIOReturnError:kIOReturnSuccess));
  assert(net.references==2 && native.borrowed==&net && owner.references==2);
  Ifnet other;
  assert(native.prepareBSDInterface(&net,17)==kIOReturnBusy);
  assert(native.prepareBSDInterface(&other,17)==kIOReturnBusy);
  assert(net.references==2 && other.references==1 && native.calls==1 && owner.references==2);
  owner.release(); // Framework drops legacy object ownership before native free.
  assert(owner.references==1 && net.references==2);
  assert(net.softc->references); // Even softc callback context remains allocated.
  order.clear();native.free();
  assert(net.references==0 && !owner.references && native.frees==1);
  assert(!native._nativeBSDReference && !native._nativeBSDOwner);
  assert((order==std::vector<unsigned>{1,2,3,4,5,4}));
 }
 {Owner owner;owner.net.deny=true;Controller controller{&owner};Ath10kNativeInterface native;native.controller=&controller;
  assert(native.prepareBSDInterface(&owner.net,17)==kIOReturnError);
  assert(owner.net.references==1 && owner.references==1 && !native.calls && !native._nativeBSDReference && !native._nativeBSDOwner);
  native.free();assert(owner.net.references==1 && owner.references==1);
  owner.release();assert(!owner.net.references);
 }
 {Ath10kNativeInterface partial;Ifnet orphan;
  assert(partial.prepareBSDInterface(nullptr,17)==kIOReturnBadArgument);
  assert(partial.prepareBSDInterface(&orphan,17)==kIOReturnNotAttached);
  partial.free();assert(!partial.calls && partial.frees==1 && orphan.references==1);
 }
 {Owner owner;Ifnet foreign;Controller controller{&owner};Ath10kNativeInterface native;native.controller=&controller;
  assert(native.prepareBSDInterface(&foreign,17)==kIOReturnNotAttached);
  assert(owner.references==1 && foreign.references==1 && !native.calls);
  native.free();owner.release();
 }
}

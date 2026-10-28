#include <cassert>
#include <cstdint>
#include <vector>
using IOReturn=int;
constexpr IOReturn kIOReturnSuccess=0,kIOReturnBadArgument=1,kIOReturnBusy=2,kIOReturnError=3;
struct Ifnet {unsigned references=1;bool deny=false;};
using ifnet_t=Ifnet *;
static std::vector<unsigned> order;
static int ifnet_reference(ifnet_t net){if(net->deny)return 1;assert(net->references);++net->references;return 0;}
static void ifnet_release(ifnet_t net){assert(net->references);--net->references;order.push_back(4);}
struct IO80211InfraProtocol {
 ifnet_t borrowed=nullptr;bool fail=false;unsigned calls=0,frees=0;
 IOReturn prepareBSDInterface(ifnet_t net,unsigned int options){
  assert(net->references==2 && options==17);borrowed=net;++calls;
  return fail?kIOReturnError:kIOReturnSuccess;
 }
 void free(){assert(!borrowed || borrowed->references);++frees;order.push_back(3);borrowed=nullptr;}
};
struct Ath10kNativeInterface:IO80211InfraProtocol {
 ifnet_t _nativeBSDReference=nullptr;
 IOReturn prepareBSDInterface(ifnet_t,unsigned int);
 void releaseTerminationNotification(){order.push_back(1);}
 void detachRegistrationLoan(){order.push_back(2);}
 void free();
};
#include "native_bsd_reference.inc"
#include "native_termination_free.inc"
int main(){
 for(bool failed:{false,true}){
  Ifnet net;Ath10kNativeInterface native;native.fail=failed;order.clear();
  assert(native.prepareBSDInterface(&net,17)==(failed?kIOReturnError:kIOReturnSuccess));
  assert(net.references==2 && native.borrowed==&net);
  Ifnet other;
  assert(native.prepareBSDInterface(&net,17)==kIOReturnBusy);
  assert(native.prepareBSDInterface(&other,17)==kIOReturnBusy);
  assert(net.references==2 && other.references==1 && native.calls==1);
  ifnet_release(&net); // Legacy BSD owner goes away before native free.
  assert(net.references==1);order.clear();native.free();
  assert(net.references==0 && native.frees==1 && !native._nativeBSDReference);
  assert((order==std::vector<unsigned>{1,2,3,4}));
 }
 {Ifnet denied;denied.deny=true;Ath10kNativeInterface native;
  assert(native.prepareBSDInterface(&denied,17)==kIOReturnError);
  assert(denied.references==1 && !native.calls && !native._nativeBSDReference);
  native.free();assert(denied.references==1);
 }
 {Ath10kNativeInterface partial;
  assert(partial.prepareBSDInterface(nullptr,17)==kIOReturnBadArgument);
  partial.free();assert(!partial.calls && partial.frees==1);
 }
}

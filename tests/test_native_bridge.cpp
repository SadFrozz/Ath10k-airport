#include <cassert>
#include <cstdint>
#include <vector>
using UInt64=uint64_t;using IOReturn=int;using thread_call_param_t=void *;
constexpr IOReturn kIOReturnSuccess=0,kIOReturnNotReady=1,kIOReturnBadArgument=2,kIOReturnAborted=3;
struct OSObject {};
#define OSDynamicCast(type,obj) static_cast<type *>(obj)
namespace Ath10k {inline UInt64 uptimeNS(){return 123000000u;}}
static unsigned scheduled=0,rank=0,cancelled=0,freed=0;static std::vector<unsigned> order;
static void thread_call_enter(void *){++scheduled;}
static bool thread_call_cancel_wait(void *){assert(rank==0);++cancelled;return true;}
static bool thread_call_free(void *){assert(rank==0 && cancelled>freed);++freed;return true;}
using Action=IOReturn (*)(OSObject *,void *,void *,void *,void *);
struct Gate {
 unsigned ownRank;OSObject *owner;
 Gate *getWorkLoop(){return this;}void commandWakeup(void *){}
 IOReturn runAction(Action action){
  assert(ownRank>rank);unsigned previous=rank;rank=ownRank;order.push_back(rank);
  auto result=action(owner,nullptr,nullptr,nullptr,nullptr);rank=previous;return result;
 }
};
class Ath10kPCIDevice:public OSObject {
public:
 bool _nativeStopping=false,_nativeServicePending=false,_nativeMACWaiting=false;
 IOReturn _nativeMACResult=kIOReturnSuccess;
 void *_nativeServiceCall=this;unsigned services=0;
 struct {bool active=true;} _wmiLive;
 Gate wcl{1,this},radio{2,this};Gate *_nativeBSDGate=&wcl,*_nativeGate=&radio;
 void requestNativeService();
 void stopNativeRequests();
 static IOReturn nativeStopAction(OSObject *,void *,void *,void *,void *);
 static void nativeServiceThread(thread_call_param_t,thread_call_param_t);
 static IOReturn nativeServiceWCLAction(OSObject *,void *,void *,void *,void *);
 static IOReturn nativeServiceRadioAction(OSObject *,void *,void *,void *,void *);
 void serviceNative(UInt64 now){assert(rank==2 && now==123);++services;}
};
#include "native_bridge_methods.inc"
#include "native_bridge_stop.inc"
int main(){
 Ath10kPCIDevice d;d.requestNativeService();d.requestNativeService();
 assert(scheduled==1 && d._nativeServicePending && order.empty());
 d.nativeServiceThread(&d,nullptr);
 assert((order==std::vector<unsigned>{1,2}) && d.services==1 && !d._nativeServicePending && rank==0);
 d.requestNativeService();assert(scheduled==2);d._nativeStopping=true;
 d.nativeServiceThread(&d,nullptr);assert(d.services==1 && !d._nativeServicePending);
 d.requestNativeService();assert(scheduled==2);
 Ath10kPCIDevice inactive;inactive._wmiLive.active=false;inactive.requestNativeService();inactive.nativeServiceThread(&inactive,nullptr);assert(!inactive.services);
 Ath10kPCIDevice unattached;unattached._nativeServiceCall=nullptr;unattached.requestNativeService();assert(scheduled==3);
 Ath10kPCIDevice stopping;stopping.requestNativeService();stopping._nativeMACWaiting=true;
 stopping.stopNativeRequests();assert(stopping._nativeStopping && !stopping._nativeServiceCall && !stopping._nativeServicePending && stopping._nativeMACResult==kIOReturnAborted && cancelled==1 && freed==1);
 stopping.stopNativeRequests();assert(cancelled==1 && freed==1);
 assert(Ath10kPCIDevice::nativeServiceRadioAction(nullptr,nullptr,nullptr,nullptr,nullptr)==kIOReturnBadArgument);
 assert(Ath10kPCIDevice::nativeServiceWCLAction(nullptr,nullptr,nullptr,nullptr,nullptr)==kIOReturnNotReady);
}

#include <cassert>
#include <cstdint>
#include <vector>
using UInt64=uint64_t;using IOReturn=int;using thread_call_param_t=void *;
constexpr IOReturn kIOReturnSuccess=0,kIOReturnNotReady=1,kIOReturnBadArgument=2,kIOReturnAborted=3,kIOReturnCannotLock=4,kIOReturnNoMemory=5;
using AbsoluteTime=UInt64;constexpr unsigned kMillisecondScale=1;
static void clock_interval_to_deadline(unsigned n,unsigned,AbsoluteTime *out){*out=n;}
static unsigned delayed=0;
static void thread_call_enter_delayed(void *,AbsoluteTime deadline){assert(deadline==10);++delayed;}
struct OSObject {};
#define OSDynamicCast(type,obj) static_cast<type *>(obj)
namespace Ath10k {inline UInt64 uptimeNS(){return 123000000u;}}
static unsigned scheduled=0,rank=0,cancelled=0,freed=0;static std::vector<unsigned> order;
static void thread_call_enter(void *){++scheduled;}
static bool thread_call_cancel_wait(void *){assert(rank==0);++cancelled;return true;}
static bool thread_call_free(void *){assert(rank==0 && cancelled>freed);++freed;return true;}
using Action=IOReturn (*)(OSObject *,void *,void *,void *,void *);
struct Gate {
 unsigned ownRank;OSObject *owner;bool busy=false;
 IOReturn attemptAction(Action action){return busy?kIOReturnCannotLock:runAction(action);}
 Gate *getWorkLoop(){return this;}void commandWakeup(void *){}
 IOReturn runAction(Action action){
  assert(ownRank>rank);unsigned previous=rank;rank=ownRank;order.push_back(rank);
  auto result=action(owner,nullptr,nullptr,nullptr,nullptr);rank=previous;return result;
 }
};
class Ath10kPCIDevice:public OSObject {
public:
 bool blocked=false;bool powerIOBlocked(){return blocked;}
 void discardNativeSecurity(){++securityDiscards;}unsigned securityDiscards=0;
 bool _nativeWasUp=false,_nativeJoinPending=false,_nativeScanPending=false;
 bool _nativeLinkUpSent=false,_nativeAbortRequested=false,failPost=false;
 IOReturn _nativePostError=kIOReturnSuccess;
 bool _nativeStarted=true,_nativeReadyRequested=true,_nativeReadyPublished=false;
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
 void serviceNative(UInt64 now){assert(rank==2 && now==123);++services;_nativePostError=failPost?kIOReturnNoMemory:kIOReturnSuccess;}
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
 Ath10kPCIDevice contended;contended.requestNativeService();
 contended.radio.busy=true;contended.nativeServiceThread(&contended,nullptr);
 assert(contended.services==0 && contended._nativeServicePending && delayed==1 && rank==0);
 contended.radio.busy=false;contended.wcl.busy=true;contended.nativeServiceThread(&contended,nullptr);
 assert(contended.services==0 && delayed==2 && rank==0);
 contended.wcl.busy=false;contended.nativeServiceThread(&contended,nullptr);
 assert(contended.services==1 && !contended._nativeServicePending);
 Ath10kPCIDevice inactive;inactive._wmiLive.active=false;inactive.requestNativeService();inactive.nativeServiceThread(&inactive,nullptr);assert(!inactive.services);
 inactive._nativeWasUp=true;inactive.requestNativeService();inactive.nativeServiceThread(&inactive,nullptr);assert(inactive.services==1);
 Ath10kPCIDevice unattached;unattached._nativeServiceCall=nullptr;unattached.requestNativeService();assert(scheduled==5);
 Ath10kPCIDevice stopping;stopping.requestNativeService();stopping._nativeMACWaiting=true;
 stopping.stopNativeRequests();assert(stopping._nativeStopping && !stopping._nativeServiceCall && !stopping._nativeServicePending && stopping._nativeMACResult==kIOReturnAborted && cancelled==1 && freed==1);
 stopping.stopNativeRequests();assert(cancelled==1 && freed==1);
 Ath10kPCIDevice starting;starting._nativeStarted=false;unsigned before=scheduled;
 starting.requestNativeService();assert(scheduled==before);
 starting._nativeStarted=true;starting._nativeReadyRequested=false;
 starting.requestNativeService();assert(scheduled==before);
 starting._nativeReadyPublished=true;starting.requestNativeService();assert(scheduled==before+1);
 assert(Ath10kPCIDevice::nativeServiceRadioAction(nullptr,nullptr,nullptr,nullptr,nullptr)==kIOReturnBadArgument);
 assert(Ath10kPCIDevice::nativeServiceWCLAction(nullptr,nullptr,nullptr,nullptr,nullptr)==kIOReturnNotReady);
 Ath10kPCIDevice retry;retry.failPost=true;retry.requestNativeService();
 unsigned priorDelayed=delayed;retry.nativeServiceThread(&retry,nullptr);
 assert(retry.services==1 && retry._nativeServicePending && delayed==priorDelayed+1 && rank==0);
 unsigned priorScheduled=scheduled;retry.requestNativeService();assert(scheduled==priorScheduled);
 retry.failPost=false;retry.nativeServiceThread(&retry,nullptr);
 assert(retry.services==2 && !retry._nativeServicePending);
 Ath10kPCIDevice terminal;terminal._wmiLive.active=false;terminal._nativeAbortRequested=true;
 terminal.requestNativeService();terminal.nativeServiceThread(&terminal,nullptr);assert(terminal.services==1);
 terminal._nativeAbortRequested=false;terminal._nativeLinkUpSent=true;
 terminal.requestNativeService();terminal.nativeServiceThread(&terminal,nullptr);assert(terminal.services==2);
 Ath10kPCIDevice cancelledRetry;cancelledRetry.failPost=true;cancelledRetry.requestNativeService();
 cancelledRetry.nativeServiceThread(&cancelledRetry,nullptr);
 assert(cancelledRetry._nativeServicePending);
 cancelledRetry.stopNativeRequests();
 assert(cancelledRetry._nativeStopping && !cancelledRetry._nativeServiceCall && !cancelledRetry._nativeServicePending);
 assert(cancelled==2 && freed==2);
 // A pending power action suppresses radio/crypto and success events until
 // quiescence, but cannot suppress terminal notifications after runtime ends.
 Ath10kPCIDevice power;power.blocked=true;power._nativeJoinPending=true;
 power.requestNativeService();power.nativeServiceThread(&power,nullptr);
 assert(!power.services && !power._nativeServicePending);
 power._wmiLive.active=false;power.requestNativeService();power.nativeServiceThread(&power,nullptr);
 assert(power.services==1);
 assert(stopping.securityDiscards==2 && cancelledRetry.securityDiscards==1);

}

#include <cassert>
#include <cstdint>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <thread>
using UInt64=uint64_t;using IOReturn=int;using thread_call_param_t=void *;
constexpr IOReturn kIOReturnSuccess=0,kIOReturnNotReady=1,kIOReturnBadArgument=2,kIOReturnAborted=3,kIOReturnCannotLock=4,kIOReturnNoMemory=5,kIOReturnNotAttached=6;
using AbsoluteTime=UInt64;constexpr unsigned kMillisecondScale=1;
static void clock_interval_to_deadline(unsigned n,unsigned,AbsoluteTime *out){*out=n;}
static unsigned delayed=0;
static void thread_call_enter_delayed(void *,AbsoluteTime deadline){assert(deadline==10);++delayed;}
struct IOLock {std::mutex mutex;std::condition_variable cv;};
static void IOLockLock(IOLock *lock){lock->mutex.lock();}
static void IOLockUnlock(IOLock *lock){lock->mutex.unlock();}
constexpr int THREAD_UNINT=0;
static std::atomic<bool> sleeping{false};
static void IOLockSleep(IOLock *lock,void *,int){
 std::unique_lock<std::mutex> guard(lock->mutex,std::adopt_lock);
 sleeping=true;lock->cv.wait(guard);guard.release();
}
static void IOLockWakeup(IOLock *lock,void *,bool){lock->cv.notify_all();}
struct OSObject {};
struct Ath10kNativeInterface {};
#define OSDynamicCast(type,obj) static_cast<type *>(obj)
namespace Ath10k {inline UInt64 uptimeNS(){return 123000000u;}}
static unsigned scheduled=0,cancelled=0,freed=0;static thread_local unsigned rank=0;static std::vector<unsigned> order;
static void thread_call_enter(void *){++scheduled;}
static bool dispatchStarted=false;
static bool thread_call_cancel(void *){assert(rank==0);++cancelled;return !dispatchStarted;}
static bool thread_call_free(void *){assert(rank==0 && cancelled>freed);++freed;return true;}
using Action=IOReturn (*)(OSObject *,void *,void *,void *,void *);
struct Gate {
 unsigned ownRank;OSObject *owner;bool busy=false;std::atomic<bool> *pause=nullptr,*entered=nullptr;
 IOReturn attemptAction(Action action){
  if(pause){*entered=true;while(pause->load())std::this_thread::yield();}
  return busy?kIOReturnCannotLock:runAction(action);
 }
 Gate *getWorkLoop(){return this;}void commandWakeup(void *){}
 IOReturn runAction(Action action,void *argument=nullptr){
  assert(ownRank>rank);unsigned previous=rank;rank=ownRank;order.push_back(rank);
  auto result=action(owner,argument,nullptr,nullptr,nullptr);rank=previous;return result;
 }
};
class Ath10kPCIDevice:public OSObject {
public:
 struct Security {unsigned drains=0;void drainSAEWorker(){assert(rank==0);++drains;}} security;
 Security *_nativeSecurity=&security;
 bool blocked=false;bool powerIOBlocked(){return blocked;}
 Ath10kNativeInterface interface;Ath10kNativeInterface *_nativeInterface=&interface;
 unsigned runtimeStops=0;
 void endWMIRuntime(const char *){assert(rank==2 && _nativeStopping && !_nativeStarted);++runtimeStops;_wmiLive.active=false;}
 void nativeInterfaceWillStop(Ath10kNativeInterface *);
 void prepareNativeInterfaceTermination(Ath10kNativeInterface *);
 void blockPowerIOForTermination(){blocked=true;}
 IOLock *_probePowerLock=nullptr;
 static IOReturn nativeInterfaceStopAction(OSObject *,void *,void *,void *,void *);
 void discardNativeSecurity(){++securityDiscards;}unsigned securityDiscards=0;
 bool _nativeWasUp=false,_nativeJoinPending=false,_nativeScanPending=false;
 bool _nativeLinkUpSent=false,_nativeAbortRequested=false,failPost=false;
 IOReturn _nativePostError=kIOReturnSuccess;
 bool _nativeStarted=true,_nativeReadyRequested=true,_nativeReadyPublished=false;
 bool _nativeStopping=false,_nativeServicePending=false,_nativeMACWaiting=false;
 IOReturn _nativeMACResult=kIOReturnSuccess;
 IOLock serviceLock;IOLock *_nativeServiceLock=&serviceLock;
 bool _nativeServiceQueued=false,_nativeServiceRunning=false,_nativeServiceStopping=false;
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

 // Framework leaf stop retires protocol/radio under the radio gate, without
 // waiting for a service callback which may need that same gate.
 Ath10kPCIDevice leaf;leaf.requestNativeService();
 unsigned cancelsBefore=cancelled,freesBefore=freed;
 leaf.nativeInterfaceWillStop(&leaf.interface);
 assert(leaf._nativeStopping && !leaf._nativeStarted && !leaf._wmiLive.active && leaf.runtimeStops==1);
 assert(cancelled==cancelsBefore && freed==freesBefore && leaf._nativeServiceCall);
 unsigned servicesBefore=leaf.services;leaf.nativeServiceThread(&leaf,nullptr);
 assert(leaf.services==servicesBefore);
 leaf.stopNativeRequests();assert(cancelled==cancelsBefore+1 && freed==freesBefore+1);
 Ath10kPCIDevice wrong;Ath10kNativeInterface unrelated;
 wrong.nativeInterfaceWillStop(&unrelated);
 assert(!wrong._nativeStopping && wrong._nativeStarted && !wrong.runtimeStops && !wrong.securityDiscards);
 assert(Ath10kPCIDevice::nativeInterfaceStopAction(nullptr,nullptr,nullptr,nullptr,nullptr)==kIOReturnNotAttached);
 Ath10kPCIDevice partial;partial._nativeGate=nullptr;
 partial.nativeInterfaceWillStop(&partial.interface);
 assert(partial._nativeStopping && !partial._nativeStarted && partial.securityDiscards==1 && !partial.runtimeStops);

 // Dispatch started in the kernel, but has not entered our callback yet.
 // A false cancellation must retain queued ownership and wait for entry/exit.
 Ath10kPCIDevice dispatch;dispatch.requestNativeService();dispatchStarted=true;sleeping=false;
 std::atomic<bool> finished{false};
 std::thread stopper([&]{dispatch.stopNativeRequests();finished=true;});
 while(!sleeping.load())std::this_thread::yield();
 assert(!finished.load());
 dispatch.nativeServiceThread(&dispatch,nullptr);
 stopper.join();dispatchStarted=false;
 assert(finished && !dispatch._nativeServiceCall && !dispatch._nativeServiceQueued && !dispatch._nativeServiceRunning);
 assert(!dispatch.services); // Closed admission excludes WCL/radio work.
 dispatch.stopNativeRequests();
 Ath10kPCIDevice missing;missing._nativeServiceCall=nullptr;missing._nativeServiceLock=nullptr;
 missing.stopNativeRequests(); // Allocation failure before lock/call creation.

 // Callback is already executing outside the bookkeeping lock. Stop must
 // wait for its final completion publication, even after cancel returns false.
 Ath10kPCIDevice running;running.requestNativeService();dispatchStarted=true;
 std::atomic<bool> pause{true},entered{false};running.wcl.pause=&pause;running.wcl.entered=&entered;
 std::thread callback([&]{running.nativeServiceThread(&running,nullptr);});
 while(!entered.load())std::this_thread::yield();
 sleeping=false;finished=false;
 std::thread runningStop([&]{running.stopNativeRequests();finished=true;});
 while(!sleeping.load())std::this_thread::yield();
 assert(!finished.load());pause=false;
 callback.join();runningStop.join();dispatchStarted=false;
 assert(finished && !running._nativeServiceCall && !running._nativeServiceRunning && !running.services);

}

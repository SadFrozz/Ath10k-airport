#include <cassert>
#include <atomic>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <string>
#include "Ath10kPower.hpp"
using IOReturn=int;using thread_call_param_t=void *;
constexpr int kIOReturnSuccess=0,kIOReturnBadArgument=1,kIOReturnNotReady=2,kIOReturnAborted=3,THREAD_UNINT=0;
constexpr unsigned kIOServiceRequired=1;
static thread_local unsigned probeDepth=0,privateDepth=0,radioDepth=0;
struct IOLock {bool probe;std::mutex mutex;std::condition_variable cv;explicit IOLock(bool p):probe(p){}};
static std::atomic<bool> sleeping{false},pauseExit{false},exitPaused{false};
static void IOLockLock(IOLock *l){l->mutex.lock();++(l->probe?probeDepth:privateDepth);}
static void IOLockUnlock(IOLock *l){--(l->probe?probeDepth:privateDepth);l->mutex.unlock();
 if(l->probe && pauseExit.exchange(false)){exitPaused=true;while(exitPaused.load())std::this_thread::yield();}}
static void IOLockSleep(IOLock *l,void *,int){std::unique_lock<std::mutex> g(l->mutex,std::adopt_lock);--privateDepth;sleeping=true;l->cv.wait(g);++privateDepth;g.release();}
static void IOLockWakeup(IOLock *l,void *,bool){l->cv.notify_all();}
static bool vetoCommit=false;
static bool OSCompareAndSwap(UInt32 a,UInt32 b,volatile UInt32 *p){
 if(a==2 && b==3 && vetoCommit){vetoCommit=false;__sync_lock_test_and_set(p,Ath10k::queuePowerSuspend(2));}
 return __sync_bool_compare_and_swap(p,a,b);
}
struct Call {bool queued=false;};using thread_call_t=Call *;
static unsigned freed=0;
static void thread_call_enter(thread_call_t c){assert(c);c->queued=true;}
static bool thread_call_cancel(thread_call_t c){bool old=c->queued;c->queued=false;return old;}
static bool thread_call_free(thread_call_t c){assert(!c->queued);++freed;delete c;return true;}
struct IOService {
 std::atomic<unsigned> references{1};void (*onLastRelease)(IOService *)=nullptr;
 bool retired=false;bool isInactive(){return retired;}
 virtual ~IOService()=default;
 void retain(){++references;}
 void release(){assert(!privateDepth);if(--references==0 && onLastRelease)onLastRelease(this);}
 std::string phase;
 void setProperty(const char *,const char *value){assert(!privateDepth);phase=value;}
};
using OSObject=IOService;
#define OSDynamicCast(type,p) static_cast<type *>(p)
struct Gate {
 IOReturn runAction(IOReturn (*fn)(OSObject *,void *,void *,void *,void *),OSObject *d,void *out){
  assert(probeDepth && !privateDepth && !radioDepth);++radioDepth;auto result=fn(d,out,nullptr,nullptr,nullptr);--radioDepth;return result;
 }
};
class Ath10kPCIDevice:public IOService {
public:
 IOLock scheduler{false},probe{true};IOLock *_deferredProbeLock=&scheduler,*_probePowerLock=&probe;
 thread_call_t _wakeRecoveryCall=new Call;bool _wakeRecoveryPending=false,_deferredProbeStopping=false,_deferredProbeStarted=true;
 UInt64 _wakeRecoveryGeneration=0;volatile UInt32 _powerIOBlock=2;
 bool _reprobeRequested=false,_systemSuspended=false,_dmaQuarantine=false,inactive=false;
 bool _runtimeActive=false,_runtimeInterruptsEnabled=false,_irqRegistered=false,_irqEnabled=false,_intxConfigChanged=false;
 bool _aspmDisableAttempted=true,_aspmRestoreSucceeded=true,_pcieParityAttempted=true,_pcieParityRestored=true;
 Ath10k::PowerState _power{};struct {bool active=false;} _wmiLive;
 IOService pci;IOService *_pci=&pci;Gate gate;
 bool terminateOK=true,inlineStop=true,sleepAfterCommit=false;unsigned terminations=0;
 Ath10kPCIDevice(){_power.needsRestart=true;}
 Gate *getWorkLoop(){return &gate;}bool isInactive(){return inactive;}
 bool powerRestartAllowed(){return __sync_bool_compare_and_swap(&_powerIOBlock,2,2);}
 void queueWakeRecovery();void cancelWakeRecovery();
 static IOReturn prepareWakeRecovery(OSObject *,void *,void *,void *,void *);
 static void wakeRecoveryCall(void *,void *);
 bool terminate(unsigned flags){
  assert(!privateDepth && !probeDepth && !radioDepth && !_wakeRecoveryPending && flags==kIOServiceRequired);
  ++terminations;if(sleepAfterCommit)_powerIOBlock=Ath10k::queuePowerSuspend(_powerIOBlock);if(inlineStop)cancelWakeRecovery();return terminateOK;
 }
 void dispatch(){auto call=_wakeRecoveryCall;assert(call && call->queued);call->queued=false;wakeRecoveryCall(this,nullptr);}
 ~Ath10kPCIDevice(){assert(!_wakeRecoveryCall && !_wakeRecoveryPending && pci.references==1);}
};
#include "wake_recovery_methods.inc"
static unsigned destroyed=0;
static void destroy(IOService *p){delete static_cast<Ath10kPCIDevice *>(p);++destroyed;}
int main(){
 {Ath10kPCIDevice d;d.queueWakeRecovery();d.queueWakeRecovery();assert(d.references==2 && d._wakeRecoveryPending);
  d.dispatch();assert(d.terminations==1 && d._reprobeRequested && d._powerIOBlock==3 && d.references==1 && !d._wakeRecoveryCall);
  assert(d.pci.phase=="wake-rematch-requested");d.queueWakeRecovery();assert(d.references==1);
 }
 {Ath10kPCIDevice d;d.queueWakeRecovery();d.cancelWakeRecovery();assert(d.references==1 && !d.terminations);d.cancelWakeRecovery();}
 {Ath10kPCIDevice d;d.queueWakeRecovery();vetoCommit=true;d.dispatch();
  assert(!d.terminations && !d._reprobeRequested && d._powerIOBlock==5 && d.references==1);d.cancelWakeRecovery();}
 for(unsigned reason=0;reason<16;++reason){
  Ath10kPCIDevice d;d.queueWakeRecovery();
  switch(reason){
   case 0:d._dmaQuarantine=true;break;case 1:d._systemSuspended=true;break;
   case 2:d._power.deviceOn=false;break;case 3:d._power.rootSleeping=true;break;
   case 4:d._power.needsRestart=false;break;case 5:d._wmiLive.active=true;break;
   case 6:d._runtimeActive=true;break;case 7:d._runtimeInterruptsEnabled=true;break;
   case 8:d._irqRegistered=true;break;case 9:d._irqEnabled=true;break;
   case 10:d._intxConfigChanged=true;break;case 11:d._aspmRestoreSucceeded=false;break;
   case 12:d._pcieParityRestored=false;break;case 13:d.inactive=true;break;case 14:d._pci=nullptr;break;case 15:d.pci.retired=true;break;
  }
  d.dispatch();assert(!d.terminations && !d._reprobeRequested && d.references==1 && !d._wakeRecoveryPending && !d._wakeRecoveryCall->queued);
  d.cancelWakeRecovery();
 }
 { // New On between an obsolete attempt and pending-clear must not be lost.
  Ath10kPCIDevice d;d.queueWakeRecovery();d._powerIOBlock=1;pauseExit=true;exitPaused=false;
  std::thread body([&]{d.dispatch();});while(!exitPaused.load())std::this_thread::yield();
  d._powerIOBlock=2;d.queueWakeRecovery();assert(d.references==2);
  exitPaused=false;body.join();assert(d._wakeRecoveryPending && d._wakeRecoveryCall->queued && !d.terminations);
  d.dispatch();assert(d.terminations==1 && d.references==1);
 }
 { // Already dispatched, not entered: cancellation must wait for the real tail.
  Ath10kPCIDevice d;d.queueWakeRecovery();d._wakeRecoveryCall->queued=false;sleeping=false;
  std::atomic<bool> done{false};std::thread cancel([&]{d.cancelWakeRecovery();done=true;});
  while(!sleeping.load())std::this_thread::yield();assert(!done);
  d.wakeRecoveryCall(&d,nullptr);cancel.join();assert(done && d.references==1 && !d.terminations);
 }
 {Ath10kPCIDevice d;d.inlineStop=false;d.terminateOK=false;d.queueWakeRecovery();d.dispatch();
  assert(d._powerIOBlock==3 && d._reprobeRequested && d.terminations==1 && d.pci.phase=="wake-terminate-rejected");
  d.queueWakeRecovery();assert(!d._wakeRecoveryCall->queued && d.references==1);d.cancelWakeRecovery();}
 {auto d=new Ath10kPCIDevice;d->onLastRelease=destroy;d->queueWakeRecovery();d->release();
  d->dispatch();assert(destroyed==1); // Own running call was freed by inline stop.
 }
 {Ath10kPCIDevice d;d._deferredProbeStarted=false;d.queueWakeRecovery();assert(d.references==1 && !d._wakeRecoveryPending);d.cancelWakeRecovery();}
 {Ath10kPCIDevice d;d.sleepAfterCommit=true;d.queueWakeRecovery();d.dispatch();
  assert(d.terminations==1 && d._reprobeRequested && d._powerIOBlock==0xffffffffu && d.references==1);}
 assert(freed==25);
}

#include <cassert>
#include <cstdint>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <string>
#include <vector>
#include "Ath10kPower.hpp"
using IOOptionBits=unsigned;using IOReturn=int;using thread_call_param_t=void *;
constexpr int kIOReturnBadArgument=-3,kIOReturnSuccess=0,kIOReturnNotReady=-1,kIOReturnAborted=-2,THREAD_UNINT=0;
constexpr int THREAD_CALL_PRIORITY_KERNEL=0,THREAD_CALL_OPTIONS_ONCE=1;
struct IOLock {std::mutex mutex;std::condition_variable cv;};
static unsigned locksFreed=0,callsFreed=0;
static bool failLock=false,failCall=false,failDictionary=false,failNotifier=false;
static thread_local unsigned wclDepth=0,lockDepth=0,radioDepth=0;
static IOLock *IOLockAlloc(){return failLock?nullptr:new IOLock;}
static void IOLockFree(IOLock *lock){++locksFreed;delete lock;}
static void IOLockLock(IOLock *lock){lock->mutex.lock();++lockDepth;}
static void IOLockUnlock(IOLock *lock){--lockDepth;lock->mutex.unlock();}
static void IOLockSleep(IOLock *lock,void *,int){
 std::unique_lock<std::mutex> guard(lock->mutex,std::adopt_lock);--lockDepth;
 lock->cv.wait(guard);++lockDepth;guard.release();
}
static void IOLockWakeup(IOLock *lock,void *,bool){lock->cv.notify_all();}
struct Call {void (*fn)(void *,void *);void *context;bool queued=false;};
using thread_call_t=Call *;
static thread_call_t thread_call_allocate_with_options(void (*fn)(void *,void *),void *arg,int,int){return failCall?nullptr:new Call{fn,arg};}
static void thread_call_enter(thread_call_t call){call->queued=true;}
static bool thread_call_free(thread_call_t call){assert(!call->queued);++callsFreed;delete call;return true;}
static UInt32 OSAddAtomic(int n,volatile UInt32 *p){return __sync_fetch_and_add(p,n);}
static bool OSCompareAndSwap(UInt32 a,UInt32 b,volatile UInt32 *p){return __sync_bool_compare_and_swap(p,a,b);}
struct IOService;struct IONotifier;
using Handler=bool(*)(void *,void *,IOService *,IONotifier *);
static const char *gIOWillTerminateNotification="will-terminate";
static unsigned removals=0,dictReleases=0;
struct OSDictionary {void release(){++dictReleases;delete this;}};
struct IONotifier {Handler handler;void *target;void remove(){++removals;delete this;}};
struct IOService {
 IOService *_provider=nullptr;IOService *getProvider(){return _provider;}
 unsigned references=1;bool opened=false;void (*onLastRelease)(IOService *)=nullptr;
 void retain(){++references;}void release(){assert(references);if(!--references && onLastRelease)onLastRelease(this);}
 bool isOpen(IOService *){assert(!lockDepth);return opened;}
 static OSDictionary *serviceMatching(const char *name){assert(std::string(name)=="Ath10kNativeInterface");return failDictionary?nullptr:new OSDictionary;}
 static IONotifier *addMatchingNotification(const char *type,OSDictionary *,Handler fn,void *arg){assert(type==gIOWillTerminateNotification);return failNotifier?nullptr:new IONotifier{fn,arg};}
};
using OSObject=IOService;
struct Loop {
 std::mutex gate;std::atomic<bool> attempting{false};
 IOReturn runAction(IOReturn (*action)(OSObject *,void *,void *,void *,void *),OSObject *owner,void *a=nullptr,void *b=nullptr,void *c=nullptr,void *d=nullptr){
  assert(!lockDepth && !radioDepth);attempting=true;std::lock_guard<std::mutex> guard(gate);++wclDepth;auto result=action(owner,a,b,c,d);--wclDepth;return result;
 }
};
struct IO80211InfraProtocol:IOService {
 void *borrowed=nullptr;unsigned bsdFinalizes=0;
 void *getBSDInterface(){assert(wclDepth);return borrowed;}
 void finalizeBSDInterface(void *interface,unsigned int){assert(wclDepth && !lockDepth && !radioDepth && interface==borrowed);++bsdFinalizes;borrowed=nullptr;}
 unsigned finalizes=0,powerCalls=0,pmStops=0,didCalls=0,baseFrees=0;bool timeout=true;
 std::atomic<bool> parentEntered{false},parentExit{false};std::mutex powerGate;
 std::thread *pending=nullptr;IOService *didProvider=nullptr;IOOptionBits didOptions=0;
 IOReturn setPowerState(unsigned long ordinal,IOService *device){
  assert(!lockDepth && ordinal==1 && device);++powerCalls;parentEntered=true;
  std::lock_guard<std::mutex> guard(powerGate);parentExit=true;return 47;
 }
 void PMstop(){assert(!lockDepth && !radioDepth);++pmStops;if(!timeout && pending && pending->joinable())pending->join();}
 bool didTerminate(IOService *provider,IOOptionBits options,bool *defer){
  assert(!lockDepth && !radioDepth && wclDepth && !*defer);++didCalls;didProvider=provider;didOptions=options;return true;
 }
 bool finalize(IOOptionBits){assert(!lockDepth && !radioDepth && wclDepth);++finalizes;return true;}
 void free(){++baseFrees;}
 void setProperty(const char *key,const char *value){assert(std::string(key)=="Ath10kNativeTerminationPhase");assert(std::string(value)=="power-admission-closed" || std::string(value)=="bsd-binding-mismatch");}
};
static void ifnet_release(void *){assert(false);}
class Ath10kPCIDevice;
class Ath10kNativeInterface:public IO80211InfraProtocol {
public:
 Loop loop;Loop *getWorkLoop(){return &loop;}
 Ath10kPCIDevice *controller=nullptr;void *_nativeBSDReference=nullptr;
 struct Owner {void release(){assert(false);}};Owner *_nativeBSDOwner=nullptr;
 IONotifier *_terminationNotifier=nullptr;IOLock *_terminationLock=nullptr;thread_call_t _terminationCall=nullptr;
 UInt32 _nativePowerCalls=0;bool _powerAdmissionClosed=false,_terminationRequested=false;
 bool _terminationScheduled=false,_terminationPMStopped=false,_terminationCompleted=false;
 IOService *_terminationProvider=nullptr;IOOptionBits _terminationOptions=0;
 bool _terminationFinalizePending=false;IOOptionBits _terminationFinalizeOptions=0;
 bool prepareTerminationNotification();void releaseTerminationNotification();void closePowerAdmission();void drainPowerCalls();
 IOReturn setPowerState(unsigned long,IOService *);bool didTerminate(IOService *,IOOptionBits,bool *);bool finalize(IOOptionBits);
 static IOReturn finalizeBSDAction(OSObject *,void *,void *,void *,void *);
 static IOReturn resumeTerminationAction(OSObject *,void *,void *,void *,void *);
 static void terminationThread(void *,void *);static bool willTerminateNotification(void *,void *,IOService *,IONotifier *);
 void detachRegistrationLoan(){}void free();
 void runWorker(){auto call=_terminationCall;assert(call && call->queued);call->queued=false;call->fn(call->context,nullptr);}
};
class Ath10kPCIDevice {
public:
 Ath10kNativeInterface *_nativeInterface=nullptr;IOLock *_probePowerLock=nullptr;
 volatile UInt32 _powerIOBlock=0;unsigned retirements=0;
 void blockPowerIOForTermination();void prepareNativeInterfaceTermination(Ath10kNativeInterface *);
 void nativeInterfaceWillStop(Ath10kNativeInterface *object){assert(object==_nativeInterface);++retirements;}
};
// Kernel logging is not part of the termination-order model.
static void IOLog(const char *,...) {}
#include "native_termination_power.inc"
#include "native_termination_controller.inc"
#include "native_termination_notifier.inc"
#include "native_termination_free.inc"
static unsigned destroyed=0;
static void destroyNative(IOService *service){auto native=static_cast<Ath10kNativeInterface *>(service);native->free();delete native;++destroyed;}
int main(){
 for(bool providerOpen:{false,true}){
  Ath10kNativeInterface native;Ath10kPCIDevice controller;IOService provider,device,other;
  controller._nativeInterface=&native;native.controller=&controller;native._provider=&provider;provider.opened=providerOpen;
  assert(native.prepareTerminationNotification());auto call=native._terminationCall;
  int ifnet=0;native.borrowed=native._nativeBSDReference=&ifnet;
  native.powerGate.lock();IOReturn powerResult=0;
  std::thread power([&]{powerResult=native.setPowerState(1,&device);});
  while(!native.parentEntered.load())std::this_thread::yield();
  assert(native._terminationNotifier->handler(&native,nullptr,&other,nullptr));
  assert(!native._powerAdmissionClosed && !controller.retirements);
  assert(native._terminationNotifier->handler(&native,nullptr,&native,nullptr));
  assert(native._powerAdmissionClosed && controller.retirements==1 && controller._powerIOBlock==3 && !native.pmStops);
  bool defer=false;radioDepth=1; // didTerminate must not block its caller's workloop.
  assert(native.didTerminate(&provider,123,&defer));radioDepth=0;
  assert(defer && native.references==2 && provider.references==2 && call->queued && !native.didCalls);
  radioDepth=1;native.finalize(124);radioDepth=0;
  assert(!native.finalizes); // Active-provider finalize must not bypass deferral.
  native.runWorker(); // PMstop returns while the parent body still runs.
  assert(!native.bsdFinalizes && native.pmStops==1 && !native.didCalls && !native._terminationCompleted && !call->queued);
  assert(native.references==2 && provider.references==2 && native._nativePowerCalls==1);
  assert(native.setPowerState(1,&device)==kIOReturnAborted && native.powerCalls==1);
  defer=false;native.didTerminate(&provider,123,&defer);
  assert(native.references==2 && provider.references==2 && !call->queued);
  native.powerGate.unlock();power.join();assert(powerResult==47 && call->queued);
  native.runWorker();
  native._nativeBSDReference=nullptr; // Fixture reference has no real ifnet allocation.
  assert(native.bsdFinalizes==1 && native.finalizes==1 && native.pmStops==1 && native.didCalls==1 && native.didProvider==&provider && native.didOptions==123);
  assert(native.references==1 && provider.references==1 && native._terminationCompleted && !native._nativePowerCalls);
  native.didTerminate(&provider,123,&defer);assert(!defer && native.didCalls==1);
  native.free();assert(native.baseFrees==1 && !native._terminationLock && !native._terminationCall);
 }
 { // Ordinary completion before the worker's first PMstop.
  Ath10kNativeInterface native;IOService provider,device;assert(native.prepareTerminationNotification());
  assert(native.setPowerState(1,&device)==47);bool defer=false;
  native.didTerminate(&provider,8,&defer);native.runWorker();
  assert(native.didCalls==1 && native.pmStops==1 && native._terminationCompleted);native.free();
 }
 { // Direct cleanup after partial startup: actual callback exit, not timeout,
   // gates resource teardown. No global termination worker participates.
  Ath10kNativeInterface native;IOService device;assert(native.prepareTerminationNotification());native.powerGate.lock();
  std::thread power([&]{assert(native.setPowerState(1,&device)==47);});
  while(!native.parentEntered.load())std::this_thread::yield();
  std::atomic<bool> done{false};std::thread cleanup([&]{native.drainPowerCalls();done=true;});
  for(;;){IOLockLock(native._terminationLock);bool closed=native._powerAdmissionClosed;IOLockUnlock(native._terminationLock);if(closed)break;std::this_thread::yield();}
  assert(!done);native.powerGate.unlock();power.join();cleanup.join();assert(done && !native._nativePowerCalls);native.free();
 }
 { // Final self-release from inside the real production thread-call body.
  auto native=new Ath10kNativeInterface;IOService provider;native->onLastRelease=destroyNative;
  assert(native->prepareTerminationNotification());bool defer=false;native->didTerminate(&provider,77,&defer);
  native->release(); // Framework ownership drops; only the deferred job remains.
  auto call=native->_terminationCall;auto fn=call->fn;auto context=call->context;call->queued=false;
  fn(context,nullptr); // Frees native, its lock, and this running call.
  assert(destroyed==1 && provider.references==1);
 }
 { // Compatibility finalize without a preceding didTerminate still starts a safe job.
  Ath10kNativeInterface native;IOService provider;native._provider=&provider;
  assert(native.prepareTerminationNotification());assert(native.finalize(99));
  assert(!native.didCalls && !native.finalizes && native._terminationCall->queued);
  native.runWorker();assert(native.didCalls==1 && native.finalizes==1);native.free();
 }
 { // Callback completion is insufficient until the worker enters the WCL fence.
  Ath10kNativeInterface native;IOService provider;native._provider=&provider;
  assert(native.prepareTerminationNotification());bool defer=false;native.didTerminate(&provider,31,&defer);
  native.loop.gate.lock();std::thread worker([&]{native.runWorker();});
  while(!native.loop.attempting.load())std::this_thread::yield();
  assert(!native._terminationCompleted && !native.didCalls);
  wclDepth=1;native.finalize(32);wclDepth=0;
  assert(!native.finalizes);native.loop.gate.unlock();worker.join();
  assert(native._terminationCompleted && native.finalizes==1 && native.didCalls==1);native.free();
 }
 for(unsigned failure=0;failure<4;++failure){
  failLock=failure==0;failCall=failure==1;failDictionary=failure==2;failNotifier=failure==3;
  Ath10kNativeInterface partial;assert(!partial.prepareTerminationNotification());partial.free();assert(partial.baseFrees==1);
  failLock=failCall=failDictionary=failNotifier=false;
 }
 {Ath10kNativeInterface partial;partial.drainPowerCalls();assert(partial.setPowerState(1,nullptr)==kIOReturnNotReady);partial.free();}
 assert(locksFreed==callsFreed+1 && removals==7); // One lock allocation survives failed call allocation.
}

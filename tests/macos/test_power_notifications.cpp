#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <vector>
#include <chrono>
#include "Ath10kPower.hpp"
using IOReturn=int;using vm_size_t=unsigned long;
constexpr int kIOReturnSuccess=0,kIOReturnBadArgument=1,THREAD_UNINT=0;
constexpr unsigned kIOMessageSystemWillSleep=1,kIOMessageSystemHasPoweredOn=2,kIOMessageSystemWillNotSleep=3;
constexpr int THREAD_CALL_PRIORITY_KERNEL=0,THREAD_CALL_OPTIONS_ONCE=1;
using thread_call_param_t=void *;
class Ath10kPCIDevice;using OSObject=Ath10kPCIDevice;using IOService=Ath10kPCIDevice;
#define OSDynamicCast(type,p) (p)
static void IOLog(const char *,...){}
struct IOLock {std::mutex mutex;std::condition_variable_any cv;void lock(){mutex.lock();}void unlock(){mutex.unlock();}};
static IOLock *IOLockAlloc(){return new IOLock;}
static void IOLockFree(IOLock *p){delete p;}
static void IOLockLock(IOLock *p){p->lock();}
static void IOLockUnlock(IOLock *p){p->unlock();}
static void IOLockSleep(IOLock *p,void *,int){p->cv.wait(*p);}
static void IOLockWakeup(IOLock *p,void *,bool){p->cv.notify_all();}
struct Call {void (*fn)(void *,void *);void *context;bool queued=false;};
using thread_call_t=Call *;static unsigned liveCalls=0;static bool callFails=false;
static thread_call_t thread_call_allocate_with_options(void (*f)(void *,void *),void *c,int,int){if(callFails)return nullptr;++liveCalls;return new Call{f,c,false};}
static void thread_call_enter(thread_call_t c){assert(!c->queued);c->queued=true;}
static void thread_call_free(thread_call_t c){--liveCalls;delete c;}
static void dispatch(thread_call_t c){assert(c && c->queued);auto f=c->fn;auto context=c->context;c->queued=false;f(context,nullptr);}
struct IOPowerStateChangeNotification {void *powerRef=nullptr;unsigned long returnValue=123;};
struct IONotifier {bool removed=false;void remove(){removed=true;}};
static IONotifier notifier;static bool registrationFails=false;
using Handler=IOReturn(*)(void *,void *,UInt32,IOService *,void *,vm_size_t);
static IONotifier *registerPrioritySleepWakeInterest(Handler,void *,void *){return registrationFails?nullptr:&notifier;}
static std::vector<void *> acknowledgements;
static void acknowledgeSleepWakeNotification(void *ref){acknowledgements.push_back(ref);}
class Ath10kPCIDevice {
public:
 struct PowerMessage {UInt32 message=0;void *powerRef=nullptr;};
 static constexpr UInt32 kPowerMessageCapacity=8;
 PowerMessage _powerMessages[kPowerMessageCapacity]{};UInt32 _powerMessageHead=0,_powerMessageCount=0;
 IONotifier *_powerNotifier=nullptr;IOLock *_powerMessageLock=nullptr;
 thread_call_t _powerMessageCall=nullptr;
 bool _powerMessageRunning=false,_powerMessageClosing=false;
 bool preparePowerNotifications();void releasePowerNotifications();bool queuePowerNotification(UInt32,void *);
 static void powerMessageCall(thread_call_param_t,thread_call_param_t);
 static IOReturn powerNotification(void *,void *,UInt32,IOService *,void *,vm_size_t);
 unsigned references=1;void retain(){++references;}void release(){assert(references>1);--references;}
 unsigned suspendsQueued=0;void beginPowerSuspend(){++suspendsQueued;}
 std::mutex radio;std::vector<Ath10k::PowerEvent> events;
 std::atomic<bool> entered{false},allowWork{true};bool closed=false;
 void requestPowerEvent(Ath10k::PowerEvent e,bool preblocked=false){
  assert(preblocked==(e==Ath10k::PowerEvent::SystemSleep && _powerMessageRunning));
  entered=true;while(!allowWork.load())std::this_thread::yield();
  std::lock_guard<std::mutex> g(radio);if(!closed)events.push_back(e);
 }
 ~Ath10kPCIDevice(){releasePowerNotifications();assert(references==1);if(_powerMessageLock)IOLockFree(_powerMessageLock);}
};
#include "power_notification_methods.inc"
#include "power_notification_callback.inc"
static void send(Ath10kPCIDevice &d,unsigned message,IOPowerStateChangeNotification *note=nullptr){
 assert(d.powerNotification(&d,nullptr,message,nullptr,note,note?sizeof(*note):0)==kIOReturnSuccess);
}
// A broken callback must fail the host run instead of hanging CI indefinitely.
class TestDeadline {
 std::mutex lock;std::condition_variable changed;bool complete=false;
 std::thread watchdog;
public:
 TestDeadline():watchdog([this]{std::unique_lock<std::mutex> guard(lock);
  if(!changed.wait_for(guard,std::chrono::seconds(10),[this]{return complete;}))std::abort();}){}
 ~TestDeadline(){{std::lock_guard<std::mutex> guard(lock);complete=true;}changed.notify_one();watchdog.join();}
};
int main(){
 TestDeadline deadline;
 using Ath10k::PowerEvent;
 {
  Ath10kPCIDevice d;assert(d.preparePowerNotifications());assert(d.preparePowerNotifications());
  IOPowerStateChangeNotification note;note.powerRef=&d;
  // An unavailable radio/producer must not block the root callback itself.
  // Admission leaves the root waiting for the worker's explicit ack.
  d.radio.lock();auto start=std::chrono::steady_clock::now();send(d,kIOMessageSystemWillSleep,&note);
  assert(std::chrono::steady_clock::now()-start<std::chrono::seconds(1));
  assert(note.returnValue==30000000 && d.suspendsQueued==1 && acknowledgements.empty() && d.events.empty() && d.references==2);
  auto call=d._powerMessageCall;std::thread worker([&]{dispatch(call);});
  while(!d.entered.load())std::this_thread::yield();
  assert(acknowledgements.empty()); // Radio has not quiesced.
  d.radio.unlock();worker.join();
  assert(d.events==std::vector<PowerEvent>{PowerEvent::SystemSleep});
  assert(acknowledgements==std::vector<void *>{&d} && d.references==1);
  // Wake and cancellation retain their FIFO order, with no extra sleep ack.
  send(d,kIOMessageSystemHasPoweredOn);send(d,kIOMessageSystemWillNotSleep);
  assert(d.references==2);dispatch(d._powerMessageCall);
  assert(d.events.size()==2 && d.events[1]==PowerEvent::SleepCancelled);
  assert(acknowledgements.size()==1 && d.references==1);
  d.releasePowerNotifications();assert(notifier.removed && !d._powerMessageCall);
  assert(!d.preparePowerNotifications());
  // After closure, fallback may synchronously acknowledge ONLY because the
  // controller has already quiesced before releasePowerNotifications is called.
  d.closed=true;IOPowerStateChangeNotification late;late.powerRef=&late;send(d,kIOMessageSystemWillSleep,&late);
  assert(!late.returnValue && acknowledgements.size()==1 && d.events.size()==2);
 }
 acknowledgements.clear();
 {
  // Stop must drain accepted work, not cancel a sleep cookie or free its call
  // while the worker still owns the controller.
  Ath10kPCIDevice d;assert(d.preparePowerNotifications());d.allowWork=false;
  IOPowerStateChangeNotification note;note.powerRef=&note;send(d,kIOMessageSystemWillSleep,&note);
  auto call=d._powerMessageCall;std::thread worker([&]{dispatch(call);});
  while(!d.entered.load())std::this_thread::yield();
  send(d,kIOMessageSystemHasPoweredOn); // Accepted during an existing worker.
  std::atomic<bool> done{false};std::thread stopper([&]{d.releasePowerNotifications();done=true;});
  std::this_thread::sleep_for(std::chrono::milliseconds(10));assert(!done && acknowledgements.empty());
  d.allowWork=true;worker.join();stopper.join();
  assert(done && d.references==1 && !d._powerMessageCall);
  assert(acknowledgements==std::vector<void *>{&note});
  assert(d.events==std::vector<PowerEvent>({PowerEvent::SystemSleep,PowerEvent::SystemWake}));
 }
 acknowledgements.clear();
 {
  // Awake storms cannot exhaust the preallocated queue or allocate in a
  // root callback. Each sleep cookie still has a distinct immutable record.
  Ath10kPCIDevice d;assert(d.preparePowerNotifications());
  for(unsigned i=0;i<2000;++i)send(d,i%2?kIOMessageSystemHasPoweredOn:kIOMessageSystemWillNotSleep);
  assert(d._powerMessageCount==1 && d.references==2);
  IOPowerStateChangeNotification note;note.powerRef=&note;send(d,kIOMessageSystemWillSleep,&note);
  send(d,kIOMessageSystemHasPoweredOn);assert(d._powerMessageCount==3);
  dispatch(d._powerMessageCall);
  assert(d.events==std::vector<PowerEvent>({PowerEvent::SystemWake,PowerEvent::SystemSleep,PowerEvent::SystemWake}));
  assert(acknowledgements==std::vector<void *>{&note} && d.references==1);
 }
 {
  callFails=true;Ath10kPCIDevice d;assert(!d.preparePowerNotifications());callFails=false;
 }
 {
  registrationFails=true;Ath10kPCIDevice d;assert(!d.preparePowerNotifications());registrationFails=false;
 }
 assert(liveCalls==0);
}

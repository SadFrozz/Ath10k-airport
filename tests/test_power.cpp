#include <cassert>
#include <cstring>
#include <cstdint>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include "Ath10kPower.hpp"
using IOReturn=int;using vm_size_t=unsigned long;
constexpr int kIOReturnBadArgument=1,kIOReturnSuccess=0;
constexpr unsigned kIOMessageSystemWillSleep=1,kIOMessageSystemHasPoweredOn=2,kIOMessageSystemWillNotSleep=3;
class Ath10kPCIDevice;using OSObject=Ath10kPCIDevice;using IOService=Ath10kPCIDevice;
#define OSDynamicCast(type,p) (p)
static void IOLog(const char *,...){}
static bool OSCompareAndSwap(UInt32 old,UInt32 next,volatile UInt32 *address){
    return __sync_bool_compare_and_swap(address,old,next);
}
static UInt32 OSAddAtomic(int amount,volatile UInt32 *address){return __sync_fetch_and_add(address,amount);}
using IOLock=std::mutex;
static void IOLockLock(IOLock *lock){lock->lock();}
static void IOLockUnlock(IOLock *lock){lock->unlock();}
struct IONotifier{bool removed=false;void remove(){removed=true;}};
static IONotifier notifier;static bool registrationFail=false;static unsigned registrations=0;
using Handler=IOReturn(*)(void *,void *,UInt32,IOService *,void *,vm_size_t);
static IONotifier *registerPrioritySleepWakeInterest(Handler,void *,void *){++registrations;return registrationFail?nullptr:&notifier;}
struct IOPowerStateChangeNotification{void *powerRef=nullptr;unsigned long returnValue=123;};
static void *acked=nullptr;static void acknowledgeSleepWakeNotification(void *ref){acked=ref;}
struct Gate{
 bool inside=false;
 template<class F> int runAction(F fn,Ath10kPCIDevice *d,void *p){inside=true;int r=fn(d,p,nullptr,nullptr,nullptr);inside=false;return r;}
};
struct MockPCI {template<class... T> bool setProperty(T...){return true;}};
class Ath10kPCIDevice{
 MockPCI mockPCI;MockPCI *_pci=&mockPCI;
public:
 Gate loop;Gate *_wmiWorkLoop=&loop;
 IOLock probeLock;IOLock *_probePowerLock=&probeLock;
 Gate *getWorkLoop(){return &loop;}
 Ath10k::PowerState _power{};volatile UInt32 _powerIOBlock=0;
 IONotifier *_powerNotifier=nullptr;bool _systemSuspended=false,_dmaQuarantine=false;
 struct{bool active=true;const char *status="active";} _wmiLive;
 unsigned dmaChecks=0;bool dmaSafe=true;
 bool stopDMAForRelease(){assert(loop.inside && pciPowered);++dmaChecks;return dmaSafe;}
 unsigned resets=0,published=0;bool resetQuarantines=false,pciPowered=true;
 bool preparePowerNotifications();void releasePowerNotifications();bool powerIOBlocked();bool powerRestartAllowed();
 void beginPowerSuspend();void finishPowerSuspend();
 void requestPowerEvent(Ath10k::PowerEvent);void publishPowerState();
 static IOReturn controlPowerState(OSObject *,void *,void *,void *,void *);
 static IOReturn powerNotification(void *,void *,UInt32,IOService *,void *,vm_size_t);
 template<class... T> void setProperty(T...){}
 void publishWMIRuntimeProperties(){++published;}
 void endWMIRuntime(const char *reason){
  assert(loop.inside && powerIOBlocked());
  if(!_wmiLive.active)return;
  assert(pciPowered);++resets;_wmiLive.active=false;_wmiLive.status=reason;
  if(resetQuarantines)_dmaQuarantine=true;
 }
};
#include "power_methods.inc"
int main(){
 using Ath10k::PowerEvent;
 Ath10kPCIDevice d;assert(d.preparePowerNotifications() && registrations==1);
 assert(d.preparePowerNotifications() && registrations==1);
 // Priority root notice quiesces while PCI is still on, before acknowledging.
 IOPowerStateChangeNotification note;note.powerRef=&d;
 assert(d.powerNotification(&d,nullptr,kIOMessageSystemWillSleep,nullptr,&note,sizeof(note))==0);
 assert(note.returnValue==0 && acked==&d && d.resets==1 && d.powerIOBlocked());
 d.pciPowered=false;d.requestPowerEvent(PowerEvent::DeviceOff);
 d.requestPowerEvent(PowerEvent::DeviceOff);
 assert(d.resets==1 && d._power.sleeps==1 && d._systemSuspended);
 // DeviceOn can occur before SystemHasPoweredOn; it must not permit recovery.
 d.pciPowered=true;d.requestPowerEvent(PowerEvent::DeviceOn);
 assert(d._systemSuspended && d._power.needsRestart && d.powerIOBlocked() && !d.powerRestartAllowed());
 d.powerNotification(&d,nullptr,kIOMessageSystemHasPoweredOn,nullptr,nullptr,0);
 assert(!d._systemSuspended && d._power.wakes==1 && !d._wmiLive.active && d.powerIOBlocked() && d.powerRestartAllowed());
 assert(!strcmp(d._wmiLive.status,"wake-restart-required"));
 d.powerNotification(&d,nullptr,kIOMessageSystemHasPoweredOn,nullptr,nullptr,0);
 assert(d._power.wakes==1 && d.resets==1);d.releasePowerNotifications();
 assert(notifier.removed && !d._powerNotifier);d.releasePowerNotifications();
 // A second sleep before the app completed rematching blocks Restart again.
 d.requestPowerEvent(PowerEvent::SystemSleep);
 assert(d._systemSuspended && !d.powerRestartAllowed() && d._power.sleeps==2 && d.resets==1);
 // DeviceOff may be the first notice; later root notice must not access PCI.
 Ath10kPCIDevice deviceFirst;deviceFirst.requestPowerEvent(PowerEvent::DeviceOff);
 deviceFirst.pciPowered=false;deviceFirst.requestPowerEvent(PowerEvent::SystemSleep);
 assert(deviceFirst.resets==1 && deviceFirst._systemSuspended);
 // Root wake before the device returns also stays blocked until both are on.
 Ath10kPCIDevice late;late.requestPowerEvent(PowerEvent::SystemSleep);
 late.requestPowerEvent(PowerEvent::DeviceOff);late.requestPowerEvent(PowerEvent::SystemWake);
 assert(late._systemSuspended);late.requestPowerEvent(PowerEvent::DeviceOn);
 assert(!late._systemSuspended && late.powerIOBlocked() && late.resets==1);
 // Cancelled sleep after quiescence still needs a clean boot, not old DMA.
 Ath10kPCIDevice cancel;cancel.requestPowerEvent(PowerEvent::SystemSleep);
 cancel.requestPowerEvent(PowerEvent::SleepCancelled);
 assert(!cancel._systemSuspended && cancel._power.needsRestart && cancel.powerIOBlocked());
 // DeviceOn can win the gate after a sleep callback raised the block but
 // before that callback recorded rootSleeping. Keep the pending intent.
 Ath10kPCIDevice pending;pending._powerIOBlock=1;
 pending.requestPowerEvent(PowerEvent::DeviceOn);
 assert(pending.powerIOBlocked() && !pending._power.needsRestart && !strcmp(pending._power.status,"suspend-pending"));
 pending.requestPowerEvent(PowerEvent::SystemSleep);
 pending.requestPowerEvent(PowerEvent::SystemWake);
 assert(pending.powerRestartAllowed() && pending.resets==1);
 // Initial DeviceOn and unsolicited wake never stop a running connection.
 Ath10kPCIDevice initial;initial.requestPowerEvent(PowerEvent::DeviceOn);
 initial.requestPowerEvent(PowerEvent::SystemWake);initial.requestPowerEvent(PowerEvent::SleepCancelled);
 assert(initial._wmiLive.active && !initial.resets && !initial.powerIOBlocked() && !initial._power.needsRestart);
 // Ambiguous DMA ownership remains a blocker after wake.
 Ath10kPCIDevice fail;fail.resetQuarantines=true;fail.requestPowerEvent(PowerEvent::SystemSleep);
 fail.requestPowerEvent(PowerEvent::SystemWake);
 assert(fail._dmaQuarantine && fail.powerIOBlocked() && !strcmp(fail._power.status,"wake-dma-quarantined"));

 // Sleep during bootstrap blocks I/O immediately, then waits for the producer
 // to relinquish initialization ownership before touching the radio or acking.
 // There is no WMI workloop yet; the controller loop is the required fallback.
 Ath10kPCIDevice boot;boot._wmiWorkLoop=nullptr;boot._wmiLive.active=false;
 boot.probeLock.lock();std::atomic<bool> callbackDone{false};
 IOPowerStateChangeNotification bootNote;bootNote.powerRef=&boot;acked=nullptr;
 std::thread sleeper([&]{boot.powerNotification(&boot,nullptr,kIOMessageSystemWillSleep,nullptr,&bootNote,sizeof(bootNote));callbackDone=true;});
 const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
 while(!boot.powerIOBlocked() && std::chrono::steady_clock::now()<deadline)std::this_thread::yield();
 assert(boot.powerIOBlocked() && !callbackDone && !acked);
 // This point models the last bootstrap DMA producer leaving the barrier.
 boot.probeLock.unlock();sleeper.join();
 assert(callbackDone && acked==&boot && boot.dmaChecks==1 && boot._systemSuspended && !boot.resets);
 // Partial bootstrap DMA which cannot be verified stays quarantined at wake.
 Ath10kPCIDevice partial;partial._wmiLive.active=false;partial.dmaSafe=false;
 partial.requestPowerEvent(PowerEvent::SystemSleep);
 assert(partial.dmaChecks==1 && partial._dmaQuarantine);
 partial.pciPowered=false;partial.requestPowerEvent(PowerEvent::DeviceOff);
 partial.requestPowerEvent(PowerEvent::SystemSleep);assert(partial.dmaChecks==1);
 partial.pciPowered=true;partial.requestPowerEvent(PowerEvent::DeviceOn);
 partial.requestPowerEvent(PowerEvent::SystemWake);
 assert(partial._dmaQuarantine && partial.powerIOBlocked());

 // A new root/device suspend can arrive while an older DeviceOn owns the
 // initialization barrier. Neither wake readiness nor the pending count may
 // be overwritten when the older action reaches its 1 -> 2 promotion.
 Ath10kPCIDevice again;again.requestPowerEvent(PowerEvent::SystemSleep);
 again.requestPowerEvent(PowerEvent::SystemWake);assert(again.powerRestartAllowed());
 again.probeLock.lock();
 std::thread rootSleep([&]{again.requestPowerEvent(PowerEvent::SystemSleep);});
 std::thread deviceOff([&]{again.requestPowerEvent(PowerEvent::DeviceOff);});
 const auto pendingDeadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
 while(OSAddAtomic(0,&again._powerIOBlock)<8 && std::chrono::steady_clock::now()<pendingDeadline)std::this_thread::yield();
 assert(OSAddAtomic(0,&again._powerIOBlock)==9 && !again.powerRestartAllowed());
 again.loop.runAction(again.controlPowerState,&again,reinterpret_cast<void *>(static_cast<uintptr_t>(PowerEvent::DeviceOn)));
 assert(OSAddAtomic(0,&again._powerIOBlock)==9 && !again.powerRestartAllowed());
 assert(!strcmp(again._power.status,"suspend-pending"));
 again.probeLock.unlock();rootSleep.join();deviceOff.join();
 assert(OSAddAtomic(0,&again._powerIOBlock)==1 && again._systemSuspended);
 again.requestPowerEvent(PowerEvent::SystemWake);assert(!again.powerRestartAllowed());
 again.requestPowerEvent(PowerEvent::DeviceOn);assert(again.powerRestartAllowed());
 // Saturation is fail-closed; malformed request counts never wrap into active.
 assert(Ath10k::queuePowerSuspend(0)==5 && Ath10k::queuePowerSuspend(2)==5);
 assert(Ath10k::queuePowerSuspend(5)==9 && Ath10k::applyPowerSuspend(9)==5);
 assert(Ath10k::applyPowerSuspend(5)==1);
 assert(Ath10k::queuePowerSuspend(0xfffffffdu)==0xffffffffu);
 assert(Ath10k::applyPowerSuspend(0xffffffffu)==0xffffffffu);
 registrationFail=true;Ath10kPCIDevice alloc;assert(!alloc.preparePowerNotifications() && !alloc._powerNotifier);
}

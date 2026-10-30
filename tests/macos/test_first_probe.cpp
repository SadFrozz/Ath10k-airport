#include <cassert>
#include <cstdint>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <functional>
#include <string>
using thread_call_param_t=void *;
constexpr int THREAD_UNINT=0;
struct IOLock {std::mutex mutex;std::condition_variable cv;};
static std::atomic<bool> sleeping{false};
static void IOLockLock(IOLock *l){l->mutex.lock();}
static void IOLockUnlock(IOLock *l){l->mutex.unlock();}
static void IOLockSleep(IOLock *l,void *,int){std::unique_lock<std::mutex> g(l->mutex,std::adopt_lock);sleeping=true;l->cv.wait(g);g.release();}
static void IOLockWakeup(IOLock *l,void *,bool){l->cv.notify_all();}
struct Call {bool queued=false;};using thread_call_t=Call *;
static bool dispatchStarted=false;static unsigned enters=0,frees=0;
static void thread_call_enter(thread_call_t c){assert(c);c->queued=true;++enters;}
static bool thread_call_cancel(thread_call_t c){bool queued=c->queued;c->queued=false;return queued && !dispatchStarted;}
static bool thread_call_free(thread_call_t c){assert(!c->queued);++frees;delete c;return true;}
static std::function<void()> statusHook;
static void ath10kSetRecoveryStatus(void *,const char *,const char *){if(statusHook)statusHook();}
#define ATH10K_TRACE(...) do{}while(0)
constexpr int kIOPCIConfigCommand=4;
struct PCI {
 std::atomic<bool> *blocked;unsigned reads=0,writes=0;
 unsigned configRead16(int){assert(!blocked->load());++reads;return 7;}
 void setMemoryEnable(bool){assert(!blocked->load());++writes;}
 void setBusMasterEnable(bool){assert(!blocked->load());++writes;}
};
struct BAR {unsigned getLength(){return 4096;}};
struct Regs {unsigned attaches=0;void attach(void *,unsigned length){assert(length==4096);++attaches;}};
class Ath10kPCIDevice {
public:
 IOLock lock;IOLock *_deferredProbeLock=&lock;thread_call_t _deferredProbeCall=new Call;
 bool _deferredProbePending=false,_deferredProbeStarted=false,_deferredProbeStopping=false;
 std::atomic<bool> blocked{true};unsigned starts=0;
 IOLock producer;IOLock *_probePowerLock=&producer;
 PCI pci{&blocked};PCI *_pci=&pci;BAR bar;BAR *_bar0Map=&bar;void *_bar0=this;
 Regs _regs;bool _pciConfigured=false,profileAccepted=true,mapAccepted=true;unsigned _originalCommand=0,identifications=0;
 bool identifyDevice(){assert(!blocked);++identifications;return profileAccepted;}
 bool mapBAR0(){assert(!blocked);return mapAccepted;}
 void dumpPCIConfig(){}void dumpPCICapabilities(){}void validateRegisterLayer(){}void dumpHardwareCandidates(){}
 bool preparePoweredPCI();
 bool powerIOBlocked(){return blocked.load();}
 void queueDeferredProbe();void cancelDeferredProbe();
 static void deferredProbeCall(void *,void *);
 void runDeferredProbe();
 void dispatch(){assert(_deferredProbeCall->queued);_deferredProbeCall->queued=false;deferredProbeCall(this,nullptr);}
 ~Ath10kPCIDevice(){assert(!_deferredProbeCall && !_deferredProbePending);}
};
#include "first_probe_pci.inc"
#include "first_probe_run.inc"
#include "first_probe_scheduler.inc"
#include "first_probe_callback.inc"
#include "first_probe_cancel.inc"
int main(){
 {Ath10kPCIDevice d;unsigned before=enters;d.queueDeferredProbe();assert(enters==before);
  d.blocked=false;d.queueDeferredProbe();d.queueDeferredProbe();assert(enters==before+1 && d._deferredProbePending);
  d.dispatch();assert(d.starts==1 && d._deferredProbeStarted && !d._deferredProbePending && d.identifications==1 && d.pci.reads==1 && d.pci.writes==2 && d._regs.attaches==1 && d._pciConfigured);
  d.queueDeferredProbe();assert(enters==before+1);auto lock=d._deferredProbeLock;d.cancelDeferredProbe();assert(d._deferredProbeLock==lock);
  d.cancelDeferredProbe();assert(!d._deferredProbeCall);
 }
 {Ath10kPCIDevice d;d.blocked=false;d.queueDeferredProbe();d.blocked=true;statusHook=[&]{d.blocked=false;IOLockLock(d._probePowerLock);d.queueDeferredProbe();IOLockUnlock(d._probePowerLock);};
  unsigned before=enters;d.dispatch();
  assert(!d.starts && d._deferredProbePending && d._deferredProbeCall->queued && enters==before+1);
  statusHook=nullptr;d.dispatch();assert(d.starts==1 && !d._deferredProbePending);d.cancelDeferredProbe();
 }
 {Ath10kPCIDevice d;d.blocked=false;d.queueDeferredProbe();d.cancelDeferredProbe();
  unsigned before=enters;d.queueDeferredProbe();assert(enters==before && d._deferredProbeStopping && !d.starts);
 }
 { // A dispatched call has not entered our callback: false cancel must wait.
  Ath10kPCIDevice d;d.blocked=false;d.queueDeferredProbe();d._deferredProbeCall->queued=false;
  dispatchStarted=true;d.blocked=true;sleeping=false;std::atomic<bool> done{false};
  std::thread stop([&]{d.cancelDeferredProbe();done=true;});
  while(!sleeping.load())std::this_thread::yield();assert(!done);
  d.deferredProbeCall(&d,nullptr);stop.join();dispatchStarted=false;
  assert(done && !d._deferredProbeCall && !d.starts && !d._deferredProbePending);
 }
 {Ath10kPCIDevice partial;thread_call_free(partial._deferredProbeCall);partial._deferredProbeCall=nullptr;
  partial.queueDeferredProbe();partial.cancelDeferredProbe();
 }
 {Ath10kPCIDevice badProfile;badProfile.profileAccepted=false;badProfile.blocked=false;badProfile.queueDeferredProbe();badProfile.dispatch();
  assert(badProfile._deferredProbeStarted && !badProfile.starts && !badProfile.pci.reads && !badProfile._pciConfigured);badProfile.cancelDeferredProbe();
 }
 {Ath10kPCIDevice badBAR;badBAR.mapAccepted=false;badBAR.blocked=false;badBAR.queueDeferredProbe();badBAR.dispatch();
  assert(badBAR._deferredProbeStarted && !badBAR.starts && badBAR.pci.reads==1 && badBAR._pciConfigured && !badBAR._regs.attaches);badBAR.cancelDeferredProbe();
 }
 assert(frees==7);
}

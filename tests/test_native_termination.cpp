#include <cassert>
#include <cstdint>
#include <atomic>
#include <thread>
#include <mutex>
#include <chrono>
#include <vector>
#include <string>
#include "Ath10kPower.hpp"
static thread_local unsigned probeDepth=0,radioDepth=0;
struct IOLock {std::mutex mutex;};
static void IOLockLock(IOLock *lock){lock->mutex.lock();++probeDepth;}
static void IOLockUnlock(IOLock *lock){assert(probeDepth);--probeDepth;lock->mutex.unlock();}
static UInt32 OSAddAtomic(int n,volatile UInt32 *p){return __sync_fetch_and_add(p,n);}
static bool OSCompareAndSwap(UInt32 a,UInt32 b,volatile UInt32 *p){return __sync_bool_compare_and_swap(p,a,b);}
struct IOService;struct IONotifier;
using Handler=bool(*)(void *,void *,IOService *,IONotifier *);
static unsigned dictReleases=0,registrations=0,notifierRemoves=0;
static bool failDictionary=false,failNotifier=false;
static const char *gIOWillTerminateNotification="will-terminate";
static std::vector<unsigned> cleanupOrder;
struct OSDictionary {std::string providerClass;void release(){++dictReleases;delete this;}};
struct IONotifier {
    std::string providerClass;Handler handler;void *target;
    void remove(){++notifierRemoves;cleanupOrder.push_back(1);delete this;}
};
struct IOService {
    uint64_t entry=0; // Registry entry ID is not assigned before attachment.
    static OSDictionary *serviceMatching(const char *name){
        assert(std::string(name)=="Ath10kNativeInterface");return failDictionary?nullptr:new OSDictionary{name};
    }
    static IONotifier *addMatchingNotification(const char *type,OSDictionary *matching,Handler fn,void *target){
        assert(type==gIOWillTerminateNotification);++registrations;
        return failNotifier?nullptr:new IONotifier{matching->providerClass,fn,target};
    }
};
struct IO80211InfraProtocol:IOService {
    std::thread *pendingCallout=nullptr;IOLock *probeToCheck=nullptr;std::mutex *radioToCheck=nullptr;
    std::atomic<bool> pmWaiting{false},pmDone{false};bool simulateTimeout=false;unsigned pmStops=0,baseFrees=0;
    std::vector<std::string> phases;
    void PMstop(){
        assert(!probeDepth && !radioDepth);
        if(probeToCheck){assert(probeToCheck->mutex.try_lock());probeToCheck->mutex.unlock();}
        if(radioToCheck){assert(radioToCheck->try_lock());radioToCheck->unlock();}
        ++pmStops;pmWaiting=true;
        if(simulateTimeout)return;
        if(pendingCallout && pendingCallout->joinable())pendingCallout->join();
        pmDone=true;
    }
    void setProperty(const char *key,const char *value){assert(std::string(key)=="Ath10kNativeTerminationPhase");phases.emplace_back(value);}
    virtual void free(){++baseFrees;cleanupOrder.push_back(3);}
};
class Ath10kPCIDevice;
class Ath10kNativeInterface:public IO80211InfraProtocol {
public:
    Ath10kPCIDevice *controller=nullptr;IONotifier *_terminationNotifier=nullptr;
    bool prepareTerminationNotification();void releaseTerminationNotification();
    static bool willTerminateNotification(void *,void *,IOService *,IONotifier *);
    void detachRegistrationLoan(){cleanupOrder.push_back(2);}
    void free() override;
};
class Ath10kPCIDevice {
public:
    IOLock probe;IOLock *_probePowerLock=&probe;std::mutex radio;
    Ath10kNativeInterface *_nativeInterface=nullptr;
    volatile UInt32 _powerIOBlock=0;std::atomic<unsigned> retired{0};bool stopped=false;
    void blockPowerIOForTermination();void prepareNativeInterfaceTermination(Ath10kNativeInterface *);
    void nativeInterfaceWillStop(Ath10kNativeInterface *interface){
        assert(interface==_nativeInterface && (_probePowerLock?probeDepth==1:probeDepth==0));
        std::lock_guard<std::mutex> gate(radio);++radioDepth;
        assert((OSAddAtomic(0,&_powerIOBlock)&3u)==3u);stopped=true;++retired;
        --radioDepth;
    }
};
#include "native_termination_power.inc"
#include "native_termination_controller.inc"
#include "native_termination_notifier.inc"
#include "native_termination_free.inc"
template<class F> static void waitUntil(F condition){
    auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
    while(!condition() && std::chrono::steady_clock::now()<deadline)std::this_thread::yield();
    assert(condition());
}
int main(){
    Ath10kPCIDevice driver;Ath10kNativeInterface interface;driver._nativeInterface=&interface;interface.controller=&driver;
    assert(interface.prepareTerminationNotification());unsigned installed=registrations,released=dictReleases;
    assert(interface.entry==0 && interface._terminationNotifier->providerClass=="Ath10kNativeInterface");
    assert(interface.prepareTerminationNotification() && registrations==installed && dictReleases==released);
    // A pending PM callout needs WCL; an existing WCL command could need radio.
    // Keep WCL busy until PMstop begins to wait, then let that callout use both.
    std::mutex wcl;std::unique_lock<std::mutex> wclCommand(wcl);
    std::atomic<bool> pmEntered{false},callbackDone{false};
    std::thread pm([&]{pmEntered=true;std::lock_guard<std::mutex> queue(wcl);std::lock_guard<std::mutex> radio(driver.radio);assert(driver.stopped);});
    interface.pendingCallout=&pm;interface.probeToCheck=&driver.probe;interface.radioToCheck=&driver.radio;
    IOLockLock(&driver.probe);waitUntil([&]{return pmEntered.load();});
    std::thread termination([&]{
        assert(interface._terminationNotifier->handler(interface._terminationNotifier->target,nullptr,&interface,interface._terminationNotifier));callbackDone=true;
    });
    waitUntil([&]{return OSAddAtomic(0,&driver._powerIOBlock)==3;});
    assert(driver.retired==0 && !interface.pmWaiting && !callbackDone);
    IOLockUnlock(&driver.probe);waitUntil([&]{return interface.pmWaiting.load();});
    assert(driver.retired==1 && !callbackDone && !interface.pmDone);
    wclCommand.unlock();termination.join();assert(callbackDone && interface.pmDone && !pm.joinable());
    assert((interface.phases==std::vector<std::string>{"draining-power","pm-stop-returned"}));
    assert(!OSCompareAndSwap(1,2,&driver._powerIOBlock)); // Old wake cannot revive retired instance.
    cleanupOrder.clear();unsigned removed=notifierRemoves;
    interface.free();assert(notifierRemoves==removed+1 && interface.baseFrees==1 && !interface._terminationNotifier);
    assert((cleanupOrder==std::vector<unsigned>{1,2,3}));
    interface.releaseTerminationNotification();assert(notifierRemoves==removed+1);
    {
        Ath10kNativeInterface other;IOService unrelated;Ath10kPCIDevice owner;
        other.controller=&owner;owner._nativeInterface=&other;
        assert(other.willTerminateNotification(nullptr,nullptr,&other,nullptr));
        assert(other.willTerminateNotification(&other,nullptr,&unrelated,nullptr));
        assert(!owner.retired && !other.pmStops && OSAddAtomic(0,&owner._powerIOBlock)==0);
        Ath10kNativeInterface foreign;
        assert(other.willTerminateNotification(&other,nullptr,&foreign,nullptr));
        assert(!owner.retired && !other.pmStops);
        owner.prepareNativeInterfaceTermination(&foreign);
        assert(!owner.retired && OSAddAtomic(0,&owner._powerIOBlock)==0);
        other.free();foreign.free();
    }
    {
        Ath10kNativeInterface orphan;
        assert(orphan.willTerminateNotification(&orphan,nullptr,&orphan,nullptr) && orphan.pmStops==1);
        orphan.free();
    }
    for(unsigned failure=0;failure<2;++failure){
        Ath10kNativeInterface failed;failDictionary=failure==0;failNotifier=failure==1;
        unsigned before=dictReleases;
        assert(!failed.prepareTerminationNotification() && !failed._terminationNotifier);
        assert(dictReleases==before+(failure==1?1u:0u));failed.free();
        failDictionary=failNotifier=false;
    }
    { // The real PMstop can return on timeout while a callout remains alive.
        // The notifier must report only return, not verified completion.
        Ath10kNativeInterface timed;timed.simulateTimeout=true;
        std::mutex pending;std::unique_lock<std::mutex> hold(pending);
        std::atomic<bool> entered{false},finished{false};
        std::thread callout([&]{entered=true;std::lock_guard<std::mutex> lock(pending);finished=true;});
        timed.pendingCallout=&callout;waitUntil([&]{return entered.load();});
        assert(timed.willTerminateNotification(&timed,nullptr,&timed,nullptr));
        assert(timed.pmWaiting && !timed.pmDone && !finished && callout.joinable());
        assert(timed.phases.back()=="pm-stop-returned");
        // Cleanup safety for this unfinished call is still a required driver
        // change, so the seam releases it before exercising final free.
        hold.unlock();callout.join();timed.free();
    }
    // Permanent termination preserves pending bits and is irreversible by old wake.
    Ath10kPCIDevice queued;queued._powerIOBlock=9;queued.blockPowerIOForTermination();
    assert(OSAddAtomic(0,&queued._powerIOBlock)==11);
    assert(Ath10k::applyPowerSuspend(11)==11 && !OSCompareAndSwap(1,2,&queued._powerIOBlock));
}

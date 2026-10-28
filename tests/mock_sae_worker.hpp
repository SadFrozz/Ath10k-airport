#pragma once
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <thread>
using namespace std::chrono_literals;
static thread_local unsigned heldLocks=0;
static thread_local bool ownerGate=false;
static std::atomic<unsigned> objects{0},locks{0},calls{0},sleeps{0};
static bool failLock=false,failCall=false;
static bool failObjectInit=false;
static void (*objectInitHook)()=nullptr;
class OSObject;
static void (*objectFreeObserver)(OSObject *)=nullptr;
static std::mutex observation;
static std::condition_variable observed;
class OSObject {
    std::atomic<unsigned> refs{1};
public:
    OSObject(){++objects;}
    virtual ~OSObject(){--objects;}
    virtual bool init(){
        if(failObjectInit){failObjectInit=false;return false;}
        auto hook=objectInitHook;objectInitHook=nullptr;if(hook)hook();return true;
    }
    virtual void free(){if(objectFreeObserver)objectFreeObserver(this);delete this;}
    void retain(){++refs;}
    void release(){if(--refs==0)free();}
    unsigned references() const {return refs;}
};
#define OSDynamicCast(type,obj) dynamic_cast<type *>(obj)
#define OSDeclareAbstractStructors(name)
#define OSDeclareDefaultStructors(name)
#define OSDefineMetaClassAndAbstractStructors(name,base)
#define OSDefineMetaClassAndStructors(name,base)
struct IOLock {std::mutex mutex;std::condition_variable cv;};
static IOLock *IOLockAlloc(){if(failLock){failLock=false;return nullptr;}++locks;return new IOLock;}
static void IOLockFree(IOLock *p){--locks;delete p;}
static void IOLockLock(IOLock *p){p->mutex.lock();++heldLocks;}
static void IOLockUnlock(IOLock *p){assert(heldLocks);--heldLocks;p->mutex.unlock();}
static constexpr int THREAD_UNINT=0,THREAD_CALL_PRIORITY_KERNEL=0,THREAD_CALL_OPTIONS_ONCE=1;
static void IOLockSleep(IOLock *p,void *,int){
    assert(!ownerGate && heldLocks==1);--heldLocks;
    {std::lock_guard<std::mutex> guard(observation);++sleeps;observed.notify_all();}
    std::unique_lock<std::mutex> guard(p->mutex,std::adopt_lock);
    p->cv.wait(guard);guard.release();++heldLocks;
}
static void IOLockWakeup(IOLock *p,void *,bool){p->cv.notify_all();}
using thread_call_param_t=void *;
struct Call {
    void (*function)(void *,void *);void *context;
    bool queued=false,inflight=false,rescheduled=false,freed=false;
};
using thread_call_t=Call *;
static std::mutex kernel;
static Call *latest=nullptr;
static Call *thread_call_allocate_with_options(void (*fn)(void *,void *),void *ctx,int,int options){
    assert(options==THREAD_CALL_OPTIONS_ONCE);
    if(failCall){failCall=false;return nullptr;}
    std::lock_guard<std::mutex> guard(kernel);++calls;latest=new Call{fn,ctx};return latest;
}
static bool thread_call_enter(Call *p){
    std::lock_guard<std::mutex> guard(kernel);assert(!p->freed);
    const bool old=p->queued || p->rescheduled;if(p->inflight)p->rescheduled=true;else p->queued=true;return old;
}
static bool thread_call_cancel(Call *p){
    std::lock_guard<std::mutex> guard(kernel);
    if(p->rescheduled){p->rescheduled=false;return true;}
    if(p->queued){p->queued=false;return true;}return false;
}
static bool thread_call_free(Call *p){
    std::lock_guard<std::mutex> guard(kernel);assert(!p->freed && !p->queued && !p->rescheduled);
    p->freed=true;if(!p->inflight){--calls;delete p;}return true;
}
// Model the XNU dispatch-before-callback and callback-before-kernel-return gaps.
static void claim(Call *p){std::lock_guard<std::mutex> guard(kernel);assert(p->queued && !p->inflight);p->queued=false;p->inflight=true;}
static void invoke(Call *p){p->function(p->context,nullptr);}
static void finish(Call *p){
    std::lock_guard<std::mutex> guard(kernel);assert(p->inflight);p->inflight=false;
    if(p->freed){assert(!p->rescheduled);--calls;delete p;return;}
    if(p->rescheduled){p->rescheduled=false;p->queued=true;}
}
static void run(Call *p){claim(p);invoke(p);finish(p);}
#include "sae_worker.inc"


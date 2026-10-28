#pragma once
#include <IOKit/IOLib.h>
#include <libkern/c++/OSObject.h>
#include <kern/thread_call.h>

// Jobs retain their immutable session/snapshots, not borrowed NativeSecurity
// pointers. execute/discard/free must never enter driver gates or drain this
// queue. Final release always discards, including after normal consumption.
class Ath10kSAEWorkItem : public OSObject {
    OSDeclareAbstractStructors(Ath10kSAEWorkItem)
    void free() override final;
public:
    virtual void execute()=0;
    virtual void discard()=0; // Idempotent, nonblocking; never concurrent with execute.
};

// Single in-flight job plus its unconsumed result. Completion never enters WCL
// or radio: the owner takes the result and checks its session/generation there.
class Ath10kSAEWorker : public OSObject {
    OSDeclareDefaultStructors(Ath10kSAEWorker)
    enum class State { Idle, Queued, Running, Complete };
    IOLock *_lock=nullptr;
    thread_call_t _call=nullptr;
    Ath10kSAEWorkItem *_job=nullptr;
    State _state=State::Idle;
    unsigned _retiring=0;
    bool _cancelled=false,_stopping=false;
    struct Retirement {Ath10kSAEWorkItem *job=nullptr;bool callbackRetain=false;};
    Retirement cancelLocked();
    void retire(Retirement);
    static void dispatch(thread_call_param_t,thread_call_param_t);
    void free() override;
public:
    bool init() override;
    bool submit(Ath10kSAEWorkItem *); // Caller retains its own job reference.
    bool available(); // Advisory only; submit still rechecks under its lock.
    Ath10kSAEWorkItem *takeCompleted(); // Transfers one retained reference.
    void cancel(); // Safe under owner gate: no wait for queued/running callback.
    void shutdown(); // Outside ALL owner gates and this callback; waits/drains.
};

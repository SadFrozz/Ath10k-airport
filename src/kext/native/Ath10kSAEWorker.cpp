#include "Ath10kSAEWorker.hpp"

OSDefineMetaClassAndAbstractStructors(Ath10kSAEWorkItem,OSObject)
OSDefineMetaClassAndStructors(Ath10kSAEWorker,OSObject)

void Ath10kSAEWorkItem::free() {
    discard();OSObject::free();
}
bool Ath10kSAEWorker::init() {
    if(!OSObject::init())return false;
    _lock=IOLockAlloc();if(!_lock)return false;
    _call=thread_call_allocate_with_options(dispatch,this,THREAD_CALL_PRIORITY_KERNEL,THREAD_CALL_OPTIONS_ONCE);
    return _call!=nullptr;
}
bool Ath10kSAEWorker::submit(Ath10kSAEWorkItem *job) {
    if(!job || !_lock)return false;
    IOLockLock(_lock);
    if(_stopping || !_call || _state!=State::Idle || _retiring){IOLockUnlock(_lock);return false;}
    job->retain();retain(); // Job ownership and one queue reference per callback.
    _job=job;_state=State::Queued;_cancelled=false;
    thread_call_enter(_call);
    IOLockUnlock(_lock);return true;
}
bool Ath10kSAEWorker::available() {
    if(!_lock)return false;
    IOLockLock(_lock);
    const bool ready=!_stopping && _call && _state==State::Idle && !_retiring;
    IOLockUnlock(_lock);return ready;
}
Ath10kSAEWorkItem *Ath10kSAEWorker::takeCompleted() {
    if(!_lock)return nullptr;
    IOLockLock(_lock);
    Ath10kSAEWorkItem *job=nullptr;
    if(!_stopping && _state==State::Complete){job=_job;_job=nullptr;_state=State::Idle;}
    IOLockUnlock(_lock);return job;
}
Ath10kSAEWorker::Retirement Ath10kSAEWorker::cancelLocked() {
    Retirement result;_cancelled=true;
    if(_state==State::Complete || (_state==State::Queued && _call && thread_call_cancel(_call))){
        result.job=_job;result.callbackRetain=_state==State::Queued;
        _job=nullptr;_state=State::Idle;++_retiring;
    }
    // False cancellation can mean dispatch has started before callback entry.
    // Keep Queued + its retained job/queue until dispatch observes cancellation.
    return result;
}
void Ath10kSAEWorker::retire(Retirement item) {
    if(!item.job)return;
    // Discard/release can destroy a retained session. Never hold bookkeeping lock.
    item.job->discard();item.job->release();
    IOLockLock(_lock);--_retiring;IOLockWakeup(_lock,&_state,false);IOLockUnlock(_lock);
    if(item.callbackRetain)release(); // Cancelled callback will not release it.
}
void Ath10kSAEWorker::cancel() {
    if(!_lock)return;
    IOLockLock(_lock);const auto retired=cancelLocked();IOLockUnlock(_lock);
    retire(retired);
}
void Ath10kSAEWorker::shutdown() {
    if(!_lock)return;
    IOLockLock(_lock);_stopping=true;const auto retired=cancelLocked();IOLockUnlock(_lock);
    retire(retired);
    IOLockLock(_lock);
    while(_state==State::Queued || _state==State::Running || _retiring)
        IOLockSleep(_lock,&_state,THREAD_UNINT);
    auto call=_call;_call=nullptr;
    IOLockUnlock(_lock);
    if(call)thread_call_free(call);
}
void Ath10kSAEWorker::dispatch(thread_call_param_t context,thread_call_param_t) {
    auto self=static_cast<Ath10kSAEWorker *>(context);auto lock=self->_lock;
    IOLockLock(lock);
    auto job=self->_job;self->_state=State::Running;
    const bool run=!self->_cancelled && !self->_stopping;
    IOLockUnlock(lock);
    if(run)job->execute();
    IOLockLock(lock);
    if(!self->_cancelled && !self->_stopping){
        self->_state=State::Complete;IOLockWakeup(lock,&self->_state,false);IOLockUnlock(lock);
    }else{
        self->_job=nullptr;
        IOLockUnlock(lock);
        job->discard();job->release();
        IOLockLock(lock);self->_state=State::Idle;
        IOLockWakeup(lock,&self->_state,false);IOLockUnlock(lock);
    }
    // No queue access after releasing this callback's reference. XNU retains
    // executing allocated ONCE calls until callback return, even after free.
    self->release();
}
void Ath10kSAEWorker::free() {
    shutdown();
    if(_lock){IOLockFree(_lock);_lock=nullptr;}
    OSObject::free();
}

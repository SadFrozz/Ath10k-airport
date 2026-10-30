#include "Ath10kPCIDevice.hpp"
#include <libkern/OSAtomic.h>

void Ath10kPCIDevice::queueWakeRecovery()
{
    // The power dispatcher owns the producer barrier. Read scheduler state
    // under its lock; all detailed hardware checks happen on radio below.
    if(!_deferredProbeLock || !powerRestartAllowed())return;
    IOLockLock(_deferredProbeLock);
    if(!_deferredProbeStopping && _deferredProbeStarted && _wakeRecoveryCall && powerRestartAllowed()){
        ++_wakeRecoveryGeneration;
        if(!_wakeRecoveryPending){
            _wakeRecoveryPending=true;retain();thread_call_enter(_wakeRecoveryCall);
        }
    }
    IOLockUnlock(_deferredProbeLock);
}
IOReturn Ath10kPCIDevice::prepareWakeRecovery(OSObject *owner,void *output,void *,void *,void *)
{
    auto self=OSDynamicCast(Ath10kPCIDevice,owner);
    if(!self || !output)return kIOReturnBadArgument;
    if(!self->powerRestartAllowed() || !self->_deferredProbeStarted || self->isInactive() || self->_reprobeRequested || !self->_pci || self->_pci->isInactive() ||
       self->_systemSuspended || !self->_power.deviceOn || self->_power.rootSleeping || !self->_power.needsRestart)
        return kIOReturnNotReady;
    if(self->_dmaQuarantine || self->_wmiLive.active || self->_runtimeActive || self->_runtimeInterruptsEnabled ||
       self->_irqRegistered || self->_irqEnabled || self->_intxConfigChanged ||
       (self->_aspmDisableAttempted && !self->_aspmRestoreSucceeded) ||
       (self->_pcieParityAttempted && !self->_pcieParityRestored)){
        self->setProperty("Ath10kWakeRecovery","retirement-not-verified");return kIOReturnNotReady;
    }
    // Linearization point. A sleep/off queued before this changes the same
    // word and vetoes recovery. After commit, retirement is irreversible and
    // the new instance must obey its parent's current power permission.
    if(!OSCompareAndSwap(2,3,&self->_powerIOBlock))return kIOReturnAborted;
    self->_reprobeRequested=true;
    self->_pci->retain();*static_cast<IOService **>(output)=self->_pci;
    return kIOReturnSuccess;
}
void Ath10kPCIDevice::wakeRecoveryCall(thread_call_param_t context,thread_call_param_t)
{
    auto self=static_cast<Ath10kPCIDevice *>(context);
    IOLockLock(self->_deferredProbeLock);
    const auto generation=self->_wakeRecoveryGeneration;
    const bool stopping=self->_deferredProbeStopping;
    IOLockUnlock(self->_deferredProbeLock);
    IOService *provider=nullptr;
    if(!stopping){
        IOLockLock(self->_probePowerLock);
        if(auto loop=self->getWorkLoop())loop->runAction(prepareWakeRecovery,self,&provider);
        IOLockUnlock(self->_probePowerLock);
    }
    IOLockLock(self->_deferredProbeLock);
    if(!provider && !self->_deferredProbeStopping && generation!=self->_wakeRecoveryGeneration && self->powerRestartAllowed()){
        // A new eligible wake arrived while this attempt was pending. Transfer
        // the existing job reference to the resubmitted ONCE callback.
        thread_call_enter(self->_wakeRecoveryCall);IOLockUnlock(self->_deferredProbeLock);return;
    }
    // Hand cancellation ownership off BEFORE terminate can invoke stop. Stop
    // may free this call, but the callback owns self until its final release.
    self->_wakeRecoveryPending=false;
    IOLockWakeup(self->_deferredProbeLock,&self->_wakeRecoveryPending,false);
    IOLockUnlock(self->_deferredProbeLock);
    if(provider){
        provider->setProperty("Ath10kRecoveryPhase","wake-rematch-requested");
        if(!self->terminate(kIOServiceRequired))
            provider->setProperty("Ath10kRecoveryPhase","wake-terminate-rejected");
        provider->release();
    }
    self->release(); // No access to self or the thread call after this point.
}
void Ath10kPCIDevice::cancelWakeRecovery()
{
    if(!_deferredProbeLock)return;
    IOLockLock(_deferredProbeLock);_deferredProbeStopping=true;
    bool releaseJob=false;
    if(_wakeRecoveryCall && thread_call_cancel(_wakeRecoveryCall) && _wakeRecoveryPending){
        _wakeRecoveryPending=false;releaseJob=true;
    }
    while(_wakeRecoveryPending)IOLockSleep(_deferredProbeLock,&_wakeRecoveryPending,THREAD_UNINT);
    auto call=_wakeRecoveryCall;_wakeRecoveryCall=nullptr;
    IOLockUnlock(_deferredProbeLock);
    if(call)thread_call_free(call);
    if(releaseJob)release(); // May destroy this object; no later access.
}

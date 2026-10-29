#include "Ath10kPCIDevice.hpp"
#include <IOKit/IOMessage.h>
#include <IOKit/pwr_mgt/RootDomain.h>

bool Ath10kPCIDevice::preparePowerNotifications()
{
    if(_powerNotifier)return true;
    if(_powerMessageClosing)return false; // A retired notifier cannot reopen admission.
    if(!_powerMessageLock)_powerMessageLock=IOLockAlloc();
    if(!_powerMessageLock)return false;
    if(!_powerMessageCall)_powerMessageCall=thread_call_allocate_with_options(
        powerMessageCall,this,THREAD_CALL_PRIORITY_KERNEL,THREAD_CALL_OPTIONS_ONCE);
    if(!_powerMessageCall)return false;
    _powerNotifier=registerPrioritySleepWakeInterest(powerNotification,this,nullptr);
    return _powerNotifier!=nullptr;
}

bool Ath10kPCIDevice::queuePowerNotification(UInt32 message,void *argument)
{
    auto *note=static_cast<IOPowerStateChangeNotification *>(argument);
    if(!_powerMessageLock || !_powerMessageCall ||
       (message==kIOMessageSystemWillSleep && !note))return false;
    IOLockLock(_powerMessageLock);
    if(_powerMessageClosing){IOLockUnlock(_powerMessageLock);return false;}
    // Both awake notices have the same rootSleeping=false transition. Collapse
    // adjacent notices only; never cross a sleep or discard its ack cookie.
    const bool awake=message!=kIOMessageSystemWillSleep;
    if(awake && _powerMessageCount){
        auto &tail=_powerMessages[(_powerMessageHead+_powerMessageCount-1)%kPowerMessageCapacity];
        if(tail.message!=kIOMessageSystemWillSleep){
            tail.message=message;IOLockUnlock(_powerMessageLock);return true;
        }
    }
    // A conforming root waits for the sleep cookie before starting the next
    // sleep phase. With adjacent awake notices coalesced there cannot be more
    // than one queued sleep and one queued awake notice. Keep spare slots and
    // fail without overwriting any accepted work on a protocol violation.
    if(_powerMessageCount==kPowerMessageCapacity){
        IOLockUnlock(_powerMessageLock);return false;
    }
    // No allocation in the PM callback. XNU calls priority clients under the
    // PM gate; return an explicit delay and do the waits on our retained call.
    // A fast worker's ack is consumed only after root releases its gate.
    if(note){
        beginPowerSuspend(); // Atomic admission fence before leaving root.
        note->returnValue=30000000;
    }
    auto &entry=_powerMessages[(_powerMessageHead+_powerMessageCount)%kPowerMessageCapacity];
    entry.message=message;entry.powerRef=note?note->powerRef:nullptr;
    ++_powerMessageCount;
    if(!_powerMessageRunning){
        _powerMessageRunning=true;retain();thread_call_enter(_powerMessageCall);
    }
    IOLockUnlock(_powerMessageLock);
    return true;
}

void Ath10kPCIDevice::powerMessageCall(thread_call_param_t context,thread_call_param_t)
{
    auto *self=static_cast<Ath10kPCIDevice *>(context);
    for(;;){
        IOLockLock(self->_powerMessageLock);
        if(!self->_powerMessageCount){
            self->_powerMessageRunning=false;
            IOLockWakeup(self->_powerMessageLock,&self->_powerMessageRunning,false);
            IOLockUnlock(self->_powerMessageLock);
            self->release();return; // No later self/thread-call access.
        }
        const auto entry=self->_powerMessages[self->_powerMessageHead];
        self->_powerMessages[self->_powerMessageHead]={};
        self->_powerMessageHead=(self->_powerMessageHead+1)%kPowerMessageCapacity;
        --self->_powerMessageCount;
        IOLockUnlock(self->_powerMessageLock);
        // Preserve order across sleep, cancellation and wake notifications.
        const auto event=entry.message==kIOMessageSystemWillSleep?Ath10k::PowerEvent::SystemSleep:
            (entry.message==kIOMessageSystemHasPoweredOn?Ath10k::PowerEvent::SystemWake:Ath10k::PowerEvent::SleepCancelled);
        self->requestPowerEvent(event,entry.message==kIOMessageSystemWillSleep);
        if(entry.message==kIOMessageSystemWillSleep){
            // requestPowerEvent releases the producer and radio gates first.
            // Terminal closure is admitted only after its own quiescence, so a
            // late queued sleep is safe to acknowledge there as well.
            IOLog("Ath10kMac: POWER notification=%u phase=worker-quiesced-ack\n",entry.message);
            acknowledgeSleepWakeNotification(entry.powerRef);
        }
    }
}

void Ath10kPCIDevice::releasePowerNotifications()
{
    // No producer or radio lock is held. remove synchronizes callbacks, then
    // drain every accepted notification (including its sleep ack) before PMstop
    // or PCI/work-loop release. Never cancel and silently drop a sleep cookie.
    if(_powerNotifier){_powerNotifier->remove();_powerNotifier=nullptr;}
    if(!_powerMessageLock)return;
    IOLockLock(_powerMessageLock);_powerMessageClosing=true;
    while(_powerMessageRunning)IOLockSleep(_powerMessageLock,&_powerMessageRunning,THREAD_UNINT);
    auto call=_powerMessageCall;_powerMessageCall=nullptr;
    IOLockUnlock(_powerMessageLock);
    if(call)thread_call_free(call);
    // Lock storage outlives late callback admission and base controller free.
}

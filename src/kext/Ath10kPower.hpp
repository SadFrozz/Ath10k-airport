#pragma once
#include <IOKit/IOTypes.h>
namespace Ath10k {
enum class PowerEvent : UInt32 { DeviceOff, DeviceOn, SystemSleep, SystemWake, SleepCancelled };
// Low two bits: 0 active, 1 suspended/pending, 2 clean restart allowed.
// Upper bits count suspend requests which raised the block but have not yet
// recorded their root/device state under the radio gate. 3 is fail-closed.
inline UInt32 queuePowerSuspend(UInt32 word) {
    if((word&3u)==3u || (word&~3u)==0xfffffffcu)return 0xffffffffu;
    return ((word&~3u)+4u)|1u;
}
inline UInt32 applyPowerSuspend(UInt32 word) {
    if((word&3u)==3u)return word;
    return (word>=4u?((word&~3u)-4u):0u)|1u;
}
// Changed only under the shared hardware gate. The atomic I/O block is separate.
struct PowerState {
    bool deviceOn=true, rootSleeping=false, needsRestart=false;
    UInt32 sleeps=0,wakes=0,notifications=0;
    const char *status="active";
};
}

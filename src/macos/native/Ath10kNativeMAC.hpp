#pragma once
#include "../../core/Ath10kWMI.hpp"
namespace AthNative {
inline bool validMAC(const UInt8 *mac) {
    if(!mac || (mac[0]&1))return false;
    UInt8 nz=0;for(unsigned i=0;i<6;++i)nz|=mac[i];return nz!=0;
}
// Delete -> ECHO -> create with the requested address -> ECHO. Both barriers
// must complete before publishing the new address or allowing scan/join/TX.
inline UInt32 macFrame(UInt8 *f,UInt32 capacity,UInt8 endpoint,UInt32 step,
                       const UInt8 *mac,UInt32 cookie) {
    if(!validMAC(mac) || !f || !endpoint || endpoint==255)return 0;
    if(step==1){
        if(capacity<20)return 0;
        Ath10k::htcZero(f,20);f[0]=endpoint;f[1]=1;
        Ath10k::htcWriteLE16(f+2,12);Ath10k::htcWriteLE32(f+8,0x5002);
        Ath10k::htcWriteLE16(f+12,4);Ath10k::htcWriteLE16(f+14,87);return 20;
    }
    if(step==2 || step==4)return Ath10k::buildWMIEcho(f,capacity,endpoint,cookie)?20:0;
    if(step==3)return Ath10k::buildWMIVdevCreate(f,capacity,endpoint,mac)?36:0;
    return 0;
}
}

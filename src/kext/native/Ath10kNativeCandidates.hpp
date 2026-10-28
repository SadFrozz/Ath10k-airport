#pragma once
#include "../Ath10kConnection.hpp"
#include "Ath10kNativeWire.hpp"
namespace AthNative {
struct CandidateCache {
    static constexpr UInt64 maxAgeMs=30000;
    Ath10k::WMIBSSCache bss{};
    UInt64 observed[64]{};
    void expire(UInt64 now){
        for(UInt32 i=0;i<bss.count;){
            if(now<observed[i] || now-observed[i]>maxAgeMs){
                --bss.count;bss.entries[i]=bss.entries[bss.count];observed[i]=observed[bss.count];
                bss.entries[bss.count]={};observed[bss.count]=0;
            }else ++i;
        }
    }
    void add(const Ath10k::WMIBSS &entry,UInt64 now){
        expire(now);UInt32 slot=bss.count;
        for(UInt32 i=0;i<bss.count;++i){
            bool same=true;for(unsigned j=0;j<6;++j)if(bss.entries[i].bssid[j]!=entry.bssid[j])same=false;
            if(same){slot=i;break;}
        }
        if(slot==bss.count){
            if(bss.count<64)++bss.count;
            else {slot=0;for(UInt32 i=1;i<bss.count;++i)if(observed[i]<observed[slot])slot=i;}
        }
        bss.entries[slot]=entry;observed[slot]=now;
    }
};
// Pure eligibility/preparation only; no ranking, live-state change or firmware IO.
inline const char *prepareRoamCandidate(const Ath10k::ConnectionState &live,
    const NativeReassocRequest &request,const Ath10k::WMIBSS &ap,
    Ath10k::CandidateConfiguration &out){
    if(request.channelCount>50 || request.ssidLength>32 || live.ssidLength>32 || (request.flags&~1u))return "roam-request-invalid";
    if(request.ssidLength!=live.ssidLength)return "roam-request-ssid-mismatch";
    for(UInt32 i=0;i<request.ssidLength;++i)
        if(request.ssid[i]!=live.ssid[i])return "roam-request-ssid-mismatch";
    bool broadcast=true,nonzero=false;
    for(UInt32 i=0;i<6;++i){broadcast&=request.bssid[i]==255;nonzero|=request.bssid[i]!=0;}
    if(!broadcast && (!nonzero || (request.bssid[0]&1)))return "roam-target-invalid";
    if(!broadcast && !Ath10k::sameMAC(request.bssid,ap.bssid))return "roam-target-mismatch";
    const UInt32 primary=ap.advertisedChannel?ap.advertisedChannel:ap.rxChannel;
    if(!Ath10k::wmiScanChannelAllowed(primary))return "bss-channel-unsupported";
    const UInt16 spec=UInt16(primary|(primary>14?0xd000:0x1000));
    if(!nativeReassocChannelMatches(request,spec))return "roam-channel-mismatch";
    return Ath10k::prepareBSSCandidate(live,ap,out);
}

// Rank eligible observations without committing a roam. The caller still owns
// hysteresis/force policy and the firmware/security transaction.
inline bool chooseRoamCandidate(const Ath10k::ConnectionState &live,
    const NativeReassocRequest &request,const CandidateCache &cache,UInt64 now,
    Ath10k::CandidateConfiguration &out){
    if(cache.bss.count>64)return false;
    bool found=false;UInt64 bestObserved=0;
    Ath10k::CandidateConfiguration prepared{};
    for(UInt32 i=0;i<cache.bss.count;++i){
        if(now<cache.observed[i] || now-cache.observed[i]>CandidateCache::maxAgeMs)continue;
        const auto &ap=cache.bss.entries[i];
        if(prepareRoamCandidate(live,request,ap,prepared))continue;
        bool better=!found;
        if(found){
            const int32_t signal=static_cast<int32_t>(ap.snr),best=static_cast<int32_t>(out.ap.snr);
            better=signal>best || (signal==best && cache.observed[i]>bestObserved);
            if(signal==best && cache.observed[i]==bestObserved){
                for(UInt32 j=0;j<6;++j){
                    if(ap.bssid[j]==out.ap.bssid[j])continue;
                    better=ap.bssid[j]<out.ap.bssid[j];break;
                }
            }
        }
        if(better){out=prepared;bestObserved=cache.observed[i];found=true;}
    }
    return found;
}

}

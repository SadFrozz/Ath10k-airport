#pragma once
#include "Ath10kNativeCandidates.hpp"
#include "Ath10kNativeMAC.hpp"
#include "Ath10kNativeScanPlan.hpp"

namespace AthNative {
// Radio-gate-owned request, not a firmware scan owner. The adapter must drain
// its scan/CE/RX before consuming the result or admitting a replacement join.
class OWEDiscovery {
    AirportWCL::JoinRequest request_{};
    UInt8 station_[6]{},target_[6]{},ssid_[32]{};
    UInt32 ssidLength_=0,scanGeneration_=0;
    UInt64 sequence_=0,generation_=0,started_=0,deadline_=0;
public:
    OWEDiscovery()=default;
    OWEDiscovery(const OWEDiscovery &)=delete;
    OWEDiscovery &operator=(const OWEDiscovery &)=delete;
    ~OWEDiscovery(){clear();}
    void clear(){
        AthSecurity::wipe(&request_,sizeof(request_));
        AthSecurity::wipe(station_,sizeof(station_));AthSecurity::wipe(target_,sizeof(target_));
        AthSecurity::wipe(ssid_,sizeof(ssid_));ssidLength_=scanGeneration_=0;
        generation_=started_=deadline_=0;
    }
    bool active() const{return generation_!=0;}
    UInt64 generation() const{return generation_;}
    UInt64 deadline() const{return deadline_;}
    bool current(UInt64 generation,const UInt8 *station,UInt64 now) const {
        return generation && generation==generation_ && station &&
            !memcmp(station,station_,6) && now>=started_ && now<deadline_;
    }
    // Only absence/age of the protected peer permits discovery. Malformed,
    // nonreciprocal, foreign or insecure cached peers are terminal failures.
    bool begin(const AirportWCL::JoinRequest &request,const CandidateCache &cache,
               const UInt8 *station,UInt64 now,UInt64 deadline){
        if(active() || !station || !validMAC(station) || !memcmp(station,request.bssid,6) ||
           sequence_==~UInt64(0) || deadline<=now || deadline-now>30000)return false;
        OWETransitionTarget target{};
        const char *error=selectOWETransitionTarget(request,cache,now,target);
        if(!error || (strcmp(error,"owe-transition-peer-missing") && strcmp(error,"owe-transition-peer-stale")))return false;
        const Ath10k::WMIBSS *open=nullptr;
        for(UInt32 i=0;i<cache.bss.count;++i)
            if(!memcmp(cache.bss.entries[i].bssid,request.bssid,6)){open=&cache.bss.entries[i];break;}
        OWETransitionView forward{};
        if(!open || !parseOWETransition(*open,forward) || !memcmp(station,forward.bssid,6))return false;
        request_=request;AthSecurity::wipe(request_.key,sizeof(request_.key));
        memcpy(station_,station,6);memcpy(target_,forward.bssid,6);
        ssidLength_=forward.ssidLength;memcpy(ssid_,forward.ssid,ssidLength_);
        started_=now;deadline_=deadline;generation_=++sequence_;return true;
    }
    bool prepareScan(UInt64 generation,const UInt8 *station,UInt64 now,AirportWCL::ScanRequest &out) const {
        if(!current(generation,station,now) || scanGeneration_)return false;
        AirportWCL::ScanRequest scan{};scan.type=1; // directed active probe; firmware keeps DFS passive
        scan.ssidLength=ssidLength_;memcpy(scan.ssid,ssid_,ssidLength_);memcpy(scan.bssid,target_,6);
        // The partner need not share the visible AP's channel. Intersect all
        // channels with the actual regulatory domain at firmware submission.
        NativeScanPlan plan{};if(!nativeScanPlan(scan,plan))return false;
        out=scan;return true;
    }
    bool bindScan(UInt64 generation,const UInt8 *station,UInt64 now,UInt32 scanGeneration){
        if(!current(generation,station,now) || scanGeneration_ || !scanGeneration)return false;
        scanGeneration_=scanGeneration;return true;
    }
    // Consume only the corresponding completed and fully retired scan. An
    // unrelated late completion must not clear or complete the current owner.
    // On success return the original visible profile, for normal admission to
    // revalidate and resolve the protected pair under the same radio gate.
    bool finish(UInt64 generation,const UInt8 *station,UInt64 now,UInt32 scanGeneration,
                bool retired,bool failed,const CandidateCache &cache,AirportWCL::JoinRequest &out){
        if(!generation || generation!=generation_ || !scanGeneration_ || scanGeneration!=scanGeneration_ || !retired)return false;
        bool valid=current(generation,station,now) && !failed;
        OWETransitionTarget target{};
        if(valid)valid=selectOWETransitionTarget(request_,cache,now,target)==nullptr;
        if(valid){
            const auto &ap=cache.bss.entries[target.index];
            valid=!memcmp(ap.bssid,target_,6) && target.ssidLength==ssidLength_ && !memcmp(target.ssid,ssid_,ssidLength_);
        }
        if(valid)out=request_;
        clear();return valid;
    }
};
}

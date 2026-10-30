#pragma once
#include "../abi/Ath10kNativeTarget.hpp"
#include <WCL.hpp>
static_assert(sizeof(AirportWCL::BeaconMetadata)==0x40, "Sequoia beacon ABI must precede WCL declarations");
static_assert(offsetof(AirportWCL::BeaconMetadata,flags)==0x3c, "Sequoia beacon flags offset");
#include "../../core/Ath10kWMI.hpp"
struct NativeScanPlan {
    Ath10k::WMIScanSSID ssids[10]{};
    UInt32 count=0;
    bool active=false;
};
inline bool nativeScanPlan(const AirportWCL::ScanRequest &request,NativeScanPlan &out) {
    if(request.ssidLength>32 || request.ssids.count>10 || request.type<1 || request.type>4)return false;
    NativeScanPlan plan{};
    plan.active=request.type==1 || request.type==4;
    if(request.ssids.count){
        if(request.ssidLength)return false; // Stock serializer rejects mixed forms.
        plan.count=request.ssids.count;
        for(unsigned i=0;i<plan.count;++i){
            const auto &entry=request.ssids.entries[i];
            if(entry.version>1 || entry.length>32 || (!entry.version && entry.length))return false;
            for(auto byte:entry.metadata)if(byte)return false; // Unknown scan constraints.
            plan.ssids[i].length=entry.length;
            for(unsigned j=0;j<entry.length;++j)plan.ssids[i].bytes[j]=entry.bytes[j];
        }
    }else{
        plan.count=1;plan.ssids[0].length=request.ssidLength;
        for(unsigned i=0;i<request.ssidLength;++i)plan.ssids[0].bytes[i]=request.ssid[i];
    }
    out=plan;return true;
}

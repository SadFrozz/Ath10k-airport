#pragma once
#include "../Ath10kBSS.hpp"
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
}

#pragma once
#include "../../core/Ath10kConnection.hpp"
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
// Borrowed only during radio-gated candidate selection; never retain IE pointers.
struct OWETransitionView {const UInt8 *bssid=nullptr,*ssid=nullptr;UInt8 ssidLength=0;};
inline bool parseOWETransition(const Ath10k::WMIBSS &ap,OWETransitionView &out){
    const auto *ie=ap.oweTransition;const UInt32 n=ap.oweTransitionLength;
    if(n<13 || n>sizeof(ap.oweTransition) || ie[0]!=221 || UInt32(ie[1])+2!=n ||
       ie[2]!=0x50 || ie[3]!=0x6f || ie[4]!=0x9a || ie[5]!=0x1c ||
       !ie[12] || ie[12]>32 || UInt32(13+ie[12])>n || (ie[6]&1))return false;
    bool nonzero=false;for(unsigned i=0;i<6;++i)nonzero|=ie[6+i]!=0;
    if(!nonzero || !memcmp(ie+6,ap.bssid,6))return false;
    out={ie+6,ie+13,ie[12]};return true;
}
struct OWETransitionTarget {
    UInt32 index=0;UInt64 observed=0;
    UInt8 ssid[32]{},ssidLength=0;
};
// A transition advertisement is an untrusted pointer to another BSS, not
// permission to downgrade. Require fresh reciprocal identity and actual OWE.
// No output changes on failure; caller must revalidate before firmware admission.
inline const char *selectOWETransitionTarget(const AirportWCL::JoinRequest &join,
    const CandidateCache &cache,UInt64 now,OWETransitionTarget &out){
    if(!nativeOWEEnvelope(join) || join.allowAuths!=0x20000001u || join.rsnLength)
        return "owe-transition-policy";
    if(cache.bss.count>Ath10k::kWMIBSSMax)return "owe-transition-cache-bounds";
    const Ath10k::WMIBSS *open=nullptr;UInt32 openIndex=0;
    for(UInt32 i=0;i<cache.bss.count;++i)
        if(!memcmp(cache.bss.entries[i].bssid,join.bssid,6)){open=&cache.bss.entries[i];openIndex=i;break;}
    if(!open)return "owe-transition-open-missing";
    auto fresh=[&](UInt32 i){return now>=cache.observed[i] && now-cache.observed[i]<=CandidateCache::maxAgeMs;};
    if(!fresh(openIndex))return "owe-transition-open-stale";
    if(open->hidden || open->ssidLength!=join.ssidLength || memcmp(open->ssid,join.ssid,join.ssidLength) ||
       open->privacy || open->rsnPresent || open->rsnLength || open->wpaPresent || open->wpaLength)
        return "owe-transition-open-identity";
    OWETransitionView forward{};if(!parseOWETransition(*open,forward))return "owe-transition-open-ie";
    for(UInt32 i=0;i<cache.bss.count;++i){const auto &peer=cache.bss.entries[i];
        if(memcmp(peer.bssid,forward.bssid,6))continue;
        if(!fresh(i))return "owe-transition-peer-stale";
        if(!peer.privacy || !peer.rsnPresent || peer.wpaPresent || peer.wpaLength ||
           peer.rsnLength>sizeof(peer.rsn) || !AthSecurity::validOWEPersonalRSN(peer.rsn,peer.rsnLength))return "owe-transition-peer-security";
        // A hidden beacon can omit its SSID; the reciprocal pair supplies it.
        if(!(peer.hidden && !peer.ssidLength) &&
           (peer.ssidLength!=forward.ssidLength || memcmp(peer.ssid,forward.ssid,forward.ssidLength)))
            return "owe-transition-peer-ssid";
        OWETransitionView reverse{};
        if(!parseOWETransition(peer,reverse) || memcmp(reverse.bssid,open->bssid,6) ||
           reverse.ssidLength!=open->ssidLength || memcmp(reverse.ssid,open->ssid,open->ssidLength))
            return "owe-transition-nonreciprocal";
        const UInt32 channel=peer.advertisedChannel?peer.advertisedChannel:peer.rxChannel;
        if(!Ath10k::wmiScanChannelAllowed(channel))return "owe-transition-peer-channel";
        OWETransitionTarget selected{};selected.index=i;selected.observed=cache.observed[i];
        selected.ssidLength=forward.ssidLength;memcpy(selected.ssid,forward.ssid,forward.ssidLength);
        out=selected;return nullptr;
    }
    return "owe-transition-peer-missing";
}
// Build the radio request separately from the visible Open alias. The actual
// protected beacon retains its reciprocal IE for IO80211's alias presentation.
inline const char *prepareOWETransitionJoin(const AirportWCL::JoinRequest &request,
    const CandidateCache &cache,UInt64 now,AirportWCL::JoinRequest &out,UInt32 &index){
    OWETransitionTarget target{};
    if(const char *error=selectOWETransitionTarget(request,cache,now,target))return error;
    const auto &ap=cache.bss.entries[target.index];
    AirportWCL::JoinRequest next=request;
    memcpy(next.bssid,ap.bssid,6);memset(next.ssid,0,sizeof(next.ssid));
    next.ssidLength=target.ssidLength;memcpy(next.ssid,target.ssid,target.ssidLength);
    const UInt32 channel=ap.advertisedChannel?ap.advertisedChannel:ap.rxChannel;
    next.channelSpec=UInt16(channel|(channel>14?0xd000:0x1000));
    out=next;index=target.index;return nullptr;
}
// Pure eligibility/preparation only; no ranking, live-state change or firmware IO.
inline const char *prepareRoamCandidate(const Ath10k::ConnectionState &live,
    const NativeReassocRequest &request,const Ath10k::WMIBSS &ap,
    Ath10k::CandidateConfiguration &out){
    if(request.channelCount>50 || request.ssidLength>32 || live.ssidLength>32 || (request.flags&~1u))return "roam-request-invalid";
    if(request.ssidLength!=live.ssidLength)return "roam-request-ssid-mismatch";
    for(UInt32 i=0;i<request.ssidLength;++i)
        if(request.ssid[i]!=live.ssid[i])return "roam-request-ssid-mismatch";
    if(!request.bssidCount || request.bssidCount>7)return "roam-target-invalid";
    bool matches=false;
    for(UInt32 target=0;target<request.bssidCount;++target){
        const auto address=target?request.additionalBSSIDs[target-1]:request.bssid;
        bool broadcast=true,nonzero=false;
        for(UInt32 i=0;i<6;++i){broadcast&=address[i]==255;nonzero|=address[i]!=0;}
        // A wildcard is supported only as the single-target request form.
        if((broadcast && request.bssidCount!=1) || (!broadcast && (!nonzero || (address[0]&1))))return "roam-target-invalid";
        matches|=broadcast || Ath10k::sameMAC(address,ap.bssid);
    }
    if(!matches)return "roam-target-mismatch";
    bool apNonzero=false;for(UInt32 i=0;i<6;++i)apNonzero|=ap.bssid[i]!=0;
    if(!apNonzero || (ap.bssid[0]&1))return "roam-candidate-address-invalid";
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
    Ath10k::CandidateConfiguration &out,UInt64 *observedOut=nullptr){
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
    if(found && observedOut)*observedOut=bestObserved;
    return found;
}

}

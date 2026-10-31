#pragma once
#include "Ath10kNativeWire.hpp"
#include "Ath10kNativeMAC.hpp"
#include "Ath10kNativeCandidates.hpp"

namespace AthNative {
// Credential owner for an explicitly admitted profile, separate from one
// association's PTK/GTK/IGTK. NativeSecurity retains it after join admission
// and clears it on terminal reset; prepared handoffs own separate wiped copies.
// Radio-gate ownership is required; no allocation, worker wait or I/O here.
class ProfileCredentials {
    AirportWCL::JoinRequest request_{};
    UInt8 local_[6]{};
    UInt8 visibleSSID_[32]{},visibleSSIDLength_=0;
    UInt64 sequence_=0,active_=0;
    NativeJoinAuth auth_=NativeJoinAuth::Unsupported;
    UInt8 pairwise_=0;bool legacy_=false;
public:
    ProfileCredentials()=default;
    ProfileCredentials(const ProfileCredentials &)=delete;
    ProfileCredentials &operator=(const ProfileCredentials &)=delete;
    ~ProfileCredentials(){clear();}
    void clear(){
        active_=0;auth_=NativeJoinAuth::Unsupported;pairwise_=0;legacy_=false;
        AthSecurity::wipe(&request_,sizeof(request_));
        AthSecurity::wipe(local_,sizeof(local_));
        AthSecurity::wipe(visibleSSID_,sizeof(visibleSSID_));visibleSSIDLength_=0;
        // Never recycle a retired token after forget/radio-off/profile change.
    }
    UInt64 generation() const {return active_;}
    bool visibleSSID(UInt64 generation,const UInt8 *ssid,UInt32 length) const {
        return generation && generation==active_ && auth_==NativeJoinAuth::OWE && ssid &&
            visibleSSIDLength_ && length==visibleSSIDLength_ && !memcmp(ssid,visibleSSID_,length);
    }
    bool permitsTransitionCandidate(UInt64 generation,const Ath10k::WMIBSS &candidate,
        const CandidateCache &cache,UInt64 now) const {
        if(!generation || generation!=active_)return false;
        if(!visibleSSIDLength_)return true;
        OWETransitionView reverse{};
        if(auth_!=NativeJoinAuth::OWE || !parseOWETransition(candidate,reverse) ||
           reverse.ssidLength!=visibleSSIDLength_ || memcmp(reverse.ssid,visibleSSID_,visibleSSIDLength_))return false;
        AirportWCL::JoinRequest alias=request_;
        alias.ssidLength=visibleSSIDLength_;memset(alias.ssid,0,sizeof(alias.ssid));
        memcpy(alias.ssid,visibleSSID_,visibleSSIDLength_);memcpy(alias.bssid,reverse.bssid,6);
        // Selected RSNE in a retained roam request is not the AP's transition policy.
        memset(alias.rsn,0,sizeof(alias.rsn));alias.rsnLength=0;
        OWETransitionTarget target{};
        return !selectOWETransitionTarget(alias,cache,now,target) &&
            !memcmp(cache.bss.entries[target.index].bssid,candidate.bssid,6);
    }
    bool replace(const AirportWCL::JoinRequest &request,const UInt8 *local,bool allowSAE,bool allowEAP=false,UInt8 pairwise=AthSecurity::cipherCCMP,bool legacy=false,bool allowWPA1=false,bool allowWEP=false,bool allowOWE=false,const Ath10k::WMIBSS *candidate=nullptr){
        clear(); // Even a rejected replacement must not expose the old secret.
        const auto auth=nativeJoinAuth(request,allowSAE,allowEAP,allowWPA1,allowWEP,allowOWE,candidate);
        const bool wpa1=auth==NativeJoinAuth::WPA1PSK || auth==NativeJoinAuth::WPA1EAP;
        const bool wep=auth==NativeJoinAuth::WEPOpen || auth==NativeJoinAuth::WEPShared;
        if(wep){NativeSelectedRSN selected{};
            if(!legacy || !nativeSelectedRSN(request,auth,selected,true) || selected.pairwise!=pairwise)return false;
        }
        if(wpa1){NativeSelectedRSN selected{};
            if(!legacy || !nativeSelectedRSN(request,auth,selected,true,true) ||
               (selected.specified && selected.pairwise!=pairwise))return false;
        }
        if((!wep && pairwise!=AthSecurity::cipherCCMP && pairwise!=AthSecurity::cipherTKIP) ||
           (pairwise==AthSecurity::cipherTKIP && (!legacy || (auth!=NativeJoinAuth::PSK && auth!=NativeJoinAuth::EAP && !wpa1))) ||
           (legacy && auth!=NativeJoinAuth::PSK && auth!=NativeJoinAuth::EAP && !wpa1 && !wep))return false;
        if(sequence_==~UInt64(0) || !validMAC(local) || !validMAC(request.bssid) ||
           !request.ssidLength || request.ssidLength>sizeof(request.ssid) ||
           request.keyLength>sizeof(request.key) || request.rsnLength>sizeof(request.rsn) ||
           auth==NativeJoinAuth::Unsupported)return false;
        // Copy only meaningful octets; callers may supply nonzero unused tails.
        request_.lowerAuth=request.lowerAuth;request_.upperAuth=request.upperAuth;
        request_.upperAuthExt=request.upperAuthExt;request_.allowAuths=request.allowAuths;
        request_.transitionDisable=request.transitionDisable;
        request_.ssidLength=request.ssidLength;
        AthSecurity::copy(request_.ssid,request.ssid,request.ssidLength);
        request_.keyLength=request.keyLength;request_.keyCipher=request.keyCipher;
        request_.keyFlags=request.keyFlags;request_.keyIndex=request.keyIndex;
        AthSecurity::copy(request_.key,request.key,request.keyLength);
        AthSecurity::copy(request_.bssid,request.bssid,6);
        request_.channelSpec=request.channelSpec;request_.rsnLength=request.rsnLength;
        AthSecurity::copy(request_.rsn,request.rsn,request.rsnLength);
        if(auth==NativeJoinAuth::OWE && candidate && candidate->oweTransitionLength){
            OWETransitionView alias{};
            if(!candidate->privacy || memcmp(candidate->bssid,request.bssid,6) ||
               !parseOWETransition(*candidate,alias))return false;
            memcpy(visibleSSID_,alias.ssid,alias.ssidLength);visibleSSIDLength_=alias.ssidLength;
        }
        AthSecurity::copy(local_,local,6);auth_=auth;pairwise_=pairwise;legacy_=legacy;active_=++sequence_;return true;
    }
    bool matchesSecurity(UInt64 generation,UInt8 pairwise,bool legacy,bool wpa1=false) const {
        return generation && generation==active_ && pairwise==pairwise_ && legacy==legacy_ &&
            wpa1==(auth_==NativeJoinAuth::WPA1PSK || auth_==NativeJoinAuth::WPA1EAP);
    }
    // Call only for authenticated transition-disable delivery. More restrictive
    // policy invalidates prepared work through a new generation; never clear bits.
    bool restrictPolicy(UInt64 generation,UInt8 flags){
        if(!generation || generation!=active_)return false;
        if(flags&~NativeTransitionDisable::Known){clear();return false;}
        const UInt8 combined=request_.transitionDisable|flags;
        if(combined==request_.transitionDisable)return true;
        request_.transitionDisable=combined;
        if(sequence_==~UInt64(0) || (auth_==NativeJoinAuth::Open && nativeOptionalOpenPolicy(request_)?NativeJoinAuth::Open:nativeJoinAuth(request_,auth_==NativeJoinAuth::SAE,auth_==NativeJoinAuth::EAP || auth_==NativeJoinAuth::EAPSHA256 || auth_==NativeJoinAuth::WPA1EAP,auth_==NativeJoinAuth::WPA1PSK || auth_==NativeJoinAuth::WPA1EAP,auth_==NativeJoinAuth::WEPOpen || auth_==NativeJoinAuth::WEPShared,auth_==NativeJoinAuth::OWE))!=auth_){
            clear();return false;
        }
        active_=++sequence_;return true;
    }
    // Snapshot only for the same profile and station identity. Caller owns and
    // must wipe the returned copy; a failed lookup never changes its output.
    bool snapshot(UInt64 generation,const UInt8 *local,const UInt8 *ssid,
                  size_t ssidLength,NativeJoinAuth auth,AirportWCL::JoinRequest &out) const {
        if(!generation || generation!=active_ || !local || !ssid || auth!=auth_ ||
           ssidLength!=request_.ssidLength ||
           !AthSecurity::equal(local,local_,6) ||
           !AthSecurity::equal(ssid,request_.ssid,ssidLength))return false;
        out=request_;return true;
    }
};
// Prepare an isolated next-association request. Selection and profile checks
// finish before either output changes; no old keys or radio state are reused.
// Caller must retire the old association and revalidate the profile generation
// before admitting this request to firmware. This helper does not perform roam.
inline bool prepareRoamJoin(const ProfileCredentials &profile,UInt64 generation,
    const Ath10k::ConnectionState &live,const NativeReassocRequest &request,
    const CandidateCache &cache,UInt64 now,AirportWCL::JoinRequest &joinOut,
    Ath10k::CandidateConfiguration &candidateOut,UInt64 *observedOut=nullptr){
    const auto auth=!live.secure?NativeJoinAuth::Open:
        live.wepSelected?(live.sharedKeyAuth?NativeJoinAuth::WEPShared:NativeJoinAuth::WEPOpen):
        live.wpa1Selected?(live.securityAKM==2?NativeJoinAuth::WPA1PSK:NativeJoinAuth::Unsupported):
        live.securityAKM==18?NativeJoinAuth::OWE:
        live.securityAKM==8?NativeJoinAuth::SAE:
        live.securityAKM==6?NativeJoinAuth::PSKSHA256:
        live.securityAKM==2?NativeJoinAuth::PSK:NativeJoinAuth::Unsupported;
    if(auth==NativeJoinAuth::Unsupported || !profile.matchesSecurity(generation,live.pairCipher,live.legacyRSNAllowed,live.wpa1Selected))return false;
    if(live.ssidLength>sizeof(live.ssid))return false;
    NativeReassocRequest radioRequest=request;
    if(auth==NativeJoinAuth::OWE && profile.visibleSSID(generation,request.ssid,request.ssidLength)){
        radioRequest.ssidLength=live.ssidLength;memset(radioRequest.ssid,0,sizeof(radioRequest.ssid));
        memcpy(radioRequest.ssid,live.ssid,live.ssidLength);
    }
    Ath10k::CandidateConfiguration candidate{};UInt64 observed=0;
    if(!chooseRoamCandidate(live,radioRequest,cache,now,candidate,&observed) ||
       !validMAC(candidate.ap.bssid) || candidate.ap.rsnLength>sizeof(joinOut.rsn))return false;
    if(!profile.permitsTransitionCandidate(generation,candidate.ap,cache,now))return false;
    AirportWCL::JoinRequest next{};
    if(!profile.snapshot(generation,live.local,live.ssid,live.ssidLength,auth,next))return false;
    // AP-specific inputs must come from the new validated observation. Retain
    // the selected authentication and transition-disable policy without downgrade.
    AthSecurity::copy(next.bssid,candidate.ap.bssid,6);
    next.channelSpec=UInt16(candidate.operatingChannel|(candidate.operatingChannel>14?0xd000:0x1000));
    // Rebuild a selected station IE, never an AP suite list or stale PMKID.
    AthSecurity::wipe(next.rsn,sizeof(next.rsn));next.rsnLength=0;size_t selectedBytes=0;
    bool encoded=true;
    if(auth==NativeJoinAuth::SAE)encoded=AthSecurity::buildSAEStationRSN(nullptr,0,next.rsn,sizeof(next.rsn),selectedBytes);
    else if(auth==NativeJoinAuth::OWE)encoded=AthSecurity::buildOWEStationRSN(next.rsn,sizeof(next.rsn),selectedBytes);
    else if(auth==NativeJoinAuth::WPA1PSK)encoded=AthSecurity::buildWPA1StationIE(candidate.ap.wpa,candidate.ap.wpaLength,live.pairCipher,live.securityAKM,next.rsn,sizeof(next.rsn),selectedBytes);
    else if(live.secure && !live.wepSelected)encoded=AthSecurity::buildSelectedStationRSN(candidate.groupCipher,live.pairCipher,live.securityAKM,next.rsn,sizeof(next.rsn),selectedBytes);
    if(!encoded){AthSecurity::wipe(&next,sizeof(next));return false;}
    next.rsnLength=UInt16(selectedBytes);
    if(nativeJoinAuth(next,auth==NativeJoinAuth::SAE,false,auth==NativeJoinAuth::WPA1PSK,live.wepSelected,auth==NativeJoinAuth::OWE,&candidate.ap)!=auth){
        AthSecurity::wipe(&next,sizeof(next));return false;
    }
    if(observedOut)*observedOut=observed;
    candidateOut=candidate;joinOut=next;AthSecurity::wipe(&next,sizeof(next));return true;
}

// One-shot owner spanning software/firmware retirement. It does not bypass
// nativeBeginJoin's final transport admission or establish a radio connection.
class PreparedRoam {
    const ProfileCredentials *owner_=nullptr;
    AirportWCL::JoinRequest request_{};
    UInt8 local_[6]{};
    UInt64 profile_=0,prepared_=0,observed_=0;
public:
    PreparedRoam()=default;
    PreparedRoam(const PreparedRoam &)=delete;
    PreparedRoam &operator=(const PreparedRoam &)=delete;
    ~PreparedRoam(){clear();}
    void clear(){
        owner_=nullptr;profile_=prepared_=observed_=0;
        AthSecurity::wipe(&request_,sizeof(request_));
        AthSecurity::wipe(local_,sizeof(local_));
    }
    UInt64 generation() const{return profile_;}
    bool target(UInt8 *out) const{if(!profile_ || !out)return false;AthSecurity::copy(out,request_.bssid,6);return true;}
    bool prepare(const ProfileCredentials &profile,const Ath10k::ConnectionState &live,
                 const NativeReassocRequest &request,const CandidateCache &cache,UInt64 now){
        clear();
        Ath10k::CandidateConfiguration candidate{};
        UInt64 observed=0;
        if(!prepareRoamJoin(profile,profile.generation(),live,request,cache,now,request_,candidate,&observed))return false;
        AthSecurity::copy(local_,live.local,6);profile_=profile.generation();
        owner_=&profile;prepared_=now;observed_=observed;return true;
    }
    // Call beneath the radio gate only after firmware/transport retirement.
    // The common join admission still independently checks all live owners.
    // No failed or consumed request can be retried with retained credentials.
    bool validate(const ProfileCredentials &profile,const UInt8 *local,UInt64 now){
        if(owner_!=&profile || !profile_ || profile.generation()!=profile_ || !local ||
           !AthSecurity::equal(local,local_,6) || now<prepared_ || now<observed_ ||
           now-observed_>CandidateCache::maxAgeMs){clear();return false;}
        return true;
    }
    bool take(const ProfileCredentials &profile,const UInt8 *local,UInt64 now,
              AirportWCL::JoinRequest &out){
        if(!validate(profile,local,now))return false;
        out=request_;clear();return true;
    }
};

}

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
    UInt64 sequence_=0,active_=0;
    NativeJoinAuth auth_=NativeJoinAuth::Unsupported;
public:
    ProfileCredentials()=default;
    ProfileCredentials(const ProfileCredentials &)=delete;
    ProfileCredentials &operator=(const ProfileCredentials &)=delete;
    ~ProfileCredentials(){clear();}
    void clear(){
        active_=0;auth_=NativeJoinAuth::Unsupported;
        AthSecurity::wipe(&request_,sizeof(request_));
        AthSecurity::wipe(local_,sizeof(local_));
        // Never recycle a retired token after forget/radio-off/profile change.
    }
    UInt64 generation() const {return active_;}
    bool replace(const AirportWCL::JoinRequest &request,const UInt8 *local,bool allowSAE,bool allowEAP=false){
        clear(); // Even a rejected replacement must not expose the old secret.
        const auto auth=nativeJoinAuth(request,allowSAE,allowEAP);
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
        AthSecurity::copy(local_,local,6);auth_=auth;active_=++sequence_;return true;
    }
    // Call only for authenticated transition-disable delivery. More restrictive
    // policy invalidates prepared work through a new generation; never clear bits.
    bool restrictPolicy(UInt64 generation,UInt8 flags){
        if(!generation || generation!=active_)return false;
        if(flags&~NativeTransitionDisable::Known){clear();return false;}
        const UInt8 combined=request_.transitionDisable|flags;
        if(combined==request_.transitionDisable)return true;
        request_.transitionDisable=combined;
        if(sequence_==~UInt64(0) || nativeJoinAuth(request_,auth_==NativeJoinAuth::SAE,auth_==NativeJoinAuth::EAP)!=auth_){
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
        live.securityAKM==8?NativeJoinAuth::SAE:
        live.securityAKM==6?NativeJoinAuth::PSKSHA256:
        live.securityAKM==2?NativeJoinAuth::PSK:NativeJoinAuth::Unsupported;
    if(auth==NativeJoinAuth::Unsupported)return false;
    Ath10k::CandidateConfiguration candidate{};UInt64 observed=0;
    if(!chooseRoamCandidate(live,request,cache,now,candidate,&observed) ||
       !validMAC(candidate.ap.bssid) || candidate.ap.rsnLength>sizeof(joinOut.rsn))return false;
    AirportWCL::JoinRequest next{};
    if(!profile.snapshot(generation,live.local,live.ssid,live.ssidLength,auth,next))return false;
    // AP-specific inputs must come from the new validated observation. Retain
    // the selected authentication and transition-disable policy without downgrade.
    AthSecurity::copy(next.bssid,candidate.ap.bssid,6);
    next.channelSpec=UInt16(candidate.operatingChannel|(candidate.operatingChannel>14?0xd000:0x1000));
    AthSecurity::wipe(next.rsn,sizeof(next.rsn));next.rsnLength=candidate.ap.rsnLength;
    AthSecurity::copy(next.rsn,candidate.ap.rsn,candidate.ap.rsnLength);
    if(nativeJoinAuth(next,auth==NativeJoinAuth::SAE)!=auth){
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

#pragma once
#include <stddef.h>
#include <stdint.h>
#include "../../core/Ath10kHTC.hpp"
#include "Ath10kNativeMAC.hpp"

namespace AthNative { namespace RoamEvents {
// IO80211Family 24G90, UUID 0D5AC570-04D4-38B6-8577-9F21350CDD50.
// Numeric identities are controller postMessage IDs, not internal FSM events.
// Only recovered fields are emitted; all reserved/opaque bytes stay zero.
constexpr uint32_t StartID=0x89,PrepID=0x8b,ReassocID=0x49,CompleteID=0x50;
template<size_t N> struct Envelope { uint8_t bytes[N]{}; };
using Start=Envelope<12>;
using Prep=Envelope<12>;
using Reassoc=Envelope<8>;
using Complete=Envelope<168>;
static_assert(sizeof(Start)==12 && sizeof(Prep)==12 && sizeof(Reassoc)==8 && sizeof(Complete)==168,"Sequoia roam event ABI");
inline Start start(uint32_t status,uint32_t reason,int16_t extendedValue=0){
    Start event{};Ath10k::htcWriteLE32(event.bytes,status);
    Ath10k::htcWriteLE32(event.bytes+4,reason);
    Ath10k::htcWriteLE16(event.bytes+8,static_cast<uint16_t>(extendedValue));return event;
}
inline bool prep(uint32_t reason,const uint8_t *bssid,Prep &out,int16_t extendedValue=0){
    if(!validMAC(bssid))return false;
    Prep event{};Ath10k::htcWriteLE32(event.bytes,reason);
    for(unsigned i=0;i<6;++i)event.bytes[4+i]=bssid[i];
    Ath10k::htcWriteLE16(event.bytes+10,static_cast<uint16_t>(extendedValue));out=event;return true;
}
inline Reassoc reassoc(uint32_t status,uint32_t reason){
    Reassoc event{};Ath10k::htcWriteLE32(event.bytes,status);
    Ath10k::htcWriteLE32(event.bytes+4,reason);return event;
}
inline Complete completion(uint32_t status){
    // Zero asks WCL to build status from the CURRENT published BSS. Nonzero
    // supplies a mapped failure. Never pass unmapped ath10k firmware codes.
    // WCL can write 0x68 bytes back into its owned copy; keep this full writable
    // envelope even for failures. It is NOT ordinary ConnectComplete.
    Complete event{};Ath10k::htcWriteLE32(event.bytes,status);return event;
}
// Per-transaction enqueue progress. A successful post is queue acceptance,
// never a WCL-consumption acknowledgement. All calls require one owning gate.
class Delivery {
public:
    enum class Phase : uint8_t { Idle, StartPending, Started, Prepared, Reassociated, Completed };
private:
    Phase phase_=Phase::Idle;
    Prep prep_{};
    uint32_t reason_=0;
    uint64_t generation_=0;
public:
    Delivery()=default;
    Delivery(const Delivery &)=delete;
    Delivery &operator=(const Delivery &)=delete;
    Phase phase() const{return phase_;}
    uint64_t generation() const{return generation_;}
    bool begin(uint32_t reason,const uint8_t *target){
        if(generation_==~uint64_t(0) || (phase_!=Phase::Idle && phase_!=Phase::Completed))return false;
        Prep candidate{};if(!prep(reason,target,candidate))return false;
        prep_=candidate;reason_=reason;++generation_;phase_=Phase::StartPending;return true;
    }
    template<class Post> bool sendStart(uint64_t generation,Post &&post){
        if(!generation || generation!=generation_ || phase_!=Phase::StartPending)return false;
        auto event=start(0,reason_);
        if(!post(StartID,event.bytes,sizeof(event)))return false;
        phase_=Phase::Started;return true;
    }
    template<class Post> bool sendPrep(uint64_t generation,Post &&post){
        if(!generation || generation!=generation_ || phase_!=Phase::Started)return false;
        // Hand a writable local copy to the delivery path, not our retry state.
        auto event=prep_;
        if(!post(PrepID,event.bytes,sizeof(event)))return false;
        phase_=Phase::Prepared;return true;
    }
    template<class Post> bool sendReassoc(uint64_t generation,Post &&post){
        if(!generation || generation!=generation_ || phase_!=Phase::Prepared)return false;
        auto event=reassoc(0,reason_);
        if(!post(ReassocID,event.bytes,sizeof(event)))return false;
        phase_=Phase::Reassociated;return true;
    }
    template<class Post> bool sendComplete(uint64_t generation,uint32_t status,bool newBSSPublished,Post &&post){
        if(!generation || generation!=generation_ ||
           (phase_!=Phase::Started && phase_!=Phase::Prepared && phase_!=Phase::Reassociated))return false;
        // Successful completion reads the new associated BSS in WCL. Failure
        // may complete any started roam without pretending association worked.
        if(!status && (phase_!=Phase::Reassociated || !newBSSPublished))return false;
        auto event=completion(status);
        if(!post(CompleteID,event.bytes,sizeof(event)))return false;
        phase_=Phase::Completed;return true;
    }
};
}}

#pragma once
#include "Ath10kNativeEAPOwner.hpp"
#include "../../core/Ath10kConnection.hpp"

namespace AthNative {
// One entire queued key request, including mirrored writes and TX selection.
// The radio consumer supplies CE retirement, HTT receipts and an ordered
// ECHO/RX fence. A host ticket alone never identifies a firmware response.
class WEPExecution {
public:
    enum class State {Idle,Ready,Submitted,Fence,Complete,Uncertain};
private:
    EAPOwner::WEPProgram program_{};
    State state_=State::Idle;
    uint8_t operation_=0,index_=0,length_=0,expected_=0;
    uint16_t peer_=0;
    uint64_t started_=0,deadline_=0;
    bool receipt_=false;
    const EAPOwner::WEPKey *key(const EAPOwner &owner,const uint8_t *station,const uint8_t *peer,uint64_t now) const {
        const auto *k=owner.frontWEPKey(program_.generation,station,peer,now);
        return k && k->ticket==program_.ticket && k->index==index_ && k->length==length_?k:nullptr;
    }
public:
    State state() const {return state_;}
    uint64_t generation() const {return program_.generation;}
    uint64_t ticket() const {return program_.ticket;}
    uint8_t operation() const {return operation_;}
    uint8_t expectedReceipt() const {return expected_;}
    bool begin(const EAPOwner &owner,const uint8_t *station,const uint8_t *peer,
               uint16_t peerID,uint64_t now,uint64_t deadline){
        if(state_!=State::Idle || peerID>=2048 || deadline<=now)return false;
        auto p=owner.frontWEPProgram(owner.generation(),station,peer,now);
        const auto *k=owner.frontWEPKey(owner.generation(),station,peer,now);
        if(!p.valid || !k)return false;
        program_=p;peer_=peerID;index_=k->index;length_=k->length;
        started_=now;deadline_=deadline;operation_=0;receipt_=false;expected_=0;
        state_=p.count?State::Ready:State::Complete;return true;
    }
    bool poll(const EAPOwner &owner,const uint8_t *station,const uint8_t *peer,uint64_t now){
        if(state_==State::Idle || state_==State::Uncertain)return false;
        if(now<started_ || now>=deadline_ || !key(owner,station,peer,now)){
            // Earlier operations may already have modified firmware even if
            // this operation has not been submitted. Never reuse on timeout.
            state_=State::Uncertain;return false;
        }
        return true;
    }
    uint32_t build(const EAPOwner &owner,const uint8_t *station,const uint8_t *peer,
                   uint64_t now,uint8_t *out,uint32_t capacity,uint8_t endpoint,uint8_t sequence){
        if(!poll(owner,station,peer,now) || state_!=State::Ready)return 0;
        const auto *k=key(owner,station,peer,now);
        const auto write=program_.writes[operation_];
        if(write==EAPOwner::WEPWrite::SelectTransmit)
            return Ath10k::buildWEPTransmitIndexWMI(out,capacity,endpoint,sequence,index_);
        return Ath10k::buildKeyWMI(out,capacity,endpoint,sequence,peer,index_,
            write==EAPOwner::WEPWrite::Group?1:0,1,k->key,length_);
    }
    // Call before handing the command to a transport that may accept it.
    // Ambiguous submission failure requires teardown, never a blind retry.
    bool submitted(const EAPOwner &owner,const uint8_t *station,const uint8_t *peer,uint64_t now){
        if(!poll(owner,station,peer,now) || state_!=State::Ready)return false;
        const auto write=program_.writes[operation_];
        receipt_=write==EAPOwner::WEPWrite::SelectTransmit;
        expected_=receipt_?0xff:uint8_t((length_==5?3:2)|(write==EAPOwner::WEPWrite::Pair?0x80:0));
        state_=State::Submitted;return true;
    }
    bool acknowledge(uint16_t peer,uint8_t flags){
        if(state_!=State::Submitted || receipt_ || peer!=peer_ || flags!=expected_)return false;
        receipt_=true;return true;
    }
    // Consumer calls only after CE consumption AND WMI credits have retired.
    bool transportRetired(const EAPOwner &owner,const uint8_t *station,const uint8_t *peer,uint64_t now){
        if(!poll(owner,station,peer,now) || state_!=State::Submitted || !receipt_)return false;
        state_=State::Fence;return true;
    }
    // Consumer must correlate its unique ECHO cookie and drain prior RX work.
    bool fenceRetired(const EAPOwner &owner,const uint8_t *station,const uint8_t *peer,uint64_t now){
        if(!poll(owner,station,peer,now) || state_!=State::Fence)return false;
        ++operation_;receipt_=false;expected_=0;
        state_=operation_==program_.count?State::Complete:State::Ready;return true;
    }
    bool commit(EAPOwner &owner,const uint8_t *station,const uint8_t *peer,uint64_t now){
        if(!poll(owner,station,peer,now) || state_!=State::Complete)return false;
        if(!owner.finishWEPKey(program_.generation,station,peer,program_.ticket,now)){
            state_=State::Uncertain;return false;
        }
        *this=WEPExecution{};return true;
    }
    void cancel(){if(state_!=State::Idle)state_=State::Uncertain;}
    // Only the radio's proven peer/reset retirement may release uncertainty.
    void firmwareRetired(){*this=WEPExecution{};}
};
}

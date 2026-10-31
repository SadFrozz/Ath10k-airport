#pragma once
#include <stdint.h>
namespace AthSecurity {
// Serialized host bookkeeping for one firmware key operation. The HTT reply
// carries peer/cipher/cast, NOT this ticket or a key index. The caller must
// establish ordered firmware admission; a ticket alone proves no wire identity.
class KeyTransaction {
public:
    enum class State : uint8_t { Idle, Reserved, Submitted, Acknowledged, Uncertain };
    struct Ticket { uint64_t serial=0,generation=0; };
private:
    State state_=State::Idle;
    uint64_t serial_=0,generation_=0,started_=0,deadline_=0;
    uint16_t peer_=0;
    uint8_t index_=0,cipherCast_=0;
    bool same(const Ticket &t) const {return t.serial && t.serial==serial_ && t.generation==generation_;}
public:
    State state() const {return state_;}
    bool reserve(uint64_t generation,uint16_t peer,uint8_t index,uint8_t cipherCast,
                 uint64_t now,uint64_t timeout,Ticket &out){
        if(state_!=State::Idle || !generation || peer>=2048 || index>3 ||
           (cipherCast&0x7f)>=8 || !timeout || now>UINT64_MAX-timeout || serial_==UINT64_MAX)return false;
        generation_=generation;peer_=peer;index_=index;cipherCast_=cipherCast;
        started_=now;deadline_=now+timeout;state_=State::Reserved;out={++serial_,generation};return true;
    }
    bool submitted(const Ticket &ticket,uint64_t now){
        if(!same(ticket) || !poll(now) || state_!=State::Reserved)return false;
        state_=State::Submitted;return true;
    }
    // Call only when transport definitively did not accept the command.
    bool rejectBeforeSubmission(const Ticket &ticket){
        if(state_!=State::Reserved || !same(ticket))return false;
        state_=State::Idle;return true;
    }
    bool poll(uint64_t now){
        const bool active=state_==State::Reserved || state_==State::Submitted || state_==State::Acknowledged;
        if(active && (now<started_ || now>=deadline_)){
            state_=state_==State::Reserved?State::Idle:State::Uncertain;return false;
        }
        return active;
    }
    void cancel(){
        if(state_==State::Submitted || state_==State::Acknowledged)state_=State::Uncertain;
        else if(state_==State::Reserved)state_=State::Idle;
    }
    bool acknowledge(const Ticket &ticket,uint16_t peer,uint8_t cipherCast,uint64_t now){
        if(!poll(now) || state_!=State::Submitted || !same(ticket) || peer!=peer_ || cipherCast!=cipherCast_)return false;
        state_=State::Acknowledged;return true;
    }
    // HTT has no key-index/ticket field. A matching indication is not enough
    // to reuse the channel for another slot with the same cipher/cast. Caller
    // must prove an ordered firmware fence AND retirement of prior RX work.
    // This method records that external proof; it does not manufacture it.
    bool completeAfterFence(const Ticket &ticket,uint64_t now){
        if(!same(ticket) || !poll(now) || state_!=State::Acknowledged)return false;
        state_=State::Idle;return true;
    }
    // Only a proven reset/fence which retires old firmware replies permits reuse
    // after uncertainty. Merely deleting host state or changing BSSID does not.
    void firmwareRetired(){state_=State::Idle;generation_=started_=deadline_=0;peer_=0;index_=cipherCast_=0;}
};
}

#pragma once
#include "../../security/Ath10kSecurity.hpp"
#include "../../security/Ath10kEAPOL.hpp"

namespace AthNative {
// Association-local owner for OS EAP and the translated MSK handoff. This does
// not advertise enterprise capability or authorize the controlled port.
// All methods require the radio owner; no allocation, waits or logging.
class EAPOwner {
    uint64_t sequence_=0,generation_=0,started_=0,deadline_=0;
    uint8_t station_[6]{},peer_[6]{},pmk_[32]{};
    bool ready_=false,consumed_=false,replacement_=false;
    static constexpr size_t PacketLimit=1522,QueueLimit=4;
    struct Packet {uint8_t bytes[PacketLimit]{};size_t length=0;uint64_t since=0;} tx_[QueueLimit]{};
    size_t read_=0,count_=0;
    static bool unicast(const uint8_t *p){
        if(!p || (p[0]&1))return false;
        uint8_t any=0;for(unsigned i=0;i<6;++i)any|=p[i];return any!=0;
    }
    bool current(uint64_t generation,const uint8_t *station,const uint8_t *peer) const {
        return generation && generation==generation_ && station && peer &&
            AthSecurity::equal(station_,station,6) && AthSecurity::equal(peer_,peer,6);
    }
public:
    enum class KeyResult {Invalid,Stale,Accepted,Duplicate,Conflict,Empty,Cleared};
    enum class Enqueue {Invalid,Full,Queued};
    enum class PacketOwner {Reject,SystemEAP,InternalKey};
    EAPOwner()=default;
    EAPOwner(const EAPOwner &)=delete;
    EAPOwner &operator=(const EAPOwner &)=delete;
    ~EAPOwner(){clear();}
    void clear(){
        generation_=started_=deadline_=0;ready_=consumed_=replacement_=false;
        AthSecurity::wipe(tx_,sizeof(tx_));read_=count_=0;
        AthSecurity::wipe(station_,sizeof(station_));AthSecurity::wipe(peer_,sizeof(peer_));
        AthSecurity::wipe(pmk_,sizeof(pmk_));
    }
    uint64_t generation() const {return generation_;}
    bool begin(const uint8_t *station,const uint8_t *peer,uint64_t now,uint64_t deadline){
        clear();
        if(sequence_==~uint64_t(0) || !unicast(station) || !unicast(peer) ||
           AthSecurity::equal(station,peer,6) || deadline<=now)return false;
        AthSecurity::copy(station_,station,6);AthSecurity::copy(peer_,peer,6);
        generation_=++sequence_;started_=now;deadline_=deadline;return true;
    }
    // Preserve queued frames for the same association. The service must drain
    // queue and firmware/transport owners before consuming the replacement PMK.
    bool beginReplacement(uint64_t generation,const uint8_t *station,const uint8_t *peer,
                          uint64_t now,uint64_t deadline){
        if(!current(generation,station,peer) || !consumed_ || replacement_ ||
           !validAt(now) || deadline<=now || sequence_==~uint64_t(0))return false;
        AthSecurity::wipe(pmk_,sizeof(pmk_));ready_=consumed_=false;
        generation_=++sequence_;started_=now;deadline_=deadline;
        replacement_=true;return true;
    }
    bool replacementPending() const {return replacement_;}
    bool replacementKeyReady() const {return replacement_ && consumed_;}
    bool replacementCompletable(uint64_t generation,const uint8_t *station,const uint8_t *peer,uint64_t now) const {
        return current(generation,station,peer) && replacement_ && consumed_ && validAt(now);
    }
    // A PMK handoff is not completion. Only the native owner, after key/receipt
    // barriers, may retire this deadline for the same replacement generation.
    bool finishReplacement(uint64_t generation,const uint8_t *station,const uint8_t *peer,uint64_t now){
        if(!current(generation,station,peer) || !replacement_ || !consumed_ || !validAt(now))return false;
        replacement_=false;return true;
    }
    // Admission checks must use the same clock as service expiry: packet or
    // key callbacks can arrive before a delayed workloop processes its timer.
    bool validAt(uint64_t now) const {
        return generation_ && now>=started_ && ((consumed_ && !replacement_) || now<deadline_);
    }
    bool expire(uint64_t now){
        if(!generation_ || validAt(now))return false;
        clear();return true;
    }
    // Ordinary WPA2 EAP's kernel-translated MSK is 32 bytes. Suite-B/FT,
    // passwords, PMKSA and direct PTK/GTK are deliberately different contracts.
    KeyResult setMSK(uint64_t generation,const uint8_t *station,const uint8_t *peer,
                     uint32_t cipher,const uint8_t *key,size_t bytes,uint64_t now){
        if(!current(generation,station,peer))return KeyResult::Stale;
        if(cipher!=9 || (bytes!=0 && bytes!=32) || (bytes && !key))return KeyResult::Invalid;
        if(!bytes){
            // macOS clears its prior MSK when entering Authenticating, before
            // producing the first key. There is no key to revoke in this owner;
            // preserve its EAP queue, generation and original deadline.
            if(!ready_){
                if(!validAt(now)){clear();return KeyResult::Stale;}
                return KeyResult::Empty;
            }
            clear();return KeyResult::Cleared;
        }
        if(!validAt(now)){clear();return KeyResult::Stale;}
        if(ready_)return AthSecurity::equal(pmk_,key,32)?KeyResult::Duplicate:KeyResult::Conflict;
        AthSecurity::copy(pmk_,key,32);ready_=true;return KeyResult::Accepted;
    }
    bool takePMK(uint64_t generation,const uint8_t *station,const uint8_t *peer,
                 uint64_t now,uint8_t *out){
        if(!out || !current(generation,station,peer) || !ready_ || consumed_)return false;
        if(now<started_ || now>=deadline_){clear();return false;}
        AthSecurity::copy(out,pmk_,32);consumed_=true;return true;
    }
    Enqueue enqueuePacket(uint64_t generation,const uint8_t *station,const uint8_t *peer,
                    const uint8_t *frame,size_t length,uint64_t now){
        if(length>PacketLimit || !validAt(now) ||
           route(generation,station,peer,frame,length,true)!=PacketOwner::SystemEAP)return Enqueue::Invalid;
        if(count_==QueueLimit)return Enqueue::Full;
        const auto envelope=AthSecurity::classifyEAPOL(frame,length);
        auto &slot=tx_[(read_+count_)%QueueLimit];
        AthSecurity::copy(slot.bytes,frame,envelope.bytes);slot.length=envelope.bytes;slot.since=now;
        ++count_;return Enqueue::Queued;
    }
    const uint8_t *front(size_t &length,uint64_t &since) const {
        length=0;since=0;if(!count_)return nullptr;
        length=tx_[read_].length;since=tx_[read_].since;return tx_[read_].bytes;
    }
    void pop(){if(count_){AthSecurity::wipe(&tx_[read_],sizeof(Packet));read_=(read_+1)%QueueLimit;--count_;}}
    bool pending() const {return count_!=0;}
    PacketOwner route(uint64_t generation,const uint8_t *station,const uint8_t *peer,
                      const uint8_t *frame,size_t length,bool transmit) const {
        if(!current(generation,station,peer))return PacketOwner::Reject;
        const auto envelope=AthSecurity::classifyEAPOL(frame,length);
        if(envelope.kind==AthSecurity::EAPOLKind::Invalid)return PacketOwner::Reject;
        const uint8_t group[6]={1,0x80,0xc2,0,0,3};
        if(!AthSecurity::equal(frame+6,transmit?station_:peer_,6) ||
           (!AthSecurity::equal(frame,transmit?peer_:station_,6) &&
            !AthSecurity::equal(frame,group,6)))return PacketOwner::Reject;
        if(envelope.kind==AthSecurity::EAPOLKind::Key)
            return !transmit && AthSecurity::equal(frame,station_,6)?PacketOwner::InternalKey:PacketOwner::Reject;
        if(envelope.kind==AthSecurity::EAPOLKind::EAP){
            const uint8_t code=frame[18];
            if(transmit?code!=2:(code!=1 && code!=3 && code!=4))return PacketOwner::Reject;
            return PacketOwner::SystemEAP;
        }
        return transmit?PacketOwner::SystemEAP:PacketOwner::Reject;
    }
};
}

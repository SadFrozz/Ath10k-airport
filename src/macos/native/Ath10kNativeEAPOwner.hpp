#pragma once
#include "../../security/Ath10kSecurity.hpp"
#include "../../security/Ath10kEAPOL.hpp"
#include "Ath10kNativeWEPKey.hpp"

namespace AthNative {
// Association-local owner for OS EAP and the translated MSK handoff. This does
// not advertise enterprise capability or authorize the controlled port.
// All methods require the radio owner; no allocation, waits or logging.
class EAPOwner {
    uint64_t sequence_=0,generation_=0,started_=0,deadline_=0;
    uint8_t station_[6]{},peer_[6]{},pmk_[32]{};
    bool ready_=false,consumed_=false,replacement_=false;
    AthSecurity::EAPOLKeyProtocol protocol_=AthSecurity::EAPOLKeyProtocol::RSN;
    static constexpr size_t PacketLimit=1522,QueueLimit=4;
    struct Packet {uint8_t bytes[PacketLimit]{};size_t length=0;uint64_t since=0;} tx_[QueueLimit]{};
    size_t read_=0,count_=0;
public:
    struct WEPKey {uint8_t key[13]{};uint8_t length=0,index=0;uint16_t flags=0;uint64_t ticket=0;};
private:
    static constexpr size_t WEPQueueLimit=8; // four slots, unicast and group owners
    WEPKey wep_[WEPQueueLimit]{},wepInstalled_[2][4]{};
    size_t wepRead_=0,wepCount_=0;
    uint64_t wepSequence_=0;
    uint8_t wepTransmitIndex_=0;
    bool wepTransmitValid_=false,staticWEP_=false;

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
        protocol_=AthSecurity::EAPOLKeyProtocol::RSN;
        AthSecurity::wipe(tx_,sizeof(tx_));read_=count_=0;
        AthSecurity::wipe(wep_,sizeof(wep_));wepRead_=wepCount_=0;
        AthSecurity::wipe(wepInstalled_,sizeof(wepInstalled_));
        wepTransmitIndex_=0;wepTransmitValid_=false;staticWEP_=false;
        AthSecurity::wipe(station_,sizeof(station_));AthSecurity::wipe(peer_,sizeof(peer_));
        AthSecurity::wipe(pmk_,sizeof(pmk_));
    }
    uint64_t generation() const {return generation_;}
    AthSecurity::EAPOLEnvelope envelope(const uint8_t *frame,size_t length) const {
        return generation_?AthSecurity::classifyEAPOL(frame,length,protocol_):AthSecurity::EAPOLEnvelope{};
    }
    bool begin(const uint8_t *station,const uint8_t *peer,uint64_t now,uint64_t deadline,bool wpa1=false){
        clear();
        if(sequence_==~uint64_t(0) || !unicast(station) || !unicast(peer) ||
           AthSecurity::equal(station,peer,6) || deadline<=now)return false;
        AthSecurity::copy(station_,station,6);AthSecurity::copy(peer_,peer,6);
        protocol_=wpa1?AthSecurity::EAPOLKeyProtocol::WPA1:AthSecurity::EAPOLKeyProtocol::RSN;
        generation_=++sequence_;started_=now;deadline_=deadline;return true;
    }
    // Explicit entry point only for an independently admitted dynamic-WEP
    // association. No native join currently selects it. WEP keys belong to the
    // system client, never the internal RSN/WPA supplicant or MSK handoff.
    bool beginDynamicWEP(const uint8_t *station,const uint8_t *peer,uint64_t now,uint64_t deadline){
        if(!begin(station,peer,now,deadline))return false;
        protocol_=AthSecurity::EAPOLKeyProtocol::DynamicWEP;return true;
    }
    bool wep() const {return generation_ && protocol_==AthSecurity::EAPOLKeyProtocol::DynamicWEP;}
    bool dynamicWEP() const {return wep() && !staticWEP_;}
    bool staticWEP() const {return wep() && staticWEP_;}
    // Seed the same firmware slot program from an admitted static profile,
    // without pretending the key arrived from the system EAP client.
    bool beginStaticWEP(const uint8_t *station,const uint8_t *peer,uint64_t now,uint64_t deadline,
                        const uint8_t *key,size_t length,uint8_t index){
        if(!key || (length!=5 && length!=13) || index>3){clear();return false;}
        struct Record {uint8_t bytes[148]{};~Record(){AthSecurity::wipe(this,sizeof(*this));}} record;
        // Copy before begin clears the preceding association's secrets.
        AthSecurity::copy(record.bytes+16,key,length);
        if(!beginDynamicWEP(station,peer,now,deadline))return false;
        record.bytes[0]=1;record.bytes[4]=uint8_t(length);record.bytes[8]=length==5?1:2;
        record.bytes[12]=2;record.bytes[14]=index;
        if(setWEPKey(generation_,station,peer,record.bytes,sizeof(record.bytes),now)!=KeyResult::Accepted){clear();return false;}
        record.bytes[12]=5; // Same pair bytes, followed by default-TX selection.
        if(setWEPKey(generation_,station,peer,record.bytes,sizeof(record.bytes),now)!=KeyResult::Accepted){clear();return false;}
        staticWEP_=true;return true;
    }
    bool staticWEPReady(uint64_t generation,const uint8_t *station,const uint8_t *peer,uint64_t now) const {
        if(!staticWEP() || !current(generation,station,peer) || !validAt(now) || pending() || !wepTransmitValid_)return false;
        const auto &pair=wepInstalled_[0][wepTransmitIndex_],&group=wepInstalled_[1][wepTransmitIndex_];
        if(!pair.ticket || !group.ticket || pair.length!=group.length || !AthSecurity::equal(pair.key,group.key,pair.length))return false;
        return true;
    }
    // Retire the authentication deadline only after firmware authorization.
    bool finishStaticWEP(uint64_t generation,const uint8_t *station,const uint8_t *peer,uint64_t now){
        if(!staticWEPReady(generation,station,peer,now))return false;
        consumed_=true;return true;
    }
    KeyResult setWEPKey(uint64_t generation,const uint8_t *station,const uint8_t *peer,
                        const void *record,size_t size,uint64_t now){
        if(!current(generation,station,peer))return KeyResult::Stale;
        if(!dynamicWEP())return KeyResult::Invalid;
        if(!validAt(now)){clear();return KeyResult::Stale;}
        DynamicWEPKeyView key{};
        if(!decodeDynamicWEPKey(record,size,peer,key))return KeyResult::Invalid;
        // Compare only the latest queued value for this slot/cast. A,B,A
        // means three ordered requests, not a duplicate of the first A.
        bool transmitValid=wepTransmitValid_;uint8_t transmitIndex=wepTransmitIndex_;
        for(size_t i=0;i<wepCount_;++i){
            const auto &queued=wep_[(wepRead_+i)%WEPQueueLimit];
            if(queued.flags&4){transmitValid=true;transmitIndex=queued.index;}
        }
        const bool transmitMatches=!key.transmit || (transmitValid && transmitIndex==key.index);
        // QCA station group WEP programming also writes the pairwise slot.
        // Account for later queued writes to either cast at that index.
        const WEPKey *effectivePair=&wepInstalled_[0][key.index];
        for(size_t i=0;i<wepCount_;++i){
            const auto &queued=wep_[(wepRead_+i)%WEPQueueLimit];
            if(queued.index==key.index)effectivePair=&queued;
        }
        const bool mirrorMatches=!key.group || (effectivePair->ticket && effectivePair->length==key.length &&
            AthSecurity::equal(effectivePair->key,key.key,key.length));
        bool queuedSlot=false;
        for(size_t i=wepCount_;i>0;--i){
            const auto &old=wep_[(wepRead_+i-1)%WEPQueueLimit];
            // Group programming also replaces the pairwise slot. For an
            // individual request, that queued mirror is a replacement even
            // if no explicit individual request exists in the queue.
            if(old.index!=key.index || (key.group && old.flags!=2))continue;
            queuedSlot=true;
            if(mirrorMatches && transmitMatches && old.flags==key.flags && old.length==key.length &&
               AthSecurity::equal(old.key,key.key,key.length))return KeyResult::Duplicate;
            break;
        }
        // Do not reprogram an already completed identical slot. A queued
        // replacement takes precedence over installed history (installed A,
        // pending B, requested A must preserve the final requested value).
        if(!queuedSlot){
            const auto &old=wepInstalled_[key.group?1:0][key.index];
            if(mirrorMatches && transmitMatches && old.ticket && old.flags==key.flags && old.length==key.length &&
               AthSecurity::equal(old.key,key.key,key.length))return KeyResult::Duplicate;
        }
        if(wepCount_==WEPQueueLimit || wepSequence_==UINT64_MAX)return KeyResult::Conflict;
        auto &slot=wep_[(wepRead_+wepCount_)%WEPQueueLimit];
        AthSecurity::wipe(&slot,sizeof(slot));AthSecurity::copy(slot.key,key.key,key.length);
        slot.length=key.length;slot.index=key.index;slot.flags=key.flags;slot.ticket=++wepSequence_;
        ++wepCount_;return KeyResult::Accepted;
    }
    // Borrow only while holding the radio owner. Completion requires the
    // separate firmware operation/fence proof; this queue grants no port access.
    const WEPKey *frontWEPKey(uint64_t generation,const uint8_t *station,const uint8_t *peer,uint64_t now) const {
        return current(generation,station,peer) && wep() && validAt(now) && wepCount_?&wep_[wepRead_]:nullptr;
    }
    enum class WEPAction {None,Install,InstallGroupOnly,RepairPairMirror,SelectTransmit,MetadataOnly};
    WEPAction frontWEPAction(uint64_t generation,const uint8_t *station,const uint8_t *peer,uint64_t now) const {
        const auto *key=frontWEPKey(generation,station,peer,now);
        if(!key)return WEPAction::None;
        const auto &installed=wepInstalled_[key->flags==2?1:0][key->index];
        const bool same=installed.ticket && installed.length==key->length &&
            AthSecurity::equal(installed.key,key->key,key->length);
        if(key->flags==2){
            const auto &pair=wepInstalled_[0][key->index];
            const bool mirror=pair.ticket && pair.length==key->length && AthSecurity::equal(pair.key,key->key,key->length);
            if(!same)return mirror?WEPAction::InstallGroupOnly:WEPAction::Install;
            if(!mirror)return WEPAction::RepairPairMirror;
        }else if(!same)return WEPAction::Install;
        // Same bytes must not reset firmware IV state merely to select the
        // default TX slot. The consumer uses VDEV_PARAM_DEF_KEYID instead.
        if((key->flags&4) && (!wepTransmitValid_ || wepTransmitIndex_!=key->index))return WEPAction::SelectTransmit;
        return WEPAction::MetadataOnly;
    }
    enum class WEPWrite : uint8_t {Group,Pair,SelectTransmit};
    struct WEPProgram {
        uint64_t generation=0,ticket=0;
        WEPWrite writes[3]{};
        uint8_t count=0;
        bool valid=false;
    };
    // Freeze the complete operation order before submitting anything. The
    // program contains no key bytes; the queue retains the borrowed material.
    // Every write needs its own transport retirement/fence. Never publish a
    // completed slot after only the first half of a mirrored group install.
    WEPProgram frontWEPProgram(uint64_t generation,const uint8_t *station,const uint8_t *peer,uint64_t now) const {
        const auto *key=frontWEPKey(generation,station,peer,now);
        if(!key)return {};
        WEPProgram program{};program.generation=generation;program.ticket=key->ticket;program.valid=true;
        switch(frontWEPAction(generation,station,peer,now)){
        case WEPAction::Install:
            if(key->flags==2)program.writes[program.count++]=WEPWrite::Group;
            program.writes[program.count++]=WEPWrite::Pair;break;
        case WEPAction::InstallGroupOnly:program.writes[program.count++]=WEPWrite::Group;break;
        case WEPAction::RepairPairMirror:program.writes[program.count++]=WEPWrite::Pair;break;
        case WEPAction::SelectTransmit:case WEPAction::MetadataOnly:break;
        case WEPAction::None:return {};
        }
        // Changing the selected TX slot is distinct from writing key bytes.
        // A new individual install may require both operations, not just one.
        if((key->flags&4) && (!wepTransmitValid_ || wepTransmitIndex_!=key->index))
            program.writes[program.count++]=WEPWrite::SelectTransmit;
        return program;
    }
    // Group completion means all planned group/pair mirror operations and
    // their fences succeeded. Partial completion must never call this method.
    bool finishWEPKey(uint64_t generation,const uint8_t *station,const uint8_t *peer,uint64_t ticket,uint64_t now){
        const auto *key=frontWEPKey(generation,station,peer,now);
        if(!key || !ticket || key->ticket!=ticket)return false;
        auto &installed=wepInstalled_[key->flags==2?1:0][key->index];
        AthSecurity::wipe(&installed,sizeof(installed));installed=*key;
        if(key->flags==2){
            auto &pair=wepInstalled_[0][key->index];
            AthSecurity::wipe(&pair,sizeof(pair));pair=*key;pair.flags=1;
        }
        if(key->flags&4){wepTransmitValid_=true;wepTransmitIndex_=key->index;}
        AthSecurity::wipe(&wep_[wepRead_],sizeof(WEPKey));wepRead_=(wepRead_+1)%WEPQueueLimit;--wepCount_;return true;
    }
    const WEPKey *installedWEPKey(uint64_t generation,const uint8_t *station,const uint8_t *peer,
                                  uint8_t index,bool group,uint64_t now) const {
        if(index>3 || !current(generation,station,peer) || !wep() || !validAt(now))return nullptr;
        const auto &key=wepInstalled_[group?1:0][index];return key.ticket?&key:nullptr;
    }
    bool confirmedWEPTransmitIndex(uint64_t generation,const uint8_t *station,const uint8_t *peer,uint64_t now,uint8_t &index) const {
        index=0;
        if(!current(generation,station,peer) || !wep() || !validAt(now) || !wepTransmitValid_ ||
           !wepInstalled_[0][wepTransmitIndex_].ticket)return false;
        index=wepTransmitIndex_;return true;
    }
    // Preserve queued frames for the same association. The service must drain
    // queue and firmware/transport owners before consuming the replacement PMK.
    bool beginReplacement(uint64_t generation,const uint8_t *station,const uint8_t *peer,
                          uint64_t now,uint64_t deadline){
        if(staticWEP_ || !current(generation,station,peer) || !consumed_ || replacement_ ||
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
        if(protocol_==AthSecurity::EAPOLKeyProtocol::DynamicWEP || cipher!=9 || (bytes!=0 && bytes!=32) || (bytes && !key))return KeyResult::Invalid;
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
        const auto envelope=AthSecurity::classifyEAPOL(frame,length,protocol_);
        auto &slot=tx_[(read_+count_)%QueueLimit];
        AthSecurity::copy(slot.bytes,frame,envelope.bytes);slot.length=envelope.bytes;slot.since=now;
        ++count_;return Enqueue::Queued;
    }
    const uint8_t *front(size_t &length,uint64_t &since) const {
        length=0;since=0;if(!count_)return nullptr;
        length=tx_[read_].length;since=tx_[read_].since;return tx_[read_].bytes;
    }
    void pop(){if(count_){AthSecurity::wipe(&tx_[read_],sizeof(Packet));read_=(read_+1)%QueueLimit;--count_;}}
    bool keyPending() const {return wepCount_!=0;}
    // Lifecycle guards must retain both packet and key requests. A key-only
    // owner has no front() packet but still blocks roam and data resumption.
    bool pending() const {return count_!=0 || keyPending();}
    PacketOwner route(uint64_t generation,const uint8_t *station,const uint8_t *peer,
                      const uint8_t *frame,size_t length,bool transmit) const {
        if(staticWEP_ || !current(generation,station,peer))return PacketOwner::Reject;
        const auto envelope=AthSecurity::classifyEAPOL(frame,length,protocol_);
        if(envelope.kind==AthSecurity::EAPOLKind::Invalid)return PacketOwner::Reject;
        const uint8_t group[6]={1,0x80,0xc2,0,0,3};
        if(!AthSecurity::equal(frame+6,transmit?station_:peer_,6) ||
           (!AthSecurity::equal(frame,transmit?peer_:station_,6) &&
            !AthSecurity::equal(frame,group,6)))return PacketOwner::Reject;
        if(envelope.kind==AthSecurity::EAPOLKind::Key){
            if(transmit || !AthSecurity::equal(frame,station_,6))return PacketOwner::Reject;
            return protocol_==AthSecurity::EAPOLKeyProtocol::DynamicWEP?
                PacketOwner::SystemEAP:PacketOwner::InternalKey;
        }
        if(envelope.kind==AthSecurity::EAPOLKind::EAP){
            const uint8_t code=frame[18];
            if(transmit?code!=2:(code!=1 && code!=3 && code!=4))return PacketOwner::Reject;
            return PacketOwner::SystemEAP;
        }
        return transmit?PacketOwner::SystemEAP:PacketOwner::Reject;
    }
};
}

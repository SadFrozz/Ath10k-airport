#pragma once
#include "Ath10kSecurity.hpp"
namespace AthSecurity {
// Shared-Key authentication encrypts transaction3's body with RC4(IV || WEP
// key), with no WPA1-style 256-byte discard. The caller owns IV uniqueness,
// authentication state, peer validation and the Protected management header.
// Output is IV/key-id followed by encrypted body and little-endian CRC32.
// This bounded encoder is not an integrity verifier or port authorization.
inline size_t encryptWEPAuthentication(const uint8_t *key,size_t keyBytes,
    const uint8_t *iv,uint8_t index,const uint8_t *body,size_t bytes,
    uint8_t *output,size_t capacity){
    if(!key || (keyBytes!=5 && keyBytes!=13) || !iv || index>3 || !body ||
       bytes<8 || bytes>263 || !output || capacity<bytes+8)return 0;
    // Transaction3, algorithm Shared Key, success and one complete challenge IE.
    if(body[0]!=1 || body[1] || body[2]!=3 || body[3] || body[4] || body[5] ||
       body[6]!=16 || !body[7] || size_t(body[7])+8!=bytes)return 0;
    const auto overlaps=[](const uint8_t *a,size_t n,const uint8_t *b,size_t m){
        const uintptr_t x=reinterpret_cast<uintptr_t>(a),y=reinterpret_cast<uintptr_t>(b);
        return x>=y?x-y<m:y-x<n;
    };
    // Reject before mutation; output must not overwrite a borrowed key or IV.
    if(overlaps(output,bytes+8,key,keyBytes) || overlaps(output,bytes+8,iv,3) ||
       overlaps(output,bytes+8,body,bytes))return 0;
    struct Temporary {
        uint8_t seed[16]{},permutation[256]{},payload[267]{};
        ~Temporary(){wipe(this,sizeof(*this));}
    } t;
    copy(t.seed,iv,3);copy(t.seed+3,key,keyBytes);copy(t.payload,body,bytes);
    uint32_t crc=0xffffffffu;
    for(size_t n=0;n<bytes;++n){
        crc^=body[n];for(unsigned bit=0;bit<8;++bit)crc=(crc>>1)^(0xedb88320u&uint32_t(0-int32_t(crc&1)));
    }
    crc=~crc;for(unsigned n=0;n<4;++n)t.payload[bytes+n]=uint8_t(crc>>(8*n));
    for(unsigned n=0;n<256;++n)t.permutation[n]=uint8_t(n);
    uint8_t j=0;
    for(unsigned n=0;n<256;++n){
        j=uint8_t(j+t.permutation[n]+t.seed[n%(keyBytes+3)]);
        const auto saved=t.permutation[n];t.permutation[n]=t.permutation[j];t.permutation[j]=saved;
    }
    copy(output,iv,3);output[3]=uint8_t(index<<6);uint8_t i=0;j=0;
    for(size_t n=0;n<bytes+4;++n){
        ++i;j=uint8_t(j+t.permutation[i]);
        const auto saved=t.permutation[i];t.permutation[i]=t.permutation[j];t.permutation[j]=saved;
        output[4+n]=t.payload[n]^t.permutation[uint8_t(t.permutation[i]+t.permutation[j])];
    }
    return bytes+8;
}
// One Shared-Key exchange. Retries reuse the exact ciphertext; a changed
// challenge cannot reuse its IV. Firmware TX retirement remains the caller's
// responsibility before advancing/replacing a submitted frame.
class WEPSharedAuthentication {
public:
    enum class State {Idle,Request,Challenge,ResponseReady,Response,Complete,Failed};
private:
    State state_=State::Idle;
    uint64_t generation_=0,started_=0,deadline_=0;
    uint8_t station_[6]{},peer_[6]{},key_[13]{},iv_[3]{},challenge_[255]{},response_[271]{};
    size_t keyBytes_=0,challengeBytes_=0,responseBytes_=0;
    uint8_t index_=0;
    static bool unicast(const uint8_t *p){
        if(!p || (p[0]&1))return false;
        uint8_t any=0;for(unsigned n=0;n<6;++n)any|=p[n];return any!=0;
    }
    bool owner(uint64_t generation,const uint8_t *station,const uint8_t *peer,uint64_t now)const{
        return generation && generation==generation_ && station && peer &&
            equal(station,station_,6) && equal(peer,peer_,6) && now>=started_ && now<deadline_;
    }
public:
    WEPSharedAuthentication()=default;
    WEPSharedAuthentication(const WEPSharedAuthentication &)=delete;
    WEPSharedAuthentication &operator=(const WEPSharedAuthentication &)=delete;
    ~WEPSharedAuthentication(){clear();}
    void clear(){wipe(key_,sizeof(key_));wipe(iv_,sizeof(iv_));wipe(challenge_,sizeof(challenge_));
        wipe(response_,sizeof(response_));wipe(station_,6);wipe(peer_,6);
        generation_=started_=deadline_=0;keyBytes_=challengeBytes_=responseBytes_=0;index_=0;state_=State::Idle;}
    void cancel(){clear();state_=State::Failed;}
    State state()const{return state_;}
    size_t keyLength()const{return keyBytes_;}
    bool begin(uint64_t generation,const uint8_t *station,const uint8_t *peer,
        const uint8_t *key,size_t keyBytes,uint8_t index,const uint8_t *iv,uint64_t now,uint64_t deadline){
        clear();
        if(!generation || !unicast(station) || !unicast(peer) || equal(station,peer,6) ||
           !key || (keyBytes!=5 && keyBytes!=13) || index>3 || !iv || deadline<=now)return false;
        // Skip known FMS weak-IV families. The caller supplies a fresh IV;
        // rejection must request new randomness, not silently reuse another.
        if(iv[1]==255 && iv[0]>=3 && iv[0]<3+keyBytes)return false;
        generation_=generation;started_=now;deadline_=deadline;index_=index;keyBytes_=keyBytes;
        copy(station_,station,6);copy(peer_,peer,6);copy(key_,key,keyBytes);copy(iv_,iv,3);
        state_=State::Request;return true;
    }
    bool poll(uint64_t now){
        if(state_==State::Idle || state_==State::Failed)return false;
        if(now<started_ || now>=deadline_){cancel();return false;}return true;
    }
    // Call only after the request frame has entered the owned TX transaction.
    bool requestSubmitted(){if(state_!=State::Request)return false;state_=State::Challenge;return true;}
    bool receive(uint64_t generation,const uint8_t *station,const uint8_t *peer,
        const uint8_t *body,size_t bytes,uint64_t now){
        if(!owner(generation,station,peer,now) || !body || bytes<6 ||
           (state_!=State::Challenge && state_!=State::ResponseReady && state_!=State::Response))return false;
        if(body[0]!=1 || body[1] || body[3])return false;
        if(body[2]==4 && state_==State::Response){
            if(bytes!=6)return false;
            if(body[4] || body[5]){cancel();return false;}
            wipe(key_,sizeof(key_));wipe(response_,sizeof(response_));responseBytes_=0;
            wipe(challenge_,sizeof(challenge_));challengeBytes_=0;state_=State::Complete;return true;
        }
        if(body[2]!=2)return false;
        if(body[4] || body[5]){cancel();return false;}
        if(bytes<9 || bytes>263 || body[6]!=16 || !body[7] || size_t(body[7])+8!=bytes)return false;
        if(state_==State::ResponseReady || state_==State::Response){
            // A duplicate response2 is harmless, but a replacement challenge
            // must never overwrite the live ciphertext/IV owner.
            return challengeBytes_==body[7] && equal(challenge_,body+8,challengeBytes_);
        }
        uint8_t plain[263]{};copy(plain,body,bytes);plain[2]=3;
        responseBytes_=encryptWEPAuthentication(key_,keyBytes_,iv_,index_,plain,bytes,response_,sizeof(response_));
        wipe(plain,sizeof(plain));
        if(!responseBytes_){cancel();return false;}
        challengeBytes_=body[7];copy(challenge_,body+8,challengeBytes_);
        state_=State::ResponseReady;return true;
    }
    size_t buildResponseFrame(uint64_t generation,const uint8_t *station,const uint8_t *peer,
        uint64_t now,uint16_t sequence,uint8_t *frame,size_t capacity)const{
        size_t bytes=0;const auto *payload=response(generation,station,peer,now,bytes);
        if(!payload || !frame || sequence>4095 || capacity<24+bytes)return 0;
        // Destination must not alias retained owner storage or borrowed IDs.
        const auto overlap=[](const void *a,size_t n,const void *b,size_t m){
            const uintptr_t x=reinterpret_cast<uintptr_t>(a),y=reinterpret_cast<uintptr_t>(b);
            return x>=y?x-y<m:y-x<n;
        };
        if(overlap(frame,24+bytes,this,sizeof(*this)) || overlap(frame,24+bytes,station,6) ||
           overlap(frame,24+bytes,peer,6))return 0;
        wipe(frame,24);frame[0]=0xb0;frame[1]=0x40;
        copy(frame+4,peer,6);copy(frame+10,station,6);copy(frame+16,peer,6);
        frame[22]=uint8_t(sequence<<4);frame[23]=uint8_t(sequence>>4);
        copy(frame+24,payload,bytes);return 24+bytes;
    }
    bool matchesResponseFrame(uint64_t generation,const uint8_t *station,const uint8_t *peer,
        uint64_t now,const uint8_t *frame,size_t bytes)const{
        size_t n=0;const auto *payload=response(generation,station,peer,now,n);
        // Retry flag and sequence number may differ; no fragmentation, order,
        // DS, duration or alternate address fields are admitted by this owner.
        return payload && frame && bytes==24+n && frame[0]==0xb0 &&
            (frame[1]==0x40 || frame[1]==0x48) && !frame[2] && !frame[3] && !(frame[22]&15) &&
            equal(frame+4,peer,6) && equal(frame+10,station,6) && equal(frame+16,peer,6) &&
            equal(frame+24,payload,n);
    }
    bool responseSubmitted(){if(state_!=State::ResponseReady)return false;state_=State::Response;return true;}
    const uint8_t *response(uint64_t generation,const uint8_t *station,const uint8_t *peer,uint64_t now,size_t &bytes)const{
        bytes=0;if((state_!=State::ResponseReady && state_!=State::Response) || !owner(generation,station,peer,now))return nullptr;
        bytes=responseBytes_;return response_;
    }
};

}

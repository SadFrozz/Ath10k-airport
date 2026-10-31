#pragma once
#include "Ath10kSecurity.hpp"
namespace AthSecurity {
// WPA descriptor-version 1 key data: RC4(IV || KEK), discard first 256 bytes.
// Caller MUST authenticate the EAPOL MIC and validate replay/profile before
// decrypting. This primitive neither authenticates nor installs keys.
inline bool decryptWPA1KeyData(const uint8_t *iv,const uint8_t *kek,
    const uint8_t *input,size_t bytes,uint8_t *output,size_t capacity){
    if(!iv || !kek || !input || !output || !bytes || bytes>512 || capacity<bytes)return false;
    // Exact in-place operation is valid. Partial overlap would corrupt input.
    const uintptr_t in=reinterpret_cast<uintptr_t>(input),out=reinterpret_cast<uintptr_t>(output);
    if(in!=out && (in>out?in-out:out-in)<bytes)return false;
    struct State {
        uint8_t key[32]{},permutation[256]{},i=0,j=0;
        ~State(){wipe(this,sizeof(*this));}
    } state;
    copy(state.key,iv,16);copy(state.key+16,kek,16);
    for(unsigned n=0;n<256;++n)state.permutation[n]=uint8_t(n);
    for(unsigned n=0;n<256;++n){
        state.j=uint8_t(state.j+state.permutation[n]+state.key[n%32]);
        const uint8_t saved=state.permutation[n];
        state.permutation[n]=state.permutation[state.j];state.permutation[state.j]=saved;
    }
    state.j=0;
    for(size_t n=0;n<256+bytes;++n){
        ++state.i;state.j=uint8_t(state.j+state.permutation[state.i]);
        const uint8_t saved=state.permutation[state.i];
        state.permutation[state.i]=state.permutation[state.j];state.permutation[state.j]=saved;
        const uint8_t stream=state.permutation[uint8_t(state.permutation[state.i]+state.permutation[state.j])];
        if(n>=256)output[n-256]=input[n-256]^stream;
    }
    return true;
}
// Authenticate descriptor-version1 key data before releasing any plaintext.
// p begins at EAPOL version, not Ethernet. Association identity, message role
// and replay checks remain the handshake owner's responsibility.
template<class Crypto> inline bool authenticateWPA1KeyData(const uint8_t *kck,
    const uint8_t *kek,const uint8_t *p,size_t bytes,uint8_t *output,size_t capacity){
    if(!kck || !kek || !p || !output || bytes<100 || bytes>512 ||
       p[0]<1 || p[0]>3 || p[1]!=3 || p[4]!=254 ||
       be16(p+2)!=bytes-4 || be16(p+97)!=bytes-99 ||
       (be16(p+5)&7)!=1 || !(be16(p+5)&0x100) || capacity<bytes-99)return false;
    struct Temporary {
        uint8_t packet[512]{},digest[16]{};
        ~Temporary(){wipe(this,sizeof(*this));}
    } temporary;
    copy(temporary.packet,p,bytes);wipe(temporary.packet+81,16);
    if(!Crypto::hmacMD5(kck,16,temporary.packet,bytes,temporary.digest) ||
       !equal(temporary.digest,p+81,16))return false;
    return decryptWPA1KeyData(p+49,kek,p+99,bytes-99,output,capacity);
}

// WPA1 group message 1 carries a raw GTK, not an RSN KDE. This decoder
// deliberately does not commit replay state or install a firmware key. The
// association owner must first bind the frame to its peer and completed PTK,
// and must handle exact retransmissions through its cached acknowledgement.
struct WPA1GroupKey {
    uint8_t key[32]{},rsc[6]{},index=0,cipher=0;
    uint64_t replay=0;
    bool transmit=false;
    ~WPA1GroupKey(){wipe(this,sizeof(*this));}
};
template<class Crypto> inline bool decodeWPA1GroupKey(const uint8_t *kck,
    const uint8_t *kek,const uint8_t *p,size_t bytes,uint8_t groupCipher,
    uint64_t replayFloor,WPA1GroupKey &result){
    if(!p || bytes<99)return false;
    const size_t keyBytes=groupCipher==cipherTKIP?32:(groupCipher==cipherCCMP?16:0);
    if(!keyBytes || bytes!=99+keyBytes || be16(p+7)!=keyBytes ||
       be16(p+97)!=keyBytes)return false;
    const uint16_t info=be16(p+5);
    // Version 1, ACK and MIC are mandatory; index, TX/RX and SECURE are
    // allowed. Pairwise, request, error and RSN encrypted-KDE flags are not.
    if((info&~uint16_t(0x0270))!=0x0181 || be64(p+9)<=replayFloor)return false;
    // Only the 48-bit receive sequence is representable by this driver.
    if(p[71] || p[72])return false;
    WPA1GroupKey candidate;
    if(!authenticateWPA1KeyData<Crypto>(kck,kek,p,bytes,candidate.key,sizeof(candidate.key)))return false;
    candidate.index=uint8_t((info>>4)&3);candidate.transmit=(info&0x40)!=0;
    candidate.cipher=groupCipher;candidate.replay=be64(p+9);copy(candidate.rsc,p+65,6);
    result=candidate;return true;
}

}

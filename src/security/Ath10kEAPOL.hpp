#pragma once
#include <stddef.h>
#include <stdint.h>

namespace AthSecurity {
// Wire facts: IEEE 802.1X EAPOL; corroborated by Apple's eap8021x EAPOL.h.
// This is an envelope classifier, not authentication, peer validation or an
// authorization decision. Caller retains packet ownership and validates peer.
enum class EAPOLKind : uint8_t { Invalid, EAP, Start, Logoff, Key };
struct EAPOLEnvelope {
    EAPOLKind kind=EAPOLKind::Invalid;
    size_t bytes=0; // Ethernet header + declared EAPOL payload, excluding padding.
};
enum class EAPOLKeyProtocol : uint8_t { RSN, WPA1, DynamicWEP };
inline EAPOLEnvelope classifyEAPOL(const uint8_t *frame,size_t length,EAPOLKeyProtocol protocol=EAPOLKeyProtocol::RSN){
    if(!frame || length<18 || frame[12]!=0x88 || frame[13]!=0x8e ||
       frame[14]<1 || frame[14]>3)return {};
    const size_t body=(size_t(frame[16])<<8)|frame[17];
    if(body>length-18)return {};
    // Ethernet minimum-frame padding is not part of the EAPOL body. Never
    // hand padding to the EAP parser or authenticate it as key data.
    const size_t bytes=18+body;
    switch(frame[15]){
    case 0: {
        if(body<4)return {};
        const size_t eapBytes=(size_t(frame[20])<<8)|frame[21];
        if(eapBytes!=body)return {};
        const uint8_t code=frame[18];
        if((code==1 || code==2)?body<5:((code!=3 && code!=4) || body!=4))return {};
        return {EAPOLKind::EAP,bytes};
    }
    case 1: return body?EAPOLEnvelope{}:EAPOLEnvelope{EAPOLKind::Start,bytes};
    case 2: return body?EAPOLEnvelope{}:EAPOLEnvelope{EAPOLKind::Logoff,bytes};
    case 3:
        // Descriptor1: type, key length, replay8, IV16, index, signature16.
        // Only the stock EAP client authenticates/decrypts this envelope.
        if(protocol==EAPOLKeyProtocol::DynamicWEP){
            if(body<44 || frame[18]!=1)return {};
            const size_t keyBytes=(size_t(frame[19])<<8)|frame[20];
            if((keyBytes!=5 && keyBytes!=13) || (frame[45]&0x7f)>3 ||
               (body!=44 && body!=44+keyBytes))return {};
            return {EAPOLKind::Key,bytes};
        }
        // The association's selected protocol owns exactly one descriptor.
        if(body<95 || frame[18]!=(protocol==EAPOLKeyProtocol::WPA1?254:2))return {};
        if(((size_t(frame[111])<<8)|frame[112])!=body-95)return {};
        return {EAPOLKind::Key,bytes};
    default: return {};
    }
}
}

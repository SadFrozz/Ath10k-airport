#pragma once
#include <stddef.h>
#include <stdint.h>

namespace AthNative {
// Borrowed view of the installed 24G90 eapolclient's dynamic-WEP SET_KEY
// envelope. The caller must copy/own and wipe the complete callback record;
// this view must never survive that record or be queued to firmware directly.
// Decoding is not association admission, firmware completion or authorization.
struct DynamicWEPKeyView {
    const uint8_t *key=nullptr;
    uint8_t length=0,index=0;
    uint16_t flags=0;
    bool group=false,transmit=false;
};
inline bool decodeDynamicWEPKey(const void *record,size_t size,
                               const uint8_t *currentPeer,DynamicWEPKeyView &out){
    out={};
    if(!record || size!=148 || !currentPeer || (currentPeer[0]&1))return false;
    uint8_t peerAny=0;for(unsigned i=0;i<6;++i)peerAny|=currentPeer[i];
    if(!peerAny)return false;
    const auto *p=static_cast<const uint8_t *>(record);
    const auto u16=[p](size_t at)->uint16_t{return uint16_t(p[at])|(uint16_t(p[at+1])<<8);};
    const auto u32=[p](size_t at)->uint32_t{return uint32_t(p[at])|(uint32_t(p[at+1])<<8)|
        (uint32_t(p[at+2])<<16)|(uint32_t(p[at+3])<<24);};
    const uint32_t length=u32(4),cipher=u32(8);
    const uint16_t flags=u16(12),index=u16(14);
    // Apple cipher2 is WEP104, not the WMI TKIP cipher2. WMI uses cipher1
    // for both WEP lengths. Empty/removal requests need a separate contract.
    if(u32(0)!=1 || !((cipher==1 && length==5)||(cipher==2 && length==13)) ||
       index>3 || (flags!=1 && flags!=2 && flags!=5 && flags!=9) ||
       u32(80) || u32(100) || u32(120))return false;
    // The recovered system producer has no RSC/WoW payload for WEP. Ignore
    // unused backing bytes, but reject advertised extensions we cannot own.
    bool zero=true,broadcast=true,same=true;
    for(unsigned i=0;i<6;++i){zero&=p[92+i]==0;broadcast&=p[92+i]==255;same&=p[92+i]==currentPeer[i];}
    if(!zero && !broadcast && !same)return false;
    out.key=p+16;out.length=uint8_t(length);out.index=uint8_t(index);out.flags=flags;
    out.group=flags==2;out.transmit=(flags&4)!=0;
    return true;
}
}

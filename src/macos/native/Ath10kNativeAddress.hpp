#pragma once

namespace AthNative {
// Sequoia 24G90: fixed ioctl records, no version prefix. IPv6 begins with
// a little-endian count followed by up to ten 16-byte addresses.
struct IPv4Params { UInt8 bytes[16]; };
struct IPv6Params { UInt8 bytes[164]; };
static_assert(sizeof(IPv4Params)==16 && sizeof(IPv6Params)==164,"address ABI");
inline bool copyIPv4Params(const void *input,size_t length,IPv4Params &out) {
    if(!input || length!=sizeof(out))return false;
    const auto p=static_cast<const UInt8 *>(input);
    IPv4Params next{};
    for(size_t i=0;i<14;++i)next.bytes[i]=p[i]; // trailing ABI padding is not data
    out=next;return true;
}
inline bool copyIPv6Params(const void *input,size_t length,IPv6Params &out) {
    if(!input || length!=sizeof(out))return false;
    const auto p=static_cast<const UInt8 *>(input);
    const UInt32 count=UInt32(p[0])|(UInt32(p[1])<<8)|(UInt32(p[2])<<16)|(UInt32(p[3])<<24);
    if(count>10)return false;
    IPv6Params next{};
    for(size_t i=0;i<4+size_t(count)*16;++i)next.bytes[i]=p[i];
    out=next;return true;
}
// Legacy records carry a leading version word. ARP's next word controls
// local-address replacement, not radio enable. Gateway/MAC always update.
inline bool translateARPParams(const void *input,size_t length,const void *previous,IPv4Params &out) {
    if(!input || length!=24 || !previous)return false;
    const auto p=static_cast<const UInt8 *>(input);
    const auto old=static_cast<const UInt8 *>(previous);
    IPv4Params next{};
    const bool replace=p[4] || p[5] || p[6] || p[7];
    for(size_t i=0;i<4;++i)next.bytes[i]=replace?p[8+i]:old[i];
    for(size_t i=0;i<4;++i)next.bytes[4+i]=p[12+i];
    for(size_t i=0;i<6;++i)next.bytes[8+i]=p[16+i];
    // BCM's IPv4 notification clears gateway only when replacing with zero.
    if(replace && !(next.bytes[0]|next.bytes[1]|next.bytes[2]|next.bytes[3]))
        for(size_t i=4;i<8;++i)next.bytes[i]=0;
    out=next;return true;
}
inline bool translateNDPParams(const void *input,size_t length,IPv6Params &out) {
    if(!input || length!=72)return false;
    const auto p=static_cast<const UInt8 *>(input);
    const UInt32 count=UInt32(p[4])|(UInt32(p[5])<<8)|(UInt32(p[6])<<16)|(UInt32(p[7])<<24);
    if(count>4)return false;
    IPv6Params next{};next.bytes[0]=UInt8(count);
    for(size_t i=0;i<size_t(count)*16;++i)next.bytes[4+i]=p[8+i];
    out=next;return true;
}
} // namespace AthNative

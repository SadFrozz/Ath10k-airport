#pragma once
#include "../Ath10kBSS.hpp"
#include "../Ath10kScanPlan.hpp"
#include <WCL.hpp>
#include <string.h>
// Keep wire decoding separate from implemented authentication. In particular,
// a 64-byte password slot is not a 32-byte PMK and must never be truncated.
enum class NativeJoinAuth { Unsupported, Open, PSK, PSKSHA256 };
inline NativeJoinAuth nativeJoinAuth(const AirportWCL::JoinRequest &join){
    if(join.lowerAuth!=1)return NativeJoinAuth::Unsupported;
    if(!join.upperAuth && !join.keyLength)return NativeJoinAuth::Open;
    if(join.keyLength!=32 || (join.keyCipher!=6 && join.keyCipher!=7))return NativeJoinAuth::Unsupported;
    if(join.upperAuth==(1u<<3))return NativeJoinAuth::PSK;
    if(join.upperAuth==(1u<<10))return NativeJoinAuth::PSKSHA256;
    // SAE/FT-SAE, enterprise and mixed requests remain unsupported until their
    // complete authentication/protection paths exist. Never downgrade an AKM.
    return NativeJoinAuth::Unsupported;
}
// Confirmed against Sequoia channelFlagsFromIEEEOperatingClass: 83=0x20c,
// 84=0x0c, 116=0x214, 117=0x14, 119=0x314, 120=0x114, 128=0x410.
// Add known DFS for the actual primary channel; an 80MHz operating class alone
// cannot identify DFS. This describes the configured home channel, not a scan hop.
inline UInt32 nativeChannelFlags(UInt32 primary,UInt32 center,UInt32 width) {
    if(!Ath10k::channelDefinitionAllowed(primary,center,width,true))return 0;
    UInt32 flags=primary<=14?0x8u:0x10u;
    flags|=width==80?0x400u:(width==40?0x4u:0x2u);
    if(width==40 && center>primary)flags|=0x200u;
    if(Ath10k::channelNeedsDFS(primary))flags|=0x100u;
    return flags;
}
// Sequoia's BEACON_INFO is a length followed by the actual received 802.11
// beacon. Keep its TSF intact: rebuilding it from cached IEs would invent
// freshness and hide a dead association from WCL.
inline bool nativeBeaconInfo(const UInt8 *frame,size_t length,void *out,size_t capacity) {
    if(!frame || !out || capacity<0x808 || length<36 || length>0x800 ||
       (frame[0]&0xfc)!=0x80 || !AirportWCL::validIEs(frame+36,length-36))return false;
    auto bytes=static_cast<UInt8 *>(out);bzero(bytes,0x808);
    Ath10k::htcWriteLE32(bytes,static_cast<uint32_t>(length));
    bcopy(frame,bytes+4,length);return true;
}

// Fixed Sequoia 15.2+ ABI. Tahoe uses a different extended-BSS layout.
struct NativeExtendedBSSInput {
    const UInt8 *rates=nullptr,*htRates=nullptr,*rsn=nullptr;
    size_t rateCount=0,htRateCount=0,rsnLength=0;
    UInt16 vhtMap=0xffff;
};
inline bool nativeExtendedBSS(const NativeExtendedBSSInput &in,void *out,size_t capacity) {
    if(!out || capacity<0x1e0 || !in.rates || !in.rateCount || in.rateCount>32 ||
       in.htRateCount>16 || (in.htRateCount && !in.htRates) ||
       in.rsnLength>257 || (in.rsnLength && (!in.rsn ||
       in.rsn[0]!=48 || in.rsnLength<2 || in.rsnLength!=size_t(in.rsn[1])+2 ||
       !AirportWCL::validIEs(in.rsn,in.rsnLength))))return false;
    for(size_t i=0;i<in.htRateCount;++i)if(in.htRates[i]>=96)return false;
    auto bytes=static_cast<UInt8 *>(out);bzero(bytes,0x1e0);
    Ath10k::htcWriteLE32(bytes,1);
    // apple80211_rate_set_data has 15 entries (12 bytes each).
    const size_t count=in.rateCount<15?in.rateCount:15;
    bytes[4]=static_cast<UInt8>(count);
    for(size_t i=0;i<count;++i){
        Ath10k::htcWriteLE32(bytes+8+12*i,1);
        Ath10k::htcWriteLE32(bytes+12+12*i,in.rates[i]);
    }
    Ath10k::htcWriteLE32(bytes+0xbc,1);
    for(size_t i=0;i<in.htRateCount;++i)bytes[0xc0+in.htRates[i]/8]|=1u<<(in.htRates[i]%8);
    Ath10k::htcWriteLE32(bytes+0xcc,1);bytes[0xd0]=in.vhtMap&255;bytes[0xd1]=in.vhtMap>>8;
    // HE is unavailable on QCA9377. Never advertise a fabricated HE MCS map.
    Ath10k::htcWriteLE32(bytes+0xd4,1);bytes[0xd8]=bytes[0xd9]=0xff;
    if(in.rsnLength)bcopy(in.rsn,bytes+0xdd,in.rsnLength);
    return true;
}
// Shared by the real adapter and sanitizer-backed host tests.
inline bool nativeScanMatches(const AirportWCL::ScanRequest &scan,const Ath10k::WMIBSS &b) {
    unsigned channel=b.advertisedChannel?b.advertisedChannel:b.rxChannel;
    if(scan.ssidLength>32 || b.ssidLength>32)return false;
    if(!AirportWCL::scanChannelSelected(scan.channels,scan.channelCount!=0,channel))return false;
    if(scan.ssidLength && (scan.ssidLength!=b.ssidLength || memcmp(scan.ssid,b.ssid,b.ssidLength)))return false;
    UInt8 any=0,notBroadcast=0;
    for(auto byte:scan.bssid){any|=byte;notBroadcast|=UInt8(byte^0xff);}
    return !any || !notBroadcast || memcmp(scan.bssid,b.bssid,6)==0;
}
inline size_t nativeBSSMessage(const Ath10k::WMIBSS &b,UInt8 *buffer,size_t capacity) {
    if(!buffer || b.ssidLength>sizeof(b.ssid) || b.rateCount>sizeof(b.rates) ||
       b.rsnLength>sizeof(b.rsn) || b.countryLength>sizeof(b.country))return 0;
    if(b.rsnLength && !AirportWCL::validIEs(b.rsn,b.rsnLength))return 0;
    if(capacity<sizeof(AirportWCL::BeaconMetadata)+800)return 0;
    auto m=reinterpret_cast<AirportWCL::BeaconMetadata *>(buffer);bzero(m,sizeof(*m));
    unsigned ch=b.advertisedChannel?b.advertisedChannel:b.rxChannel;
    m->channel=ch;m->channelSpec=UInt16(ch|(ch<=14?0x1000:0xd000));
    m->ssidLength=b.ssidLength;bcopy(b.ssid,m->ssid,b.ssidLength);bcopy(b.bssid,m->bssid,6);
    m->rssi=int32_t(b.snr)-95;m->interval=b.beaconInterval;m->capability=b.capabilities;
    // Visible names are parsed from the SSID IE. A metadata name override
    // is reserved for hidden advertisements.
    m->flags=AirportWCL::RSSIValid|(b.hidden?AirportWCL::SSIDPresent:0);
    UInt8 *out=buffer+sizeof(*m);size_t bytes=0;
    auto ie=[&](UInt8 id,const UInt8 *data,size_t length){out[bytes++]=id;out[bytes++]=length;bcopy(data,out+bytes,length);bytes+=length;};
    ie(0,b.ssid,b.ssidLength);ie(1,b.rates,b.rateCount>8?8:b.rateCount);
    if(b.rateCount>8)ie(50,b.rates+8,b.rateCount-8);
    UInt8 channel=ch;ie(3,&channel,1);
    if(b.rsnLength){bcopy(b.rsn,out+bytes,b.rsnLength);bytes+=b.rsnLength;}
    if(b.htPresent)ie(45,b.ht,26);if(b.htOperation)ie(61,b.htOp,22);
    if(b.vhtPresent)ie(191,b.vht,12);if(b.vhtOperation)ie(192,b.vhtOp,5);
    if(b.countryPresent)ie(7,b.country,b.countryLength);
    // Keep the original RSN advertisement intact. Unsupported WPA3/PMF joins
    // are explicitly rejected rather than rewriting the AP's security policy.
    m->ieLength=bytes;return sizeof(*m)+bytes;
}

// Both WCL channel queries use the same physical plan and regulatory limits.
inline bool nativeWCLChannels(const Ath10k::RegulatoryPolicy &policy,AirportWCL::ChannelInfo &out) {
    memset(&out,0,sizeof(out));
    if(policy.country)memcpy(out.country,policy.country->alpha2,2);
    for(const auto &physical:Ath10k::kWMIScanPlan){
        const unsigned ch=physical.channel;
        if(!Ath10k::regulatoryPower(policy,ch,ch,20,false))continue;
        auto &entry=out.channels[out.count++];
        entry.channel=ch;entry.channelSpec=uint16_t(ch|(ch>14?0xd000:0x1000));
        entry.flags=4|((ch>=52 && ch<=144)?2:0); // All scans are passive.
    }
    return out.count!=0;
}

// No low-latency/P2P session is implemented. WCL's query is a four-byte
// session mask, not a request to enable an unsupported offload.
inline bool nativeLowLatencySessions(void *out,size_t capacity) {
    if(!out || capacity<4)return false;
    memset(out,0,4);return true;
}

inline UInt32 nativeScanDwellBudget(UInt32 maximumAwayMs){
    return maximumAwayMs && maximumAwayMs<120?maximumAwayMs:120;
}

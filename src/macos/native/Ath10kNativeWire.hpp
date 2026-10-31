#pragma once
#include "../../security/Ath10kPSKPassword.hpp"
#include "../../core/Ath10kBSS.hpp"
#include "../../core/Ath10kScanPlan.hpp"
#include "../abi/Ath10kNativeTarget.hpp"
#include <WCL.hpp>
static_assert(sizeof(AirportWCL::BeaconMetadata)==0x40, "Sequoia beacon ABI must precede WCL declarations");
static_assert(offsetof(AirportWCL::BeaconMetadata,flags)==0x3c, "Sequoia beacon flags offset");
#include <string.h>
// Keep wire decoding separate from implemented authentication. In particular,
// a 64-byte password slot is not a 32-byte PMK and must never be truncated.
enum class NativeJoinAuth { Unsupported, Open, PSK, PSKSHA256, SAE, EAP, WPA1PSK, WPA1EAP, WEPOpen, WEPShared, OWE, EAPSHA256 };
// WFA Transition Disable bitmap. Stock WCL forwards bits 0..4 unchanged;
// bit 4 has not been identified for this ABI and cannot be silently ignored.
namespace NativeTransitionDisable {
constexpr uint8_t Personal=1,SAEPK=2,Enterprise=4,EnhancedOpen=8,Known=15;
}
inline bool nativeJoinPolicyKnown(const AirportWCL::JoinRequest &join){
    // Stock authtypeupper2str(0,1) names OWE. It is not plaintext Open.
    return !join.upperAuthExt && !(join.transitionDisable&~NativeTransitionDisable::Known);
}
// Decode the stock static-WEP envelope independently of admission. The
// Apple80211 producer uses lower auth1/2 (Open System/Shared Key), upper0,
// cipher1/2 with5/13 bytes and combined unicast/multicast/TX/RX flags0xf.
// A decoded request still needs authentication, firmware keys and port barriers.
struct NativeWEPJoinView {
    const uint8_t *key=nullptr;
    uint8_t length=0,index=0;
    bool shared=false;
};
inline bool nativeWEPJoinEnvelope(const AirportWCL::JoinRequest &join,NativeWEPJoinView &out){
    out={};
    if((join.lowerAuth!=1 && join.lowerAuth!=2) || join.upperAuth ||
       !nativeJoinPolicyKnown(join) || join.transitionDisable || join.rsnLength ||
       join.keyFlags!=15 || join.keyIndex>3 || !join.ssidLength ||
       join.ssidLength>sizeof(join.ssid) || (join.bssid[0]&1) ||
       !((join.keyCipher==1 && join.keyLength==5) ||
         (join.keyCipher==2 && join.keyLength==13)))return false;
    uint8_t any=0;for(auto value:join.bssid)any|=value;
    if(!any)return false;
    out.key=join.key;out.length=uint8_t(join.keyLength);out.index=uint8_t(join.keyIndex);
    out.shared=join.lowerAuth==2;return true;
}
inline bool nativeSAEPasswordEnvelope(const AirportWCL::JoinRequest &join);
inline bool nativePSKPasswordEnvelope(const AirportWCL::JoinRequest &join,bool allowWPA1=false){
    if(join.lowerAuth!=1 || !nativeJoinPolicyKnown(join) ||
       (join.transitionDisable&(NativeTransitionDisable::Personal|NativeTransitionDisable::SAEPK)) ||
       (join.upperAuth!=8 && join.upperAuth!=1024 && !(allowWPA1 && join.upperAuth==2)) || join.keyCipher!=10 || join.keyFlags || join.keyIndex ||
       !join.ssidLength || join.ssidLength>sizeof(join.ssid) || join.rsnLength>sizeof(join.rsn) ||
       !AthSecurity::validPSKPassword(join.key,join.keyLength) || (join.bssid[0]&1))return false;
    UInt8 any=0;for(auto value:join.bssid)any|=value;return any!=0;
}
inline bool nativeOWEEnvelope(const AirportWCL::JoinRequest &join){
    UInt8 any=0;for(auto b:join.bssid)any|=b;
    return join.lowerAuth==1 && !join.upperAuth && join.upperAuthExt==1 &&
        !(join.transitionDisable&~NativeTransitionDisable::Known) &&
        !join.keyLength && !join.keyCipher && !join.keyFlags && !join.keyIndex &&
        join.ssidLength && join.ssidLength<=sizeof(join.ssid) && join.rsnLength<=sizeof(join.rsn) &&
        any && !(join.bssid[0]&1);
}
inline NativeJoinAuth nativeJoinAuth(const AirportWCL::JoinRequest &join,bool allowSAE=false,bool allowEAP=false,bool allowWPA1=false,bool allowWEP=false,bool allowOWE=false){
    if(allowOWE && nativeOWEEnvelope(join))return NativeJoinAuth::OWE;
    NativeWEPJoinView wep{};
    if(allowWEP && nativeWEPJoinEnvelope(join,wep))return wep.shared?NativeJoinAuth::WEPShared:NativeJoinAuth::WEPOpen;
    if(join.lowerAuth!=1 || !nativeJoinPolicyKnown(join))return NativeJoinAuth::Unsupported;
    if(allowWPA1 && allowEAP && join.upperAuth==1 && !join.keyLength && !join.keyFlags &&
       !join.keyIndex && !join.keyCipher && !(join.transitionDisable&NativeTransitionDisable::Enterprise))return NativeJoinAuth::WPA1EAP;
    if(allowWPA1 && join.upperAuth==2 && !join.keyFlags && !join.keyIndex &&
       !(join.transitionDisable&(NativeTransitionDisable::Personal|NativeTransitionDisable::SAEPK)) &&
       (nativePSKPasswordEnvelope(join,true) || (join.keyLength==32 && (join.keyCipher==6 || join.keyCipher==7))))return NativeJoinAuth::WPA1PSK;
    // Explicit WPA2-Enterprise profiles: credentials belong to the system EAP
    // client. Never interpret a supplied password/PMK as an enterprise profile.
    // AKM5 is admitted only with CCMP and required PMF downstream, satisfying
    // Enterprise transition-disable; do not mistake it for the legacy AKM1 path.
    if(allowEAP && join.upperAuth==(1u<<11) && !join.keyLength && !join.keyFlags &&
       !join.keyIndex && !join.keyCipher)
        return NativeJoinAuth::EAPSHA256;
    if(allowEAP && join.upperAuth==(1u<<2) && !join.keyLength && !join.keyFlags &&
       !join.keyIndex && !join.keyCipher && !(join.transitionDisable&NativeTransitionDisable::Enterprise))
        return NativeJoinAuth::EAP;
    if(allowSAE && nativeSAEPasswordEnvelope(join) && !join.keyFlags && !join.keyIndex)return NativeJoinAuth::SAE;
    if(!join.upperAuth && !join.keyLength){
        if(join.keyCipher==1 || join.keyCipher==2)return NativeJoinAuth::Unsupported;
        if(join.transitionDisable&NativeTransitionDisable::EnhancedOpen)return NativeJoinAuth::Unsupported;
        return NativeJoinAuth::Open;
    }
    if(join.transitionDisable&(NativeTransitionDisable::Personal|NativeTransitionDisable::SAEPK))return NativeJoinAuth::Unsupported;
    if(nativePSKPasswordEnvelope(join))return join.upperAuth==8?NativeJoinAuth::PSK:NativeJoinAuth::PSKSHA256;
    if(join.keyLength!=32 || (join.keyCipher!=6 && join.keyCipher!=7))return NativeJoinAuth::Unsupported;
    if(join.upperAuth==(1u<<3))return NativeJoinAuth::PSK;
    if(join.upperAuth==(1u<<10))return NativeJoinAuth::PSKSHA256;
    // FT-SAE, enterprise and mixed requests are not admitted. SAE requires the
    // explicit experimental path above. Never downgrade an AKM.
    return NativeJoinAuth::Unsupported;
}
// Selected association RSNE is independent of the PMK/password cipher field.
// Empty override preserves the currently supported CCMP default. A nonempty
// request must select one suite/AKM; an AP multi-suite list is not a selection.
struct NativeSelectedRSN {uint8_t pairwise=AthSecurity::cipherCCMP,group=0;bool specified=false,legacy=false,wpa1=false;};
inline bool nativeSelectedRSN(const AirportWCL::JoinRequest &join,NativeJoinAuth auth,
    NativeSelectedRSN &out,bool allowLegacy=false,bool allowWPA1=false){
    if(auth==NativeJoinAuth::WEPOpen || auth==NativeJoinAuth::WEPShared){
        NativeWEPJoinView wep{};
        if(!allowLegacy || !nativeWEPJoinEnvelope(join,wep) || wep.shared!=(auth==NativeJoinAuth::WEPShared))return false;
        NativeSelectedRSN selected{};selected.pairwise=selected.group=wep.length==5?1:5;
        selected.legacy=true;out=selected;return true;
    }
    if(auth==NativeJoinAuth::OWE){
        if(!nativeOWEEnvelope(join))return false;
        NativeSelectedRSN selected{};
        if(join.rsnLength){AthSecurity::RSNInfo info{};
            if(!AthSecurity::validOWEPersonalRSN(join.rsn,join.rsnLength) ||
               !AthSecurity::parseRSN(join.rsn,join.rsnLength,info) || info.akms!=(1u<<18) || info.pairwise!=(1u<<4) || info.pmkidCount)return false;
            selected.group=4;selected.specified=true;
        }
        out=selected;return true;
    }
    if(join.lowerAuth!=1 || !nativeJoinPolicyKnown(join) || join.rsnLength>sizeof(join.rsn))return false;
    if(auth==NativeJoinAuth::WPA1PSK || auth==NativeJoinAuth::WPA1EAP){
        const bool eap=auth==NativeJoinAuth::WPA1EAP;
        if(!allowWPA1 || join.upperAuth!=(eap?1u:2u) ||
           (join.transitionDisable&(eap?NativeTransitionDisable::Enterprise:(NativeTransitionDisable::Personal|NativeTransitionDisable::SAEPK))))return false;
        NativeSelectedRSN selected{};selected.pairwise=2;selected.legacy=selected.wpa1=true;
        if(join.rsnLength){
            AthSecurity::WPAInfo info{};uint8_t encoded[24]{};size_t n=0;
            if(!AthSecurity::parseWPA(join.rsn,join.rsnLength,info) || join.rsnLength<24 ||
               AthSecurity::rsnLE16(join.rsn+12)!=1 || AthSecurity::rsnLE16(join.rsn+18)!=1 ||
               !AthSecurity::buildWPA1StationIE(join.rsn,join.rsnLength,join.rsn[17],eap?1:2,encoded,sizeof(encoded),n) ||
               info.akms!=(1u<<(eap?1:2)))return false;
            selected.pairwise=join.rsn[17];selected.group=info.group;selected.specified=true;
        }
        out=selected;return true;
    }
    const uint32_t upper=auth==NativeJoinAuth::Open?0:auth==NativeJoinAuth::PSK?8:
        auth==NativeJoinAuth::PSKSHA256?1024:auth==NativeJoinAuth::SAE?4096:auth==NativeJoinAuth::EAP?4:auth==NativeJoinAuth::EAPSHA256?2048:~uint32_t(0);
    if(auth==NativeJoinAuth::Unsupported || join.upperAuth!=upper)return false;
    NativeSelectedRSN selected{};
    if(!join.rsnLength){out=selected;return true;}
    if(auth==NativeJoinAuth::Open)return false;
    AthSecurity::RSNInfo info{};
    if(!AthSecurity::parseRSN(join.rsn,join.rsnLength,info) ||
       AthSecurity::rsnLE16(join.rsn+8)!=1 || AthSecurity::rsnLE16(join.rsn+14)!=1)return false;
    const uint8_t pair=join.rsn[13],akm=auth==NativeJoinAuth::EAPSHA256?5:auth==NativeJoinAuth::EAP?1:auth==NativeJoinAuth::SAE?8:auth==NativeJoinAuth::PSKSHA256?6:2;
    if((pair!=2 && pair!=4) || info.pairwise!=(1u<<pair) || info.akms!=(1u<<akm))return false;
    if(auth==NativeJoinAuth::EAPSHA256){if(pair!=4 || !AthSecurity::validEAPSHA256RSN(join.rsn,join.rsnLength) || info.pmkidCount)return false;}
    else if(auth==NativeJoinAuth::SAE){if(pair!=4 || !AthSecurity::validSAEPersonalRSN(join.rsn,join.rsnLength))return false;}
    else if(!AthSecurity::supportsSelectedRSN(join.rsn,join.rsnLength,akm,pair,allowLegacy))return false;
    selected.pairwise=pair;selected.group=info.group;selected.specified=true;
    selected.legacy=pair==2 || (auth==NativeJoinAuth::EAP && info.group==2);
    out=selected;return true;
}
// A bounded password-shaped request; admission also checks owners and AP policy.
// Sequoia ciphertype2str maps 10 to CIPHER_PWD, distinct from PMK (6).
inline bool nativeSAEPasswordEnvelope(const AirportWCL::JoinRequest &join){
    if(join.lowerAuth!=1 || !nativeJoinPolicyKnown(join) || (join.transitionDisable&NativeTransitionDisable::SAEPK) ||
       join.upperAuth!=(1u<<12) || join.keyCipher!=10 ||
       !join.keyLength || join.keyLength>sizeof(join.key) || !join.ssidLength ||
       join.ssidLength>sizeof(join.ssid) || join.rsnLength>sizeof(join.rsn) || (join.bssid[0]&1))return false;
    UInt8 any=0;for(auto value:join.bssid)any|=value;return any!=0;
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
    if(scan.ssidLength>32 || b.ssidLength>32 || scan.ssids.count>10)return false;
    if(!AirportWCL::scanChannelSelected(scan.channels,scan.channelCount!=0,channel))return false;
    if(scan.ssidLength && (scan.ssidLength!=b.ssidLength || memcmp(scan.ssid,b.ssid,b.ssidLength)))return false;
    if(scan.ssids.count){
        bool matched=false;
        for(unsigned i=0;i<scan.ssids.count;++i){
            const auto &ssid=scan.ssids.entries[i];
            if(ssid.length>32 || ssid.version>1)return false;
            // Empty SSID is the broadcast probe; retain other BSS observations.
            if(!ssid.length || (ssid.length==b.ssidLength && !memcmp(ssid.bytes,b.ssid,b.ssidLength)))matched=true;
        }
        if(!matched)return false;
    }
    UInt8 any=0,notBroadcast=0;
    for(auto byte:scan.bssid){any|=byte;notBroadcast|=UInt8(byte^0xff);}
    return !any || !notBroadcast || memcmp(scan.bssid,b.bssid,6)==0;
}
inline size_t nativeBSSMessage(const Ath10k::WMIBSS &b,UInt8 *buffer,size_t capacity) {
    if(!buffer || b.ssidLength>sizeof(b.ssid) || b.rateCount>sizeof(b.rates) ||
       b.oweTransitionLength>sizeof(b.oweTransition) || b.rsnLength>sizeof(b.rsn) || b.wpaLength>sizeof(b.wpa) || b.rsnxeLength>sizeof(b.rsnxe) || b.countryLength>sizeof(b.country))return 0;
    if(b.rsnLength && !AirportWCL::validIEs(b.rsn,b.rsnLength))return 0;
    if(b.rsnxeLength && !AthSecurity::validRSNXE(b.rsnxe,b.rsnxeLength))return 0;
    if(b.wpaLength && (b.wpaLength<6 || b.wpa[0]!=221 ||
       size_t(b.wpa[1])+2!=b.wpaLength || b.wpa[2]!=0 || b.wpa[3]!=0x50 ||
       b.wpa[4]!=0xf2 || b.wpa[5]!=1))return 0;
    if(b.oweTransitionLength && (b.oweTransitionLength<6 || b.oweTransition[0]!=221 ||
       size_t(b.oweTransition[1])+2!=b.oweTransitionLength || b.oweTransition[2]!=0x50 ||
       b.oweTransition[3]!=0x6f || b.oweTransition[4]!=0x9a || b.oweTransition[5]!=0x1c))return 0;
    // Preflight the entire advertisement before writing any bytes. WPA and
    // RSN may coexist; neither may disappear because the other is present.
    const size_t ieBytes=2+b.ssidLength+2+b.rateCount+(b.rateCount>8?2:0)+3+
        b.rsnLength+b.wpaLength+b.oweTransitionLength+b.rsnxeLength+(b.htPresent?28:0)+
        (b.htOperation?24:0)+(b.vhtPresent?14:0)+(b.vhtOperation?7:0)+
        (b.countryPresent?2+b.countryLength:0);
    if(capacity<sizeof(AirportWCL::BeaconMetadata) ||
       ieBytes>capacity-sizeof(AirportWCL::BeaconMetadata))return 0;
    // The byte buffer may be unaligned inside Connection/Native objects.
    AirportWCL::BeaconMetadata metadata{};auto m=&metadata;
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
    if(b.wpaLength){bcopy(b.wpa,out+bytes,b.wpaLength);bytes+=b.wpaLength;}
    if(b.oweTransitionLength){bcopy(b.oweTransition,out+bytes,b.oweTransitionLength);bytes+=b.oweTransitionLength;}
    if(b.rsnxeLength){bcopy(b.rsnxe,out+bytes,b.rsnxeLength);bytes+=b.rsnxeLength;}
    if(b.htPresent)ie(45,b.ht,26);if(b.htOperation)ie(61,b.htOp,22);
    if(b.vhtPresent)ie(191,b.vht,12);if(b.vhtOperation)ie(192,b.vhtOp,5);
    if(b.countryPresent)ie(7,b.country,b.countryLength);
    // Keep the original RSN advertisement intact. Unsupported WPA3/PMF joins
    // are explicitly rejected rather than rewriting the AP's security policy.
    m->ieLength=bytes;bcopy(m,buffer,sizeof(*m));return sizeof(*m)+bytes;
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

// Sequoia WCL request shape recovered from sendReassocCommand and its ten
// direct producers. This decoder does not imply a working roaming backend.
struct NativeReassocRequest {
    UInt16 channels[50]{};UInt32 channelCount=0;
    UInt8 bssid[6]{},additionalBSSIDs[6][6]{};UInt32 bssidCount=1;
    // Bit0 follows WCL 6GHz channel filtering; it is not a force-roam bit.
    UInt8 flags=0,ssid[32]{},ssidLength=0;
};
inline bool nativeDecodeReassoc(const void *data,size_t bytes,NativeReassocRequest &out){
    if(!data || bytes!=0xbc)return false;
    const auto *p=static_cast<const UInt8 *>(data);
    const UInt32 count=AirportWCL::read32(p+0x94);
    // Stock V3 consumer copies up to seven six-byte BSSIDs from +0x64.
    // Reject overlong/empty lists rather than silently truncating requests.
    const UInt32 bssids=AirportWCL::read32(p+0x90);
    if(!bssids || bssids>7 || count>50 || p[0xb9]>32 || (p[0x98]&~1u))return false;
    NativeReassocRequest decoded{};decoded.channelCount=count;
    for(UInt32 i=0;i<count;++i)decoded.channels[i]=Ath10k::htcReadLE16(p+2*i);
    decoded.bssidCount=bssids;
    for(UInt32 target=0;target<bssids;++target){
        auto address=target?decoded.additionalBSSIDs[target-1]:decoded.bssid;
        for(UInt32 i=0;i<6;++i)address[i]=p[0x64+6*target+i];
    }
    decoded.flags=p[0x98];decoded.ssidLength=p[0xb9];
    for(UInt32 i=0;i<decoded.ssidLength;++i)decoded.ssid[i]=p[0x99+i];
    out=decoded;return true;
}

// Sequoia ChanSpecGetPrimaryChannel representation normalization. This is
// deliberately NOT a regulatory/channel-validity check.
inline UInt8 nativePrimaryChannel(UInt16 spec){
    const unsigned index=(spec>>11)&7;
    unsigned center=spec&255;
    const unsigned widths[]={5,10,20,40,80,160,160};
    if(index==7 || !center || widths[index]<20)return static_cast<UInt8>(center);
    unsigned width=widths[index];
    if((spec&0xc000)==0xc000 && index==6 && center<=5){
        const unsigned centers[]={42,58,106,122,138,155};
        center=centers[center];width=80;
    }
    const int low=int(center)-int(width/10)+2;
    const int primary=low+4*((spec>>8)&7);
    if(low<0 || low>255 || primary>255)return 0;
    return static_cast<UInt8>(primary);
}
inline bool nativeChannelSpecsMatch(UInt16 a,UInt16 b){
    return (a&0xc000)==(b&0xc000) && nativePrimaryChannel(a)==nativePrimaryChannel(b);
}
inline bool nativeReassocChannelMatches(const NativeReassocRequest &request,UInt16 candidate){
    if(request.channelCount>50)return false;
    if(!request.channelCount)return true;
    for(UInt32 i=0;i<request.channelCount;++i)
        if(nativeChannelSpecsMatch(request.channels[i],candidate))return true;
    return false;
}

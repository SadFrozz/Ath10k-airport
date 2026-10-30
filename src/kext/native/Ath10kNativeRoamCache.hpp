#pragma once
#include "../Ath10kWMI.hpp"
#include "../Ath10kRegulatory.hpp"
#include <string.h>
namespace AthNative {
// Recovered 24G90 command 0x1af envelope. This decodes policy, not firmware
// channel support: callers must validate entries before committing a request.
struct RoamCacheChannel { UInt32 version=0,channel=0,flags=0; };
struct RoamCacheRequest {
    RoamCacheChannel channels[10]{};
    UInt16 count=0;
    bool overrideEnabled=false,clear=false,updateOverride=false,readChannels=false,readOverride=false;
};
inline bool decodeRoamCache(const void *data,size_t bytes,RoamCacheRequest &out){
    if(!data || bytes!=128)return false;
    const auto p=static_cast<const UInt8 *>(data);
    const UInt16 count=Ath10k::htcReadLE16(p+0x78);
    if(count>10 || p[0x7f])return false;
    for(unsigned i=0x7a;i<=0x7e;++i)if(p[i]>1)return false;
    RoamCacheRequest request{};request.count=count;
    request.overrideEnabled=p[0x7a];request.clear=p[0x7b];request.updateOverride=p[0x7c];
    request.readChannels=p[0x7d];request.readOverride=p[0x7e];
    for(unsigned i=0;i<count;++i){
        request.channels[i]={Ath10k::wmiReadLE32(p+12*i),Ath10k::wmiReadLE32(p+12*i+4),Ath10k::wmiReadLE32(p+12*i+8)};
    }
    out=request;return true;
}
inline bool validRoamCacheChannel(const Ath10k::RegulatoryPolicy &policy,const RoamCacheChannel &entry){
    const UInt32 primary=entry.channel,flags=entry.flags;
    if(entry.version>1 || !Ath10k::wmiScanChannelAllowed(primary) || (flags&~0x7ffu) ||
       (flags&0x18u)!=(primary<=14?0x8u:0x10u))return false;
    const UInt32 widthBits=flags&0x407u;
    const UInt32 width=widthBits==2?20:widthBits==4?40:widthBits==0x400?80:0;
    if(!width || ((flags&0x200u) && width!=40))return false;
    UInt32 center=primary;
    if(width==40){if(!(flags&0x200u) && primary<3)return false;center=(flags&0x200u)?primary+2:primary-2;}
    if(width==80){
        center=0;const UInt32 centers[]={42,58,106,122,138,155};
        for(auto candidate:centers)if(Ath10k::channelDefinitionAllowed(primary,candidate,80,true)){center=candidate;break;}
    }
    return center && Ath10k::channelDefinitionAllowed(primary,center,width,true) &&
        Ath10k::regulatoryPower(policy,primary,center,width,false)!=0;
}
// Radio-gated cache state; apply is transactional. The validator must enforce
// supported channel/band/width and regulatory policy, not merely nonzero bytes.
// Roam scan scheduling must consume this policy before its setter is enabled.
class UserRoamCache {
public:
    RoamCacheChannel channels[10]{};
    UInt16 count=0;
    bool overrideEnabled=false;
    void reset(){*this=UserRoamCache{};}
    // Atomic in/out command: validation precedes both state and output changes.
    // Read flags return the resulting state, including mutations in this request.
    template<class Validator> bool exchange(void *data,size_t bytes,Validator valid){
        RoamCacheRequest request{};
        if(count>10 || !decodeRoamCache(data,bytes,request))return false;
        auto next=*this;if(!next.apply(request,valid))return false;
        UInt8 reply[128];memcpy(reply,data,sizeof(reply));
        if(request.readChannels){
            memset(reply,0,120);Ath10k::htcWriteLE16(reply+0x78,next.count);
            for(unsigned i=0;i<next.count;++i){
                Ath10k::htcWriteLE32(reply+12*i,next.channels[i].version);
                Ath10k::htcWriteLE32(reply+12*i+4,next.channels[i].channel);
                Ath10k::htcWriteLE32(reply+12*i+8,next.channels[i].flags);
            }
        }
        if(request.readOverride)reply[0x7a]=next.overrideEnabled;
        *this=next;memcpy(data,reply,sizeof(reply));return true;
    }
    template<class Validator> bool apply(const RoamCacheRequest &request,Validator valid){
        if(request.count>10)return false;
        if(!request.count && !request.clear && !request.updateOverride && !request.readChannels && !request.readOverride)return false;
        for(unsigned i=0;i<request.count;++i)if(!valid(request.channels[i]))return false;
        auto next=*this;
        if(request.count || request.clear){
            for(auto &channel:next.channels)channel={};
            next.count=request.count;
            for(unsigned i=0;i<request.count;++i)next.channels[i]=request.channels[i];
        }
        if(request.updateOverride)next.overrideEnabled=request.overrideEnabled;
        *this=next;return true;
    }
};
}

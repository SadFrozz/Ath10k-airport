#include <cassert>
#include <cstring>
#include <memory>
#include <climits>
#define __MAC_15_2 150200
#define __IO80211_TARGET __MAC_15_2
#include "../src/kext/Ath10kConnection.hpp"
#include "../src/kext/native/Ath10kNativeWire.hpp"
#include "../src/kext/native/Ath10kNativeOps.hpp"
using IOReturn=int;
constexpr int kIOReturnSuccess=0,kIOReturnBadArgument=1,kIOReturnNotReady=2,kIOReturnUnsupported=3;
constexpr unsigned APPLE80211_UNIT_DBM=0;
struct apple80211_channel_data {UInt32 version;struct {UInt32 version,channel,flags;} channel;};
struct apple80211_rssi_data {UInt32 version,num_radios,rssi_unit;int32_t rssi[4],aggregate_rssi,rssi_ext[4],aggregate_rssi_ext;};
struct apple80211_rate_data {UInt32 version,num_radios,rate[4];};
static_assert(sizeof(apple80211_channel_data)==16 && sizeof(apple80211_rssi_data)==52 && sizeof(apple80211_rate_data)==24,"query wire layouts");
class Ath10kPCIDevice {
public:
    Ath10k::ConnectionState _connection{};
    IOReturn nativeLinkMetrics(AthNativeOp,void *);
};
#include "native_link_metrics.inc"
int main(){
    struct Definition {unsigned primary,center,width,flags;};
    // Independent expected Sequoia flags: band, one width, extension-above, DFS.
    const Definition valid[]={
        {1,1,20,0xa},{6,6,20,0xa},
        {1,3,40,0x20c},{5,3,40,0xc},{11,9,40,0xc},
        {36,36,20,0x12},{52,52,20,0x112},
        {36,38,40,0x214},{40,38,40,0x14},
        {52,54,40,0x314},{56,54,40,0x114},
        {36,42,80,0x410},{40,42,80,0x410},{48,42,80,0x410},
        {52,58,80,0x510},{64,58,80,0x510},{149,155,80,0x410},{161,155,80,0x410},
    };
    auto d=std::make_unique<Ath10kPCIDevice>();auto &s=d->_connection;s.stage=Ath10k::LinkStage::Connected;
    for(auto c:valid){
        assert(nativeChannelFlags(c.primary,c.center,c.width)==c.flags);
        s.operatingChannel=c.primary;s.centerChannel=c.center;s.width=c.width;
        struct {apple80211_channel_data reply;UInt32 tail;} out;memset(&out,0xa5,sizeof(out));
        assert(d->nativeLinkMetrics(AthNativeOp::getCHANNEL,&out.reply)==kIOReturnSuccess);
        assert(out.reply.version==1 && out.reply.channel.version==1 && out.reply.channel.channel==c.primary);
        assert(out.reply.channel.flags==c.flags && out.tail==0xa5a5a5a5);
    }
    const Definition invalid[]={{14,14,20,0},{0,0,20,0},{169,169,20,0},{36,38,20,0},{6,6,80,0},{36,44,80,0},
        {40,42,40,0},{165,163,40,0},{36,50,160,0},{14,12,40,0},{36,42,0,0}};
    for(auto c:invalid){
        assert(!nativeChannelFlags(c.primary,c.center,c.width));
        s.operatingChannel=c.primary;s.centerChannel=c.center;s.width=c.width;
        apple80211_channel_data out;memset(&out,0xa5,sizeof(out));
        assert(d->nativeLinkMetrics(AthNativeOp::getCHANNEL,&out)==kIOReturnNotReady);
        for(auto b:reinterpret_cast<const UInt8 (&)[sizeof(out)]>(out))assert(b==0xa5);
    }
    s.operatingChannel=s.centerChannel=6;s.width=20;s.signalDbm=-63;s.fwStats.rateValid=true;s.fwStats.txKbps=866700;
    for(unsigned state=0;state<7;++state){
        s.stage=Ath10k::LinkStage::Connected;s.cancelRequested=false;s.disconnect=Ath10k::DisconnectStage::None;
        s.portAuthorized=false;s.rekeyKind=0;
        if(state==0)s.stage=Ath10k::LinkStage::Disabled;
        if(state==1)s.stage=Ath10k::LinkStage::Failed;
        if(state==2)s.cancelRequested=true;
        if(state==3)s.disconnect=Ath10k::DisconnectStage::Drain;
        if(state==4)s.stage=Ath10k::LinkStage::Scan;
        if(state==5)s.rekeyKind=2;
        if(state==6)s.portAuthorized=true;
        for(auto op:{AthNativeOp::getCHANNEL,AthNativeOp::getRSSI,AthNativeOp::getRATE}){
            UInt8 out[64];memset(out,0xa5,sizeof(out));
            const bool available=state>=5 || (state==4 && op==AthNativeOp::getCHANNEL);
            assert(d->nativeLinkMetrics(op,out)==(available?kIOReturnSuccess:kIOReturnNotReady));
            if(!available)for(auto b:out)assert(b==0xa5);
        }
    }
    apple80211_rssi_data rssi{};assert(d->nativeLinkMetrics(AthNativeOp::getRSSI,&rssi)==kIOReturnSuccess);
    assert(rssi.num_radios==1 && rssi.rssi_unit==0 && rssi.rssi[0]==-63 && rssi.aggregate_rssi==-63);
    s.signalDbm=INT32_MIN;assert(d->nativeLinkMetrics(AthNativeOp::getRSSI,&rssi)==kIOReturnNotReady);
    apple80211_rate_data rate{};assert(d->nativeLinkMetrics(AthNativeOp::getRATE,&rate)==kIOReturnSuccess);
    assert(rate.num_radios==1 && rate.rate[0]==1733 && !rate.rate[1]);
    for(UInt32 kbps:{0u,1u,499u,2000001u}){s.fwStats.txKbps=kbps;assert(d->nativeLinkMetrics(AthNativeOp::getRATE,&rate)==kIOReturnNotReady);}
    s.fwStats.txKbps=54000;s.fwStats.rateValid=false;assert(d->nativeLinkMetrics(AthNativeOp::getRATE,&rate)==kIOReturnNotReady);
    assert(d->nativeLinkMetrics(AthNativeOp::getCHANNEL,nullptr)==kIOReturnBadArgument);
    assert(d->nativeLinkMetrics(AthNativeOp::getTXPOWER,&rate)==kIOReturnUnsupported);
}

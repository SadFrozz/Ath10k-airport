#include <cassert>
#include <cstring>
#include <memory>
#include <climits>
#define __MAC_15_2 150200
#define __IO80211_TARGET __MAC_15_2
#include "../../src/core/Ath10kConnection.hpp"
#include "../../src/macos/native/Ath10kNativeWire.hpp"
#include "../../src/macos/native/Ath10kNativeOps.hpp"
using IOReturn=int;
constexpr int kIOReturnSuccess=0,kIOReturnBadArgument=1,kIOReturnNotReady=2,kIOReturnUnsupported=3;
constexpr int kIO80211NetworkLinkUp=1,kIO80211NetworkLinkDown=0;
struct ether_addr {UInt8 bytes[6];};
struct Interface {
    unsigned addressCalls=0,linkCalls=0;bool hasAP=false,debounced=false;
    UInt8 ap[6]{};int link=-1;UInt32 interval=0;
    void setCurrentApAddress(ether_addr *p){++addressCalls;hasAP=p;if(p)memcpy(ap,p->bytes,6);else memset(ap,0,6);}
    void setLinkState(int value,unsigned reason,bool debounce,UInt32 milliseconds){
        assert(reason==0);++linkCalls;link=value;debounced=debounce;interval=milliseconds;
    }
};
class Ath10kPCIDevice {
public:
    Ath10k::ConnectionState _connection{};
    UInt8 _nativeBSSMessage[1600]{};
    Interface interface;Interface *_nativeInterface=&interface;
    IOReturn nativeCurrentAPInfo(AthNativeOp,void *);
    IOReturn nativeLinkStateUpdate(void *);
};
#include "native_link_state.inc"
static void associated(Ath10kPCIDevice &d){
    auto &s=d._connection;s.stage=Ath10k::LinkStage::Connected;s.operatingChannel=6;
    UInt8 ap[]={2,1,2,3,4,5};memcpy(s.bssid,ap,6);memcpy(s.ap.bssid,ap,6);
    s.ap.ssidLength=4;memcpy(s.ap.ssid,"test",4);s.ap.rateCount=1;s.ap.rates[0]=12;s.ap.rxChannel=6;
    s.beaconFrameBytes=36;s.beaconFrame[0]=0x80;
    memcpy(s.beaconFrame+10,ap,6);memcpy(s.beaconFrame+16,ap,6);
}
int main(){
    using L=Ath10k::LinkStage;using D=Ath10k::DisconnectStage;
    const AthNativeOp queries[]={AthNativeOp::getWCL_BSS_INFO,AthNativeOp::getBEACON_INFO,AthNativeOp::getWCL_EXTENDED_BSS_INFO};
    for(unsigned state=0;state<9;++state){
        auto d=std::make_unique<Ath10kPCIDevice>();associated(*d);auto &s=d->_connection;
        if(state==0)s.stage=L::Disabled;
        if(state==1)s.stage=L::Scan;
        if(state==2)s.stage=L::Assoc;
        if(state==3)s.stage=L::Failed;
        if(state==4)s.cancelRequested=true;
        if(state==5)s.disconnect=D::Drain;
        if(state==6)s.disconnect=D::Barrier;
        if(state==7){s.portAuthorized=false;s.rekeyKind=1;}
        if(state==8)s.portAuthorized=true;
        const bool present=state>=7;
        UInt8 update[16]{};memcpy(update,s.bssid,6);update[6]=update[7]=update[8]=1;
        assert(d->nativeLinkStateUpdate(update)==(present?kIOReturnSuccess:kIOReturnNotReady));
        assert(d->interface.addressCalls==unsigned(present) && d->interface.linkCalls==unsigned(present));
        if(present)assert(d->interface.hasAP && d->interface.link==1 && !memcmp(d->interface.ap,s.bssid,6));
        memset(d->_nativeBSSMessage,0xcc,sizeof(d->_nativeBSSMessage));
        for(auto op:queries){
            UInt8 output[0x900];memset(output,0xa5,sizeof(output));
            assert(d->nativeCurrentAPInfo(op,output)==(present?kIOReturnSuccess:kIOReturnNotReady));
            if(present && op==AthNativeOp::getWCL_BSS_INFO)
                assert(!memcmp(output+offsetof(AirportWCL::BeaconMetadata,bssid),s.bssid,6));
            if(!present)for(auto b:output)assert(b==0xa5); // Rejected queries do not publish stale data.
        }
        // Down remains available even when the old connection has been cleared.
        memset(update,0,sizeof(update));update[12]=250;
        assert(d->nativeLinkStateUpdate(update)==kIOReturnSuccess);
        assert(!d->interface.hasAP && d->interface.link==0 && d->interface.debounced && d->interface.interval==250);
        update[12]=0;assert(d->nativeLinkStateUpdate(update)==kIOReturnSuccess);
        assert(!d->interface.debounced && !d->interface.interval);
    }
    auto d=std::make_unique<Ath10kPCIDevice>();associated(*d);UInt8 update[16]{};
    memcpy(update,d->_connection.bssid,6);update[6]=1;update[0]^=2;
    assert(d->nativeLinkStateUpdate(update)==kIOReturnBadArgument && !d->interface.linkCalls && !d->interface.addressCalls);
    update[0]^=2; // WCL's independent address/link flags are not interchangeable.
    update[8]=1;assert(d->nativeLinkStateUpdate(update)==kIOReturnSuccess);
    assert(d->interface.addressCalls==1 && !d->interface.linkCalls);
    update[8]=0;update[7]=1;assert(d->nativeLinkStateUpdate(update)==kIOReturnSuccess);
    assert(d->interface.addressCalls==1 && d->interface.linkCalls==1);
    // Reassociation ordering: WCL handles link-up by querying current BSS.
    // A queued update for AP A must not overwrite AP B after radio commit,
    // and scan scratch containing AP A must not leak into the queried beacon.
    const auto oldAP=d->_connection.ap;UInt8 oldUpdate[16]{};
    memcpy(oldUpdate,oldAP.bssid,6);oldUpdate[6]=oldUpdate[7]=oldUpdate[8]=1;
    for(UInt8 suffix: {UInt8(9),UInt8(10),UInt8(11)}){
        auto &state=d->_connection;state.ap.bssid[5]=state.bssid[5]=suffix;
        state.operatingChannel=state.ap.rxChannel=11;
        memcpy(state.beaconFrame+10,state.bssid,6);memcpy(state.beaconFrame+16,state.bssid,6);
        assert(nativeBSSMessage(oldAP,d->_nativeBSSMessage,sizeof(d->_nativeBSSMessage)));
        const auto calls=d->interface.linkCalls;
        assert(d->nativeLinkStateUpdate(oldUpdate)==kIOReturnBadArgument);
        assert(d->interface.linkCalls==calls);
        UInt8 bss[0x840]{},beacon[0x808]{};
        assert(d->nativeCurrentAPInfo(AthNativeOp::getWCL_BSS_INFO,bss)==kIOReturnSuccess);
        assert(!memcmp(bss+offsetof(AirportWCL::BeaconMetadata,bssid),state.bssid,6));
        assert(d->nativeCurrentAPInfo(AthNativeOp::getBEACON_INFO,beacon)==kIOReturnSuccess);
        assert(!memcmp(beacon+4+16,state.bssid,6));
        UInt8 newUpdate[16]{};memcpy(newUpdate,state.bssid,6);newUpdate[6]=newUpdate[7]=newUpdate[8]=1;
        assert(d->nativeLinkStateUpdate(newUpdate)==kIOReturnSuccess);
        assert(!memcmp(d->interface.ap,state.bssid,6));
        memcpy(oldUpdate,newUpdate,sizeof(oldUpdate));
    }
    d->_connection.beaconFrameBytes=0;UInt8 output[0x900];memset(output,0xa5,sizeof(output));
    assert(d->nativeCurrentAPInfo(queries[0],output)==kIOReturnNotReady && output[0]==0xa5);
    for(auto op:queries)assert(d->nativeCurrentAPInfo(op,nullptr)==kIOReturnBadArgument);
    assert(d->nativeCurrentAPInfo(AthNativeOp::getRATE,output)==kIOReturnUnsupported);
    assert(d->nativeLinkStateUpdate(nullptr)==kIOReturnBadArgument);
    d->_nativeInterface=nullptr;assert(d->nativeLinkStateUpdate(update)==kIOReturnNotReady);
}

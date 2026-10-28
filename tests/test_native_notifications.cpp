#include <cassert>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>
#include <map>
#include <memory>
#include <climits>
#define __MAC_15_2 150200
#define __IO80211_TARGET __MAC_15_2
#include "../src/kext/native/Ath10kNativeWire.hpp"
#include "../src/kext/Ath10kWMI.hpp"
#include "../src/shared/Ath10kSupplicant.hpp"
using IOReturn=int;using SInt64=int64_t;
constexpr IOReturn kIOReturnSuccess=0,kIOReturnError=1,kIOReturnAborted=2,kIOReturnNoMemory=3;
class Ath10kPCIDevice {
public:
    Ath10k::ConnectionState _connection{};
    Ath10k::WMIScanState _wmiScan{};
    Ath10k::WMIBSSCache _wmiBSS{};
    struct {bool active=true;} _wmiLive;
    AirportWCL::JoinRequest _nativeJoin{};
    AirportWCL::ScanRequest _nativeScan{};
    struct Security {unsigned resets=0;void reset(){++resets;}} security;
    Security *_nativeSecurity=&security;
    void *_nativeInterface=this;
    bool _nativeStarted=true,_nativeStopping=false,_nativeMACActive=false,_nativeMACWaiting=false;
    bool _nativeReadyRequested=false,_nativeReadyPublished=true,_nativeReadyResetSent=false;
    bool _nativeAbortRequested=false,_nativeScanPending=false,_nativeJoinPending=false;
    bool _nativeAssocSent=false,_nativeBeaconSent=false,_nativeJoinBSSSent=false;
    bool _nativeLinkUpSent=false,_nativeWasUp=false,_nativeDeauthSent=false,_nativeJoinFailed=false;
    bool _networkLinkUp=true;
    UInt32 _nativeScanResultIndex=0,_nativeScanResultsEmitted=0,_nativeReportedBeacon=0;
    UInt64 _nativeJoinDeadline=10000,_nativePostFailures=0;
    IOReturn _nativePostError=kIOReturnSuccess;
    int _nativeReportedQuality=-2;
    UInt8 _nativeLastBSSID[6]{},_nativeBSSMessage[1600]{};UInt32 _nativeBSSBytes=0;
    unsigned attempts=0,failAt=0,networkStops=0;bool failAlways=false;
    struct Event {UInt32 id;std::vector<UInt8> data;};
    std::vector<Event> events;
    std::map<std::string,UInt64> properties;
    void setProperty(const char *name,UInt64 value,unsigned){properties[name]=value;}
    void networkLink(bool up){_networkLinkUp=up;if(!up)++networkStops;}
    IOReturn postMessage(void *interface,UInt32 id,void *data,size_t bytes,bool flag){
        assert(interface==this && flag && (data || !bytes));
        if(++attempts==failAt || failAlways)return kIOReturnNoMemory;
        Event e{id,{}};if(bytes)e.data.assign(static_cast<UInt8 *>(data),static_cast<UInt8 *>(data)+bytes);
        events.push_back(e);return kIOReturnSuccess;
    }
    void serviceNativeNotifications(UInt64);
};
#include "native_notifications.inc"
static void connected(Ath10kPCIDevice &d){
    auto &s=d._connection;s.stage=Ath10k::LinkStage::Connected;s.portAuthorized=true;
    s.beaconFrameBytes=36;s.beaconFrameSerial=8;s.signalDbm=-60;
    const UInt8 ap[]={2,0x11,0x22,0x33,0x44,0x55};memcpy(s.bssid,ap,6);
    memcpy(s.ap.bssid,ap,6);s.ap.hidden=false;s.ap.ssidLength=4;memcpy(s.ap.ssid,"test",4);
    s.ap.rateCount=1;s.ap.rates[0]=12;s.ap.rxChannel=52;s.ap.snr=35;
    memcpy(d._nativeJoin.bssid,ap,6);memset(d._nativeJoin.key,0xa5,sizeof(d._nativeJoin.key));
}
static void bootJoin(Ath10kPCIDevice &d){
    connected(d);d._nativeReadyRequested=true;d._nativeReadyPublished=false;
    d._nativeJoinPending=true;d._nativeScanPending=true;
    d._wmiScan.completed=true;d._wmiScan.generation=7;
    d._wmiBSS.count=2;d._wmiBSS.entries[0]=d._connection.ap;d._wmiBSS.entries[1]=d._connection.ap;
    d._wmiBSS.entries[1].bssid[5]=0x66;
}
static std::vector<UInt32> ids(const Ath10kPCIDevice &d){
    std::vector<UInt32> result;for(const auto &e:d.events)result.push_back(e.id);return result;
}
int main(){
    // Independent expected WCL sequence. Every single enqueue can fail once:
    // the exact production notification method must resume without duplicates.
    const std::vector<UInt32> expected={49,55,201,201,237,211,201,216,212,213,39};
    auto baseline=std::make_unique<Ath10kPCIDevice>();bootJoin(*baseline);
    baseline->serviceNativeNotifications(100);assert(ids(*baseline)==expected);
    for(unsigned fail=1;fail<=expected.size();++fail){
        auto d=std::make_unique<Ath10kPCIDevice>();bootJoin(*d);d->failAt=fail;
        d->serviceNativeNotifications(100);
        assert(d->_nativePostError==kIOReturnNoMemory && d->events.size()==fail-1);
        assert(d->_nativePostFailures==1);
        d->failAlways=true;d->serviceNativeNotifications(110);
        assert(d->_nativePostError==kIOReturnNoMemory && d->events.size()==fail-1);
        d->failAlways=false;d->serviceNativeNotifications(120);
        assert(d->_nativePostError==kIOReturnSuccess && ids(*d)==expected);
        for(size_t i=0;i<expected.size();++i)assert(d->events[i].data==baseline->events[i].data);
        assert(d->_nativeReadyPublished && !d->_nativeScanPending && !d->_nativeJoinPending);
        assert(d->_nativeScanResultsEmitted==2 && d->_nativeScanResultIndex==2);
        assert(d->_nativeBeaconSent && d->_nativeLinkUpSent && d->_nativeWasUp);
        assert(d->properties["Ath10kNativeScanDoneGeneration"]==7);
        assert(d->events[4].data.size()==4 && Ath10k::wmiReadLE32(d->events[4].data.data())==0);
        for(auto key:d->_nativeJoin.key)assert(key==0);
        d->serviceNativeNotifications(130);assert(ids(*d)==expected);
    }
    { // Cancellation supersedes only the unsubmitted remainder of scan results.
        auto d=std::make_unique<Ath10kPCIDevice>();bootJoin(*d);
        d->_nativeReadyRequested=false;d->_nativeReadyPublished=true;d->_nativeJoinPending=false;
        d->_connection={};d->_networkLinkUp=false;d->failAt=2;
        d->serviceNativeNotifications(100);assert((ids(*d)==std::vector<UInt32>{201}));
        d->_wmiScan.cancelRequested=true;d->serviceNativeNotifications(110);
        assert((ids(*d)==std::vector<UInt32>{201,237}) && !d->_nativeScanPending);
        assert(Ath10k::wmiReadLE32(d->events.back().data.data())==kIOReturnAborted);
        assert(d->_nativeScanResultsEmitted==1);
    }
    { // Abort completion still retries when the radio timer has stopped.
        auto d=std::make_unique<Ath10kPCIDevice>();d->_networkLinkUp=false;
        d->_wmiLive.active=false;d->_nativeAbortRequested=true;d->failAt=1;
        d->serviceNativeNotifications(100);assert(d->_nativeAbortRequested && d->events.empty());
        d->serviceNativeNotifications(110);assert(!d->_nativeAbortRequested);
        assert((ids(*d)==std::vector<UInt32>{214}));
    }
    { // A deadline cannot both announce success and run failure cleanup.
        auto d=std::make_unique<Ath10kPCIDevice>();connected(*d);d->_nativeJoinPending=true;
        d->_nativeJoinDeadline=100;d->failAt=1;
        d->serviceNativeNotifications(100);
        assert(d->_nativeJoinPending && d->_nativeJoinFailed && d->events.empty());
        assert(!d->_connection.portAuthorized && d->_connection.cancelRequested && !d->_networkLinkUp);
        assert(d->networkStops==1 && d->security.resets==1);
        for(auto key:d->_nativeJoin.key)assert(key==0);
        d->_connection={};d->serviceNativeNotifications(110);
        assert(!d->_nativeJoinPending && d->networkStops==1 && d->security.resets==1);
        assert((ids(*d)==std::vector<UInt32>{213}));
        auto event=reinterpret_cast<const AirportWCL::ConnectionEvent *>(d->events[0].data.data());
        assert(event->status==1 && event->peers[0].bssid[5]==0x55);
    }
    { // Healthy group/pair rekey closes the controlled port, not the association.
        auto d=std::make_unique<Ath10kPCIDevice>();bootJoin(*d);d->serviceNativeNotifications(100);
        d->events.clear();d->_connection.portAuthorized=false;d->_connection.rekeyKind=1;
        d->serviceNativeNotifications(110);assert(d->events.empty() && d->_nativeWasUp);
        d->_connection.rekeyKind=2;d->serviceNativeNotifications(120);
        assert(d->events.empty() && d->_nativeWasUp);
        d->_connection.portAuthorized=true;d->_connection.rekeyKind=0;d->serviceNativeNotifications(130);
        assert(d->events.empty() && !d->security.resets);
        // Real failure during rekey must still report a lost association.
        d->_connection.cancelRequested=true;d->_connection.portAuthorized=false;
        d->_connection.rekeyKind=2;d->serviceNativeNotifications(140);
        assert((ids(*d)==std::vector<UInt32>{203,216}) && !d->_nativeWasUp);
    }
    for(unsigned failDown=1;failDown<=2;++failDown){ // Retain old BSSID after radio reset.
        auto d=std::make_unique<Ath10kPCIDevice>();bootJoin(*d);d->serviceNativeNotifications(100);
        d->events.clear();d->attempts=0;d->failAt=failDown;d->_connection={};d->_networkLinkUp=false;
        d->serviceNativeNotifications(110);
        assert(d->events.size()==failDown-1 && d->_nativeWasUp);
        assert(d->_nativeDeauthSent==(failDown==2));
        d->serviceNativeNotifications(120);
        assert((ids(*d)==std::vector<UInt32>{203,216}) && !d->_nativeWasUp && !d->_nativeLinkUpSent);
        auto link=reinterpret_cast<const AirportWCL::LinkStatusEvent *>(d->events.back().data.data());
        assert(link->bssid[0]==2 && link->bssid[5]==0x55 && !link->up);
        d->serviceNativeNotifications(130);assert(d->events.size()==2);
    }
    { // A partial LinkUp followed by failed join still needs one LinkDown.
        auto d=std::make_unique<Ath10kPCIDevice>();connected(*d);
        d->_nativeJoinPending=true;d->_connection.portAuthorized=false;
        d->serviceNativeNotifications(100);assert(d->_nativeLinkUpSent && !d->_nativeWasUp);
        d->events.clear();d->_connection.cancelRequested=true;d->serviceNativeNotifications(110);
        assert((ids(*d)==std::vector<UInt32>{213,203,216}));
        assert(!d->_nativeJoinPending && !d->_nativeLinkUpSent);
    }
    for(UInt8 subtype:{UInt8(0xc0),UInt8(0xa0)}){ // Real AP reason survives teardown and enqueue failure.
        auto d=std::make_unique<Ath10kPCIDevice>();bootJoin(*d);d->serviceNativeNotifications(100);
        UInt8 frame[26]{};frame[0]=subtype;
        memcpy(frame+4,d->_connection.local,6);memcpy(frame+10,d->_connection.bssid,6);memcpy(frame+16,d->_connection.bssid,6);
        Ath10k::htcWriteLE16(frame+24,15);
        Ath10k::receiveStationManagement(d->_connection,frame,sizeof(frame),0,52);
        assert(d->_connection.apDisconnect.valid && d->_connection.apDisconnect.reason==15);
        // Repeated terminal frames cannot overwrite the first reason/subtype.
        frame[0]=subtype==0xc0?0xa0:0xc0;Ath10k::htcWriteLE16(frame+24,4);
        Ath10k::receiveStationManagement(d->_connection,frame,sizeof(frame),0,52);
        Ath10k::resetDisconnected(d->_connection);d->_networkLinkUp=false;
        d->events.clear();d->attempts=0;d->failAt=1;
        d->serviceNativeNotifications(110);assert(d->events.empty());
        d->serviceNativeNotifications(120);assert((ids(*d)==std::vector<UInt32>{203,216}));
        auto event=reinterpret_cast<const AirportWCL::DeauthEvent *>(d->events[0].data.data());
        assert(event->reason==15 && event->deauthentication==(subtype==0xc0));
        assert(d->events[0].data[8]==15 && d->events[0].data[9]==0);
        assert(d->events[0].data[0x10]==(subtype==0xc0?1:0));
        assert(event->bssid[5]==0x55);
        d->serviceNativeNotifications(130);assert(d->events.size()==2);
    }
    { // Foreign/stale AP metadata must not describe a local disconnect.
        auto d=std::make_unique<Ath10kPCIDevice>();bootJoin(*d);d->serviceNativeNotifications(100);
        d->_connection.apDisconnect.valid=true;d->_connection.apDisconnect.reason=15;
        memset(d->_connection.apDisconnect.bssid,0xaa,6);
        d->_connection.cancelRequested=true;d->_networkLinkUp=false;d->events.clear();
        d->serviceNativeNotifications(110);
        auto event=reinterpret_cast<const AirportWCL::DeauthEvent *>(d->events[0].data.data());
        assert(event->reason==3 && event->deauthentication==1);
    }
    { // Permanent allocation pressure advances no delivery phase and stop is immediate.
        auto d=std::make_unique<Ath10kPCIDevice>();bootJoin(*d);d->failAlways=true;
        for(unsigned n=0;n<200;++n)d->serviceNativeNotifications(100+n*10);
        assert(d->events.empty() && !d->_nativeReadyResetSent && !d->_nativeReadyPublished);
        assert(d->_nativeScanResultIndex==0 && !d->_nativeAssocSent && d->_nativeJoinPending);
        assert(d->_nativePostFailures==200);
        d->_nativeStopping=true;unsigned attempts=d->attempts;
        d->serviceNativeNotifications(2200);assert(d->attempts==attempts);
    }
}

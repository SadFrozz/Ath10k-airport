#include <cassert>
#include "../../src/macos/native/Ath10kNativeEAPOwner.hpp"
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>
#include <map>
#include <memory>
#include <climits>
#define __MAC_15_2 150200
#define __IO80211_TARGET __MAC_15_2
#include "../../src/macos/native/Ath10kNativeWire.hpp"
#include "../../src/macos/native/Ath10kNativeProfile.hpp"
#include "../../src/macos/native/Ath10kNativeRoamEvents.hpp"
#include "../../build/generated/itlwm/Airport/apple80211_ioctl.h"
#include "../../src/core/Ath10kWMI.hpp"
#include "../../src/security/Ath10kSupplicant.hpp"
using IOReturn=int;using SInt64=int64_t;
constexpr IOReturn kIOReturnNotReady=5,kIOReturnBusy=6;
constexpr IOReturn kIOReturnSuccess=0,kIOReturnError=1,kIOReturnAborted=2,kIOReturnNoMemory=3,kIOReturnBadArgument=4;
enum class N {setWCL_JOIN_ABORT,setWCL_LEAVE_NETWORK,PowerSet};
class Ath10kPCIDevice {
public:
    Ath10k::ConnectionState _connection{};
    Ath10k::WMIScanState _wmiScan{};
    Ath10k::WMIBSSCache _wmiBSS{};
    struct {bool active=true;} _wmiLive;
    AirportWCL::JoinRequest _nativeJoin{};
    AirportWCL::ScanRequest _nativeScan{};
    struct Security {
 UInt8 tkipMICNoticeBSSID[6]{};UInt32 tkipMICNoticeGeneration=0;unsigned tkipMICNotices=0;UInt8 tkipMICNoticeKinds[2]{6,6};
        struct PMF {UInt64 generation=91;bool ready=true;
            UInt64 activeGeneration() const{return generation;}bool portReady() const{return ready;}} pmf;
        PMF *pmfSession=&pmf;
        struct Export {AthSecurity::TransitionDisableUpdate pending{};bool pairing=false;
            bool pairwisePending() const{return pairing;}
            bool takeTransitionDisable(const UInt8 *local,const UInt8 *ap,AthSecurity::TransitionDisableUpdate &out){
                if(!pending.length || !AthSecurity::equal(pending.station,local,6) || !AthSecurity::equal(pending.bssid,ap,6))return false;
                out=pending;pending={};return true;}} supplicant;
        AthSecurity::TransitionDisableDelivery transitionPolicy;
        AthNative::EAPOwner eapOwner;
        AthNative::ProfileCredentials profile;
        AthNative::PreparedRoam preparedRoam;
        AthNative::RoamEvents::Delivery roamDelivery;
        bool replyPending=false,keysPending=false,authorizePending=false,ptkUpdatePending=false;
        UInt32 ptkUpdateGeneration=0;UInt64 ptkUpdateSince=0;
        UInt64 roamRetirement=0;
        bool preserve=false;
        template<class State> bool preserveRoamRetirement(const State &,UInt64){return preserve;}
        unsigned resets=0;
        void reset(){tkipMICNotices=0;++resets;eapOwner.clear();ptkUpdatePending=false;ptkUpdateGeneration=0;ptkUpdateSince=0;profile.clear();preparedRoam.clear();roamRetirement=0;preserve=false;transitionPolicy.clear();supplicant.pending={};pmfSession=nullptr;}
    } security;
    Security *_nativeSecurity=&security;
    void *_nativeInterface=this;
    bool _nativeStarted=true,_nativeStopping=false,_nativeMACActive=false,_nativeMACWaiting=false;
    bool _nativeReadyRequested=false,_nativeReadyPublished=true,_nativeReadyResetSent=false;
    bool _nativeAbortRequested=false,_nativeScanPending=false,_nativeJoinPending=false;
    bool _nativeAssocSent=false,_nativeBeaconSent=false,_nativeJoinBSSSent=false;
    bool _nativeLinkUpSent=false,_nativeWasUp=false,_nativeDeauthSent=false,_nativeJoinFailed=false;
    bool _networkLinkUp=true,_networkEnabled=true;
    struct {bool rfKill=false;} _wmiEvents;UInt8 _nativeMACCurrent[6]{};
    bool powerIOBlocked(){return false;}
    IOReturn disconnectResult=kIOReturnNotReady,continueResult=kIOReturnNotReady;
    bool continueAuthorize=true;
    unsigned disconnectCalls=0,continueCalls=0;
    IOReturn nativeDisconnectForRoam(UInt64){
        ++disconnectCalls;if(disconnectResult==kIOReturnSuccess){security.roamRetirement=security.roamDelivery.generation();security.preserve=true;}
        return disconnectResult;
    }
    IOReturn nativeContinueRoam(UInt64){
        ++continueCalls;if(continueResult==kIOReturnSuccess){
            _nativeJoinPending=true;_nativeRoamJoinGeneration=security.roamDelivery.generation();
            security.roamRetirement=0;security.preserve=false;
            _nativeWasUp=_nativeLinkUpSent=false;_nativeAssocSent=_nativeBeaconSent=_nativeJoinBSSSent=false;
            _connection.stage=Ath10k::LinkStage::Connected;_connection.portAuthorized=_networkLinkUp=continueAuthorize;
            security.preparedRoam.target(_connection.bssid);memcpy(_connection.ap.bssid,_connection.bssid,6);
            memcpy(_nativeJoin.bssid,_connection.bssid,6);
        }return continueResult;
    }
    bool _nativeScanStreamed=false;
    UInt32 _nativeScanResultIndex=0,_nativeScanResultsEmitted=0,_nativeReportedBeacon=0;
    UInt64 _nativeRoamPending=0,_nativeRoamDeadline=0;UInt64 _nativeRoamJoinGeneration=0;
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
    bool _nativeRadioOn=true,_nativeDeferredLinkDown=false;
    void discardNativeSecurity(){security.reset();AthSecurity::wipe(_nativeJoin.key,sizeof(_nativeJoin.key));}
    IOReturn power(apple80211_power_data *data){auto &s=_connection;switch(N::PowerSet){
#include "native_radio_power.inc"
    default:return kIOReturnError;}}
    unsigned requestedServices=0;
    void requestNativeService(){++requestedServices;}
    IOReturn leave(N op){auto &s=_connection;switch(op){
#include "native_leave.inc"
    default:return kIOReturnError;}}
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
static void policyJoin(Ath10kPCIDevice &d){
    bootJoin(d);auto &s=d._connection;s.securityAKM=8;s.secure=s.pmfRequired=true;s.securityPhase=5;
    const UInt8 local[]={2,0,0,0,0,1};memcpy(s.local,local,6);
    assert(d.security.transitionPolicy.bind(s.local,s.bssid,91,16));
    auto &u=d.security.supplicant.pending;u.length=1;u.bitmap[0]=1;u.replay=2;
    memcpy(u.station,s.local,6);memcpy(u.bssid,s.bssid,6);
}
static void policyNotifications(){
    { auto d=std::make_unique<Ath10kPCIDevice>();policyJoin(*d);auto &s=d->_connection;
      d->security.transitionPolicy.clear();assert(d->security.transitionPolicy.bind(s.local,s.bssid,91,0));
      AirportWCL::JoinRequest request{};request.lowerAuth=1;request.upperAuth=1u<<12;
      request.keyCipher=10;request.keyLength=8;memcpy(request.key,"password",8);
      request.ssidLength=4;memcpy(request.ssid,"test",4);memcpy(request.bssid,s.bssid,6);
      assert(d->security.profile.replace(request,s.local,true));
      const auto original=d->security.profile.generation();AthSecurity::wipe(&request,sizeof(request));
      d->serviceNativeNotifications(100);
      const auto restricted=d->security.profile.generation();assert(restricted && restricted!=original);
      assert(d->security.profile.snapshot(restricted,s.local,reinterpret_cast<const UInt8 *>("test"),4,NativeJoinAuth::SAE,request));
      assert(request.transitionDisable==1);AthSecurity::wipe(&request,sizeof(request));
      auto &u=d->security.supplicant.pending;u.length=1;u.bitmap[0]=2;u.replay=3;
      memcpy(u.station,s.local,6);memcpy(u.bssid,s.bssid,6);
      d->serviceNativeNotifications(110);assert(!d->security.profile.generation());
    }

    const std::vector<UInt32> expected={49,55,201,201,237,211,201,216,212,213,76,39};
    for(unsigned akm:{8u,5u,18u})for(unsigned fail=0;fail<=expected.size();++fail){
        auto d=std::make_unique<Ath10kPCIDevice>();policyJoin(*d);d->failAt=fail;
        d->_connection.securityAKM=akm;
        d->serviceNativeNotifications(100);d->serviceNativeNotifications(110);
        assert(ids(*d)==expected && !d->_nativeJoinPending);
        const auto &bytes=d->events[10].data;
        const UInt8 golden[40]={6,4,0x82,0xe0,0,0x2c,0x82,0xe0,0,0,0,0,17};
        assert(bytes.size()==40 && !memcmp(bytes.data(),golden,40));
        d->serviceNativeNotifications(120);assert(ids(*d)==expected);
        // Healthy rekey waits for its data/PMF port and retains accumulated policy.
        auto &u=d->security.supplicant.pending;u.length=1;u.bitmap[0]=2;u.replay=3;
        memcpy(u.station,d->_connection.local,6);memcpy(u.bssid,d->_connection.bssid,6);
        d->_connection.portAuthorized=false;d->_connection.rekeyKind=1;
        d->serviceNativeNotifications(130);assert(u.length && ids(*d)==expected);
        d->_connection.portAuthorized=true;d->_connection.rekeyKind=0;
        d->serviceNativeNotifications(140);assert(d->events.back().id==76);
        assert(Ath10k::wmiReadLE32(d->events.back().data.data()+12)==19);
    }
    for(unsigned retire=0;retire<4;++retire){
        auto d=std::make_unique<Ath10kPCIDevice>();policyJoin(*d);d->failAt=11;
        d->serviceNativeNotifications(100);assert(d->events.size()==10 && !d->_nativeJoinPending);
        if(retire==0)d->_connection.cancelRequested=true;
        if(retire==1)++d->security.pmf.generation;
        if(retire==2)d->_connection.bssid[5]^=4;
        if(retire==3)d->_wmiLive.active=false;
        d->serviceNativeNotifications(110);
        for(const auto &e:d->events)assert(e.id!=76);
    }
    for(unsigned barrier=0;barrier<5;++barrier){
        auto d=std::make_unique<Ath10kPCIDevice>();policyJoin(*d);
        // A newly authenticated rekey M3 can still see the old open port
        // before the next radio tick starts the key transaction.
        if(barrier==0)d->security.replyPending=true;
        if(barrier==1)d->security.keysPending=true;
        if(barrier==2)d->security.authorizePending=true;
        if(barrier==3)d->security.supplicant.pairing=true;
        if(barrier==4)d->security.pmf.ready=false;
        d->serviceNativeNotifications(100);
        for(const auto &e:d->events)assert(e.id!=76);
        assert(d->security.supplicant.pending.length);
        d->security.replyPending=d->security.keysPending=d->security.authorizePending=false;
        d->security.supplicant.pairing=false;d->security.pmf.ready=true;
        d->serviceNativeNotifications(110);assert(d->events.back().id==76);
    }
    { // Preserve the admission binding while Auth is still in progress.
        auto d=std::make_unique<Ath10kPCIDevice>();policyJoin(*d);
        d->_connection.stage=Ath10k::LinkStage::Auth;d->_connection.portAuthorized=false;
        d->serviceNativeNotifications(100);
        assert(d->security.transitionPolicy.matches(d->_connection.local,d->_connection.bssid,91));
        assert(d->security.supplicant.pending.length);
        d->_connection.stage=Ath10k::LinkStage::Connected;d->_connection.portAuthorized=true;
        d->serviceNativeNotifications(110);bool delivered=false;
        for(const auto &e:d->events)delivered|=e.id==76;assert(delivered);
    }
}
static void prepareRoam(Ath10kPCIDevice &d){
    connected(d);auto &s=d._connection;d._nativeWasUp=d._nativeLinkUpSent=true;
    d._nativeReportedBeacon=s.beaconFrameSerial;
    memcpy(d._nativeLastBSSID,s.bssid,6);s.ssidLength=4;memcpy(s.ssid,"test",4);
    const UInt8 station[]={2,0,0,0,0,1};memcpy(s.local,station,6);memcpy(d._nativeMACCurrent,station,6);
    AirportWCL::JoinRequest profile{};profile.lowerAuth=1;profile.ssidLength=4;memcpy(profile.ssid,"test",4);memcpy(profile.bssid,s.bssid,6);
    assert(d.security.profile.replace(profile,station,false));
    auto ap=s.ap;ap.bssid[5]=0x66;ap.capabilities=1;ap.beaconInterval=100;
    ap.rateCount=1;ap.rates[0]=0x82;ap.rxChannel=ap.advertisedChannel=6;
    auto cache=std::make_unique<AthNative::CandidateCache>();cache->add(ap,0);
    NativeReassocRequest request{};request.ssidLength=4;memcpy(request.ssid,"test",4);memcpy(request.bssid,ap.bssid,6);
    assert(d.security.preparedRoam.prepare(d.security.profile,s,request,*cache,0));
    assert(d.security.roamDelivery.begin(0,ap.bssid));
    d._nativeRoamPending=d.security.roamDelivery.generation();d._nativeRoamDeadline=30000;
}
static void roamDispatcher(){
    using namespace AthNative::RoamEvents;
    // Roam backpressure must still service the old link's key completion.
    // Otherwise the teardown guard waits for an event this dispatcher starves.
    for(unsigned wait=0;wait<4;++wait){
        auto d=std::make_unique<Ath10kPCIDevice>();prepareRoam(*d);
        auto &sec=d->security;auto &link=d->_connection;
        d->_nativeBeaconSent=true;link.securityPhase=5;link.securityGeneration=8;
        sec.ptkUpdatePending=true;sec.ptkUpdateGeneration=8;sec.ptkUpdateSince=1;
        d->disconnectResult=kIOReturnBusy;
        if(wait<2)d->failAt=wait+1; // Start or Prep enqueue fails once.
        if(wait==3){sec.preparedRoam.clear();d->failAt=2;} // Failed Complete retry.
        d->serviceNativeNotifications(100);
        unsigned updates=0;for(const auto &e:d->events)if(e.id==AirportWCL::SupplicantEvent)++updates;
        assert(updates==(wait==2?1u:0u) && sec.ptkUpdatePending==(wait!=2) && d->_nativeRoamPending);
        assert(!sec.roamRetirement && !d->continueCalls && link.portAuthorized);
        d->serviceNativeNotifications(110);
        updates=0;for(const auto &e:d->events)if(e.id==AirportWCL::SupplicantEvent)++updates;
        assert(updates==1 && !sec.ptkUpdatePending); // Retry after enqueue failure; no replay after acceptance.
    }
    const std::vector<UInt32> expected={StartID,PrepID,ReassocID,AirportWCL::ScanResult,AirportWCL::LinkStatus,AirportWCL::FirstBeacon,CompleteID};
    for(unsigned failure=0;failure<=expected.size();++failure){
        auto d=std::make_unique<Ath10kPCIDevice>();prepareRoam(*d);
        d->disconnectResult=d->continueResult=kIOReturnSuccess;d->failAt=failure;
        d->serviceNativeNotifications(100);d->serviceNativeNotifications(110);
        assert(ids(*d)==expected && !d->_nativeRoamPending && !d->_nativeRoamJoinGeneration && !d->_nativeJoinPending);
        assert(d->disconnectCalls==1 && d->continueCalls==1);
        assert(d->events.back().data.size()==168 && AirportWCL::read32(d->events.back().data.data())==0);
        assert(d->_nativeLastBSSID[5]==0x66);
        d->serviceNativeNotifications(120);assert(ids(*d)==expected);
    }
    {auto d=std::make_unique<Ath10kPCIDevice>();prepareRoam(*d);auto &s=d->_connection;
     s.securityAKM=8;s.secure=s.pmfRequired=true;s.securityPhase=5;
     assert(d->security.transitionPolicy.bind(s.local,s.bssid,91,0));
     auto &update=d->security.supplicant.pending;update.length=1;update.bitmap[0]=2;update.replay=1;
     memcpy(update.station,s.local,6);memcpy(update.bssid,s.bssid,6);
     d->disconnectResult=d->continueResult=kIOReturnSuccess;
     d->serviceNativeNotifications(100);
     assert(!d->_nativeRoamPending && !d->disconnectCalls && !d->continueCalls);
     assert(d->events[0].id==StartID && d->events[1].id==CompleteID && AirportWCL::read32(d->events[1].data.data())!=0);
    }
    for(auto op:{N::setWCL_JOIN_ABORT,N::setWCL_LEAVE_NETWORK})for(bool afterJoin:{false,true}){
        auto d=std::make_unique<Ath10kPCIDevice>();prepareRoam(*d);
        if(afterJoin){
            d->disconnectResult=d->continueResult=kIOReturnSuccess;d->continueAuthorize=false;
            d->serviceNativeNotifications(100);assert(d->_nativeRoamJoinGeneration && d->_nativeJoinPending);
        }
        assert(d->leave(op)==kIOReturnSuccess);d->serviceNativeNotifications(110);
        assert(!d->_nativeRoamPending && !d->_nativeRoamJoinGeneration && !d->_nativeJoinPending);
        unsigned completed=0;for(const auto &event:d->events){
            assert(event.id!=AirportWCL::ConnectComplete && event.id!=AirportWCL::JoinAbortComplete);
            if(event.id==CompleteID){++completed;assert(AirportWCL::read32(event.data.data())!=0);}
        }assert(completed==1);
        d->serviceNativeNotifications(120);
        if(op==N::setWCL_JOIN_ABORT)assert(d->events.back().id==AirportWCL::JoinAbortComplete);
        const auto count=d->events.size();d->serviceNativeNotifications(130);assert(d->events.size()==count);
    }
    for(unsigned failure=0;failure<4;++failure){
        auto d=std::make_unique<Ath10kPCIDevice>();prepareRoam(*d);
        d->disconnectResult=kIOReturnSuccess;d->continueResult=kIOReturnBusy;
        if(failure==0)d->security.preparedRoam.clear();
        if(failure==1)d->disconnectResult=kIOReturnNotReady;
        if(failure==2)d->continueResult=kIOReturnNotReady;
        d->serviceNativeNotifications(100);
        if(failure==3){assert(d->_nativeRoamPending);d->security.preparedRoam.clear();d->serviceNativeNotifications(110);}
        assert(!d->_nativeRoamPending && d->events.back().id==CompleteID);
        assert(AirportWCL::read32(d->events.back().data.data())!=0);
        assert(!d->security.preparedRoam.generation());
        const auto count=d->events.size();d->serviceNativeNotifications(120);assert(d->events.size()==count);
    }
}
static void pairwiseNotifications(){
    for(unsigned mode=0;mode<4;++mode){
        auto d=std::make_unique<Ath10kPCIDevice>();policyJoin(*d);d->serviceNativeNotifications(10);d->events.clear();
        auto &s=d->_connection;auto &o=d->security.eapOwner;uint8_t key[32]{},out[32]{};
        assert(o.begin(s.local,s.bssid,1,100));auto g=o.generation();
        assert(o.setMSK(g,s.local,s.bssid,9,key,32,2)==AthNative::EAPOwner::KeyResult::Accepted);
        assert(o.takePMK(g,s.local,s.bssid,3,out));assert(o.beginReplacement(g,s.local,s.bssid,4,120));g=o.generation();
        assert(o.setMSK(g,s.local,s.bssid,9,key,32,5)==AthNative::EAPOwner::KeyResult::Accepted);
        if(mode!=2)assert(o.takePMK(g,s.local,s.bssid,6,out));
        s.securityGeneration=8;d->security.ptkUpdateGeneration=8;d->security.ptkUpdatePending=true;d->security.ptkUpdateSince=10;
        if(mode==0){d->failAlways=true;d->serviceNativeNotifications(110);assert(o.replacementPending());d->failAlways=false;}
        if(mode==3)s.bssid[5]^=1;
        d->serviceNativeNotifications(mode==1?120:119);
        unsigned updates=0;for(const auto &event:d->events)if(event.id==AirportWCL::SupplicantEvent)++updates;
        assert(updates==((mode==0 || mode==2)?1u:0u));
        if(mode==0)assert(!o.replacementPending() && !s.cancelRequested);
        else if(mode==2)assert(o.replacementPending() && !s.cancelRequested); // Old event cannot finish new EAP.
        else assert(s.cancelRequested && !s.portAuthorized);
    }

    for(unsigned mode=0;mode<5;++mode){
        auto d=std::make_unique<Ath10kPCIDevice>();policyJoin(*d);
        d->serviceNativeNotifications(100);d->events.clear();
        auto &s=d->_connection;s.securityGeneration=8;
        d->security.ptkUpdateGeneration=8;d->security.ptkUpdatePending=true;d->security.ptkUpdateSince=100;
        if(mode==1)s.cancelRequested=true;
        if(mode==2)++s.securityGeneration;
        if(mode==3){d->security.pmf.ready=false;d->serviceNativeNotifications(110);
            assert(d->security.ptkUpdatePending && d->events.empty());d->security.pmf.ready=true;}
        if(mode==4){d->failAlways=true;d->serviceNativeNotifications(110);
            assert(d->security.ptkUpdatePending && d->events.empty());d->failAlways=false;}
        d->serviceNativeNotifications(120);
        unsigned updates=0;
        for(const auto &e:d->events)if(e.id==AirportWCL::SupplicantEvent){
            assert(e.data.size()==40);AirportWCL::SupplicantEventData event{};
            memcpy(&event,e.data.data(),40);assert(event.reason==0xe0822c15u);
            assert(event.status==0xe0820406u && event.transitionDisabledFlags==17);++updates;
        }
        assert(updates==((mode==1 || mode==2)?0u:1u));assert(!d->security.ptkUpdatePending && !d->security.ptkUpdateSince);
        d->events.clear();d->serviceNativeNotifications(130);
        for(const auto &e:d->events)assert(e.id!=AirportWCL::SupplicantEvent);
    }
}
int main(){
 {auto d=std::make_unique<Ath10kPCIDevice>();connected(*d);auto &sec=d->security;
  sec.tkipMICNotices=2;sec.tkipMICNoticeKinds[0]=5;sec.tkipMICNoticeKinds[1]=6;sec.tkipMICNoticeGeneration=d->_connection.securityGeneration;
  memcpy(sec.tkipMICNoticeBSSID,d->_connection.bssid,6);d->failAt=1;
  d->serviceNativeNotifications(100);assert(sec.tkipMICNotices==2);
  d->serviceNativeNotifications(101);assert(!sec.tkipMICNotices);
  unsigned delivered=0;for(const auto &e:d->events)if(e.id==5 || e.id==6){assert(e.id==(delivered?6u:5u));++delivered;assert(e.data.size()==6 && !memcmp(e.data.data(),d->_connection.bssid,6));}
  assert(delivered==2);const auto count=d->events.size();d->serviceNativeNotifications(102);assert(d->events.size()==count);
  sec.tkipMICNotices=1;++d->_connection.securityGeneration;d->serviceNativeNotifications(103);
  assert(!sec.tkipMICNotices && d->events.size()==count);
 }

    pairwiseNotifications();
    roamDispatcher();
    policyNotifications();
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
    { // Deliver discovered BSS records before the full channel sweep finishes.
        auto d=std::make_unique<Ath10kPCIDevice>();bootJoin(*d);
        d->_nativeReadyRequested=false;d->_nativeJoinPending=false;
        d->_connection={};d->_networkLinkUp=false;
        d->_wmiScan.completed=false;d->_wmiBSS.count=1;
        d->serviceNativeNotifications(100);
        assert((ids(*d)==std::vector<UInt32>{201}) && d->_nativeScanPending);
        d->serviceNativeNotifications(110);assert(d->events.size()==1);
        d->_wmiBSS.count=2;d->failAt=d->attempts+1;
        d->serviceNativeNotifications(120);assert(d->_nativeScanResultIndex==1);
        d->serviceNativeNotifications(130);
        assert((ids(*d)==std::vector<UInt32>{201,201}) && d->_nativeScanPending);
        d->_wmiScan.completed=true;d->serviceNativeNotifications(140);
        assert((ids(*d)==std::vector<UInt32>{201,201,201,201,237}) && !d->_nativeScanPending);
        d->serviceNativeNotifications(150);assert(d->events.size()==5);
    }
    for(bool cancelled:{false,true}){
        auto d=std::make_unique<Ath10kPCIDevice>();bootJoin(*d);
        d->_nativeReadyRequested=false;d->_nativeJoinPending=false;
        d->_connection={};d->_networkLinkUp=false;
        d->_wmiScan.completed=false;d->_wmiBSS.count=1;
        d->serviceNativeNotifications(100);assert(d->events.size()==1);
        d->_wmiScan.cancelRequested=cancelled;d->_wmiScan.failed=!cancelled;
        d->_wmiBSS.count=2;d->serviceNativeNotifications(110);
        assert(d->events.size()==1 && d->_nativeScanPending);
        d->_wmiScan.completed=true;d->failAt=d->attempts+1;
        d->serviceNativeNotifications(120);assert(d->events.size()==1 && d->_nativeScanPending);
        d->serviceNativeNotifications(130);
        assert((ids(*d)==std::vector<UInt32>{201,237}) && !d->_nativeScanPending);
        assert(Ath10k::wmiReadLE32(d->events.back().data.data())==
               (cancelled?kIOReturnAborted:kIOReturnError));
        d->serviceNativeNotifications(140);assert(d->events.size()==2);
    }
    { // A failed final refresh enqueue must resume, never restart the pass.
        auto d=std::make_unique<Ath10kPCIDevice>();bootJoin(*d);
        d->_nativeReadyRequested=false;d->_nativeJoinPending=false;
        d->_connection={};d->_networkLinkUp=false;d->_wmiScan.completed=false;
        d->serviceNativeNotifications(100);assert(d->events.size()==2);
        d->_wmiBSS.entries[0].ssid[0]='X';
        d->_wmiScan.completed=true;d->failAt=d->attempts+2;
        d->serviceNativeNotifications(110);assert(d->events.size()==3 && d->_nativeScanResultIndex==1);
        assert(d->events[0].data!=d->events[2].data);
        d->serviceNativeNotifications(120);
        assert((ids(*d)==std::vector<UInt32>{201,201,201,201,237}) && !d->_nativeScanPending);
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
    { // Association and physical LinkUp are not completed WPA authorization.
        auto d=std::make_unique<Ath10kPCIDevice>();connected(*d);
        d->_nativeJoinPending=true;d->_connection.portAuthorized=false;
        d->serviceNativeNotifications(100);
        assert(d->_nativeAssocSent && d->_nativeLinkUpSent && d->_nativeBeaconSent);
        assert(d->_nativeJoinPending);
        for(const auto &e:d->events)assert(e.id!=AirportWCL::ConnectComplete);
        d->events.clear();d->serviceNativeNotifications(110);
        assert(d->events.empty() && d->_nativeJoinPending);
        d->_connection.portAuthorized=true;d->serviceNativeNotifications(120);
        unsigned completions=0;
        for(const auto &e:d->events)if(e.id==AirportWCL::ConnectComplete){
            ++completions;
            auto event=reinterpret_cast<const AirportWCL::ConnectionEvent *>(e.data.data());
            assert(event->status==0 && event->peers[0].driverStatus==kIOReturnSuccess);
        }
        assert(completions==1 && !d->_nativeJoinPending);
        d->events.clear();d->serviceNativeNotifications(130);assert(d->events.empty());
    }
    for(unsigned blockedPhase=1;blockedPhase<=5;++blockedPhase){
        // Cancellation between a failed enqueue and retry must never revive
        // the old join, including when only ConnectComplete was left to send.
        auto d=std::make_unique<Ath10kPCIDevice>();connected(*d);
        d->_nativeJoinPending=true;d->failAt=blockedPhase;
        d->serviceNativeNotifications(100);
        assert(d->_nativeJoinPending && d->_nativePostError==kIOReturnNoMemory);
        d->_connection.cancelRequested=true;
        d->events.clear();d->serviceNativeNotifications(110);
        unsigned completions=0;
        for(const auto &e:d->events){
            assert(e.id!=AirportWCL::AssocComplete && e.id!=AirportWCL::FirstBeacon);
            if(e.id==AirportWCL::ConnectComplete){
                ++completions;
                auto event=reinterpret_cast<const AirportWCL::ConnectionEvent *>(e.data.data());
                assert(event->status!=0 && event->peers[0].driverStatus!=kIOReturnSuccess);
            }
            if(e.id==AirportWCL::LinkStatus){
                auto link=reinterpret_cast<const AirportWCL::LinkStatusEvent *>(e.data.data());
                assert(!link->up);
            }
        }
        assert(completions==1 && !d->_nativeJoinPending && !d->_connection.portAuthorized);
        const auto delivered=d->events.size();d->serviceNativeNotifications(120);
        assert(d->events.size()==delivered);
    }
    { // LEAVE must retire a WCL join even after radio teardown completed.
        auto d=std::make_unique<Ath10kPCIDevice>();connected(*d);
        d->_nativeJoinPending=true;
        Ath10k::resetDisconnected(d->_connection);
        assert(d->leave(N::setWCL_LEAVE_NETWORK)==kIOReturnSuccess);
        assert(!d->_connection.cancelRequested && !d->_networkLinkUp);
        const unsigned resets=d->security.resets;
        d->failAlways=true;
        d->serviceNativeNotifications(110);
        assert(d->_nativeJoinPending && d->events.empty());
        assert(d->security.resets==resets && !d->_connection.cancelRequested);
        d->failAlways=false;d->serviceNativeNotifications(120);
        assert(!d->_nativeJoinPending && d->events.size()==1);
        assert(d->events[0].id==AirportWCL::ConnectComplete);
        const auto *event=reinterpret_cast<const AirportWCL::ConnectionEvent *>(d->events[0].data.data());
        assert(event->status!=0 && event->peers[0].driverStatus==kIOReturnError);
        assert(event->peers[0].bssid[5]==0x55);
        d->serviceNativeNotifications(130);assert(d->events.size()==1);
        assert(d->security.resets==resets && !d->_connection.cancelRequested);
    }
    { // Radio-off must survive radio teardown before the notification worker.
        auto d=std::make_unique<Ath10kPCIDevice>();connected(*d);
        d->_connection.stage=Ath10k::LinkStage::Scan;d->_nativeJoinPending=true;
        d->_nativeScanPending=true;d->_wmiScan.completed=false;
        apple80211_power_data power{};power.num_radios=1;power.power_state[0]=0;
        assert(d->power(&power)==kIOReturnSuccess);
        assert(!d->_nativeRadioOn && !d->_connection.portAuthorized && d->_wmiScan.cancelRequested);
        Ath10k::resetDisconnected(d->_connection);d->_wmiScan.completed=true;
        d->failAlways=true;d->serviceNativeNotifications(100);
        assert(d->_nativeJoinPending && d->_nativeScanPending && d->events.empty());
        d->failAlways=false;d->serviceNativeNotifications(110);
        assert(!d->_nativeJoinPending && !d->_nativeScanPending);
        assert((ids(*d)==std::vector<UInt32>{AirportWCL::ScanDone,AirportWCL::ConnectComplete}));
        assert(Ath10k::wmiReadLE32(d->events[0].data.data())==kIOReturnAborted);
        const auto *result=reinterpret_cast<const AirportWCL::ConnectionEvent *>(d->events[1].data.data());
        assert(result->status!=0);
        d->serviceNativeNotifications(120);assert(d->events.size()==2);
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
    { // Intentional roam retirement retains the old WCL BSS. Losing that
      // entitlement must restore ordinary terminal notification exactly once.
      auto d=std::make_unique<Ath10kPCIDevice>();bootJoin(*d);d->serviceNativeNotifications(100);
      d->events.clear();d->_connection={};d->_networkLinkUp=false;d->security.preserve=true;
      d->serviceNativeNotifications(110);d->serviceNativeNotifications(120);
      assert(d->events.empty() && d->_nativeWasUp && d->_nativeLinkUpSent && !d->security.resets);
      d->security.preserve=false;d->serviceNativeNotifications(130);
      assert((ids(*d)==std::vector<UInt32>{203,216}) && !d->_nativeWasUp);
      auto link=reinterpret_cast<const AirportWCL::LinkStatusEvent *>(d->events.back().data.data());
      assert(link->bssid[5]==0x55 && !link->up);
      d->serviceNativeNotifications(140);assert(d->events.size()==2);
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

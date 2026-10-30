#include <cassert>
#include <cstring>
#include <vector>
#include "../../src/macos/native/Ath10kNativeCandidates.hpp"
#include "../../src/macos/native/Ath10kNativeProfile.hpp"
#include "../../src/macos/native/Ath10kNativeEAPOwner.hpp"
#include "../../src/macos/native/Ath10kNativeRoamEvents.hpp"
#include "../../src/macos/native/Ath10kNativePMFInbox.hpp"
#include "../../src/macos/native/Ath10kNativeWire.hpp"
#include "../../src/security/Ath10kSupplicant.hpp"
#include "../fixtures/sha256_vectors.inc"
// No crypto operation is invoked: begin stores the fixture and reset must
// wipe it. Definitions are deliberately absent to catch accidental operations.
struct Ath10kKernelCrypto {};
static std::vector<unsigned> cleanup;
struct Ath10kPMFSession {
    UInt64 generation=9;UInt64 activeGeneration(){return generation;}
    bool activateManagement(const AthSecurity::IGTKCMAC128 &){return true;}
    bool keyResult=true,portResult=true;unsigned keyCalls=0,portCalls=0;
    bool acknowledgePairwise(const UInt8 *,const UInt8 *,const UInt8 *){++keyCalls;return keyResult;}
    bool authorize(){++portCalls;return portResult;}
    void cancel(){cleanup.push_back(6);}
    void release(){cleanup.push_back(7);delete this;}
};
struct Ath10kSAESession {
    void cancel(){cleanup.push_back(1);}
    void release(){cleanup.push_back(4);delete this;}
};
#include "../support/mock_native_sae_radio.hpp"
struct Ath10kSAEWorkItem {
    void discard(){cleanup.push_back(2);}
    void release(){cleanup.push_back(3);delete this;}
};
struct Ath10kSAEWorker {
    static inline unsigned created=0,cancelled=0,drained=0,released=0;
    static inline bool failInit=false;
    bool init(){++created;return !failInit;}
    void cancel(){++cancelled;cleanup.push_back(5);}
    void shutdown(){++drained;}
    void release(){++released;delete this;}
};
struct Ath10kNativePSKPreparation {void cancel(){}bool active() const{return false;}};
class Ath10kPCIDevice {
public:
    class NativeSecurity;
    NativeSecurity *_nativeSecurity=nullptr;
    AirportWCL::JoinRequest _nativeJoin{};
    struct {UInt32 securityGeneration=0;UInt8 local[6]{},bssid[6]{};Ath10k::LinkStage stage=Ath10k::LinkStage::Connected;
        Ath10k::DisconnectStage disconnect=Ath10k::DisconnectStage::None;bool cancelRequested=false,pmfRequired=false,pmfTXPending=false,pairInstalled=false,portAuthorized=false;UInt8 groupCipher=4;unsigned securityPhase=0;
        struct {bool pending=false,inFlight=false;unsigned length=0,dropped=0;} spectrum;} _connection;
    void discardIfStopped(UInt64 now=0);
    void discardNativeSecurity();
    bool nativeStageManagementKey(const AthSecurity::IGTKCMAC128 &);
    bool nativeAcceptSecurityResult(UInt32);
    bool nativePMFPairwiseAcknowledged(const UInt8 *);
    bool nativePMFPortReady();
    bool firmwareReady=true;bool nativePMFFirmwareReady(){return firmwareReady;}
    const char *beforeFirmwareAuthorization(unsigned);
};
#include "native_security_class.inc"
#include "native_security_discard.inc"
#include "native_pmf_key_hooks.inc"
#include "native_pmf_firmware_guard.inc"
#include "native_security_terminal_cleanup.inc"
int main(){
    for(unsigned outcome=0;outcome<8;++outcome){
      Ath10kPCIDevice d;Ath10kPCIDevice::NativeSecurity sec;d._nativeSecurity=&sec;
      AirportWCL::JoinRequest request{};request.lowerAuth=1;request.ssidLength=4;
      memcpy(request.ssid,"test",4);memcpy(request.bssid,s_ap,6);
      assert(sec.profile.replace(request,s_sta,false));
      Ath10k::ConnectionState live{};memcpy(live.local,s_sta,6);live.ssidLength=4;memcpy(live.ssid,"test",4);
      Ath10k::WMIBSS ap{};memcpy(ap.bssid,s_ap,6);ap.bssid[5]^=1;ap.ssidLength=4;memcpy(ap.ssid,"test",4);
      ap.capabilities=1;ap.beaconInterval=100;ap.rateCount=1;ap.rates[0]=0x82;ap.rxChannel=ap.advertisedChannel=6;
      sec.candidates.add(ap,1000);NativeReassocRequest roam{};roam.ssidLength=4;memcpy(roam.ssid,"test",4);memcpy(roam.bssid,ap.bssid,6);
      assert(sec.preparedRoam.prepare(sec.profile,live,roam,sec.candidates,1100));
      assert(sec.roamDelivery.begin(0,ap.bssid));const auto delivery=sec.roamDelivery.generation();
      const auto profile=sec.profile.generation();auto post=[](uint32_t,void *,size_t){return true;};
      assert(!sec.beginRoamRetirement(profile,delivery,s_sta,1100));
      assert(sec.roamDelivery.sendStart(delivery,post));
      assert(!sec.beginRoamRetirement(profile,delivery,s_sta,1100));
      assert(sec.roamDelivery.sendPrep(delivery,post));
      assert(!sec.beginRoamRetirement(profile,delivery+1,s_sta,1100));
      assert(sec.beginRoamRetirement(profile,delivery,s_sta,1100));
      assert(!sec.beginRoamRetirement(profile,delivery,s_sta,1100));
      memcpy(d._connection.local,s_sta,6);d._connection.disconnect=Ath10k::DisconnectStage::Drain;
      UInt64 now=1200;
      if(outcome==1)d._connection.cancelRequested=true;
      if(outcome==2)d._connection.stage=Ath10k::LinkStage::Failed;
      if(outcome==3)now=31001;
      if(outcome==4)d._connection.local[5]^=1;
      if(outcome==5)assert(sec.profile.replace(request,s_sta,false));
      if(outcome==6)assert(sec.roamDelivery.sendComplete(delivery,1,false,post));
      if(outcome==7)sec.profile.clear();
      d.discardIfStopped(now);
      if(outcome){assert(!sec.profile.generation() && !sec.preparedRoam.generation() && !sec.roamRetirement);}
      else{
        assert(sec.profile.generation()==profile && sec.preparedRoam.generation()==profile);
        d._connection.disconnect=Ath10k::DisconnectStage::None;d._connection.stage=Ath10k::LinkStage::Disabled;
        d.discardIfStopped(now);assert(sec.profile.generation()==profile);
        d._connection.cancelRequested=true;d.discardIfStopped(now);assert(!sec.profile.generation());
      }
    }

    // EAP can be alive before a profile or four-way key owner is ready.
    for(unsigned terminal=0;terminal<4;++terminal){
      Ath10kPCIDevice d;Ath10kPCIDevice::NativeSecurity security;d._nativeSecurity=&security;
      assert(security.eapOwner.begin(s_sta,s_ap,100,1000));
      security.eapTXInFlight=true;
      if(terminal==0)d._connection.cancelRequested=true;
      if(terminal==1)d._connection.stage=Ath10k::LinkStage::Disabled;
      if(terminal==2)d._connection.stage=Ath10k::LinkStage::Failed;
      if(terminal==3)d._connection.disconnect=Ath10k::DisconnectStage::Drain;
      d.discardIfStopped();assert(!security.eapOwner.generation() && !security.eapTXInFlight);
    }

    // Open profiles have no crypto owner; terminal cleanup must still retire
    // their identity/generation before a subsequent prepared handoff can run.
    for(unsigned terminal=0;terminal<4;++terminal){
      Ath10kPCIDevice d;Ath10kPCIDevice::NativeSecurity security;d._nativeSecurity=&security;
      AirportWCL::JoinRequest request{};request.lowerAuth=1;request.ssidLength=4;
      memcpy(request.ssid,"open",4);memcpy(request.bssid,s_ap,6);
      assert(security.profile.replace(request,s_sta,false));
      d._connection.stage=Ath10k::LinkStage::Connected;
      if(terminal==0)d._connection.cancelRequested=true;
      if(terminal==1)d._connection.stage=Ath10k::LinkStage::Disabled;
      if(terminal==2)d._connection.stage=Ath10k::LinkStage::Failed;
      if(terminal==3)d._connection.disconnect=Ath10k::DisconnectStage::Drain;
      d.discardIfStopped();assert(!security.profile.generation());
    }

    { Ath10kPCIDevice d;d._nativeSecurity=new Ath10kPCIDevice::NativeSecurity;
      d._connection.pmfRequired=true;d._connection.spectrum.pending=true;d._connection.spectrum.length=31;
      d.discardNativeSecurity();assert(!d._connection.spectrum.pending && d._connection.spectrum.dropped==1);
      d._connection.spectrum.inFlight=true;d._connection.spectrum.length=31;
      d.discardNativeSecurity();assert(d._connection.spectrum.inFlight && d._connection.spectrum.length==31); // Transport already owns this frame; its completion must retire it.
      delete d._nativeSecurity; }

    { Ath10kPCIDevice d;d._nativeSecurity=new Ath10kPCIDevice::NativeSecurity;
      d._nativeSecurity->pmfTXKind=Ath10kPCIDevice::NativeSecurity::PMFTXKind::Spectrum;
      d._connection.spectrum.inFlight=true;d._connection.spectrum.length=31;d._connection.pmfTXPending=true;
      d.discardNativeSecurity();assert(!d._connection.spectrum.inFlight && !d._connection.spectrum.length && d._connection.spectrum.dropped==1 && !d._connection.pmfTXPending);
      delete d._nativeSecurity; }

    { Ath10kPCIDevice d;d._connection.pmfRequired=true;d._nativeSecurity=new Ath10kPCIDevice::NativeSecurity;
      d._nativeSecurity->pmfSession=new Ath10kPMFSession;d.firmwareReady=false;
      assert(!d.nativePMFPortReady() && !d._nativeSecurity->pmfSession->portCalls);
      d.firmwareReady=true;assert(d.nativePMFPortReady());delete d._nativeSecurity;cleanup.clear(); }

    { Ath10kPCIDevice d;UInt8 key[16]{};d._connection.pmfRequired=true;
      assert(!d.nativePMFPairwiseAcknowledged(key) && !d.nativePMFPortReady() && d.beforeFirmwareAuthorization(3));
      d._nativeSecurity=new Ath10kPCIDevice::NativeSecurity;
      assert(!d.nativePMFPairwiseAcknowledged(key) && !d.nativePMFPortReady());delete d._nativeSecurity;
    }

    { Ath10kPCIDevice d;assert(!d.beforeFirmwareAuthorization(3));
      d._nativeSecurity=new Ath10kPCIDevice::NativeSecurity;auto pmf=new Ath10kPMFSession;
      d._nativeSecurity->pmfSession=pmf;pmf->portResult=false;
      assert(!d.beforeFirmwareAuthorization(1) && !d.beforeFirmwareAuthorization(2) && !pmf->portCalls);
      assert(d.beforeFirmwareAuthorization(3) && pmf->portCalls==1);
      pmf->portResult=true;assert(!d.beforeFirmwareAuthorization(3) && pmf->portCalls==2);
      delete d._nativeSecurity;cleanup.clear();
    }

    // Authentication can fail before the EAPOL ready/reply/key flags exist.
    for(unsigned reason=0;reason<4;++reason)for(unsigned resource=0;resource<3;++resource){
      Ath10kPCIDevice d;d._nativeSecurity=new Ath10kPCIDevice::NativeSecurity;
      if(resource==0)d._nativeSecurity->pmfSession=new Ath10kPMFSession;
      if(resource==1)d._nativeSecurity->saeSession=new Ath10kSAESession;
      if(resource==2)d._nativeSecurity->saePendingTX=new Ath10kSAEWorkItem;
      if(reason==0)d._connection.stage=Ath10k::LinkStage::Failed;
      if(reason==1)d._connection.stage=Ath10k::LinkStage::Disabled;
      if(reason==2)d._connection.cancelRequested=true;
      if(reason==3)d._connection.disconnect=Ath10k::DisconnectStage::Down;
      d.discardIfStopped();assert(!d._nativeSecurity->pmfSession && !d._nativeSecurity->saeSession && !d._nativeSecurity->saePendingTX);
      assert(cleanup==std::vector<unsigned>(resource==0?std::initializer_list<unsigned>{6,7}:
          (resource==1?std::initializer_list<unsigned>{1,4}:std::initializer_list<unsigned>{2,3})));
      delete d._nativeSecurity;cleanup.clear();
    }
    { Ath10kPCIDevice d;d._nativeSecurity=new Ath10kPCIDevice::NativeSecurity;
      d._nativeSecurity->pmfSession=new Ath10kPMFSession;d.discardIfStopped();
      assert(d._nativeSecurity->pmfSession && cleanup.empty());delete d._nativeSecurity;cleanup.clear();
    }

    { Ath10kPCIDevice d;UInt8 key[16]{};
      assert(d.nativePMFPairwiseAcknowledged(key) && d.nativePMFPortReady());
      d._nativeSecurity=new Ath10kPCIDevice::NativeSecurity;
      assert(d.nativePMFPairwiseAcknowledged(key) && d.nativePMFPortReady());
      auto pmf=new Ath10kPMFSession;d._nativeSecurity->pmfSession=pmf;
      assert(d.nativePMFPairwiseAcknowledged(key) && pmf->keyCalls==1);
      pmf->keyResult=false;assert(!d.nativePMFPairwiseAcknowledged(key));
      pmf->portResult=false;assert(!d.nativePMFPortReady());
      pmf->portResult=true;assert(d.nativePMFPortReady() && pmf->portCalls==2);
      delete d._nativeSecurity;cleanup.clear();
    }

    { auto s=new Ath10kPCIDevice::NativeSecurity;s->pmfSession=new Ath10kPMFSession;
      s->reset();assert(!s->pmfSession && cleanup==std::vector<unsigned>({6,7}));
      s->reset();assert(cleanup==std::vector<unsigned>({6,7}));delete s;cleanup.clear();
    }
    { auto s=new Ath10kPCIDevice::NativeSecurity;
      Ath10kSAEWorker::failInit=true;assert(!s->prepareSAEWorker() && !s->saeWorker);
      assert(Ath10kSAEWorker::created==1 && Ath10kSAEWorker::released==1);
      Ath10kSAEWorker::failInit=false;assert(s->prepareSAEWorker());assert(s->prepareSAEWorker());
      assert(Ath10kSAEWorker::created==2);
      s->saeSession=new Ath10kSAESession;s->saePendingTX=new Ath10kSAEWorkItem;
      s->reset();assert(Ath10kSAEWorker::cancelled==1 && !Ath10kSAEWorker::drained);
      assert(!s->saeSession && !s->saePendingTX && cleanup==std::vector<unsigned>({1,2,3,4,5}));
      s->drainSAEWorker();assert(Ath10kSAEWorker::drained==1);delete s;
      assert(Ath10kSAEWorker::released==2 && Ath10kSAEWorker::cancelled==2);
    }
    Ath10kPCIDevice d;Ath10kPCIDevice::NativeSecurity security;
    d._nativeSecurity=&security;
    AirportWCL::JoinRequest profile{};profile.lowerAuth=1;profile.upperAuth=1024;
    profile.keyCipher=6;profile.keyLength=32;memcpy(profile.key,s_pmk,32);
    profile.ssidLength=4;memcpy(profile.ssid,"test",4);memcpy(profile.bssid,s_ap,6);
    assert(security.profile.replace(profile,s_sta,false));
    const auto profileGeneration=security.profile.generation();AthSecurity::wipe(&profile,sizeof(profile));
    assert(security.supplicant.begin(s_pmk,s_snonce,s_sta,s_ap,s_rsn,sizeof(s_rsn),6));
    memset(security.reply,0xa5,sizeof(security.reply));memset(security.keys,0x5a,sizeof(security.keys));
    memset(security.supplicant.output,0x3c,sizeof(security.supplicant.output));
    memset(security.supplicant.keys,0x4b,sizeof(security.supplicant.keys));
    security.supplicant.outputLength=123;
    security.ready=security.replyPending=security.keysPending=security.authorizePending=true;
    security.replyLength=120;security.keyOperation=3;security.pairDeadline=5000;
    assert(security.eapOwner.begin(s_sta,s_ap,100,1000));
    security.cachedGeneration=12;security.pairUpdateReply=security.ptkUpdatePending=true;security.ptkUpdateGeneration=7;security.ptkUpdateSince=100;
    memset(d._nativeJoin.key,0x7d,sizeof(d._nativeJoin.key));
    memcpy(d._nativeJoin.bssid,s_ap,6);
    security.cancelPairwiseAttempt();
    assert(!security.replyPending && !security.replyLength && !security.pairDeadline);
    for(auto byte:security.reply)assert(!byte);
    // Cancellation only removes the candidate response, not pending committed
    // key operations or readiness. Full teardown below still retires everything.
    assert(security.ready && security.keysPending && security.authorizePending);
    assert(security.profile.generation()==profileGeneration);
    assert(!security.retireForRoam(0) && !security.retireForRoam(profileGeneration+1));
    assert(security.ready && security.keysPending && security.authorizePending);
    assert(security.retireForRoam(profileGeneration));
    assert(security.profile.generation()==profileGeneration);
    assert(!security.ready && !security.keysPending && !security.authorizePending);
    assert(!security.eapOwner.generation());
    assert(!security.pairUpdateReply && !security.ptkUpdatePending && !security.ptkUpdateGeneration && !security.ptkUpdateSince);
    for(auto v:security.keys)assert(!v);
    for(auto v:security.reply)assert(!v);
    AirportWCL::JoinRequest transfer{};
    assert(security.profile.snapshot(profileGeneration,s_sta,reinterpret_cast<const UInt8 *>("test"),4,NativeJoinAuth::PSKSHA256,transfer));
    assert(transfer.keyLength==32 && !memcmp(transfer.key,s_pmk,32));
    AthSecurity::wipe(&transfer,sizeof(transfer));
    d.discardNativeSecurity();
    assert(!security.profile.generation() && !security.retireForRoam(profileGeneration));
    AthSecurity::Supplicant<Ath10kKernelCrypto,true> pristine;pristine.reset();
    assert(!memcmp(&security.supplicant,&pristine,sizeof(pristine)));
    for(auto v:security.reply)assert(!v);
    for(auto v:security.keys)assert(!v);
    for(auto v:d._nativeJoin.key)assert(!v);
    assert(!security.ready && !security.replyPending && !security.keysPending && !security.authorizePending);
    assert(!security.replyLength && !security.keyOperation && !security.pairDeadline);
    // Nonsecret association metadata survives until terminal event acceptance.
    assert(!memcmp(d._nativeJoin.bssid,s_ap,6) && security.cachedGeneration==12);
    d.discardNativeSecurity();
    assert(!memcmp(&security.supplicant,&pristine,sizeof(pristine)));
    d._nativeSecurity=nullptr;d.discardNativeSecurity();
}

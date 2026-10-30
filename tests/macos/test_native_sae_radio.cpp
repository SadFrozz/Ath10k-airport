#define ATH10K_NATIVE_KEY_STAGE_TEST
#define ATH10K_NATIVE_REAL_SAE
#include "test_native_pmf_receive.cpp"
#include "../fixtures/sae_eapol_vectors.inc"
#include "../fixtures/sha256_vectors.inc"
#include "../fixtures/rsnxe_eapol_vectors.inc"
#include "../fixtures/p256_corecrypto_fixtures.hpp"
#include "../fixtures/h2e_password_vectors.inc"
#include "../fixtures/legacy_password_vectors.inc"
#include <dlfcn.h>
#include <cstdio>
using API=AthSecurity::P256CoreCryptoAPI;
static API api;
static AthSecurity::P256FieldAPI admissionField;
static bool admissionBackendReady=true;
struct Ath10kNativeSAEKernelBackend {
 static bool providers(API &p,AthSecurity::P256FieldAPI &f){
  p={};f={};if(!admissionBackendReady)return false;p=api;f=admissionField;return true;
 }
};
using IOReturn=int;
constexpr int kIOReturnSuccess=0,kIOReturnBadArgument=1,kIOReturnNotReady=2,kIOReturnUnsupported=3,kIOReturnBusy=4;
#include "../../src/macos/native/Ath10kNativeSAEJoinStart.hpp"
#include "../../src/macos/native/Ath10kNativeMAC.hpp"
#include "../../src/macos/native/Ath10kNativeProfile.hpp"
#include "native_join_request.inc"
#include "native_security_snapshot.inc"
#include <Airport/apple80211_var.h>
#include "native_eap_callback.inc"
#include "native_eap_service.inc"
#include "native_eap_integration_completion.inc"
#include "../fixtures/eap_vectors.inc"

static uint8_t pwe[64]{},randomScalar[32]{},mask[32]{};
static AthSecurity::SAEGroup19AuthMessage request;
struct HMAC {static bool hmac256(const uint8_t *k,size_t kl,const uint8_t *d,size_t n,uint8_t *o){CCHmac(kCCHmacAlgSHA256,k,kl,d,n,o);return true;}};
static std::vector<uint8_t> apFrame(const AthSecurity::SAEGroup19AuthMessage &m){
 std::vector<uint8_t> f(1536);f[0]=0xb0;memcpy(f.data()+4,w_sta,6);memcpy(f.data()+10,w_ap,6);memcpy(f.data()+16,w_ap,6);
 size_t n=0;assert(AthSecurity::encodeSAEGroup19AuthBody(m,f.data()+24,f.size()-24,n));f.resize(n+24);return f;
}
static Ath10kPCIDevice *device(){
 nativeSAEClockMS=0;auto d=new Ath10kPCIDevice;auto &s=d->_connection;
 s.ssidLength=4;memcpy(s.ssid,"TEST",4);s.ap.ssidLength=4;memcpy(s.ap.ssid,s.ssid,4);
 s.ap.privacy=s.ap.rsnPresent=s.ap.ratesValid=true;s.ap.capabilities=0x11;s.ap.beaconInterval=100;
 s.ap.rateCount=4;const uint8_t rates[]={0x82,0x84,0x8b,0x96};memcpy(s.ap.rates,rates,4);
 s.ap.rxChannel=s.ap.advertisedChannel=s.operatingChannel=s.centerChannel=6;
 assert(!Ath10k::configureRegulatory(s.regulatory,0x64,2300,3000,4800,5925));
 s.stage=Ath10k::LinkStage::Auth;s.securityAKM=8;s.secure=s.pmfRequired=s.pmfQoSTransported=true;s.groupCipher=4;
 memcpy(s.local,w_sta,6);memcpy(s.bssid,w_ap,6);memcpy(s.ap.bssid,w_ap,6);memcpy(s.ap.rsn,w_rsn,sizeof(w_rsn));s.ap.rsnLength=sizeof(w_rsn);
 d->_nativeJoinPending=true;for(auto &q:d->_wmiRadio)q.completed=q.txConsumed=q.creditReturned=true;
 auto sec=d->_nativeSecurity=new Ath10kPCIDevice::NativeSecurity;assert(sec->prepareSAEWorker());
 sec->saeSession=new Ath10kSAESession;assert(sec->saeSession->initPrepared(api,randomScalar,32,pwe,64,request,w_sta,w_ap,301,0));
 sec->saeRadio=new Ath10kSAERadio;assert(sec->saeRadio->bind(sec->saeSession,sec->saeWorker,301,0));
 sec->pmfSession=new Ath10kPMFSession;assert(sec->pmfSession->initConnection(w_sta,w_ap,301));return d;
}
static const char *tick(Ath10kPCIDevice *d,uint64_t now){nativeSAEClockMS=now;ownerGate=true;const auto e=d->serviceNativeSAE(now);ownerGate=false;return e;}
static void retired(Ath10kPCIDevice *d){d->_connection.txOwned=false;d->_connection.txComplete=true;d->_connection.txStatus=0;}
static unsigned passwordRandomCalls=0;
static bool passwordRandom(uint8_t *out,size_t n){
 assert(!ownerGate && !heldLocks && n && n<=64);memset(out,0,n);out[n-1]=uint8_t(passwordRandomCalls++%2?3:7);return true;
}
static std::vector<uint8_t> unhex(const char *text){
 std::vector<uint8_t> out(strlen(text)/2);for(size_t i=0;i<out.size();++i){unsigned v=0;assert(sscanf(text+2*i,"%2x",&v)==1);out[i]=uint8_t(v);}return out;
}
static void passwordPreparationTests(const AthSecurity::P256FieldAPI &field){
 for(bool h2e:{false,true}){
  const auto &hv=H2EPasswordVectors::vectors[2];const auto &lv=LegacyPasswordVectors::vectors[1];
  auto name=h2e?unhex(hv.ssid):unhex("746573742d73736964");auto password=unhex(h2e?hv.password:lv.password);
  auto expectedPWE=unhex(h2e?hv.pwe:lv.pwe),expectedCommit=unhex(h2e?hv.commit:lv.commit);
  for(unsigned scenario=0;scenario<9;++scenario){auto d=device();auto sec=d->_nativeSecurity;auto &s=d->_connection;
   auto ap=s.ap;auto regulatory=s.regulatory;sec->reset();Ath10k::resetDisconnected(s);
   s.stage=Ath10k::LinkStage::Disabled;d->_nativeJoinPending=false;d->_regulatory=regulatory;
   memcpy(d->_nativeMACCurrent,w_sta,6);ap.ssidLength=uint8_t(name.size());memcpy(ap.ssid,name.data(),name.size());
   if(h2e){memcpy(ap.rsnxe,x_rsnxe,sizeof(x_rsnxe));ap.rsnxeLength=sizeof(x_rsnxe);}
   sec->candidates.add(ap,0);admissionField=field;nativePasswordRandom=passwordRandom;passwordRandomCalls=0;
   std::array<uint8_t,0x2cc> input{};
   auto u32=[&](size_t at,uint32_t value){Ath10k::htcWriteLE32(input.data()+at,value);};
   u32(0x10,1);u32(0x14,1u<<12);u32(0x1c,uint32_t(name.size()));memcpy(input.data()+0x20,name.data(),name.size());
   u32(0x44,uint32_t(password.size()));u32(0x48,10);memcpy(input.data()+0x50,password.data(),password.size());
   u32(0x214,1);memcpy(input.data()+0x21c,w_ap,6);Ath10k::htcWriteLE16(input.data()+0x228,0x1006);
   unsigned expectedGeneration=1;
   if(!scenario){
    const auto valid=input;auto worker=sec->saeWorker;const auto cached=sec->candidates;
    for(unsigned bad=0;bad<27;++bad){
     int expected=kIOReturnNotReady;
     switch(bad){
      case 0:d->experimentalSAE=false;expected=kIOReturnUnsupported;break;
      case 1:admissionBackendReady=false;expected=kIOReturnUnsupported;break;
      case 2:d->_nativeRadioOn=false;break;case 3:d->blocked=true;break;
      case 4:d->_wmiEvents.rfKill=true;break;case 5:d->_networkEnabled=false;break;
      case 6:d->_nativeJoinPending=true;expected=kIOReturnBusy;break;
      case 7:d->_nativeScanPending=true;expected=kIOReturnBusy;break;
      case 8:d->_nativeAbortRequested=true;expected=kIOReturnBusy;break;
      case 9:d->_nativeWasUp=true;expected=kIOReturnBusy;break;
      case 10:d->_nativeLinkUpSent=true;expected=kIOReturnBusy;break;
      case 11:d->_wmiScan.completed=false;expected=kIOReturnBusy;break;
      case 12:s.stage=Ath10k::LinkStage::Auth;expected=kIOReturnBusy;break;
      case 13:Ath10k::htcWriteLE16(input.data()+0x4c,1);expected=kIOReturnUnsupported;break;
      case 14:Ath10k::htcWriteLE16(input.data()+0x4e,1);expected=kIOReturnUnsupported;break;
      case 15:sec->candidates.bss.count=0;expected=kIOReturnUnsupported;break;
      case 16:sec->saeWorker=nullptr;break;
      case 17:sec->nextSAEGeneration=0xffffffffu;break;
      case 18:d->_wmiRadio[Ath10k::kWMIPMFQoSIndex].txConsumed=false;break;
      case 19:s.wmiOwned=true;expected=kIOReturnBusy;break;
      case 20:s.txOwned=true;expected=kIOReturnBusy;break;
      case 21:s.dataPending=1;expected=kIOReturnBusy;break;
      case 22:s.peerCount=1;expected=kIOReturnBusy;break;
      case 23:s.pmfTXPending=true;expected=kIOReturnBusy;break;
      case 24:d->_wmiScan.txOwned=true;expected=kIOReturnBusy;break;
      case 25:d->_wmi.credits.outstanding=1;expected=kIOReturnBusy;break;
      case 26:failObjectInit=true;break; // PMF initialization failure consumes its identity.
     }
     ownerGate=true;assert(d->nativeJoinRequest(input.data())==expected);ownerGate=false;
     assert(!sec->saePreparation.active() && !sec->pmfSession && !sec->saeSession && !sec->saeRadio && !sec->ready);
     if(bad==26){assert(sec->nextSAEGeneration==1);sec->reset();assert(sec->nextSAEGeneration==1);expectedGeneration=2;}
     else if(bad==17){assert(sec->nextSAEGeneration==0xffffffffu);sec->nextSAEGeneration=0;}
     else assert(sec->nextSAEGeneration==0);
     input=valid;d->experimentalSAE=admissionBackendReady=d->_nativeRadioOn=d->_networkEnabled=d->_wmiScan.completed=true;
     d->blocked=d->_wmiEvents.rfKill=d->_nativeJoinPending=d->_nativeScanPending=d->_nativeAbortRequested=d->_nativeWasUp=d->_nativeLinkUpSent=false;
     s.wmiOwned=s.txOwned=s.pmfTXPending=d->_wmiScan.txOwned=false;
     s.dataPending=s.peerCount=d->_wmi.credits.outstanding=0;
     s.stage=Ath10k::LinkStage::Disabled;sec->saeWorker=worker;sec->candidates=cached;
     d->_wmiRadio[Ath10k::kWMIPMFQoSIndex].txConsumed=true;
    }
   }
   // The internal entry point must validate bounds independently of the wire
   // decoder and consume secret copies on rejected, stopped and accepted paths.
   if(!scenario)for(unsigned bad=0;bad<6;++bad){
    AirportWCL::JoinRequest decoded{};assert(AirportWCL::decodeJoin(input.data(),input.size(),decoded));
    int expected=kIOReturnBadArgument;
    switch(bad){case 0:decoded.ssidLength=33;break;case 1:decoded.keyLength=65;break;
     case 2:decoded.rsnLength=258;break;case 3:decoded.bssid[0]=1;break;
     case 4:d->_nativeStopping=true;expected=kIOReturnNotReady;break;
     case 5:s.wmiOwned=true;expected=kIOReturnBusy;break;}
    const auto stateBefore=s;
    ownerGate=true;assert(d->nativeBeginJoin(decoded)==expected);ownerGate=false;
    for(auto byte:reinterpret_cast<const unsigned char (&)[sizeof(decoded)]>(decoded))assert(!byte);
    assert(!memcmp(&stateBefore,&s,sizeof(s)) && !sec->saePreparation.active());
    d->_nativeStopping=false;s.wmiOwned=false;
   }
   const auto original=input;const auto ownerRandomBefore=nativeOwnerRandomCalls;ownerGate=true;
   if(scenario&1){
    AirportWCL::JoinRequest decoded{};assert(AirportWCL::decodeJoin(input.data(),input.size(),decoded));
    // Exercise the real preparation -> common admission -> crypto path. The
    // retained profile belongs to a different former AP with the same SSID.
    decoded.bssid[5]^=1;auto &retained=sec->profile;
    assert(retained.replace(decoded,w_sta,true));
    auto oldLink=s;oldLink.secure=oldLink.pmfRequired=true;oldLink.securityAKM=8;
    oldLink.regulatory=regulatory;oldLink.ssidLength=decoded.ssidLength;
    memcpy(oldLink.ssid,decoded.ssid,decoded.ssidLength);memcpy(oldLink.local,w_sta,6);memcpy(oldLink.bssid,decoded.bssid,6);
    NativeReassocRequest roam{};roam.ssidLength=decoded.ssidLength;memcpy(roam.ssid,decoded.ssid,decoded.ssidLength);memcpy(roam.bssid,w_ap,6);
    auto &pending=sec->preparedRoam;AthSecurity::wipe(&decoded,sizeof(decoded));
    assert(pending.prepare(retained,oldLink,roam,sec->candidates,0));
    if(scenario==1){
     // Terminal cancellation must destroy the controller-owned secret copy,
     // not merely make a later take fail its generation check.
     AirportWCL::JoinRequest saved{};
     assert(retained.snapshot(retained.generation(),w_sta,oldLink.ssid,oldLink.ssidLength,NativeJoinAuth::SAE,saved));
     sec->reset();assert(!pending.generation() && !retained.generation());
     assert(!pending.take(retained,w_sta,1,decoded));
     assert(retained.replace(saved,w_sta,true));AthSecurity::wipe(&saved,sizeof(saved));
     assert(pending.prepare(retained,oldLink,roam,sec->candidates,0));
    }
    s=oldLink;s.stage=Ath10k::LinkStage::Connected;s.portAuthorized=true;
    d->_nativeWasUp=d->_nativeLinkUpSent=true;
    std::array<uint8_t,188> wire{};memcpy(wire.data()+0x64,w_ap,6);
    Ath10k::htcWriteLE32(wire.data()+0x90,1);wire[0xb9]=oldLink.ssidLength;memcpy(wire.data()+0x99,oldLink.ssid,oldLink.ssidLength);
    assert(d->nativeRoamRequest(wire.data())==kIOReturnSuccess);
    assert(d->_nativeRoamPending && d->nativeRoamRequest(wire.data())==kIOReturnBusy);
    assert(d->nativeJoinRequest(input.data())==kIOReturnBusy);
    const auto delivery=sec->roamDelivery.generation();
    auto post=[](uint32_t,void *,size_t){return true;};
    assert(sec->roamDelivery.sendStart(delivery,post) && sec->roamDelivery.sendPrep(delivery,post));
    s.txOwned=true;
    assert(d->nativeDisconnectForRoam(0)==kIOReturnBusy && !sec->roamRetirement && s.portAuthorized);
    s.txOwned=false;sec->keysPending=true;
    assert(d->nativeDisconnectForRoam(0)==kIOReturnBusy && !sec->roamRetirement && s.portAuthorized);
    sec->keysPending=false;d->_wmiScan.completed=false;
    assert(d->nativeDisconnectForRoam(0)==kIOReturnBusy && !sec->roamRetirement && s.portAuthorized);
    d->_wmiScan.completed=true;
    assert(d->nativeDisconnectForRoam(0)==kIOReturnSuccess);
    assert(s.disconnect==Ath10k::DisconnectStage::Drain && !s.portAuthorized && !d->linkUp);
    assert(d->_nativeWasUp && d->_nativeLinkUpSent && d->nativeRetainSystemLink()); // Preserve WCL and BSD publication.
    assert(d->nativeContinueRoam(1)==kIOReturnBusy);
    Ath10k::resetDisconnected(s); // Firmware teardown is separately exercised by reconnect tests.
    const auto preparedGeneration=pending.generation();
    for(unsigned held=0;held<8;++held){
     if(held==0)d->_rxSetup.pendingMPDUs=1;
     if(held==1)s.vdevStarted=true;
     if(held==2)s.vdevStartIssued=true;
     if(held==3)s.peerCreateIssued=true;
     if(held==4)d->_wmiScan.txOwned=true;
     if(held==5)s.dataPending=1;
     if(held==6)d->_wmi.credits.outstanding=1;
     if(held==7)s.disconnect=Ath10k::DisconnectStage::Barrier;
     assert(d->nativeContinueRoam(1)==kIOReturnBusy && pending.generation()==preparedGeneration);
     assert(retained.generation()==preparedGeneration && !sec->saePreparation.active());
     d->_rxSetup.pendingMPDUs=0;s.vdevStarted=s.vdevStartIssued=s.peerCreateIssued=false;
     d->_wmiScan.txOwned=false;s.dataPending=0;d->_wmi.credits.outstanding=0;
     s.disconnect=Ath10k::DisconnectStage::None;
    }
    assert(d->nativeContinueRoam(1)==kIOReturnSuccess && !pending.generation() && !sec->roamRetirement);
    d->_nativeRoamPending=0; // The production notification dispatcher performs this transfer.
    assert(d->_nativeRoamJoinGeneration==delivery && !memcmp(s.bssid,w_ap,6));
    uint8_t cacheRequest[128]{};cacheRequest[0x7b]=cacheRequest[0x7c]=1;
    assert(d->nativeRoamCacheRequest(cacheRequest)==kIOReturnSuccess);
    cacheRequest[0x7a]=1;assert(d->nativeRoamCacheRequest(cacheRequest)==kIOReturnUnsupported);
    assert(d->nativeContinueRoam(1)==kIOReturnNotReady); // Already consumed.
    for(auto byte:reinterpret_cast<const unsigned char (&)[sizeof(decoded)]>(decoded))assert(!byte);
   }else assert(d->nativeJoinRequest(input.data())==kIOReturnSuccess);
   ownerGate=false;
   AirportWCL::JoinRequest retainedCheck{};
   assert(sec->profile.generation() && sec->profile.snapshot(sec->profile.generation(),s.local,s.ssid,s.ssidLength,NativeJoinAuth::SAE,retainedCheck));
   AirportWCL::JoinRequest originalCheck{};assert(AirportWCL::decodeJoin(original.data(),original.size(),originalCheck));
   assert(retainedCheck.keyLength==originalCheck.keyLength && !memcmp(retainedCheck.key,originalCheck.key,originalCheck.keyLength));
   AthSecurity::wipe(&retainedCheck,sizeof(retainedCheck));AthSecurity::wipe(&originalCheck,sizeof(originalCheck));
   assert(nativeOwnerRandomCalls==ownerRandomBefore && input==original && !passwordRandomCalls && s.securityAKM==8 && s.secure && s.pmfRequired);
   assert(s.stage==Ath10k::LinkStage::Scan && sec->nextSAEGeneration==expectedGeneration && sec->pmfSession && sec->saePreparation.active());
   assert(!sec->saeRadio && !sec->saeSession && !sec->ready && d->_nativeJoinPending);
   for(auto value:d->_nativeJoin.key)assert(!value);
   input.fill(0);s.stage=Ath10k::LinkStage::Auth; // Common firmware progression, not another request.
   ownerGate=true;assert(!d->advanceSAEAuth(0));ownerGate=false;
   assert(sec->saePreparation.active() && !sec->saeRadio && !sec->saeSession && d->transmitted.empty() && !s.authReply);
   if(scenario){
    if(scenario==1)s.ap.rsn[20]^=1;
    if(scenario==2)s.cancelRequested=true;
    if(scenario==3)d->_nativeRadioOn=false;
    if(scenario==4)s.bssid[5]^=1;
    if(scenario==5){sec->pmfSession->cancel();sec->pmfSession->release();sec->pmfSession=new Ath10kPMFSession;assert(sec->pmfSession->initConnection(w_sta,w_ap,302));}
    if(scenario==6)d->blocked=true;
    if(scenario==7){run(latest);s.ssid[0]^=1;} // Completed work cannot bypass current-profile validation.
    // Fail through the real common Auth caller, which resets retained owners.
    ownerGate=true;assert(!d->advanceSAEAuth(scenario==8?5000:1));ownerGate=false;assert(s.cancelRequested && d->saeDiscards==1);
    assert(!sec->profile.generation() && !sec->saePreparation.active() && !sec->saeRadio && !sec->saeSession && d->transmitted.empty());stop(d);continue;
   }
   run(latest);assert(!tick(d,1));assert(!sec->saePreparation.active() && sec->saeRadio && sec->saeSession);
   assert(sec->saeSession->usingH2E()==h2e && d->transmitted.size()==1 && !s.authReply && !sec->ready);
   AthSecurity::SAEGroup19AuthMessage localCommit;auto &wire=d->transmitted[0];
   assert(AthSecurity::decodeSAEGroup19AuthBody(wire.data()+24,wire.size()-24,h2e,0,localCommit)==AthSecurity::SAEWireResult::Valid);
   assert(!memcmp(localCommit.commit,expectedCommit.data(),96));
   AthSecurity::P256CoreCryptoCandidate engine(api);AthSecurity::P256CoreCryptoWorkspace workspace;
   uint8_t peerRandom[32]{},peerMask[32]{};peerRandom[31]=11;peerMask[31]=5;auto remote=localCommit;
   assert(AthSecurity::saeGroup19Commit(engine,peerRandom,peerMask,32,expectedPWE.data(),64,remote.commit,96,workspace));
   AthSecurity::SAEGroup19Keys peerKeys{};
   assert(AthSecurity::saeGroup19ExchangeCandidate<HMAC>(engine,peerRandom,32,remote.commit,96,localCommit.commit,96,expectedPWE.data(),64,h2e,w_ap,w_sta,nullptr,0,nullptr,0,peerKeys,workspace));
   retired(d);nativeSAEClockMS=2;const auto peerWire=apFrame(remote);assert(deliver(d,peerWire.data(),peerWire.size()));
   assert(!tick(d,2));run(latest);assert(!tick(d,3));run(latest);assert(!tick(d,4) && d->transmitted.size()==2);
   AthSecurity::SAEGroup19AuthMessage remoteConfirm{};remoteConfirm.kind=AthSecurity::SAEAuthKind::Confirm;remoteConfirm.h2e=h2e;remoteConfirm.confirm[0]=1;
   assert(AthSecurity::saeGroup19Confirm<HMAC>(peerKeys.kck,32,1,remote.commit,96,localCommit.commit,96,remoteConfirm.confirm+2,32));
   const auto confirmWire=apFrame(remoteConfirm);nativeSAEClockMS=5;assert(deliver(d,confirmWire.data(),confirmWire.size()));
   assert(!tick(d,5));run(latest);assert(!tick(d,6) && !sec->ready && !s.authReply);retired(d);
   assert(!tick(d,7) && sec->ready && s.authReply);using S=AthSecurity::Supplicant<Ath10kKernelCrypto,true,true,true>;
   assert(sec->supplicant.receive(w_m1,sizeof(w_m1))==S::Reply);
   // The M2 MIC must use this freshly authenticated peer PMK, not the old fixture PMK.
   uint8_t context[76]{},ptk[48]{},mic[16]{};memcpy(context,w_sta,6);memcpy(context+6,w_ap,6);
   const uint8_t *nonce=sec->supplicant.output+31,*anonce=w_m1+31;
   const bool first=memcmp(nonce,anonce,32)<0;memcpy(context+12,first?nonce:anonce,32);memcpy(context+44,first?anonce:nonce,32);
   assert(AthSecurity::SHA256Personal<PersonalTestCrypto>::derive(peerKeys.pmk,context,ptk));
   auto eapol=std::vector<uint8_t>(sec->supplicant.output+14,sec->supplicant.output+sec->supplicant.outputLength);
   memset(eapol.data()+81,0,16);assert(AthSecurity::SHA256Personal<PersonalTestCrypto>::mic(ptk,eapol.data(),eapol.size(),mic));
   assert(!memcmp(mic,sec->supplicant.output+95,16));AthSecurity::wipe(ptk,sizeof(ptk));AthSecurity::wipe(&peerKeys,sizeof(peerKeys));stop(d);
  }
 }
}
static void securitySnapshotTests(){
 auto d=device();auto sec=d->_nativeSecurity;auto &s=d->_connection;
 sec->pmfRXVerified=3;sec->pmfRXDropped=4;sec->pmfTXSubmitted=5;sec->pmfTXDropped=6;sec->pmfQuerySucceeded=2;
 ownerGate=true;d->publishNativeSecurityState(123);ownerGate=false;
 assert(d->numericProperties["Ath10kNativeSelectedAKM"]==8 && !d->numericProperties["Ath10kNativePMFPortReady"]);
 s.stage=Ath10k::LinkStage::Connected;s.portAuthorized=true;s.pairInstalled=true;s.securityPhase=5;
 assert(!sec->pmfSession->portReady());
 assert(sec->pmfSession->acknowledgePairwise(c_key,w_sta,w_ap));assert(!sec->pmfSession->portReady());
 AthSecurity::IGTKCMAC128 key{};key.keyID=4;memcpy(key.key,c_key,16);assert(sec->pmfSession->activateManagement(key));assert(!sec->pmfSession->portReady());
 assert(sec->pmfSession->authorize() && sec->pmfSession->portReady());
 ownerGate=true;d->publishNativeSecurityState(124);ownerGate=false;
 assert(d->numericProperties["Ath10kNativePMFPortReady"] && d->numericProperties["Ath10kNativePMFGeneration"]==301 && d->numericProperties["Ath10kNativePMFPairwiseEpoch"]);
 assert(d->numericProperties["Ath10kNativePMFVerifiedRX"]==3 && d->numericProperties["Ath10kNativePMFSubmittedTX"]==5 && d->numericProperties["Ath10kNativePMFQueriesSucceeded"]==2);
 const auto writes=d->propertyWrites;ownerGate=true;d->publishNativeSecurityState(125);ownerGate=false;assert(d->propertyWrites==writes);
 sec->pmfRXVerified=4;ownerGate=true;d->publishNativeSecurityState(126);ownerGate=false;assert(d->propertyWrites==writes);
 ownerGate=true;d->publishNativeSecurityState(624);ownerGate=false;assert(d->numericProperties["Ath10kNativePMFVerifiedRX"]==4 && d->propertyWrites>writes);
 s.cancelRequested=true;ownerGate=true;d->publishNativeSecurityState(625);ownerGate=false;
 assert(!d->numericProperties["Ath10kNativeSelectedAKM"] && !d->numericProperties["Ath10kNativePMFPortReady"]);
 sec->reset();assert(!sec->pmfSession);ownerGate=true;d->publishNativeSecurityState(626);ownerGate=false;
 assert(!d->numericProperties["Ath10kNativePMFGeneration"] && !d->numericProperties["Ath10kNativePMFPairwiseEpoch"]);
 for(const auto &p:d->numericProperties)assert(p.first.find("Password")==std::string::npos && p.first.find("SSID")==std::string::npos);
 stop(d);
}
static void pskPasswordAdmissionTests(){
 nativePasswordRandom=nullptr;
 for(unsigned scenario=0;scenario<7;++scenario){auto d=device();auto sec=d->_nativeSecurity;auto &s=d->_connection;
  auto ap=s.ap;d->_regulatory=s.regulatory;sec->reset();Ath10k::resetDisconnected(s);s.stage=Ath10k::LinkStage::Disabled;d->_nativeJoinPending=false;
  memcpy(d->_nativeMACCurrent,s_sta,6);ap.ssidLength=4;memcpy(ap.ssid,"IEEE",4);memcpy(ap.rsn,s_rsn,sizeof(s_rsn));ap.rsnLength=sizeof(s_rsn);sec->candidates.add(ap,0);
  std::array<uint8_t,0x2cc> input{};auto u32=[&](size_t at,uint32_t value){Ath10k::htcWriteLE32(input.data()+at,value);};
  u32(0x10,1);u32(0x14,1024);u32(0x1c,4);memcpy(input.data()+0x20,"IEEE",4);u32(0x44,8);u32(0x48,10);memcpy(input.data()+0x50,"password",8);
  u32(0x210,0x40000004);u32(0x214,1);memcpy(input.data()+0x21c,s_ap,6);Ath10k::htcWriteLE16(input.data()+0x228,0x1006);
  const auto before=nativeHMACCalls,randomBefore=nativeOwnerRandomCalls;ownerGate=true;assert(d->nativeJoinRequest(input.data())==kIOReturnSuccess);ownerGate=false;
  assert(nativeHMACCalls==before && nativeOwnerRandomCalls==randomBefore && sec->pskPreparation.active() && !sec->ready && !sec->pmfSession && !s.pmfRequired && s.securityAKM==6);
  for(auto value:d->_nativeJoin.key)assert(!value);input.fill(0);s.stage=Ath10k::LinkStage::Auth;
  ownerGate=true;assert(!d->advanceSAEAuth(0));ownerGate=false;assert(!s.cancelRequested && d->transmitted.empty());
  if(scenario==1){ownerGate=true;sec->reset();ownerGate=false;assert(!sec->pskPreparation.active());stop(d);continue;}
  if(scenario==2){s.ssid[0]^=1;}if(scenario==3){s.securityAKM=2;}if(scenario==4){++sec->nextSAEGeneration;}
  if(scenario==5){nativeSAEClockMS=5000;ownerGate=true;assert(!d->advanceSAEAuth(5000));ownerGate=false;assert(s.cancelRequested && !sec->ready && !sec->pskPreparation.active());stop(d);continue;}
  if(scenario==6){sec->saeWorker->cancel();}
  else run(latest);
  ownerGate=true;const bool ready=d->advanceSAEAuth(1);ownerGate=false;
  if(scenario){assert(!ready && s.cancelRequested && !sec->ready && !sec->pskPreparation.active());stop(d);continue;}
  assert(ready && sec->ready && !sec->pskPreparation.active() && !s.cancelRequested && nativeHMACCalls-before==8192);
  using Supplicant=AthSecurity::Supplicant<Ath10kKernelCrypto,true,true,true>;
  assert(sec->supplicant.receive(s_m1,sizeof(s_m1))==Supplicant::Reply);
  assert(sec->supplicant.outputLength==sizeof(s_m2) && !memcmp(sec->supplicant.output,s_m2,sizeof(s_m2)));stop(d);
 }
}
int main(){
 void *lib=dlopen("/usr/lib/system/libcorecrypto.dylib",RTLD_NOW|RTLD_LOCAL);assert(lib);
#define LOAD(field,name) api.field=reinterpret_cast<decltype(api.field)>(dlsym(lib,name));assert(api.field)
 LOAD(curve,"ccec_cp_256");LOAD(importPoint,"ccec_x963_import_pub");LOAD(validatePoint,"ccec_validate_pub");LOAD(exportPoint,"ccec_x963_export");
 LOAD(project,"ccec_projectify");LOAD(affine,"ccec_affinify");LOAD(multiply,"ccec_mult_blinded");LOAD(add,"ccec_full_add");
 LOAD(subtract,"ccec_full_sub");LOAD(readScalar,"ccn_read_uint");LOAD(rng,"ccrng");
#undef LOAD
 for(unsigned i=0;i<64;++i){unsigned v=0;assert(sscanf(P256Fixtures::generator+2*i,"%2x",&v)==1);pwe[i]=uint8_t(v);}
 randomScalar[31]=7;mask[31]=3;AthSecurity::P256CoreCryptoCandidate engine(api);AthSecurity::P256CoreCryptoWorkspace workspace;
 request.kind=AthSecurity::SAEAuthKind::Commit;request.h2e=false;
 assert(AthSecurity::saeGroup19Commit(engine,randomScalar,mask,32,pwe,64,request.commit,96,workspace));
 uint8_t peerRandom[32]{},peerMask[32]{};peerRandom[31]=11;peerMask[31]=5;
 auto peer=request;assert(AthSecurity::saeGroup19Commit(engine,peerRandom,peerMask,32,pwe,64,peer.commit,96,workspace));
 AthSecurity::SAEGroup19Keys keys;assert(AthSecurity::saeGroup19ExchangeCandidate<HMAC>(engine,peerRandom,32,peer.commit,96,request.commit,96,pwe,64,true,w_ap,w_sta,nullptr,0,nullptr,0,keys,workspace));
 AthSecurity::SAEGroup19AuthMessage confirmation{};confirmation.kind=AthSecurity::SAEAuthKind::Confirm;confirmation.h2e=false;confirmation.confirm[0]=1;
 assert(AthSecurity::saeGroup19Confirm<HMAC>(keys.kck,32,1,peer.commit,96,request.commit,96,confirmation.confirm+2,32));
 const auto peerWire=apFrame(peer),confirmWire=apFrame(confirmation);
 {auto d=device();auto sec=d->_nativeSecurity;
  auto open=std::vector<uint8_t>(30);open[0]=0xb0;memcpy(open.data()+4,w_sta,6);memcpy(open.data()+10,w_ap,6);memcpy(open.data()+16,w_ap,6);open[26]=2;
  assert(deliver(d,open.data(),open.size()) && !d->_connection.authReply);
  ownerGate=true;assert(!d->advanceSAEAuth(0));ownerGate=false;
  assert(d->transmitted.size()==1 && d->transmitted[0][24]==3 && d->transmitted[0][26]==1);
  assert(!d->_connection.authReply && !sec->ready);retired(d);
  nativeSAEClockMS=1;assert(deliver(d,peerWire.data(),peerWire.size()));assert(!tick(d,1));run(latest);
  assert(!tick(d,2));run(latest);d->_wmiScan.completed=false;
  assert(!tick(d,3) && d->transmitted.size()==1);d->_wmiScan.completed=true;
  assert(!tick(d,4) && d->transmitted.size()==2 && d->transmitted[1][26]==2);
  nativeSAEClockMS=5;assert(deliver(d,confirmWire.data(),confirmWire.size()));assert(!tick(d,5));run(latest);
  assert(!tick(d,6) && !d->_connection.authReply && !sec->ready); // HTT/CE ownership remains live.
  d->_connection.txComplete=true;assert(!tick(d,7) && !d->_connection.authReply);
  retired(d);nativeSAEClockMS=8;ownerGate=true;assert(d->advanceSAEAuth(8));ownerGate=false;
  assert(d->_connection.authReply && sec->ready);
  uint8_t association[256]{};auto &s=d->_connection;
  assert(!Ath10k::buildStationManagement(association,sizeof(association),s));
  Ath10k::CandidateConfiguration candidate;assert(!Ath10k::prepareBSSCandidate(s,s.ap,candidate));
  auto transition=s.ap;std::vector<uint8_t> mixed(w_rsn,w_rsn+sizeof(w_rsn));
  mixed.insert(mixed.begin()+16,{0,15,172,2});mixed[14]=2;mixed[1]=uint8_t(mixed.size()-2);
  memcpy(transition.rsn,mixed.data(),mixed.size());transition.rsnLength=uint16_t(mixed.size());
  assert(!Ath10k::prepareBSSCandidate(s,transition,candidate) && s.securityAKM==8);
  s.pmfRequired=false;assert(Ath10k::prepareBSSCandidate(s,transition,candidate));s.pmfRequired=true;
  auto badAP=s.ap;memcpy(badAP.rsn,AthSecurity::stationRSN,sizeof(AthSecurity::stationRSN));badAP.rsnLength=sizeof(AthSecurity::stationRSN);
  assert(Ath10k::prepareBSSCandidate(s,badAP,candidate));
  s.stage=Ath10k::LinkStage::Assoc;assert(!Ath10k::buildStationManagement(association,sizeof(association),s));
  assert(d->buildNativeSAEAssociation(association,sizeof(association)));
  d->_nativeRadioOn=false;assert(!d->buildNativeSAEAssociation(association,sizeof(association)));d->_nativeRadioOn=true;
  d->_networkEnabled=false;assert(!d->buildNativeSAEAssociation(association,sizeof(association)));d->_networkEnabled=true;
  const auto associationBytes=d->buildNativeSAEAssociation(association,sizeof(association));
  size_t rsnAt=0;for(size_t at=28;at<associationBytes;at+=size_t(association[at+1])+2)if(association[at]==48)rsnAt=at;
  assert(rsnAt && association[rsnAt+1]==42 && AthSecurity::validSAEStationRSN(association+rsnAt,44));
  uint8_t station[44]{};size_t stationBytes=0;assert(sec->supplicant.copyAssociationRSN(station,sizeof(station),stationBytes));
  assert(stationBytes==44 && !memcmp(station,association+rsnAt,44) && !memcmp(station+24,w_pmkid,16));
  auto malformed=std::array<uint8_t,44>{};memcpy(malformed.data(),station,44);malformed[20]=0x80;
  assert(!Ath10k::buildStationManagement(association,sizeof(association),s,malformed.data(),malformed.size()));
  s.pmfRequired=false;assert(!d->buildNativeSAEAssociation(association,sizeof(association)));s.pmfRequired=true;
  // A temporary AP rejection preserves the verified SAE/PMF owner and the
  // exact station RSNE/PMKID for the next association packet. No open-auth or
  // fresh SAE exchange is needed by this shared radio-stage retry.
  const auto beforeRetryBytes=d->buildNativeSAEAssociation(association,sizeof(association));
  assert(beforeRetryBytes);const std::vector<uint8_t> beforeRetry(association,association+beforeRetryBytes);
  auto pmfOwner=sec->pmfSession;const auto pmfGeneration=pmfOwner->activeGeneration();const size_t authTransmits=d->transmitted.size();
  std::vector<uint8_t> temporary(37);temporary[0]=0x10;memcpy(temporary.data()+4,w_sta,6);memcpy(temporary.data()+10,w_ap,6);memcpy(temporary.data()+16,w_ap,6);
  temporary[26]=30;temporary[30]=56;temporary[31]=5;temporary[32]=3;temporary[33]=0xe8;temporary[34]=3;
  s.submitted=s.txComplete=true;s.sinceMs=8;s.managementAttempts=1;
  Ath10k::receiveStationManagement(s,temporary.data(),temporary.size(),0,6);bool waiting=false;
  assert(s.associationComeback.pending && !s.assocReply && !Ath10k::serviceAssociationComeback(s,8,waiting) && waiting);
  const auto retryAt=s.associationComeback.untilMs;assert(retryAt==1032);
  assert(!Ath10k::serviceAssociationComeback(s,retryAt,waiting) && !waiting && !s.submitted);
  assert(sec->ready && sec->pmfSession==pmfOwner && pmfOwner->activeGeneration()==pmfGeneration && d->transmitted.size()==authTransmits && s.securityAKM==8 && s.pmfRequired);
  assert(d->buildNativeSAEAssociation(association,sizeof(association))==beforeRetry.size() && !memcmp(association,beforeRetry.data(),beforeRetry.size()));
  s.submitted=true;++s.managementAttempts; // Model the retry's actual submission.
  std::vector<uint8_t> response(30);response[0]=0x10;memcpy(response.data()+4,w_sta,6);memcpy(response.data()+10,w_ap,6);memcpy(response.data()+16,w_ap,6);response[28]=1;
  auto invalid=response;invalid.insert(invalid.end(),AthSecurity::stationRSN,AthSecurity::stationRSN+sizeof(AthSecurity::stationRSN));
  Ath10k::receiveStationManagement(s,invalid.data(),invalid.size(),0,6);assert(!s.assocReply);
  response.insert(response.end(),w_rsn,w_rsn+sizeof(w_rsn));
  Ath10k::receiveStationManagement(s,response.data(),response.size(),0,6);assert(s.assocReply);
  // PSK-SHA256 response validation follows AKM6 instead of a hard-coded PSK2.
  auto sha=s;sha.securityAKM=6;sha.pmfRequired=false;sha.assocReply=false;
  auto shaResponse=std::vector<uint8_t>(response.begin(),response.begin()+30);
  auto pskResponse=shaResponse;pskResponse.insert(pskResponse.end(),AthSecurity::stationRSN,AthSecurity::stationRSN+sizeof(AthSecurity::stationRSN));
  Ath10k::receiveStationManagement(sha,pskResponse.data(),pskResponse.size(),0,6);assert(!sha.assocReply);
  shaResponse.insert(shaResponse.end(),AthSecurity::stationRSNSHA256,AthSecurity::stationRSNSHA256+sizeof(AthSecurity::stationRSNSHA256));
  Ath10k::receiveStationManagement(sha,shaResponse.data(),shaResponse.size(),0,6);assert(sha.assocReply);
  using S=AthSecurity::Supplicant<Ath10kKernelCrypto,true,true,true>;
  assert(sec->supplicant.receive(w_m1,sizeof(w_m1))==S::Reply);
  assert(sec->supplicant.outputLength==157 && !memcmp(sec->supplicant.output+113,station,44));
  assert(sec->supplicant.receive(w_m3,sizeof(w_m3))==S::Keys && !memcmp(sec->supplicant.keys,w_ptk+32,16));stop(d);
 }
 {auto d=device();d->_nativeJoinPending=false;ownerGate=true;assert(!d->advanceSAEAuth(0));ownerGate=false;
  assert(d->saeDiscards==1 && d->_connection.cancelRequested && !d->_nativeSecurity->saeRadio && !d->_nativeSecurity->saeSession);stop(d);}
 {auto d=device();d->_connection.securityAKM=2;d->_nativeSecurity->ready=true;ownerGate=true;assert(d->advanceSAEAuth(0));ownerGate=false;
  assert(d->transmitted.empty() && !d->saeDiscards);stop(d);}
 {auto d=device();d->blocked=true;assert(tick(d,0) && d->transmitted.empty() && !d->_connection.authReply);stop(d);}
 {auto d=device();auto sec=d->_nativeSecurity;sec->pmfSession->cancel();assert(tick(d,0) && d->transmitted.empty());stop(d);}
 {auto d=device();d->failSubmit=true;assert(tick(d,0) && d->transmitted.empty() && !d->_nativeSecurity->ready);stop(d);}
 {auto d=device();d->_connection.cancelRequested=true;assert(tick(d,0) && d->transmitted.empty());stop(d);}
 // Native H2E binds the accepted SAE mode to the scanned AP extension,
 // emits it in association/M2, and authenticates the AP's M3 snapshot.
 request.h2e=true;auto hPeer=peer;hPeer.h2e=true;auto hConfirm=confirmation;hConfirm.h2e=true;
 const auto hPeerWire=apFrame(hPeer),hConfirmWire=apFrame(hConfirm);
 {auto d=device();assert(tick(d,0) && d->transmitted.empty());stop(d);} // AP never advertised H2E.
 for(bool mismatch : {false,true}){auto d=device();auto sec=d->_nativeSecurity;auto &s=d->_connection;
  memcpy(s.ap.rsnxe,x_rsnxe,sizeof(x_rsnxe));s.ap.rsnxeLength=sizeof(x_rsnxe);
  assert(!tick(d,0) && d->transmitted[0][28]==126);retired(d);
  nativeSAEClockMS=1;assert(deliver(d,hPeerWire.data(),hPeerWire.size()));assert(!tick(d,1));run(latest);
  assert(!tick(d,2));run(latest);assert(!tick(d,3));
  nativeSAEClockMS=4;assert(deliver(d,hConfirmWire.data(),hConfirmWire.size()));assert(!tick(d,4));run(latest);
  retired(d);assert(!tick(d,5) && sec->ready && s.authReply);
  s.stage=Ath10k::LinkStage::Assoc;uint8_t assoc[256]{};const auto n=d->buildNativeSAEAssociation(assoc,sizeof(assoc));
  assert(n>3 && !memcmp(assoc+n-3,x_rsnxe,3));
  using S=AthSecurity::Supplicant<Ath10kKernelCrypto,true,true,true>;
  assert(sec->supplicant.receive(w_m1,sizeof(w_m1))==S::Reply && sec->supplicant.outputLength==160);
  assert(!memcmp(sec->supplicant.output,x_m2,sizeof(x_m2)));
  s.stage=Ath10k::LinkStage::Connected;ownerGate=true;assert(d->nativeAcceptSecurityResult(S::Reply));ownerGate=false;
  assert(sec->replyLength==160 && !memcmp(sec->reply,x_m2,160));sec->replyPending=false;
  const auto result=sec->supplicant.receive(mismatch?x_changed_m3:x_m3,mismatch?sizeof(x_changed_m3):sizeof(x_m3));
  assert(result==(mismatch?S::Fatal:S::Keys));
  if(!mismatch){ownerGate=true;assert(d->nativeAcceptSecurityResult(S::Keys));ownerGate=false;
   assert(sec->keysPending && sec->managementPending && !memcmp(sec->keys,w_ptk+32,16));}
  stop(d);
 }
 request.h2e=false;
 AthSecurity::P256FieldAPI field{};field.curve=api.curve;
#define FIELD(member,name) field.member=reinterpret_cast<decltype(field.member)>(dlsym(lib,name));assert(field.member)
 FIELD(units,"cczp_n");FIELD(prime,"cczp_prime");FIELD(multiply,"cczp_mul");FIELD(inverse,"cczp_inv");FIELD(add,"cczp_add");FIELD(subtract,"cczp_sub");
#undef FIELD
 for(unsigned scenario=0;scenario<4;++scenario){auto d=device();auto sec=d->_nativeSecurity;auto &s=d->_connection;
  auto ap=s.ap;auto regulatory=s.regulatory;sec->reset();Ath10k::resetDisconnected(s);
  s.stage=Ath10k::LinkStage::Disabled;d->_nativeJoinPending=false;d->_regulatory=regulatory;
  memcpy(d->_nativeMACCurrent,w_sta,6);
  memcpy(ap.rsn,AthSecurity::stationRSNEAP,sizeof(AthSecurity::stationRSNEAP));ap.rsnLength=sizeof(AthSecurity::stationRSNEAP);
  if(scenario==2)ap.rsn[19]=2;
  sec->candidates.add(ap,0);d->experimentalEAP=scenario!=0;
  AirportWCL::JoinRequest join{};join.lowerAuth=1;join.upperAuth=4;join.ssidLength=ap.ssidLength;
  memcpy(join.ssid,ap.ssid,ap.ssidLength);memcpy(join.bssid,ap.bssid,6);
  ownerGate=true;const auto result=d->nativeBeginJoin(join);ownerGate=false;
  assert(result==((scenario==1 || scenario==3)?kIOReturnSuccess:kIOReturnUnsupported));
  if(scenario==1 || scenario==3){assert(s.securityAKM==1 && s.secure && !s.portAuthorized && !sec->ready && sec->eapOwner.generation());
   assert(sec->profile.generation() && d->_nativeJoinPending);
   // Continue the admitted enterprise profile through the real native callback,
   // PMK binding, authenticated exports and durable M4 completion barrier.
   s.stage=Ath10k::LinkStage::Connected;
   apple80211_key key{};key.version=1;key.key_cipher_type=9;key.key_len=32;memcpy(key.key,e_pmk,32);
   nativeSAEClockMS=100;assert(d->nativeSetCipherKey(&key)==kIOReturnSuccess);
   ownerGate=true;d->serviceNativeEAP(100);ownerGate=false;
   assert(sec->ready && !s.portAuthorized && s.sinceMs==100);
   using E=AthSecurity::Supplicant<Ath10kKernelCrypto,true,true,true>;
   assert(sec->supplicant.receive(e_m1,sizeof(e_m1))==E::Reply);
   assert(d->nativeAcceptSecurityResult(E::Reply));
   assert(sec->replyLength==sizeof(e_m2) && !memcmp(sec->reply,e_m2,sizeof(e_m2)));
   sec->replyPending=false;sec->replyLength=0;
   assert(sec->supplicant.receive(e_m3,sizeof(e_m3))==E::Keys);
   assert(d->nativeAcceptSecurityResult(E::Keys));
   assert(sec->keysPending && !s.portAuthorized && !memcmp(sec->keys,e_ptk+32,16));
   assert(sec->replyLength==sizeof(e_m4) && !memcmp(sec->reply,e_m4,sizeof(e_m4)));
   // Emulate firmware key acknowledgements, not radio interoperability.
   sec->keysPending=false;s.securityPhase=3;sec->authorizePending=true;
   s.eapolCompletion.begin(77);d->serviceEAPCompletion(101);
   assert(!s.authorizeRequested && !s.portAuthorized);
   s.eapolCompletion.retire(76,0);d->serviceEAPCompletion(102);assert(!s.authorizeRequested);
   s.eapolCompletion.retire(77,scenario==3?1:0);d->serviceEAPCompletion(103);
   if(scenario==3){assert(s.cancelRequested && !s.authorizeRequested && !s.portAuthorized && !sec->eapOwner.generation());}
   else {
    assert(s.authorizeRequested && !s.portAuthorized && !sec->authorizePending);
    key.key_len=0;assert(d->nativeSetCipherKey(&key)==kIOReturnSuccess);
    assert(s.cancelRequested && !s.portAuthorized && !sec->eapOwner.generation());
   }}
  else assert(!sec->eapOwner.generation());
  stop(d);
 }
 passwordPreparationTests(field);
 pskPasswordAdmissionTests();
 securitySnapshotTests();
 AthSecurity::wipe(&keys,sizeof(keys));dlclose(lib);
}

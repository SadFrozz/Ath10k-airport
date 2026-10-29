#include <array>
#include <map>
#include <string>
#include <vector>
#include "mock_sae_worker.hpp"
#include "../src/kext/Ath10kWMI.hpp"
#include "../src/shared/Ath10kPMFTransport.hpp"
#include "../src/shared/Ath10kSHA256.hpp"
#include "../src/shared/Ath10kSupplicant.hpp"
#include "../src/kext/native/Ath10kNativeCandidates.hpp"
#include "../src/kext/native/Ath10kNativePMFInbox.hpp"
#include "common_crypto_personal.hpp"
#include "pmf_ccmp_vectors.inc"
static unsigned randomCalls=0;
#ifdef ATH10K_NATIVE_REAL_SAE
static unsigned nativeOwnerRandomCalls=0,nativeHMACCalls=0;
static bool (*nativePasswordRandom)(uint8_t *,size_t)=nullptr;
#endif
struct Ath10kKernelCrypto : PersonalTestCrypto {
#ifdef ATH10K_NATIVE_REAL_SAE
 static bool hmac(const uint8_t *k,size_t kl,const uint8_t *d,size_t n,uint8_t *o){++nativeHMACCalls;return PersonalTestCrypto::hmac(k,kl,d,n,o);}
#endif
 static bool random(uint8_t *out,size_t n){
#ifdef ATH10K_NATIVE_REAL_SAE
 if(ownerGate)++nativeOwnerRandomCalls;
 if(nativePasswordRandom && !ownerGate && n!=2)return nativePasswordRandom(out,n);
#endif
 if(n!=2){assert(n==32);return PersonalTestCrypto::random(out,n);}out[0]=0x12;out[1]=uint8_t(0x34+randomCalls++);return true;}
 static bool encrypt(const uint8_t *key,const uint8_t *in,uint8_t *out){assert(!ownerGate && !heldLocks);return PersonalTestCrypto::encrypt(key,in,out);}
};
#include "pmf_session.inc"
#include "../src/shared/Ath10kPSKPassword.hpp"
#include "native_psk_preparation.inc"
#ifdef ATH10K_NATIVE_REAL_SAE
#include "../src/shared/Ath10kSAEExchange.hpp"
#include "../src/shared/Ath10kSAEPassword.hpp"
#include <CommonCrypto/CommonHMAC.h>
static const void *ccsha256_di(){assert(!ownerGate && !heldLocks);return reinterpret_cast<const void *>(1);}
static void cchmac(const void *,size_t kl,const void *key,size_t n,const void *data,void *out){
 assert(!ownerGate && !heldLocks);CCHmac(kCCHmacAlgSHA256,key,kl,data,n,out);
}
#include "sae_session.inc"
#include "../src/kext/native/Ath10kNativeSAEJoin.hpp"
#include "native_sae_preparation.inc"
#else
struct Ath10kSAESession {bool usingH2E() const{return false;}void cancel(){}void release(){delete this;}};
#include "mock_native_sae_radio.hpp"
#endif
static uint64_t nativeSAEClockMS=0;
namespace Ath10k {inline uint64_t uptimeNS(){return nativeSAEClockMS*1000000u;}}

class Ath10kPCIDevice {
public:
 class NativeSecurity;NativeSecurity *_nativeSecurity=nullptr;Ath10k::ConnectionState _connection;
 static bool nativePMFManagement(void *,const UInt8 *,UInt32,UInt32,UInt32,UInt32);
 struct {bool completed=true,txOwned=false,cancelRequested=false;} _wmiScan;
 struct {struct {unsigned outstanding=0;} credits;UInt32 htCapability=0,vhtCapability=0;} _wmi;
 struct {bool active=true;} _wmiLive;
 Ath10k::WMIScanChannelsState _wmiRadio[Ath10k::kWMIRadioStepCount]{};
 bool _runtimeActive=true;
 bool _nativeJoinPending=false,_nativeRadioOn=true,_networkEnabled=true,_nativeStopping=false;
 bool nativePreparePersonalAuth(UInt64,const char *&);
 bool _dmaQuarantine=false,blocked=false,failSubmit=false;
 bool startupProbeOption=false,_nativePMFStartupQueryAttempted=false;
 unsigned pmfProbeAnnouncements=0;
 bool nativePMFStartupQueryEnabled() const{return startupProbeOption;}
#ifdef ATH10K_NATIVE_REAL_SAE
 bool experimentalSAE=true,_nativeScanPending=false,_nativeAbortRequested=false;
 bool _nativeWasUp=false,_nativeLinkUpSent=false,_nativeAssocSent=false,_nativeBeaconSent=false,_nativeJoinBSSSent=false,_nativeJoinFailed=false;
 struct {bool rfKill=false;} _wmiEvents;
 struct Payload {bool kSupportsMFP=false;} payloadData;
 const Payload &payload() const {return payloadData;}
 Ath10k::RegulatoryPolicy _regulatory;
 UInt8 _nativeMACCurrent[6]{};AirportWCL::JoinRequest _nativeJoin{};UInt64 _nativeJoinDeadline=0;
 std::map<std::string,uint64_t> numericProperties;std::map<std::string,std::string> stringProperties;
 void setProperty(const char *k,const char *v){++propertyWrites;stringProperties[k]=v;}
 void setProperty(const char *k,bool v){++propertyWrites;numericProperties[k]=v;
  if(!strcmp(k,"Ath10kNativePMFStartupQueryStarted")){assert(v);++pmfProbeAnnouncements;}}
 void setProperty(const char *k,UInt64 v,unsigned){++propertyWrites;numericProperties[k]=v;}
 bool nativeSAEEnabled() const {return experimentalSAE;}
 int nativeJoinRequest(void *);
 void publishNativeSecurityState(UInt64);
 UInt64 _nativeSecurityPublished[10]{},_nativeSecuritySnapshotMS=0;bool _nativeSecuritySnapshotPublished=false;
 unsigned propertyWrites=0;
#else
 void setProperty(const char *key,bool value){assert(value && !strcmp(key,"Ath10kNativePMFStartupQueryStarted"));++pmfProbeAnnouncements;}
#endif

 std::vector<std::vector<uint8_t>> transmitted;
 bool powerIOBlocked(){return blocked;}
 unsigned saeDiscards=0;
 void discardNativeSecurity();
 bool advanceSAEAuth(UInt64);
 const char *serviceNativeSAE(UInt64);
 UInt32 buildNativeSAEAssociation(UInt8 *,UInt32);
 bool nativeStageManagementKey(const AthSecurity::IGTKCMAC128 &);
 bool nativeAcceptSecurityResult(UInt32);
 bool nativePMFPairwiseAcknowledged(const UInt8 *);
 bool nativePMFPortReady();
 bool nativeAssociationRSNXE(void *);
 bool nativePMFFirmwareReady();
 bool nativePMFTransportReady();
 const char *submitNetworkPacket(const UInt8 *frame,UInt32 bytes,bool mgmt,UInt64,AthSecurity::ManagementTX mode=AthSecurity::ManagementTX::Plain){
  assert(ownerGate && mgmt);
  if(mode==AthSecurity::ManagementTX::HardwareCCMP)assert(nativePMFTransportReady());
  else assert(mode==AthSecurity::ManagementTX::Plain && bytes>=30 && frame[24]==3);
  assert(Ath10k::packetProtectionAllowed(frame,bytes,_connection,mgmt,mode));
  if(failSubmit)return "test-submit-failed";
  if(mode==AthSecurity::ManagementTX::Plain){_connection.txOwned=true;_connection.txComplete=false;_connection.lastTxSAE=true;_connection.txStatus=0;}
  transmitted.emplace_back(frame,frame+bytes);return nullptr;
 }
 void serviceNativePMF(UInt64);
};
#include "native_security_class.inc"
#include "native_pmf_receive.inc"
#include "native_pmf_key_hooks.inc"
void Ath10kPCIDevice::discardNativeSecurity(){++saeDiscards;_nativeSecurity->reset();}
#include "native_sae_stage.inc"
static Ath10kPCIDevice *create(){
 auto d=new Ath10kPCIDevice;auto &s=d->_connection;s.stage=Ath10k::LinkStage::Connected;
 s.secure=s.pmfRequired=s.pairInstalled=s.portAuthorized=true;s.securityPhase=5;s.pmfQoSTransported=true;for(auto &qos:d->_wmiRadio)qos.completed=qos.txConsumed=qos.creditReturned=true;randomCalls=0;memcpy(s.local,c_sta,6);memcpy(s.bssid,c_ap,6);
 auto sec=d->_nativeSecurity=new Ath10kPCIDevice::NativeSecurity;assert(sec->prepareSAEWorker());
 sec->pmfSession=new Ath10kPMFSession;assert(sec->pmfSession->initConnection(c_sta,c_ap,9));assert(sec->pmfSession->acknowledgePairwise(c_key,c_sta,c_ap));
 AthSecurity::IGTKCMAC128 key{};key.keyID=4;key.ipn=6;memcpy(key.key,c_key,16);
 assert(sec->pmfSession->activateManagement(key) && sec->pmfSession->authorize());return d;
}
static void stop(Ath10kPCIDevice *d){ownerGate=true;d->_nativeSecurity->reset();ownerGate=false;d->_nativeSecurity->drainSAEWorker();delete d->_nativeSecurity;delete d;assert(!objects && !locks && !calls);}
static bool deliver(Ath10kPCIDevice *d,const uint8_t *frame,size_t bytes,uint32_t status=0){ownerGate=true;bool result=d->nativePMFManagement(d,frame,bytes,status,36,40);ownerGate=false;return result;}
static void service(Ath10kPCIDevice *d,UInt64 now=0){ownerGate=true;d->serviceNativePMF(now);ownerGate=false;}
static void roundtrip(Ath10kPCIDevice *d){service(d);assert(d->_nativeSecurity->pmfRXInFlight);run(latest);service(d);}
class ForeignJob final : public Ath10kSAEWorkItem {public:void execute() override {}void discard() override {}};
void queryTests();void spectrumTests();void firmwareTests();void startupProbeTests();void suspendCryptoTests();
#ifndef ATH10K_NATIVE_KEY_STAGE_TEST
int main(){
 firmwareTests();queryTests();spectrumTests();startupProbeTests();suspendCryptoTests();
 { auto d=create();auto sec=d->_nativeSecurity;auto job=new ForeignJob;assert(job->init());
   assert(sec->saeWorker->submit(job));run(latest);service(d);
   assert(sec->saeWorker->takeCompleted()==job);job->release();job->release();stop(d);
 }
 // Stale PMF producer state cannot consume an SAE/preparation completion.
 for(bool rx : {true,false}){
   auto d=create();auto sec=d->_nativeSecurity;auto job=new ForeignJob;assert(job->init());
   sec->pmfRXInFlight=rx;sec->pmfTXInFlight=!rx;
   assert(sec->saeWorker->submit(job));run(latest);const auto refs=job->references();service(d);
   assert(job->references()==refs && sec->pmfRXInFlight==rx && sec->pmfTXInFlight==!rx);
   assert(!sec->pmfPendingTX && !sec->pmfRXVerified && d->transmitted.empty());
   assert(sec->saeWorker->takeCompletedFor(job)==job);job->release();job->release();
   service(d);assert(!sec->pmfRXInFlight && !sec->pmfTXInFlight);
   // The same queue remains usable for a real, correctly owned PMF result.
   sec->pmfLayoutVerified=true;assert(deliver(d,c_deauth_wire,sizeof(c_deauth_wire)));roundtrip(d);
   assert(d->_connection.cancelRequested && sec->pmfRXVerified==1);stop(d);
 }
 for(bool plaintext:{false,true}){ auto d=create();auto sec=d->_nativeSecurity;
   // A protected action's first IV byte is not a plaintext action category.
   auto f=std::array<uint8_t,sizeof(c_query_wire)>{};memcpy(f.data(),c_query_wire,f.size());f[24]=4;
   assert(AthSecurity::robustManagementFrame(f.data(),f.size()));
   assert(!sec->pmfLayoutVerified && sec->pmfRXLayout==AthSecurity::PMFCCMPRXLayout::Authenticated);
   auto raw=std::array<uint8_t,sizeof(c_deauth_wire)>{};memcpy(raw.data(),plaintext?c_deauth_decrypted:c_deauth_wire,raw.size());
   assert(deliver(d,raw.data(),raw.size()));memset(raw.data(),0xa5,raw.size());
   assert(!d->_connection.cancelRequested);roundtrip(d);
   assert(d->_connection.cancelRequested && d->_connection.apDisconnect.reason==6 && sec->pmfRXVerified==1 && sec->pmfLayoutVerified);
   assert(d->_connection.signalDbm==-55);stop(d);
 }
 { auto d=create();auto sec=d->_nativeSecurity;
   assert(deliver(d,c_bip_disconnect,sizeof(c_bip_disconnect)));roundtrip(d);
   assert(d->_connection.cancelRequested && sec->pmfRXVerified==1);stop(d);
 }
 { auto d=create();auto sec=d->_nativeSecurity;sec->pmfLayoutVerified=true;
   auto bad=std::array<uint8_t,sizeof(c_deauth_wire)>{};memcpy(bad.data(),c_deauth_wire,bad.size());bad.back()^=1;
   assert(deliver(d,bad.data(),bad.size()));roundtrip(d);assert(!d->_connection.cancelRequested && !sec->pmfRXVerified);
   assert(deliver(d,c_deauth_wire,sizeof(c_deauth_wire),16) && !sec->pmfInbox.size());
   auto unprotected=std::array<uint8_t,sizeof(c_deauth_plain)>{};memcpy(unprotected.data(),c_deauth_plain,unprotected.size());unprotected[1]&=~0x40;
   assert(deliver(d,unprotected.data(),unprotected.size()));assert(sec->pmfQueryTrigger && !d->_connection.cancelRequested);stop(d);
 }
 { auto d=create();auto sec=d->_nativeSecurity;sec->pmfLayoutVerified=true;
   assert(deliver(d,c_query_wire,sizeof(c_query_wire)));service(d);
   uint8_t next[16];memcpy(next,c_key,16);next[0]^=1;
   assert(sec->pmfSession->acknowledgePairwise(next,c_sta,c_ap) && sec->pmfSession->authorize());
   run(latest);service(d);assert(!sec->pmfRXVerified && !d->_connection.cancelRequested);stop(d);
 }
 { auto d=create();auto sec=d->_nativeSecurity;sec->pmfLayoutVerified=true;
   for(unsigned i=0;i<AthNative::PMFInbox::Capacity+1;++i)assert(deliver(d,c_query_wire,sizeof(c_query_wire)));
   assert(sec->pmfInbox.size()==4 && sec->pmfRXDropped==1);
   service(d);run(latest);service(d);assert(sec->pmfRXVerified==1); // Remaining identical PN copies cannot be replayed.
   while(sec->pmfRXInFlight){run(latest);service(d);}assert(sec->pmfRXVerified==1);stop(d);
 }
 { auto d=create();auto sec=d->_nativeSecurity;sec->pmfLayoutVerified=true;
   assert(deliver(d,c_deauth_wire,sizeof(c_deauth_wire)));service(d);run(latest);
   d->_connection.cancelRequested=true;service(d);assert(!sec->pmfRXVerified);stop(d);
 }
}

#endif

static void trigger(Ath10kPCIDevice *d){
 auto f=std::array<uint8_t,sizeof(c_deauth_plain)>{};memcpy(f.data(),c_deauth_plain,f.size());f[1]&=~0x40;
 assert(deliver(d,f.data(),f.size()));
}
void startupProbeTests(){
 {auto d=create();d->_connection.securityAKM=8;service(d,0);
  assert(!d->_nativePMFStartupQueryAttempted && !randomCalls && !d->pmfProbeAnnouncements && d->transmitted.empty());stop(d);}
 {auto d=create();d->startupProbeOption=true;d->_connection.securityAKM=6;service(d,0);
  assert(!d->_nativePMFStartupQueryAttempted && !randomCalls && !d->pmfProbeAnnouncements);stop(d);}
 // Waiting for owner/firmware readiness must not burn the fixed query deadline.
 for(unsigned barrier=0;barrier<13;++barrier){
  auto d=create();auto sec=d->_nativeSecurity;auto &s=d->_connection;
  d->startupProbeOption=true;s.securityAKM=8;
  uint8_t key[16];memcpy(key,c_key,16);key[0]^=1;
  if(barrier==0)s.dataPending=1;
  if(barrier==1)s.radio.appliedPS=true;
  if(barrier==2)d->_wmi.credits.outstanding=1;
  if(barrier==3)sec->replyPending=true;
  if(barrier==4)sec->keysPending=true;
  if(barrier==5)sec->authorizePending=true;
  if(barrier==6)s.rekeyKind=1;
  if(barrier==7)d->blocked=true;
  if(barrier==8)assert(sec->pmfSession->acknowledgePairwise(key,c_sta,c_ap));
  if(barrier==9)s.securityPhase=4;
  if(barrier==10)d->_nativeStopping=true;
  if(barrier==11)s.eapolPause=true;
  ForeignJob *foreign=nullptr;
  if(barrier==12){foreign=new ForeignJob;assert(foreign->init());assert(sec->saeWorker->submit(foreign));}
  service(d,0);assert(!d->_nativePMFStartupQueryAttempted && !d->pmfProbeAnnouncements && !randomCalls);
  s.dataPending=0;s.radio.appliedPS=false;d->_wmi.credits.outstanding=0;
  sec->replyPending=sec->keysPending=sec->authorizePending=false;s.rekeyKind=0;d->blocked=false;
  assert(sec->pmfSession->authorize());s.securityPhase=5;d->_nativeStopping=false;s.eapolPause=false;
  if(foreign){run(latest);auto item=sec->saeWorker->takeCompleted();assert(item==foreign);item->release();foreign->release();}
  service(d,30000);assert(d->_nativePMFStartupQueryAttempted && d->pmfProbeAnnouncements==1 && sec->pmfTXInFlight);
  assert(sec->pmfQuery.state()==AthSecurity::SAQueryExchange::State::Waiting && !s.cancelRequested);
  stop(d);
 }
 // Real boot regression: the AP enables PS before the diagnostic is ready.
 // Reserve the normal wake/drain path without starting or extending a query.
 {auto d=create();auto sec=d->_nativeSecurity;auto &s=d->_connection;
  d->startupProbeOption=true;s.securityAKM=8;s.radio.appliedPS=true;s.dataPending=1;
  d->_wmiScan.completed=false;
  service(d,0);assert(s.pmfTXPending && d->_wmiScan.cancelRequested && !Ath10k::dataTXAdmissionOpen(s));
  assert(!d->_nativePMFStartupQueryAttempted && sec->pmfQuery.state()==AthSecurity::SAQueryExchange::State::Idle);
  service(d,30000);assert(s.pmfTXPending && !s.cancelRequested && !randomCalls);
  s.radio.appliedPS=false;s.dataPending=0;d->_wmiScan.completed=true;
  service(d,30001);assert(d->_nativePMFStartupQueryAttempted && sec->pmfTXInFlight);
  run(latest);service(d,30002);assert(sec->pmfTXSubmitted==1 && s.pmfTXPending);
  // Retry interval must not reopen data admission or allow PS to reenter.
  service(d,30100);assert(s.pmfTXPending && !Ath10k::dataTXAdmissionOpen(s) && !sec->pmfTXInFlight);
  // Stop before the fixed 1.024s deadline; the fixture response is authentic.
  assert(deliver(d,c_query_wire,sizeof(c_query_wire)));service(d,30101);run(latest);service(d,30102);
  assert(sec->pmfQuerySucceeded==1 && !s.pmfTXPending && s.txWakePending && Ath10k::dataTXAdmissionOpen(s));stop(d);
 }
 {auto d=create();auto sec=d->_nativeSecurity;d->startupProbeOption=true;d->_connection.securityAKM=8;
  service(d,0);assert(d->_nativePMFStartupQueryAttempted && sec->pmfTXInFlight);
  run(latest);service(d,0);assert(d->transmitted.size()==1 && sec->pmfTXSubmitted==1);
  assert(deliver(d,c_query_wire,sizeof(c_query_wire)));service(d,1);run(latest);service(d,1);
  assert(sec->pmfQuerySucceeded==1 && sec->pmfRXVerified==1 && d->pmfProbeAnnouncements==1);
  service(d,20000);assert(d->transmitted.size()==1 && !d->_connection.cancelRequested);
  // Association reset/rekey cannot schedule another diagnostic query on this controller.
  sec->reset();assert(d->_nativePMFStartupQueryAttempted);
  sec->pmfSession=new Ath10kPMFSession;assert(sec->pmfSession->initConnection(c_sta,c_ap,10));
  assert(sec->pmfSession->acknowledgePairwise(c_key,c_sta,c_ap));
  AthSecurity::IGTKCMAC128 management{};management.keyID=4;memcpy(management.key,c_key,16);
  assert(sec->pmfSession->activateManagement(management) && sec->pmfSession->authorize());
  service(d,20001);assert(d->transmitted.size()==1 && d->pmfProbeAnnouncements==1 && !sec->pmfTXInFlight);
  stop(d);
 }
 {auto d=create();auto sec=d->_nativeSecurity;d->startupProbeOption=true;d->_connection.securityAKM=8;
  service(d,0);run(latest);service(d,0);service(d,1024);
  assert(d->_connection.cancelRequested && !d->_connection.portAuthorized &&
   !strcmp(d->_connection.error,"pmf-sa-query-timeout") && d->_nativePMFStartupQueryAttempted);
  service(d,2000);assert(d->pmfProbeAnnouncements==1 && !sec->pmfQuerySucceeded);stop(d);
 }
}
void queryTests(){
 // A live query admits an ID only after actual protected handoff. Radio TX
 // pressure stops new data and a late/unsent response cannot claim success.
 {auto d=create();auto sec=d->_nativeSecurity;sec->pmfLayoutVerified=true;trigger(d);
  d->_connection.dataPending=1;service(d);assert(sec->pmfTXInFlight && d->_connection.pmfTXPending);
  assert(!Ath10k::dataTXAdmissionOpen(d->_connection));run(latest);service(d);
  assert(sec->pmfPendingTX && d->transmitted.empty());
  assert(deliver(d,c_query_wire,sizeof(c_query_wire)));service(d);run(latest);service(d);
  assert(!sec->pmfQuerySucceeded && sec->pmfQuery.state()==AthSecurity::SAQueryExchange::State::Waiting);
  d->_connection.dataPending=0;service(d,1);assert(d->transmitted.size()==1 && sec->pmfTXSubmitted==1);
  // The first received PN cannot be replayed to complete the query after TX.
  assert(deliver(d,c_query_wire,sizeof(c_query_wire)));service(d,2);run(latest);service(d,2);assert(!sec->pmfQuerySucceeded);
  service(d,1024);assert(d->_connection.cancelRequested && !strcmp(d->_connection.error,"pmf-sa-query-timeout"));stop(d);}
 {auto d=create();auto sec=d->_nativeSecurity;sec->pmfLayoutVerified=true;trigger(d);
  service(d);run(latest);service(d);assert(d->transmitted.size()==1);
  const auto &tx=d->transmitted[0];assert(tx.size()==44 && tx[24]==1 && tx[27]==0x20 && tx[32]==8 && tx[33]==0 && tx[34]==0x12 && tx[35]==0x34);
  assert(deliver(d,c_query_wire,sizeof(c_query_wire)));service(d,1);run(latest);service(d,1);
  assert(sec->pmfQuerySucceeded==1 && sec->pmfQuery.state()==AthSecurity::SAQueryExchange::State::Succeeded);
  trigger(d);service(d,100);assert(!sec->pmfTXInFlight); // Per-association start rate limit.
  service(d,1024);assert(!d->_connection.cancelRequested);stop(d);}
 {auto d=create();auto sec=d->_nativeSecurity;trigger(d);
  for(unsigned i=0;i<5;++i){service(d,206*i);assert(sec->pmfTXInFlight);run(latest);service(d,206*i);}
  assert(d->transmitted.size()==5);for(unsigned i=0;i<5;++i){assert(d->transmitted[i][24]==i+1 && d->transmitted[i][35]==0x34+i);}
  trigger(d);service(d,1000);assert(!sec->pmfTXInFlight && !d->_connection.cancelRequested);
  service(d,1024);assert(d->_connection.cancelRequested);stop(d);}
 {auto d=create();auto sec=d->_nativeSecurity;d->failSubmit=true;trigger(d);service(d);run(latest);service(d);
  assert(!d->_connection.cancelRequested && sec->pmfTXDropped==1 && !sec->pmfPendingTX);
  d->failSubmit=false;service(d,206);run(latest);service(d,206);assert(d->transmitted.size()==1 && d->transmitted[0][24]==2);stop(d);}
 // Authenticated AP requests are answered with their exact ID. The response
 // consumes the same PN pool as initiated requests and never bypasses PMF.
 {auto d=create();auto sec=d->_nativeSecurity;sec->pmfLayoutVerified=true;
  assert(deliver(d,c_query_request_wire,sizeof(c_query_request_wire)));service(d);run(latest);service(d);
  assert(sec->pmfTXInFlight);run(latest);service(d);
  assert(d->transmitted.size()==1);const auto &tx=d->transmitted[0];
  assert(tx.size()==44 && !memcmp(tx.data()+24,c_tx_response_hardware+24,20));
  assert(!sec->pmfQuerySucceeded && !d->_connection.cancelRequested);stop(d);}
 // Radio/power/credit ownership postpones handoff without spinning or
 // discarding the retained result. The original query deadline still applies.
 {auto d=create();auto sec=d->_nativeSecurity;trigger(d);service(d);run(latest);
  d->_connection.radio.appliedPS=true;service(d);assert(sec->pmfPendingTX && d->transmitted.empty());
  d->_connection.radio.appliedPS=false;d->_wmi.credits.outstanding=1;service(d,1);assert(sec->pmfPendingTX);
  d->_wmi.credits.outstanding=0;d->blocked=true;service(d,2);assert(sec->pmfPendingTX);
  d->blocked=false;service(d,3);assert(d->transmitted.size()==1 && !sec->pmfPendingTX && d->_connection.pmfTXPending);stop(d);}
 {auto d=create();auto sec=d->_nativeSecurity;sec->pmfLayoutVerified=true;trigger(d);service(d);run(latest);service(d);
  auto fake=std::array<uint8_t,sizeof(c_query_plain)>{};memcpy(fake.data(),c_query_plain,fake.size());fake[1]&=~0x40;
  assert(deliver(d,fake.data(),fake.size()));service(d,1);assert(!sec->pmfQuerySucceeded && !sec->pmfRXInFlight);stop(d);}
 // PTK replacement invalidates a queued request before it reaches DMA.
 {auto d=create();auto sec=d->_nativeSecurity;trigger(d);service(d);
  uint8_t next[16];memcpy(next,c_key,16);next[0]^=1;assert(sec->pmfSession->acknowledgePairwise(next,c_sta,c_ap));assert(sec->pmfSession->authorize());
  run(latest);service(d,1);assert(d->transmitted.empty() && !sec->pmfPendingTX && !sec->pmfTXInFlight && !d->_connection.pmfTXPending);stop(d);}
 // Scan ownership goes through normal cancellation; TX cannot race its credit
 // barrier. A held response has a finite lifetime and cancellation releases it.
 {auto d=create();auto sec=d->_nativeSecurity;sec->pmfLayoutVerified=true;d->_wmiScan.completed=false;
  assert(deliver(d,c_query_request_wire,sizeof(c_query_request_wire)));service(d);run(latest);service(d);run(latest);service(d);
  assert(sec->pmfPendingTX && d->_wmiScan.cancelRequested && d->transmitted.empty());
  service(d,1024);assert(!sec->pmfPendingTX && !d->_connection.pmfTXPending && !d->_connection.cancelRequested);stop(d);}
 {auto d=create();auto sec=d->_nativeSecurity;service(d);for(unsigned i=0;i<8;++i){const uint8_t id[]={uint8_t(i),0};sec->queueQueryReply(id,0);}
  assert(sec->pmfReplyCount==4);
  const uint8_t duplicate[]={0,0};sec->queueQueryReply(duplicate,100);assert(sec->pmfReplyCount==4 && sec->pmfReplies[0].deadlineUS==1024000);
  service(d,1024);assert(!sec->pmfReplyCount);stop(d);}
 {auto d=create();trigger(d);service(d);run(latest);service(d);
  service(d,1);service(d,0);assert(d->_connection.cancelRequested && !strcmp(d->_connection.error,"pmf-sa-query-clock"));stop(d);}
}

static void spectrumRequest(Ath10kPCIDevice *d,bool measurement=false){
 d->_connection.ap.capabilities|=0x100;d->_nativeSecurity->pmfLayoutVerified=true;
 assert(measurement?deliver(d,c_measure_request_wire,sizeof(c_measure_request_wire)):deliver(d,c_tpc_request_wire,sizeof(c_tpc_request_wire)));
 service(d);assert(d->_nativeSecurity->pmfRXInFlight);run(latest);service(d);
 assert(d->_nativeSecurity->pmfTXInFlight && d->_connection.spectrum.inFlight && !d->_connection.spectrum.pending);
}
void spectrumTests(){
 {auto d=create();auto sec=d->_nativeSecurity;spectrumRequest(d);
  // TPC is refreshed at actual hardware handoff, after a queued radio-limit change.
  d->_connection.radio.appliedPower=20;run(latest);service(d);
  assert(d->transmitted.size()==1);const auto &tx=d->transmitted[0];
  assert(tx.size()==sizeof(c_tx_tpc_hardware) && !memcmp(tx.data()+24,c_tx_tpc_hardware+24,tx.size()-24));
  assert(d->_connection.lastTxSpectrum && sec->pmfTXSubmitted==1 && d->_connection.spectrum.inFlight);stop(d);}
 {auto d=create();spectrumRequest(d,true);run(latest);service(d);
  assert(d->transmitted.size()==1);const auto &tx=d->transmitted[0];
  assert(tx.size()==sizeof(c_tx_measure_hardware) && !memcmp(tx.data()+24,c_tx_measure_hardware+24,tx.size()-24));stop(d);}
 {auto d=create();spectrumRequest(d);d->failSubmit=true;run(latest);service(d);
  assert(d->transmitted.empty() && !d->_connection.spectrum.inFlight && d->_connection.spectrum.dropped==1 && !d->_connection.cancelRequested);stop(d);}
 {auto d=create();auto sec=d->_nativeSecurity;spectrumRequest(d);uint8_t key[16];memcpy(key,c_key,16);key[1]^=1;
  assert(sec->pmfSession->acknowledgePairwise(key,c_sta,c_ap) && sec->pmfSession->authorize());
  run(latest);service(d,1);assert(d->transmitted.empty() && !d->_connection.spectrum.inFlight && d->_connection.spectrum.dropped==1);stop(d);}
 {auto d=create();auto sec=d->_nativeSecurity;spectrumRequest(d);sec->saeWorker->cancel();service(d);
  assert(!d->_connection.spectrum.inFlight && !sec->pmfTXInFlight && d->_connection.spectrum.dropped==1);stop(d);}
 {auto d=create();auto sec=d->_nativeSecurity;spectrumRequest(d);d->blocked=true;run(latest);service(d);
  assert(sec->pmfPendingTX && d->_connection.pmfTXPending);service(d,5000);
  assert(!sec->pmfPendingTX && !d->_connection.spectrum.inFlight && d->_connection.spectrum.dropped==1 && !d->_connection.cancelRequested);stop(d);}
 // SA Query and reports spend the same non-rewinding management PN counter.
 {auto d=create();auto sec=d->_nativeSecurity;trigger(d);service(d);run(latest);service(d);
  assert(d->transmitted.size()==1 && d->transmitted[0][24]==1);
  d->_connection.ap.capabilities|=0x100;sec->pmfLayoutVerified=true;
  assert(deliver(d,c_tpc_request_wire,sizeof(c_tpc_request_wire)));service(d,1);run(latest);service(d,1);
  assert(sec->pmfTXInFlight);run(latest);service(d,1);
  assert(d->transmitted.size()==2 && d->transmitted[1][24]==2 && d->transmitted[1][32]==0);stop(d);}
}

void firmwareTests(){
 auto d=create();auto &qos=d->_wmiRadio[Ath10k::kWMIPMFQoSIndex];assert(d->nativePMFFirmwareReady());
 for(unsigned failure=0;failure<7;++failure){
  if(failure==0)d->_runtimeActive=false;if(failure==1)d->_wmiLive.active=false;
  if(failure==2)d->_connection.pmfQoSTransported=false;if(failure==3)qos.completed=false;
  if(failure==4)qos.txConsumed=false;if(failure==5)qos.creditReturned=false;if(failure==6)d->_dmaQuarantine=true;
  assert(!d->nativePMFFirmwareReady() && !d->nativePMFTransportReady());
  d->_runtimeActive=d->_wmiLive.active=d->_connection.pmfQoSTransported=qos.completed=qos.txConsumed=qos.creditReturned=true;d->_dmaQuarantine=false;
 }
 d->blocked=true;assert(!d->nativePMFFirmwareReady());d->blocked=false;stop(d);
}

// Use the real NativeSecurity reset, worker cancellation and PMF session.
// Firmware/PM events are mocked: this checks the security boundary used by
// sleep, not physical PCI wake or automatic macOS reassociation.
void suspendCryptoTests(){
 for(unsigned phase=0;phase<3;++phase){
  auto d=create();auto sec=d->_nativeSecurity;auto worker=sec->saeWorker;
  assert(deliver(d,c_deauth_wire,sizeof(c_deauth_wire)));service(d,0);
  assert(sec->pmfRXInFlight);auto call=latest;
  if(phase==1)claim(call); // XNU dispatch happened, callback has not entered.
  if(phase==2)run(call);   // Crypto completed, radio has not consumed it.
  d->blocked=true;d->_wmiLive.active=false;d->_connection.portAuthorized=false;
  ownerGate=true;sec->reset();ownerGate=false;
  assert(!sec->pmfSession && !sec->pmfRXInFlight && !sec->pmfInbox.size());
  assert(!sec->pmfQueryTrigger && !sec->replyPending && !sec->keysPending && !sec->managementPending);
  assert(!sec->pmfPendingTX && !sec->pmfTXInFlight && !sec->ready);
  assert(!sec->pmfRXVerified && !d->_connection.cancelRequested && d->transmitted.empty());
  if(phase==1){
   assert(!worker->available()); // Old callback still owns its immutable job.
   invoke(call);finish(call);
  }
  assert(worker->available() && !worker->takeCompleted());
  // Model fresh firmware/key authorization after wake. Same worker can be
  // reused, but no result or replay floor from the retired PMF owner may cross.
  ownerGate=true;sec->pmfSession=new Ath10kPMFSession;
  assert(sec->pmfSession->initConnection(c_sta,c_ap,10));
  assert(sec->pmfSession->acknowledgePairwise(c_key,c_sta,c_ap));
  AthSecurity::IGTKCMAC128 key{};key.keyID=4;key.ipn=6;memcpy(key.key,c_key,16);
  assert(sec->pmfSession->activateManagement(key) && sec->pmfSession->authorize());ownerGate=false;
  d->blocked=false;d->_wmiLive.active=true;d->_connection.portAuthorized=true;
  assert(deliver(d,c_deauth_wire,sizeof(c_deauth_wire)));roundtrip(d);
  assert(sec->pmfRXVerified==1 && d->_connection.cancelRequested && d->_connection.apDisconnect.reason==6);
  stop(d);
 }
}

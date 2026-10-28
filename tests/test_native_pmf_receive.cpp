#include <array>
#include "mock_sae_worker.hpp"
#include "../src/shared/Ath10kPMFTransport.hpp"
#include "../src/shared/Ath10kSHA256.hpp"
#include "../src/shared/Ath10kSupplicant.hpp"
#include "../src/kext/native/Ath10kNativeCandidates.hpp"
#include "../src/kext/native/Ath10kNativePMFInbox.hpp"
#include "common_crypto_personal.hpp"
#include "pmf_ccmp_vectors.inc"
struct Ath10kKernelCrypto : PersonalTestCrypto {
 static bool encrypt(const uint8_t *key,const uint8_t *in,uint8_t *out){assert(!ownerGate && !heldLocks);return PersonalTestCrypto::encrypt(key,in,out);}
};
#include "pmf_session.inc"
struct Ath10kSAESession {void cancel(){}void release(){delete this;}};
class Ath10kPCIDevice {
public:
 class NativeSecurity;NativeSecurity *_nativeSecurity=nullptr;Ath10k::ConnectionState _connection;
 static bool nativePMFManagement(void *,const UInt8 *,UInt32,UInt32,UInt32,UInt32);
 void serviceNativePMF();
};
#include "native_security_class.inc"
#include "native_pmf_receive.inc"
static Ath10kPCIDevice *create(){
 auto d=new Ath10kPCIDevice;auto &s=d->_connection;s.stage=Ath10k::LinkStage::Connected;
 s.secure=s.pmfRequired=s.pairInstalled=s.portAuthorized=true;memcpy(s.local,c_sta,6);memcpy(s.bssid,c_ap,6);
 auto sec=d->_nativeSecurity=new Ath10kPCIDevice::NativeSecurity;assert(sec->prepareSAEWorker());
 sec->pmfSession=new Ath10kPMFSession;assert(sec->pmfSession->initConnection(c_sta,c_ap,9));assert(sec->pmfSession->acknowledgePairwise(c_key,c_sta,c_ap));
 AthSecurity::IGTKCMAC128 key{};key.keyID=4;key.ipn=6;memcpy(key.key,c_key,16);
 assert(sec->pmfSession->activateManagement(key) && sec->pmfSession->authorize());return d;
}
static void stop(Ath10kPCIDevice *d){ownerGate=true;d->_nativeSecurity->reset();ownerGate=false;d->_nativeSecurity->drainSAEWorker();delete d->_nativeSecurity;delete d;assert(!objects && !locks && !calls);}
static bool deliver(Ath10kPCIDevice *d,const uint8_t *frame,size_t bytes,uint32_t status=0){ownerGate=true;bool result=d->nativePMFManagement(d,frame,bytes,status,36,40);ownerGate=false;return result;}
static void service(Ath10kPCIDevice *d){ownerGate=true;d->serviceNativePMF();ownerGate=false;}
static void roundtrip(Ath10kPCIDevice *d){service(d);assert(d->_nativeSecurity->pmfRXInFlight);run(latest);service(d);}
class ForeignJob final : public Ath10kSAEWorkItem {public:void execute() override {}void discard() override {}};
int main(){
 { auto d=create();auto sec=d->_nativeSecurity;auto job=new ForeignJob;assert(job->init());
   assert(sec->saeWorker->submit(job));run(latest);service(d);
   assert(sec->saeWorker->takeCompleted()==job);job->release();job->release();stop(d);
 }
 { auto d=create();auto sec=d->_nativeSecurity;
   // A protected action's first IV byte is not a plaintext action category.
   auto f=std::array<uint8_t,sizeof(c_query_wire)>{};memcpy(f.data(),c_query_wire,f.size());f[24]=4;
   assert(AthSecurity::robustManagementFrame(f.data(),f.size()));
   assert(deliver(d,c_deauth_wire,sizeof(c_deauth_wire)) && !sec->pmfInbox.size() && !d->_connection.cancelRequested);
   sec->pmfLayoutVerified=true;
   auto raw=std::array<uint8_t,sizeof(c_deauth_wire)>{};memcpy(raw.data(),c_deauth_wire,raw.size());
   assert(deliver(d,raw.data(),raw.size()));memset(raw.data(),0xa5,raw.size());
   assert(!d->_connection.cancelRequested);roundtrip(d);
   assert(d->_connection.cancelRequested && d->_connection.apDisconnect.reason==6 && sec->pmfRXVerified==1);
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

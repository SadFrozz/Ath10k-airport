#define ATH10K_NATIVE_KEY_STAGE_TEST
#define ATH10K_NATIVE_REAL_SAE
#include "test_native_pmf_receive.cpp"
#include "sae_eapol_vectors.inc"
#include "p256_corecrypto_fixtures.hpp"
#include <dlfcn.h>
#include <cstdio>
using API=AthSecurity::P256CoreCryptoAPI;
static API api;
static uint8_t pwe[64]{},randomScalar[32]{},mask[32]{};
static AthSecurity::SAEGroup19AuthMessage request;
struct HMAC {static bool hmac256(const uint8_t *k,size_t kl,const uint8_t *d,size_t n,uint8_t *o){CCHmac(kCCHmacAlgSHA256,k,kl,d,n,o);return true;}};
static std::vector<uint8_t> apFrame(const AthSecurity::SAEGroup19AuthMessage &m){
 std::vector<uint8_t> f(1536);f[0]=0xb0;memcpy(f.data()+4,w_sta,6);memcpy(f.data()+10,w_ap,6);memcpy(f.data()+16,w_ap,6);
 size_t n=0;assert(AthSecurity::encodeSAEGroup19AuthBody(m,f.data()+24,f.size()-24,n));f.resize(n+24);return f;
}
static Ath10kPCIDevice *device(){
 nativeSAEClockMS=0;auto d=new Ath10kPCIDevice;auto &s=d->_connection;
 s.stage=Ath10k::LinkStage::Auth;s.securityAKM=8;s.secure=s.pmfRequired=s.pmfQoSTransported=true;s.groupCipher=4;
 memcpy(s.local,w_sta,6);memcpy(s.bssid,w_ap,6);memcpy(s.ap.rsn,w_rsn,sizeof(w_rsn));s.ap.rsnLength=sizeof(w_rsn);
 d->_nativeJoinPending=true;for(auto &q:d->_wmiRadio)q.completed=q.txConsumed=q.creditReturned=true;
 auto sec=d->_nativeSecurity=new Ath10kPCIDevice::NativeSecurity;assert(sec->prepareSAEWorker());
 sec->saeSession=new Ath10kSAESession;assert(sec->saeSession->initPrepared(api,randomScalar,32,pwe,64,request,w_sta,w_ap,301,0));
 sec->saeRadio=new Ath10kSAERadio;assert(sec->saeRadio->bind(sec->saeSession,sec->saeWorker,301,0));
 sec->pmfSession=new Ath10kPMFSession;assert(sec->pmfSession->initConnection(w_sta,w_ap,301));return d;
}
static const char *tick(Ath10kPCIDevice *d,uint64_t now){nativeSAEClockMS=now;ownerGate=true;const auto e=d->serviceNativeSAE(now);ownerGate=false;return e;}
static void retired(Ath10kPCIDevice *d){d->_connection.txOwned=false;d->_connection.txComplete=true;d->_connection.txStatus=0;}
int main(){
 void *lib=dlopen("/usr/lib/system/libcorecrypto.dylib",RTLD_NOW|RTLD_LOCAL);assert(lib);
#define LOAD(field,name) api.field=reinterpret_cast<decltype(api.field)>(dlsym(lib,name));assert(api.field)
 LOAD(curve,"ccec_cp_256");LOAD(importPoint,"ccec_x963_import_pub");LOAD(validatePoint,"ccec_validate_pub");LOAD(exportPoint,"ccec_x963_export");
 LOAD(project,"ccec_projectify");LOAD(affine,"ccec_affinify");LOAD(multiply,"ccec_mult_blinded");LOAD(add,"ccec_full_add");
 LOAD(subtract,"ccec_full_sub");LOAD(readScalar,"ccn_read_uint");LOAD(rng,"ccrng");
#undef LOAD
 for(unsigned i=0;i<64;++i){unsigned v=0;assert(sscanf(P256Fixtures::generator+2*i,"%2x",&v)==1);pwe[i]=uint8_t(v);}
 randomScalar[31]=7;mask[31]=3;AthSecurity::P256CoreCryptoCandidate engine(api);AthSecurity::P256CoreCryptoWorkspace workspace;
 request.kind=AthSecurity::SAEAuthKind::Commit;request.h2e=true;
 assert(AthSecurity::saeGroup19Commit(engine,randomScalar,mask,32,pwe,64,request.commit,96,workspace));
 uint8_t peerRandom[32]{},peerMask[32]{};peerRandom[31]=11;peerMask[31]=5;
 auto peer=request;assert(AthSecurity::saeGroup19Commit(engine,peerRandom,peerMask,32,pwe,64,peer.commit,96,workspace));
 AthSecurity::SAEGroup19Keys keys;assert(AthSecurity::saeGroup19ExchangeCandidate<HMAC>(engine,peerRandom,32,peer.commit,96,request.commit,96,pwe,64,true,w_ap,w_sta,nullptr,0,nullptr,0,keys,workspace));
 AthSecurity::SAEGroup19AuthMessage confirmation{};confirmation.kind=AthSecurity::SAEAuthKind::Confirm;confirmation.h2e=true;confirmation.confirm[0]=1;
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
  using S=AthSecurity::Supplicant<Ath10kKernelCrypto,true,true>;
  assert(sec->supplicant.receive(w_m1,sizeof(w_m1))==S::Reply);
  assert(sec->supplicant.receive(w_m3,sizeof(w_m3))==S::Keys && !memcmp(sec->supplicant.keys,w_ptk+32,16));stop(d);
 }
 {auto d=device();d->_nativeJoinPending=false;ownerGate=true;assert(!d->advanceSAEAuth(0));ownerGate=false;
  assert(d->saeDiscards==1 && d->_connection.cancelRequested && !d->_nativeSecurity->saeRadio && !d->_nativeSecurity->saeSession);stop(d);}
 {auto d=device();d->_connection.securityAKM=2;ownerGate=true;assert(d->advanceSAEAuth(0));ownerGate=false;
  assert(d->transmitted.empty() && !d->saeDiscards);stop(d);}
 {auto d=device();d->blocked=true;assert(tick(d,0) && d->transmitted.empty() && !d->_connection.authReply);stop(d);}
 {auto d=device();auto sec=d->_nativeSecurity;sec->pmfSession->cancel();assert(tick(d,0) && d->transmitted.empty());stop(d);}
 {auto d=device();d->failSubmit=true;assert(tick(d,0) && d->transmitted.empty() && !d->_nativeSecurity->ready);stop(d);}
 {auto d=device();d->_connection.cancelRequested=true;assert(tick(d,0) && d->transmitted.empty());stop(d);}
 AthSecurity::wipe(&keys,sizeof(keys));dlclose(lib);
}

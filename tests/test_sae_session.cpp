#include "mock_sae_worker.hpp"
#include "../src/shared/Ath10kSAEExchange.hpp"
#include "../src/shared/Ath10kSAEPassword.hpp"
#include "../src/shared/Ath10kSupplicant.hpp"
#include "common_crypto_personal.hpp"
#include "sae_eapol_vectors.inc"
#include "p256_corecrypto_fixtures.hpp"
#include "h2e_password_vectors.inc"
#include "legacy_password_vectors.inc"
#include <CommonCrypto/CommonHMAC.h>
#include <dlfcn.h>
#include <array>
#include <vector>
#include <cstdio>
struct Pause {
    std::mutex mutex;std::condition_variable cv;bool entered=false,go=false;
    void waitHere(){std::unique_lock<std::mutex> guard(mutex);entered=true;cv.notify_all();assert(cv.wait_for(guard,5s,[&]{return go;}));}
    void wait(){std::unique_lock<std::mutex> guard(mutex);assert(cv.wait_for(guard,5s,[&]{return entered;}));}
    void resume(){std::lock_guard<std::mutex> guard(mutex);go=true;cv.notify_all();}
};
static bool failDigest=false,forceLegacyNoCandidate=false;
static unsigned prepareHMACCalls=0;
static Pause *pauseHMAC=nullptr;
static const void *ccsha256_di(){assert(!heldLocks && !ownerGate);return failDigest?nullptr:reinterpret_cast<void *>(1);}
static void cchmac(const void *,size_t kl,const void *key,size_t n,const void *data,void *out){
    assert(!heldLocks && !ownerGate);++prepareHMACCalls;if(pauseHMAC)pauseHMAC->waitHere();
    if(forceLegacyNoCandidate && n==59){memset(out,0xff,32);return;}
    CCHmac(kCCHmacAlgSHA256,key,kl,data,n,out);
}
#include "sae_session.inc"
#include "../src/kext/native/Ath10kNativeSAEJoin.hpp"
#include "native_sae_preparation.inc"
using Session=Ath10kSAESession;using Action=Session::Action;using Kind=Session::Kind;using Submission=Session::Submission;
using API=AthSecurity::P256CoreCryptoAPI;
static API real;
static unsigned curveCalls=0;
static const void *curve(){assert(!heldLocks && !ownerGate);++curveCalls;return real.curve();}
struct HMAC {
 static bool hmac256(const uint8_t *k,size_t kl,const uint8_t *d,size_t n,uint8_t *o){CCHmac(kCCHmacAlgSHA256,k,kl,d,n,o);return true;}
};
template<size_t N> static std::array<uint8_t,N> decode(const char *s){
    assert(strlen(s)==N*2);std::array<uint8_t,N> out{};
    for(size_t i=0;i<N;++i){unsigned v=0;assert(sscanf(s+i*2,"%2x",&v)==1);out[i]=uint8_t(v);}return out;
}
static const uint8_t local[6]={2,1,2,3,4,5},ap[6]={2,6,7,8,9,10};
static std::vector<uint8_t> fromAP(const AthSecurity::SAEGroup19AuthMessage &m){
    std::vector<uint8_t> out(1536);out[0]=0xb0;memcpy(out.data()+4,local,6);memcpy(out.data()+10,ap,6);memcpy(out.data()+16,ap,6);
    size_t n=0;assert(AthSecurity::encodeSAEGroup19AuthBody(m,out.data()+24,out.size()-24,n));out.resize(n+24);return out;
}
struct Blocker : Ath10kSAEWorkItem {void execute() override{}void discard() override{}};
static Ath10kSAEWorker *closeOnInit=nullptr;
static void closeQueue(){closeOnInit->shutdown();}
static uint8_t observedPWE[64]{},observedPMK[32]{};
static unsigned retiredJobs=0,retiredSessions=0;
static void observeFree(OSObject *object){
    size_t bytes=0;
    if(dynamic_cast<Ath10kSAEPrepareJob *>(object)){bytes=sizeof(Ath10kSAEPrepareJob);++retiredJobs;}
    else if(dynamic_cast<Ath10kSAEJob *>(object)){bytes=sizeof(Ath10kSAEJob);++retiredJobs;}
    else if(dynamic_cast<Session *>(object)){bytes=sizeof(Session);++retiredSessions;}
    if(!bytes)return;
    if(dynamic_cast<Ath10kSAEPrepareJob *>(object)){
        const auto *p=reinterpret_cast<const uint8_t *>(object);
        for(size_t i=0;i+13<=bytes;++i)assert(memcmp(p+i,"test-password",13));
    }
    const auto *p=reinterpret_cast<const uint8_t *>(object);
    for(size_t i=0;i+64<=bytes;++i)assert(memcmp(p+i,observedPWE,64));
    for(size_t i=0;i+32<=bytes;++i)assert(memcmp(p+i,observedPMK,32));
}
static unsigned legacyRandomCalls=0;
static unsigned legacyRandomMode=0;
static bool legacyRandom(uint8_t *out,size_t n){
    assert(!heldLocks && !ownerGate && n && n<=64);const auto count=legacyRandomCalls++;
    memset(out,0,n);if(legacyRandomMode==1)return false;
    if(legacyRandomMode!=2)out[n-1]=uint8_t(count%2?3:7);return true;
}
static unsigned prepareRandomCalls=0;
static int prepareRandomMode=0;
static Pause *pausePrepare=nullptr;
static bool prepareRandom(uint8_t *out,size_t n){
    assert(!heldLocks && !ownerGate && n==32);const unsigned call=prepareRandomCalls++;
    if(pausePrepare)pausePrepare->waitHere();
    memset(out,0,n);
    if(prepareRandomMode==1 || (prepareRandomMode==4 && call==1))return false;
    if(prepareRandomMode==2)return true; // Broken RNG: bounded rejection.
    if(prepareRandomMode==3){out[31]=uint8_t(call%2?3:7);return true;}
    static const auto order=decode<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    if(call%2){out[31]=call==9?3:(call==7?2:3);return true;}
    switch(call){
      case 0:return true;
      case 2:out[31]=1;return true;
      case 4:memcpy(out,order.data(),32);return true;
      case 6:case 8:memcpy(out,order.data(),32);out[31]-=2;return true;
      default:out[31]=7;return true;
    }
}
int main(){
    void *lib=dlopen("/usr/lib/system/libcorecrypto.dylib",RTLD_NOW|RTLD_LOCAL);assert(lib);
#define LOAD(field,name) real.field=reinterpret_cast<decltype(real.field)>(dlsym(lib,name));assert(real.field)
    LOAD(curve,"ccec_cp_256");LOAD(importPoint,"ccec_x963_import_pub");LOAD(validatePoint,"ccec_validate_pub");
    LOAD(exportPoint,"ccec_x963_export");LOAD(project,"ccec_projectify");LOAD(affine,"ccec_affinify");
    LOAD(multiply,"ccec_mult_blinded");LOAD(add,"ccec_full_add");LOAD(subtract,"ccec_full_sub");
    LOAD(readScalar,"ccn_read_uint");LOAD(rng,"ccrng");
#undef LOAD
    API api=real;api.curve=curve;AthSecurity::P256CoreCryptoCandidate engine(api);AthSecurity::P256CoreCryptoWorkspace workspace;
    const auto g=decode<64>(P256Fixtures::generator);
    uint8_t random[32]{},mask[32]{},peerRandom[32]{},peerMask[32]{};
    random[31]=7;mask[31]=3;peerRandom[31]=11;peerMask[31]=5;
    AthSecurity::SAEGroup19AuthMessage request{},peer{},confirmation{};
    request.kind=peer.kind=AthSecurity::SAEAuthKind::Commit;request.h2e=peer.h2e=true;
    assert(AthSecurity::saeGroup19Commit(engine,random,mask,32,g.data(),64,request.commit,96,workspace));
    assert(AthSecurity::saeGroup19Commit(engine,peerRandom,peerMask,32,g.data(),64,peer.commit,96,workspace));
    AthSecurity::SAEGroup19Keys peerKeys{};
    assert(AthSecurity::saeGroup19ExchangeCandidate<HMAC>(engine,peerRandom,32,peer.commit,96,request.commit,96,g.data(),64,true,ap,local,nullptr,0,nullptr,0,peerKeys,workspace));
    const auto expected=decode<32>("82b9391b7d38228fdb913b2d587547380bfc1310fb5c63b9b8e1baa2d568d715");
    memcpy(observedPWE,g.data(),64);memcpy(observedPMK,expected.data(),32);objectFreeObserver=observeFree;
    assert(!memcmp(peerKeys.pmk,expected.data(),32));
    confirmation.kind=AthSecurity::SAEAuthKind::Confirm;confirmation.h2e=true;confirmation.confirm[0]=1;
    assert(AthSecurity::saeGroup19Confirm<HMAC>(peerKeys.kck,32,1,peer.commit,96,request.commit,96,confirmation.confirm+2,32));
    const auto peerFrame=fromAP(peer),confirmFrame=fromAP(confirmation);
    auto worker=new Ath10kSAEWorker;assert(worker->init());auto call=latest;
    { // Real off-gate preparation, not fixture-supplied random/mask/commit.
      auto prepare=[&](uint32_t gen,uint64_t now,const uint8_t *point){
        auto job=new Ath10kSAEPrepareJob;ownerGate=true;
        const auto before=curveCalls;assert(job->initPWE(api,prepareRandom,point,64,true,local,ap,gen,now));
        assert(before==curveCalls);ownerGate=false;return job;
      };
      auto submitPrepare=[&](Ath10kSAEPrepareJob *job){
        ownerGate=true;assert(worker->submit(job));ownerGate=false;job->release();
        run(call);ownerGate=true;auto item=worker->takeCompleted();ownerGate=false;
        auto done=dynamic_cast<Ath10kSAEPrepareJob *>(item);assert(done);return done;
      };
      prepareRandomMode=0;prepareRandomCalls=0;
      auto job=submitPrepare(prepare(70,6000,g.data()));assert(prepareRandomCalls==12);
      job->execute();assert(prepareRandomCalls==12);
      ownerGate=true;auto prepared=job->takePrepared(local,ap,70,6001);ownerGate=false;assert(prepared);
      assert(!job->takePrepared(local,ap,70,6001));job->release();
      AthSecurity::SAEGroup19CommitTx tx;assert(prepared->snapshotCommit(tx,1,70,6001));
      uint8_t encoded[1536]{};size_t encodedBytes=0;
      assert(AthSecurity::encodeSAEGroup19AuthBody(request,encoded+24,sizeof(encoded)-24,encodedBytes));
      assert(tx.size()==encodedBytes+24 && !memcmp(tx.data()+24,encoded+24,encodedBytes));
      assert(prepared->poll(70,6000+AthSecurity::SAEGroup19ClientExchange::DeadlineMs)==Action::Failed);
      prepared->release();assert(objects==1);
      for(unsigned scenario=0;scenario<5;++scenario){
        prepareRandomMode=3;prepareRandomCalls=0;job=submitPrepare(prepare(71,7000,g.data()));
        uint8_t other[6];memcpy(other,ap,6);other[5]^=1;
        const auto now=scenario==3?7000+AthSecurity::SAEGroup19ClientExchange::DeadlineMs:(scenario==4?6999:7001);
        assert(!job->takePrepared(scenario==0?other:local,scenario==1?other:ap,scenario==2?72:71,now));
        assert(!job->takePrepared(local,ap,71,7001));job->release();assert(objects==1);
      }
      for(int mode : {1,2,4}){
        prepareRandomMode=mode;prepareRandomCalls=0;job=submitPrepare(prepare(73,8000,g.data()));
        assert(prepareRandomCalls==(mode==1?1u:(mode==4?2u:256u)));assert(!job->takePrepared(local,ap,73,8001));job->release();
      }
      uint8_t invalid[64]{};prepareRandomMode=3;prepareRandomCalls=0;
      job=submitPrepare(prepare(74,9000,invalid));assert(prepareRandomCalls==0);
      assert(!job->takePrepared(local,ap,74,9001));job->release();
      // Cancellation while preparation is running: retained work owns its
      // PWE/random snapshot and the queue discards it without owner callbacks.
      prepareRandomCalls=0;Pause paused;pausePrepare=&paused;
      job=prepare(75,10000,g.data());assert(worker->submit(job));job->release();
      std::thread runner([&]{run(call);});paused.wait();ownerGate=true;worker->cancel();ownerGate=false;
      paused.resume();runner.join();pausePrepare=nullptr;
      assert(!worker->takeCompleted() && objects==1);
      // Rejected initialization cannot execute RNG or publish a session.
      job=new Ath10kSAEPrepareJob;prepareRandomCalls=0;
      assert(!job->initPWE(api,prepareRandom,g.data(),64,true,local,ap,0,1));
      assert(!job->initPWE(api,prepareRandom,g.data(),64,true,local,ap,1,~uint64_t(0)));
      job->discard();assert(!job->initPWE(api,prepareRandom,g.data(),64,true,local,ap,1,1));
      job->execute();assert(!prepareRandomCalls);job->release();assert(objects==1);
    }
    { // Password -> PT -> MAC-bound PWE -> random/mask -> commit all run on the worker.
      AthSecurity::P256FieldAPI field{};field.curve=curve;
#define FIELD(member,name) field.member=reinterpret_cast<decltype(field.member)>(dlsym(lib,name));assert(field.member)
      FIELD(units,"cczp_n");FIELD(prime,"cczp_prime");FIELD(multiply,"cczp_mul");FIELD(inverse,"cczp_inv");FIELD(add,"cczp_add");FIELD(subtract,"cczp_sub");
#undef FIELD
      const uint8_t name[]="test-ssid",secret[]="test-password",identifier[]="test-id";
      const auto expectedPWE=decode<64>("8e3a78633b49752947fa2ec5fe4f9ceb7d80763eb62ecbaa468a8b570618f660a4932a75da3118352dfa78c45ed3c039d020c8e1b9f32504a8e725e085b6930d");
      const auto expectedPT=decode<64>("84347bb62237b0df47cae8e044af1c097d15f635dbed2ae56b6b1740189a73f5de793758cf3db5c47ef4e2636e730ab88551c914ebdb8e9ef4e3303b7c9d5c1b");
      auto contains=[](const void *object,size_t bytes,const uint8_t *value,size_t length){
        auto p=static_cast<const uint8_t *>(object);for(size_t at=0;at+length<=bytes;++at)if(!memcmp(p+at,value,length))return true;return false;
      };
      auto prepare=[&](bool broken=false){
        auto job=new Ath10kSAEPrepareJob;uint8_t mutableName[9],mutableSecret[13],mutableID[7];
        memcpy(mutableName,name,9);memcpy(mutableSecret,secret,13);memcpy(mutableID,identifier,7);
        auto provider=field;if(broken)provider.curve=[]()->const void *{assert(!ownerGate && !heldLocks);return nullptr;};
        const auto callsBefore=curveCalls;ownerGate=true;
        assert(job->initH2E(api,provider,prepareRandom,mutableName,9,mutableSecret,13,mutableID,7,local,ap,401,80000));
        ownerGate=false;assert(callsBefore==curveCalls);
        memset(mutableName,0,sizeof(mutableName));memset(mutableSecret,0,sizeof(mutableSecret));memset(mutableID,0,sizeof(mutableID));
        return job;
      };
      for(unsigned scenario=0;scenario<5;++scenario){
        prepareRandomMode=3;prepareRandomCalls=0;auto job=prepare(scenario==4);assert(worker->submit(job));job->release();
        run(call);auto item=worker->takeCompletedFor(job);assert(item==job);
        assert(!contains(job,sizeof(*job),secret,13) && !contains(job,sizeof(*job),expectedPT.data(),64));
        if(scenario==0){
          ownerGate=true;auto session=job->takePreparedH2E(name,9,local,ap,401,80001);ownerGate=false;assert(session && session->usingH2E());
          AthSecurity::SAEGroup19CommitTx tx;assert(session->snapshotCommit(tx,1,401,80001));
          AthSecurity::SAEGroup19AuthMessage parsed;assert(AthSecurity::decodeSAEGroup19AuthBody(tx.data()+24,tx.size()-24,true,0,parsed)==AthSecurity::SAEWireResult::Valid);
          assert(parsed.identifierPresent && parsed.identifierBytes==7 && !memcmp(parsed.identifier,identifier,7));
          uint8_t commit[96]{};assert(AthSecurity::saeGroup19Commit(engine,random,mask,32,expectedPWE.data(),64,commit,96,workspace));
          assert(!memcmp(parsed.commit,commit,96));
          auto remote=parsed;assert(AthSecurity::saeGroup19Commit(engine,peerRandom,peerMask,32,expectedPWE.data(),64,remote.commit,96,workspace));
          AthSecurity::SAEGroup19Keys remoteKeys{};
          assert(AthSecurity::saeGroup19ExchangeCandidate<HMAC>(engine,peerRandom,32,remote.commit,96,parsed.commit,96,expectedPWE.data(),64,true,ap,local,nullptr,0,nullptr,0,remoteKeys,workspace));
          assert(session->completeCommit(tx,true,401,80001));const auto remoteFrame=fromAP(remote);
          assert(session->receive(remoteFrame.data(),remoteFrame.size(),401,80002)==Action::ComputeKeys);
          ownerGate=true;assert(session->queue(worker,Kind::Keys,401,80002)==Submission::Queued);ownerGate=false;run(call);
          auto keyResult=worker->takeCompletedFor(session);assert(keyResult && session->consume(keyResult,401,80003)==Action::SendConfirm);keyResult->release();
          assert(session->queue(worker,Kind::LocalConfirm,401,80003)==Submission::Queued);run(call);auto confirmationJob=worker->takeCompletedFor(session);assert(confirmationJob);
          assert(session->consume(confirmationJob,401,80004)==Action::SendConfirm);
          assert(session->completeConfirm(confirmationJob,true,401,80004)==Action::Ignore);confirmationJob->release();
          AthSecurity::SAEGroup19AuthMessage remoteConfirm{};remoteConfirm.kind=AthSecurity::SAEAuthKind::Confirm;remoteConfirm.h2e=true;remoteConfirm.confirm[0]=1;
          assert(AthSecurity::saeGroup19Confirm<HMAC>(remoteKeys.kck,32,1,remote.commit,96,parsed.commit,96,remoteConfirm.confirm+2,32));
          const auto remoteConfirmFrame=fromAP(remoteConfirm);
          assert(session->receive(remoteConfirmFrame.data(),remoteConfirmFrame.size(),401,80005)==Action::VerifyPeer);
          assert(session->queue(worker,Kind::PeerConfirm,401,80005)==Submission::Queued);run(call);confirmationJob=worker->takeCompletedFor(session);
          assert(confirmationJob && session->consume(confirmationJob,401,80006)==Action::Accepted);confirmationJob->release();
          uint8_t authenticated[32]{},pmkid[16]{};assert(session->copyPMK(authenticated,32,pmkid,16,401,80006));
          assert(!memcmp(authenticated,remoteKeys.pmk,32) && !memcmp(pmkid,remoteKeys.pmkid,16));
          AthSecurity::wipe(authenticated,sizeof(authenticated));AthSecurity::wipe(&remoteKeys,sizeof(remoteKeys));session->release();
        }else if(scenario==1)assert(!job->takePreparedH2E(reinterpret_cast<const uint8_t *>("wrongssid"),9,local,ap,401,80001));
        else if(scenario==2)assert(!job->takePrepared(local,ap,401,80001)); // No unbound/PWE API escape.
        else if(scenario==3)assert(!job->takePreparedH2E(name,9,local,ap,401,80000+AthSecurity::SAEGroup19ClientExchange::DeadlineMs));
        else {assert(!prepareRandomCalls);assert(!job->takePreparedH2E(name,9,local,ap,401,80001));}
        assert(!job->takePreparedH2E(name,9,local,ap,401,80001));job->release();assert(objects==1);
      }
      {auto job=prepare();assert(worker->submit(job));job->release();ownerGate=true;
       assert(worker->cancelFor(job));ownerGate=false;assert(!worker->takeCompleted() && objects==1);}
      {auto job=prepare();job->release();assert(objects==1);} // Unsubmitted secrets retire too.
      {auto job=prepare();failDigest=true;prepareRandomCalls=0;assert(worker->submit(job));job->release();run(call);failDigest=false;
       auto item=worker->takeCompletedFor(job);assert(item==job && !prepareRandomCalls);
       assert(!contains(job,sizeof(*job),secret,13) && !job->takePreparedH2E(name,9,local,ap,401,80001));job->release();assert(objects==1);}
      {auto job=prepare();prepareRandomMode=3;prepareRandomCalls=0;assert(worker->submit(job));job->release();
       Pause paused;pauseHMAC=&paused;std::thread runner([&]{run(call);});paused.wait();ownerGate=true;assert(worker->cancelFor(job));ownerGate=false;
       paused.resume();runner.join();pauseHMAC=nullptr;assert(!worker->takeCompleted() && objects==1);}
      // Independent boundary vectors include embedded NULs, full 32/64/254-byte
      // fields, absent identifiers and UTF-8 octets. No strlen on credentials.
      auto octets=[](const char *hex){
        const size_t count=strlen(hex)/2;std::vector<uint8_t> out(count);
        for(size_t i=0;i<count;++i){unsigned value=0;assert(sscanf(hex+2*i,"%2x",&value)==1);out[i]=uint8_t(value);}return out;
      };
      // Synthetic native wire request -> selected BSS policy -> retained job
      // -> serialized commit. NativeJoinAuth remains Unsupported throughout.
      auto nativePrepare=[&](const std::vector<uint8_t> &ssid,const std::vector<uint8_t> &password,bool h2e,const char *commit,bool hidden=false){
        std::array<uint8_t,0x2cc> raw{};Ath10k::htcWriteLE32(raw.data()+0x10,1);Ath10k::htcWriteLE32(raw.data()+0x14,1u<<12);
        Ath10k::htcWriteLE32(raw.data()+0x1c,uint32_t(ssid.size()));memcpy(raw.data()+0x20,ssid.data(),ssid.size());
        Ath10k::htcWriteLE32(raw.data()+0x44,uint32_t(password.size()));Ath10k::htcWriteLE32(raw.data()+0x48,10);memcpy(raw.data()+0x50,password.data(),password.size());
        Ath10k::htcWriteLE32(raw.data()+0x214,1);memcpy(raw.data()+0x21c,ap,6);
        AirportWCL::JoinRequest native{};assert(AirportWCL::decodeJoin(raw.data(),raw.size(),native));
        assert(nativeSAEPasswordEnvelope(native) && nativeJoinAuth(native)==NativeJoinAuth::Unsupported);
        Ath10k::WMIBSS selected{};selected.privacy=selected.rsnPresent=true;selected.ssidLength=uint8_t(ssid.size());
        memcpy(selected.ssid,ssid.data(),ssid.size());memcpy(selected.bssid,ap,6);
        selected.hidden=hidden;if(hidden)selected.ssidLength=0;
        size_t rsnBytes=0;assert(AthSecurity::buildSAEStationRSN(nullptr,0,selected.rsn,sizeof(selected.rsn),rsnBytes));selected.rsnLength=uint16_t(rsnBytes);
        if(h2e){selected.rsnxe[0]=244;selected.rsnxe[1]=1;selected.rsnxe[2]=0x20;selected.rsnxeLength=3;}
        auto job=new Ath10kSAEPrepareJob;legacyRandomCalls=prepareRandomCalls=0;prepareRandomMode=3;legacyRandomMode=0;
        const auto before=curveCalls;ownerGate=true;
        assert(initNativeSAEPasswordCandidate(*job,native,selected,api,field,h2e?prepareRandom:legacyRandom,local,601,200000)==
          (h2e?NativeSAEPasswordMode::H2E:NativeSAEPasswordMode::Legacy));
        ownerGate=false;assert(curveCalls==before);
        memset(&native,0,sizeof(native));memset(raw.data(),0,raw.size());selected.rsnxeLength=0; // No borrowed caller storage/mode.
        assert(worker->submit(job));job->release();run(call);assert(worker->takeCompletedFor(job)==job);
        auto session=job->takePreparedPassword(ssid.data(),ssid.size(),local,ap,601,200001);assert(session && session->usingH2E()==h2e);
        AthSecurity::SAEGroup19CommitTx tx;assert(session->snapshotCommit(tx,1,601,200001));AthSecurity::SAEGroup19AuthMessage parsed;
        assert(AthSecurity::decodeSAEGroup19AuthBody(tx.data()+24,tx.size()-24,h2e,0,parsed)==AthSecurity::SAEWireResult::Valid);
        const auto expectedCommit=decode<96>(commit);assert(!memcmp(parsed.commit,expectedCommit.data(),96) && !parsed.identifierPresent);
        session->release();job->release();assert(objects==1);
      };
      for(const auto &v:H2EPasswordVectors::vectors)if(!*v.identifier)nativePrepare(octets(v.ssid),octets(v.password),true,v.commit);
      {const auto &v=H2EPasswordVectors::vectors[2];nativePrepare(octets(v.ssid),octets(v.password),true,v.commit,true);}
      for(const auto &v:LegacyPasswordVectors::vectors)nativePrepare(std::vector<uint8_t>(name,name+9),octets(v.password),false,v.commit);
      {AirportWCL::JoinRequest native{};native.lowerAuth=1;native.upperAuth=1u<<12;native.keyCipher=10;native.keyLength=13;
       native.ssidLength=9;memcpy(native.ssid,name,9);memcpy(native.key,secret,13);memcpy(native.bssid,ap,6);
       Ath10k::WMIBSS selected{};selected.privacy=selected.rsnPresent=true;selected.ssidLength=9;memcpy(selected.ssid,name,9);memcpy(selected.bssid,ap,6);
       size_t n=0;assert(AthSecurity::buildSAEStationRSN(nullptr,0,selected.rsn,sizeof(selected.rsn),n));selected.rsnLength=uint16_t(n);
       assert(nativeSAEPasswordMode(native,selected)==NativeSAEPasswordMode::Legacy);
       auto hidden=selected;hidden.hidden=true;hidden.ssidLength=0;assert(nativeSAEPasswordMode(native,hidden)==NativeSAEPasswordMode::Legacy);
       hidden.hidden=false;assert(nativeSAEPasswordMode(native,hidden)==NativeSAEPasswordMode::Unsupported);
       for(unsigned bad=0;bad<11;++bad){auto request=native;auto bss=selected;
        if(bad==0)request.keyCipher=6;if(bad==1)request.upperAuth|=8;if(bad==2)bss.ssid[8]^=1;if(bad==3)bss.bssid[5]^=1;
        if(bad==4)bss.privacy=false;if(bad==5)bss.rsn[19]=2;if(bad==6){bss.rsnxeLength=3;bss.rsnxe[0]=244;bss.rsnxe[1]=2;}
        if(bad==7){request.rsnLength=sizeof(AthSecurity::stationRSN);memcpy(request.rsn,AthSecurity::stationRSN,request.rsnLength);}
        if(bad==8)request.upperAuthExt=1;if(bad==9)request.transitionDisable=2;if(bad==10)request.transitionDisable=0x10;
        auto job=new Ath10kSAEPrepareJob;const auto before=curveCalls;prepareRandomCalls=0;ownerGate=true;
        assert(initNativeSAEPasswordCandidate(*job,request,bss,api,field,prepareRandom,local,602,200000)==NativeSAEPasswordMode::Unsupported);
        ownerGate=false;job->execute();assert(curveCalls==before && !prepareRandomCalls);job->release();assert(objects==1);
       }
      }
      // Native owner: exact AP security snapshot, original deadline, typed job
      // ownership and cancellation while the worker still owns secret buffers.
      {
        using Preparation=Ath10kNativeSAEPreparation;using State=Preparation::State;
        AirportWCL::JoinRequest request{};request.lowerAuth=1;request.upperAuth=1u<<12;request.keyCipher=10;
        request.keyLength=13;memcpy(request.key,secret,13);request.ssidLength=9;memcpy(request.ssid,name,9);memcpy(request.bssid,ap,6);
        Ath10k::WMIBSS selected{};selected.privacy=selected.rsnPresent=true;selected.ssidLength=9;
        memcpy(selected.ssid,name,9);memcpy(selected.bssid,ap,6);size_t n=0;
        assert(AthSecurity::buildSAEStationRSN(nullptr,0,selected.rsn,sizeof(selected.rsn),n));selected.rsnLength=uint16_t(n);
        selected.rsnxeLength=3;selected.rsnxe[0]=244;selected.rsnxe[1]=1;selected.rsnxe[2]=0x20;
        auto begin=[&](Preparation &owner,uint32_t gen=701){
          prepareRandomMode=3;prepareRandomCalls=0;legacyRandomMode=0;legacyRandomCalls=0;
          ownerGate=true;const auto before=curveCalls;
          assert(owner.begin(worker,request,selected,api,field,selected.rsnxeLength?prepareRandom:legacyRandom,local,gen,300000));
          assert(owner.active() && before==curveCalls);ownerGate=false;
        };
        auto collect=[&](Preparation &owner,uint64_t now=300001){
          ownerGate=true;auto result=owner.collect(name,9,selected,local,701,now);ownerGate=false;return result;
        };
        for(unsigned mode=0;mode<3;++mode){
          if(mode==1)selected.rsnxeLength=0;
          if(mode==2){selected.rsnxeLength=3;selected.hidden=true;selected.ssidLength=0;}
          Preparation owner;begin(owner);assert(!owner.begin(worker,request,selected,api,field,prepareRandom,local,702,300000));
          assert(collect(owner).state==State::Pending);run(call);
          auto result=collect(owner,300002);assert(result.state==State::Ready && result.session);
          assert(result.session->usingH2E()==(mode!=1));AthSecurity::SAEGroup19CommitTx tx;
          assert(result.session->snapshotCommit(tx,1,701,300002));result.session->release();
          assert(!owner.active() && collect(owner,300003).state==State::Idle && objects==1);
        }
        selected.hidden=false;selected.ssidLength=9;
        for(unsigned change=0;change<11;++change){
          Preparation owner;begin(owner);run(call);auto current=selected;uint8_t station[6];memcpy(station,local,6);
          auto ssid=std::vector<uint8_t>(name,name+9);uint32_t gen=701;uint64_t now=300002;
          if(change==0)current.rsn[19]^=1;if(change==1)current.rsnxe[2]^=0x20;
          if(change==2)current.bssid[5]^=1;if(change==3)station[5]^=1;if(change==4)ssid.back()^=1;
          if(change==5)++gen;if(change==6)current.privacy=false;if(change==7)current.rsnxeLength=0;
          if(change==8)current.ssidLength=255;if(change==9)now=305000;if(change==10)now=299999;
          ownerGate=true;auto result=owner.collect(ssid.data(),ssid.size(),current,station,gen,now);ownerGate=false;
          assert(!result.session && result.state==(change==9?State::Expired:(change==10?State::ClockError:State::Changed)));
          assert(!owner.active() && worker->available() && objects==1);
        }
        {Preparation owner;begin(owner);assert(collect(owner,300010).state==State::Pending);
         assert(collect(owner,300009).state==State::ClockError && worker->available() && objects==1);}
        // Waiting behind another owner neither consumes nor cancels its result.
        {auto foreign=new Ath10kSAEPrepareJob;
         assert(foreign->initH2E(api,field,prepareRandom,name,9,secret,13,nullptr,0,local,ap,700,300000));
         assert(worker->submit(foreign));Preparation owner;begin(owner);run(call);
         assert(collect(owner).state==State::Pending);owner.cancel();
         assert(worker->takeCompletedFor(foreign)==foreign);foreign->release();foreign->release();assert(objects==1);}
        {auto foreign=new Ath10kSAEPrepareJob;
         assert(foreign->initH2E(api,field,prepareRandom,name,9,secret,13,nullptr,0,local,ap,700,300000));
         assert(worker->submit(foreign));Preparation owner;begin(owner);run(call);
         assert(collect(owner,304999).state==State::Pending);
         assert(worker->takeCompletedFor(foreign)==foreign);foreign->release();foreign->release();
         assert(collect(owner,305000).state==State::Expired && worker->available() && objects==1);}
        {Preparation owner;begin(owner);ownerGate=true;owner.cancel();ownerGate=false;
         assert(worker->available() && !owner.active() && objects==1);}
        {Preparation owner;begin(owner);worker->cancel();assert(collect(owner).state==State::Failed && objects==1);}
        // Cancellation/replacement while a real crypto call is paused: the old
        // job remains retained and the replacement cannot consume its output.
        {Preparation owner;begin(owner);Pause pause;pauseHMAC=&pause;
         std::thread callback([&]{run(call);});pause.wait();
         ownerGate=true;owner.cancel();assert(!owner.active());ownerGate=false;
         // Do not reset the deterministic RNG while the old callback runs.
         ownerGate=true;assert(owner.begin(worker,request,selected,api,field,prepareRandom,local,701,300010));ownerGate=false;
         assert(collect(owner,300011).state==State::Pending);
         pause.resume();callback.join();pauseHMAC=nullptr;
         prepareRandomCalls=0;assert(collect(owner,300012).state==State::Pending);run(call);
         auto result=collect(owner,300013);assert(result.state==State::Ready && result.session);result.session->release();assert(objects==1);}
      }
      for(const auto &vector:H2EPasswordVectors::vectors){
        const auto boundName=octets(vector.ssid),boundSecret=octets(vector.password),boundID=octets(vector.identifier);
        const auto pt=decode<64>(vector.pt);const auto expectedCommit=decode<96>(vector.commit);
        for(unsigned mismatch=0;mismatch<(boundName.size()==32?7u:1u);++mismatch){
          auto mutableName=boundName,mutableSecret=boundSecret,mutableID=boundID;
          auto job=new Ath10kSAEPrepareJob;prepareRandomMode=3;prepareRandomCalls=0;
          ownerGate=true;const auto before=curveCalls;
          assert(job->initH2E(api,field,prepareRandom,mutableName.data(),mutableName.size(),mutableSecret.data(),mutableSecret.size(),
            mutableID.data(),mutableID.size(),local,ap,403,90000));
          assert(curveCalls==before);ownerGate=false;
          memset(mutableName.data(),0xa5,mutableName.size());memset(mutableSecret.data(),0xa5,mutableSecret.size());
          if(!mutableID.empty())memset(mutableID.data(),0xa5,mutableID.size());
          assert(worker->submit(job));job->release();run(call);assert(worker->takeCompletedFor(job)==job);
          assert(prepareRandomCalls==2);job->execute();assert(prepareRandomCalls==2);
          assert(!contains(job,sizeof(*job),pt.data(),pt.size()));
          if(boundSecret.size()>=8)assert(!contains(job,sizeof(*job),boundSecret.data(),boundSecret.size()));
          auto suppliedName=boundName;uint8_t suppliedStation[6],suppliedAP[6];
          memcpy(suppliedStation,local,6);memcpy(suppliedAP,ap,6);
          if(mismatch==1)suppliedName.back()^=1; // Same NUL prefix, different final SSID octet.
          if(mismatch==2)suppliedStation[5]^=1;
          if(mismatch==3)suppliedAP[5]^=1;
          const uint32_t suppliedGeneration=mismatch==4?404:403;
          const uint64_t now=mismatch==5?89999:(mismatch==6?95000:90001);
          ownerGate=true;auto session=job->takePreparedH2E(suppliedName.data(),suppliedName.size(),suppliedStation,suppliedAP,suppliedGeneration,now);ownerGate=false;
          if(mismatch)assert(!session);
          else {
            assert(session && session->usingH2E());AthSecurity::SAEGroup19CommitTx tx;
            assert(session->snapshotCommit(tx,1,403,90001));AthSecurity::SAEGroup19AuthMessage parsed;
            assert(AthSecurity::decodeSAEGroup19AuthBody(tx.data()+24,tx.size()-24,true,0,parsed)==AthSecurity::SAEWireResult::Valid);
            assert(!memcmp(parsed.commit,expectedCommit.data(),96));
            assert(parsed.identifierPresent==!boundID.empty() && parsed.identifierBytes==boundID.size());
            if(!boundID.empty())assert(!memcmp(parsed.identifier,boundID.data(),boundID.size()));session->release();
          }
          assert(!job->takePreparedH2E(boundName.data(),boundName.size(),local,ap,403,90001));
          job->release();assert(objects==1);
        }
      }
      // Non-H2E password derivation must use legacy SAE, never open auth or
      // truncation into a PMK. Expected commits come from independent arithmetic.
      for(const auto &vector:LegacyPasswordVectors::vectors){
        auto password=octets(vector.password);const auto original=password;
        const auto expectedCommit=decode<96>(vector.commit);
        legacyRandomCalls=prepareHMACCalls=0;legacyRandomMode=0;auto job=new Ath10kSAEPrepareJob;
        ownerGate=true;const auto before=curveCalls;
        assert(job->initLegacyPassword(api,field,legacyRandom,name,9,password.data(),password.size(),local,ap,405,100000));
        assert(curveCalls==before);ownerGate=false;memset(password.data(),0xa5,password.size());
        assert(worker->submit(job));job->release();run(call);assert(worker->takeCompletedFor(job)==job);
        assert(vector.counter<=40 && prepareHMACCalls==80 && legacyRandomCalls==44);
        if(original.size()>=8)assert(!contains(job,sizeof(*job),original.data(),original.size()));
        assert(!job->takePreparedH2E(name,9,local,ap,405,100001)); // Mode-specific collector cannot mislabel the result.
        assert(!job->takePrepared(local,ap,405,100001)); // This rejects and consumes the bound result.
        job->release();assert(objects==1);
        // Prepare a fresh result and collect through the explicitly bound password API.
        job=new Ath10kSAEPrepareJob;legacyRandomCalls=0;
        assert(job->initLegacyPassword(api,field,legacyRandom,name,9,original.data(),original.size(),local,ap,405,100000));
        assert(worker->submit(job));job->release();run(call);assert(worker->takeCompletedFor(job)==job);
        ownerGate=true;auto session=job->takePreparedPassword(name,9,local,ap,405,100001);ownerGate=false;
        assert(session && !session->usingH2E());AthSecurity::SAEGroup19CommitTx tx;
        assert(session->snapshotCommit(tx,1,405,100001));AthSecurity::SAEGroup19AuthMessage parsed;
        assert(AthSecurity::decodeSAEGroup19AuthBody(tx.data()+24,tx.size()-24,false,0,parsed)==AthSecurity::SAEWireResult::Valid);
        assert(!parsed.h2e && !parsed.identifierPresent && !memcmp(parsed.commit,expectedCommit.data(),96));
        assert(!job->takePreparedPassword(name,9,local,ap,405,100001));
        const auto expectedPWE=decode<64>(vector.pwe);
          auto remote=parsed;assert(AthSecurity::saeGroup19Commit(engine,peerRandom,peerMask,32,expectedPWE.data(),64,remote.commit,96,workspace));
          AthSecurity::SAEGroup19Keys remoteKeys{};
          assert(AthSecurity::saeGroup19ExchangeCandidate<HMAC>(engine,peerRandom,32,remote.commit,96,parsed.commit,96,expectedPWE.data(),64,false,ap,local,nullptr,0,nullptr,0,remoteKeys,workspace));
          assert(session->completeCommit(tx,true,405,100001));const auto remoteFrame=fromAP(remote);
          assert(session->receive(remoteFrame.data(),remoteFrame.size(),405,100002)==Action::ComputeKeys);
          ownerGate=true;assert(session->queue(worker,Kind::Keys,405,100002)==Submission::Queued);ownerGate=false;run(call);
          auto keyResult=worker->takeCompletedFor(session);assert(keyResult && session->consume(keyResult,405,100003)==Action::SendConfirm);keyResult->release();
          assert(session->queue(worker,Kind::LocalConfirm,405,100003)==Submission::Queued);run(call);auto confirmationJob=worker->takeCompletedFor(session);assert(confirmationJob);
          assert(session->consume(confirmationJob,405,100004)==Action::SendConfirm);
          assert(session->completeConfirm(confirmationJob,true,405,100004)==Action::Ignore);confirmationJob->release();
          AthSecurity::SAEGroup19AuthMessage remoteConfirm{};remoteConfirm.kind=AthSecurity::SAEAuthKind::Confirm;remoteConfirm.h2e=false;remoteConfirm.confirm[0]=1;
          assert(AthSecurity::saeGroup19Confirm<HMAC>(remoteKeys.kck,32,1,remote.commit,96,parsed.commit,96,remoteConfirm.confirm+2,32));
          const auto remoteConfirmFrame=fromAP(remoteConfirm);
          assert(session->receive(remoteConfirmFrame.data(),remoteConfirmFrame.size(),405,100005)==Action::VerifyPeer);
          assert(session->queue(worker,Kind::PeerConfirm,405,100005)==Submission::Queued);run(call);confirmationJob=worker->takeCompletedFor(session);
          assert(confirmationJob && session->consume(confirmationJob,405,100006)==Action::Accepted);confirmationJob->release();
          uint8_t authenticated[32]{},pmkid[16]{};assert(session->copyPMK(authenticated,32,pmkid,16,405,100006));
          assert(!memcmp(authenticated,remoteKeys.pmk,32) && !memcmp(pmkid,remoteKeys.pmkid,16));
          AthSecurity::wipe(authenticated,sizeof(authenticated));AthSecurity::wipe(&remoteKeys,sizeof(remoteKeys));session->release();
        job->release();assert(objects==1);
      }
      for(unsigned failure=0;failure<5;++failure){
        auto provider=field;if(failure==3)provider.curve=[]()->const void *{assert(!ownerGate && !heldLocks);return nullptr;};
        legacyRandomMode=failure==0?1:(failure==1?2:0);legacyRandomCalls=prepareHMACCalls=0;
        auto job=new Ath10kSAEPrepareJob;
        assert(job->initLegacyPassword(api,provider,legacyRandom,name,9,secret,13,local,ap,406,110000));
        failDigest=failure==2;forceLegacyNoCandidate=failure==4;assert(worker->submit(job));job->release();run(call);failDigest=forceLegacyNoCandidate=false;
        assert(worker->takeCompletedFor(job)==job && !contains(job,sizeof(*job),secret,13));
        assert(!job->takePreparedPassword(name,9,local,ap,406,110001));job->release();assert(objects==1);
        if(failure==0)assert(legacyRandomCalls==1 && !prepareHMACCalls);
        if(failure==1)assert(legacyRandomCalls==129 && !prepareHMACCalls);
        if(failure==4)assert(legacyRandomCalls==202 && prepareHMACCalls==400); // Exhausted 200 candidates without a usable x.
      }
      legacyRandomMode=0;
      {auto job=new Ath10kSAEPrepareJob;legacyRandomCalls=0;
       assert(job->initLegacyPassword(api,field,legacyRandom,name,9,secret,13,local,ap,407,120000));
       assert(worker->submit(job));job->release();Pause paused;pauseHMAC=&paused;
       std::thread runner([&]{run(call);});paused.wait();ownerGate=true;assert(worker->cancelFor(job));ownerGate=false;
       paused.resume();runner.join();pauseHMAC=nullptr;assert(!worker->takeCompleted() && objects==1);}
      {auto job=new Ath10kSAEPrepareJob;assert(!job->initH2E(api,field,prepareRandom,name,0,secret,13,nullptr,0,local,ap,402,0));
       assert(!job->initH2E(api,field,prepareRandom,name,9,secret,65,nullptr,0,local,ap,402,0));
       auto missing=field;missing.add=nullptr;assert(!job->initH2E(api,missing,prepareRandom,name,9,secret,13,nullptr,0,local,ap,402,0));job->release();assert(objects==1);}
    }
    auto create=[&](uint32_t generation,uint64_t now){
        auto s=new Session;const auto before=curveCalls;
        assert(s->initPrepared(api,random,32,g.data(),64,request,local,ap,generation,now));
        assert(curveCalls==before);return s; // Initialization must not run crypto under a gate.
    };
    auto start=[&](Session *s,uint32_t gen,uint64_t now){
        AthSecurity::SAEGroup19CommitTx tx;ownerGate=true;
        assert(s->snapshotCommit(tx,1,gen,now));assert(s->commitReady(tx,gen,now));assert(s->completeCommit(tx,true,gen,now));
        assert(s->receive(peerFrame.data(),peerFrame.size(),gen,now)==Action::ComputeKeys);ownerGate=false;
    };
    auto take=[&](const void *owner=nullptr){run(call);
        auto result=owner?worker->takeCompletedFor(owner):worker->takeCompleted();assert(result);return result;};
    auto submit=[&](Session *s,Kind kind,uint32_t gen,uint64_t now){
        ownerGate=true;assert(s->queue(worker,kind,gen,now)==Submission::Queued);ownerGate=false;
    };
    { // Real radio coordinator owns work, TX reservations and PMK publication.
      using Radio=Ath10kSAERadio;using State=Radio::State;
      Radio radio;auto owner=create(301,30000);assert(radio.bind(owner,worker,301,30000));owner->release();
      assert(radio.service(30000)==State::Progress);
      const uint8_t *tx=nullptr;size_t txBytes=99;
      ownerGate=true;assert(radio.prepareTX(1,30000,tx,txBytes));ownerGate=false;
      assert(txBytes==128 && tx[0]==0xb0 && tx[24]==3 && tx[26]==1);
      assert(radio.completeTX(true,30000) && !radio.completeTX(true,30000));
      assert(radio.receive(peerFrame.data(),peerFrame.size(),0x39,30001)==Action::Ignore);
      assert(radio.receive(peerFrame.data(),peerFrame.size(),0,30001)==Action::ComputeKeys);
      ownerGate=true;assert(radio.service(30001)==State::Progress);ownerGate=false;run(call);
      ownerGate=true;assert(radio.service(30002)==State::Progress);ownerGate=false;run(call);
      ownerGate=true;assert(radio.service(30003)==State::Progress);
      assert(radio.prepareTX(2,30003,tx,txBytes));ownerGate=false;
      assert(txBytes==64 && tx[26]==2);
      assert(radio.completeTX(true,30003));
      assert(radio.receive(confirmFrame.data(),confirmFrame.size(),0,30004)==Action::VerifyPeer);
      ownerGate=true;assert(radio.service(30004)==State::Progress);ownerGate=false;run(call);
      ownerGate=true;assert(radio.service(30005)==State::Accepted);ownerGate=false;
      using E=AthSecurity::Supplicant<PersonalTestCrypto,true,true>;E eapol;
      assert(radio.beginEAPOL(eapol,w_snonce,local,ap,w_rsn,sizeof(w_rsn),30005));
      assert(eapol.receive(w_m1,sizeof(w_m1))==E::Reply && eapol.receive(w_m3,sizeof(w_m3))==E::Keys);
      assert(!memcmp(eapol.keys,w_ptk+32,16) && !memcmp(eapol.managementKey.key,w_igtk,16));
      assert(!radio.beginEAPOL(eapol,w_snonce,local,ap,w_rsn,sizeof(w_rsn),30005));
      radio.cancel();assert(radio.service(30006)==State::Idle && objects==1);
    }
    { // TX blocked until the original deadline must never reach the channel.
      Ath10kSAERadio radio;auto owner=create(302,40000);assert(radio.bind(owner,worker,302,40000));owner->release();
      const uint8_t *tx=nullptr;size_t txBytes=0;assert(radio.prepareTX(1,40000,tx,txBytes));
      assert(!radio.completeTX(true,40000+AthSecurity::SAEGroup19ClientExchange::DeadlineMs));
      assert(radio.service(50000)==Ath10kSAERadio::State::Failed);
      assert(!radio.prepareTX(2,50000,tx,txBytes) && !tx && !txBytes);radio.cancel();assert(objects==1);
    }
    { // Revocation by the native owner cannot leave an idle protocol alive.
      Ath10kSAERadio radio;auto owner=create(305,55000);assert(radio.bind(owner,worker,305,55000));
      owner->cancel();owner->release();assert(radio.service(55001)==Ath10kSAERadio::State::Failed);
      radio.cancel();assert(objects==1);
    }
    { // Cancelling this attempt must not cancel another shared queue owner.
      Ath10kSAERadio radio;auto owner=create(303,60000);assert(radio.bind(owner,worker,303,60000));owner->release();
      auto foreign=new Blocker;assert(worker->submit(foreign));run(call);
      radio.cancel();assert(worker->takeCompletedFor(foreign)==foreign);foreign->release();foreign->release();assert(objects==1);
    }
    { // Cancel during actual key crypto, without waiting or wiping its snapshot.
      Ath10kSAERadio radio;auto owner=create(304,70000);assert(radio.bind(owner,worker,304,70000));owner->release();
      const uint8_t *tx=nullptr;size_t txBytes=0;assert(radio.prepareTX(1,70000,tx,txBytes) && radio.completeTX(true,70000));
      assert(radio.receive(peerFrame.data(),peerFrame.size(),0,70001)==Action::ComputeKeys);
      assert(radio.service(70001)==Ath10kSAERadio::State::Progress);
      Pause paused;pauseHMAC=&paused;std::thread runner([&]{run(call);});paused.wait();
      ownerGate=true;radio.cancel();ownerGate=false;paused.resume();runner.join();pauseHMAC=nullptr;
      assert(radio.service(70002)==Ath10kSAERadio::State::Idle && !worker->takeCompleted() && objects==1);
    }
    uint8_t pmk[32],id[16];memset(pmk,0xa5,32);memset(id,0xa5,16);
    { // Reject invalid/double initialization without cryptography or replacement.
      auto bad=new Session;API incomplete{};assert(!bad->initPrepared(incomplete,random,32,g.data(),64,request,local,ap,1,0));
      assert(!bad->initPrepared(api,random,31,g.data(),64,request,local,ap,1,0));
      assert(!bad->initPrepared(api,random,32,g.data(),64,request,local,ap,0,0));bad->release();
    }
    auto s=new Session;uint8_t mutableRandom[32],mutablePWE[64];auto mutableRequest=request;
    memcpy(mutableRandom,random,32);memcpy(mutablePWE,g.data(),64);
    ownerGate=true;assert(s->initPrepared(api,mutableRandom,32,mutablePWE,64,mutableRequest,local,ap,11,0));ownerGate=false;
    memset(mutableRandom,0,32);memset(mutablePWE,0,64);memset(&mutableRequest,0,sizeof(mutableRequest));
    assert(!s->initPrepared(api,random,32,g.data(),64,request,local,ap,12,0));start(s,11,0);
    // Busy admission must not consume the single key-work reservation.
    auto blocker=new Blocker;assert(worker->submit(blocker));
    assert(s->queue(worker,Kind::Keys,11,1)==Submission::Busy);
    auto unrelated=take();assert(s->consume(unrelated,11,1)==Action::Ignore);unrelated->release();blocker->release();
    failObjectInit=true;assert(s->queue(worker,Kind::Keys,11,1)==Submission::NoMemory);
    submit(s,Kind::Keys,11,1);assert(s->queue(worker,Kind::Keys,11,1)==Submission::Busy);
    auto result=take(s);auto other=create(11,0);
    assert(other->consume(result,11,2)==Action::Ignore);other->release();
    assert(s->consume(result,12,2)==Action::Ignore);
    ownerGate=true;assert(s->consume(result,11,2)==Action::SendConfirm);ownerGate=false;
    assert(s->consume(result,11,2)==Action::Ignore);result->release();
    assert(s->receive(confirmFrame.data(),confirmFrame.size(),11,3)==Action::VerifyPeer);
    submit(s,Kind::PeerConfirm,11,3);result=take(s);assert(s->consume(result,11,3)==Action::Ignore);result->release();
    assert(!s->copyPMK(pmk,32,id,16,11,3));for(auto v:pmk)assert(v==0xa5);
    {AthSecurity::Supplicant<PersonalTestCrypto,true,true> notReady;
     assert(!s->beginEAPOL(notReady,w_snonce,local,ap,w_rsn,sizeof(w_rsn),11,3));
     assert(notReady.receive(w_m1,sizeof(w_m1))==decltype(notReady)::Ignore);}
    // Provider failure consumes no authentication success; timed retry gets a new job.
    submit(s,Kind::LocalConfirm,11,4);failDigest=true;result=take(s);failDigest=false;
    assert(s->consume(result,11,4)==Action::Ignore && !s->confirmReady(result,11,4));result->release();
    assert(s->poll(11,753)==Action::Ignore && s->poll(11,754)==Action::SendConfirm);
    submit(s,Kind::LocalConfirm,11,754);auto failedTX=take(s);
    assert(s->consume(failedTX,11,754)==Action::SendConfirm);
    assert(s->completeConfirm(failedTX,false,11,754)==Action::Ignore && !s->confirmReady(failedTX,11,754));
    assert(s->poll(11,1504)==Action::SendConfirm);submit(s,Kind::LocalConfirm,11,1504);result=take(s);
    uint8_t frame[128]{};size_t bytes=999;
    assert(s->encodeConfirm(result,3,frame,sizeof(frame),bytes,11,1504) && bytes==64);
    uint16_t accepted=0;
    assert(AthSecurity::verifySAEGroup19PeerConfirm<HMAC>(peerKeys.kck,32,peer.commit,96,request.commit,96,frame+30,34,false,0,accepted));
    ownerGate=true;assert(s->confirmReady(result,11,1504));assert(s->completeConfirm(result,true,11,1504)==Action::Accepted);ownerGate=false;
    assert(s->completeConfirm(failedTX,true,11,754)==Action::Ignore);failedTX->release();
    assert(s->copyPMK(pmk,32,id,16,11,1504) && !memcmp(pmk,expected.data(),32));
    { // Real queued SAE output feeds opt-in AKM8 EAPOL without password/PSK substitution.
      using E=AthSecurity::Supplicant<PersonalTestCrypto,true,true>;E eapol;
      uint8_t otherAP[6];memcpy(otherAP,ap,6);otherAP[5]^=1;
      assert(!s->beginEAPOL(eapol,w_snonce,local,otherAP,w_rsn,sizeof(w_rsn),11,1504));
      assert(!s->beginEAPOL(eapol,w_snonce,local,ap,w_rsn,sizeof(w_rsn),12,1504));
      assert(!s->beginEAPOL(eapol,nullptr,local,ap,w_rsn,sizeof(w_rsn),11,1504));
      assert(s->beginEAPOL(eapol,w_snonce,local,ap,w_rsn,sizeof(w_rsn),11,1504));
      assert(!s->copyPMK(pmk,32,id,16,11,1504));
      assert(eapol.receive(w_m1,sizeof(w_m1))==E::Reply);
      assert(eapol.outputLength==sizeof(w_m2) && !memcmp(eapol.output,w_m2,sizeof(w_m2)));
      assert(eapol.receive(w_m3,sizeof(w_m3))==E::Keys && eapol.keyChanges==7);
      // Repeated handoff must preserve the already authenticated EAPOL state.
      assert(!s->beginEAPOL(eapol,w_snonce,local,ap,w_rsn,sizeof(w_rsn),11,1504));
      assert(eapol.receive(w_m3,sizeof(w_m3))==E::Reply);
      assert(!memcmp(eapol.keys,w_ptk+32,16) && !memcmp(eapol.managementKey.key,w_igtk,16));
    }
    assert(!s->copyPMK(pmk,32,id,16,12,1504));s->cancel();assert(!s->confirmReady(result,11,1505));
    assert(!s->copyPMK(pmk,32,id,16,11,1505));s->release();result->release();assert(objects==1);
    for(unsigned scenario=0;scenario<3;++scenario){
      // Compose actual worker preparation -> SAE confirms -> AKM8 M1/M3.
      const uint32_t gen=100+scenario;const uint64_t now=20000+1000*scenario;
      prepareRandomMode=3;prepareRandomCalls=0;
      auto preparation=new Ath10kSAEPrepareJob;
      assert(preparation->initPWE(api,prepareRandom,g.data(),64,true,local,ap,gen,now));
      assert(worker->submit(preparation));preparation->release();auto item=take(preparation);
      preparation=dynamic_cast<Ath10kSAEPrepareJob *>(item);assert(preparation);
      auto bound=preparation->takePrepared(local,ap,gen,now+1);item->release();assert(bound);
      start(bound,gen,now+1);submit(bound,Kind::Keys,gen,now+2);item=take(bound);
      assert(bound->consume(item,gen,now+2)==Action::SendConfirm);item->release();
      submit(bound,Kind::LocalConfirm,gen,now+3);item=take(bound);assert(bound->consume(item,gen,now+3)==Action::SendConfirm);
      assert(bound->completeConfirm(item,true,gen,now+3)==Action::Ignore);item->release();
      assert(bound->receive(confirmFrame.data(),confirmFrame.size(),gen,now+4)==Action::VerifyPeer);
      submit(bound,Kind::PeerConfirm,gen,now+4);item=take(bound);assert(bound->consume(item,gen,now+4)==Action::Accepted);item->release();
      using E=AthSecurity::Supplicant<PersonalTestCrypto,true,true>;E eapol;
      ownerGate=true;
      const uint64_t handoffNow=scenario==2?now+AthSecurity::SAEGroup19ClientExchange::DeadlineMs:now+4;
      const bool ok=bound->beginEAPOL(eapol,w_snonce,local,ap,scenario==1?nullptr:w_rsn,scenario==1?0:sizeof(w_rsn),gen,handoffNow);
      ownerGate=false;assert(ok==!scenario);
      if(ok){assert(eapol.receive(w_m1,sizeof(w_m1))==E::Reply);assert(eapol.receive(w_m3,sizeof(w_m3))==E::Keys);
        assert(!memcmp(eapol.keys,w_ptk+32,16) && !memcmp(eapol.managementKey.key,w_igtk,16));}
      else {assert(bound->poll(gen,now+4)==Action::Ignore);
        assert(!bound->beginEAPOL(eapol,w_snonce,local,ap,w_rsn,sizeof(w_rsn),gen,now+4));
        assert(eapol.receive(w_m1,sizeof(w_m1))==E::Ignore);}
      assert(!bound->copyPMK(pmk,32,id,16,gen,now+4));bound->release();assert(objects==1);
    }
    { // A transferred old result retains its old session; replacement cannot consume it.
      auto old=create(20,2000);start(old,20,2000);submit(old,Kind::Keys,20,2001);result=take();
      old->cancel();old->release();auto replacement=create(20,2002);
      assert(replacement->consume(result,20,2002)==Action::Ignore);result->release();replacement->release();assert(objects==1);
    }
    { // Cancellation during a real HMAC must not mutate the worker's retained context.
      auto old=create(30,3000);start(old,30,3000);submit(old,Kind::Keys,30,3001);
      Pause paused;pauseHMAC=&paused;
      std::thread runner([&]{run(call);});paused.wait();
      ownerGate=true;old->cancel();old->release();worker->cancel();ownerGate=false;
      assert(objects>=3);paused.resume();runner.join();pauseHMAC=nullptr;
      assert(!worker->takeCompleted() && objects==1);
    }
    { auto failed=create(40,4000);start(failed,40,4000);submit(failed,Kind::Keys,40,4001);
      failDigest=true;result=take();failDigest=false;assert(failed->consume(result,40,4002)==Action::Failed);
      assert(!failed->copyPMK(pmk,32,id,16,40,4002));result->release();failed->release();assert(objects==1);
    }
    { // Terminal stop between advisory availability and submit must retire the exchange.
      auto racing=new Ath10kSAEWorker;assert(racing->init());auto waiting=create(50,5000);start(waiting,50,5000);
      closeOnInit=racing;objectInitHook=closeQueue;
      assert(waiting->queue(racing,Kind::Keys,50,5001)==Submission::Aborted);
      assert(waiting->poll(50,5002)==Action::Ignore && !waiting->copyPMK(pmk,32,id,16,50,5002));
      waiting->release();racing->release();closeOnInit=nullptr;assert(objects==1);
    }
    worker->shutdown();worker->release();assert(objects==0 && locks==0 && calls==0);
    assert(retiredJobs>0 && retiredSessions>0);objectFreeObserver=nullptr;
    AthSecurity::wipe(&peerKeys,sizeof(peerKeys));dlclose(lib);
}

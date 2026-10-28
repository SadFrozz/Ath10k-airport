#include "mock_sae_worker.hpp"
#include "../src/shared/Ath10kSAEExchange.hpp"
#include "p256_corecrypto_fixtures.hpp"
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
static bool failDigest=false;
static Pause *pauseHMAC=nullptr;
static const void *ccsha256_di(){assert(!heldLocks && !ownerGate);return failDigest?nullptr:reinterpret_cast<void *>(1);}
static void cchmac(const void *,size_t kl,const void *key,size_t n,const void *data,void *out){
    assert(!heldLocks && !ownerGate);if(pauseHMAC)pauseHMAC->waitHere();
    CCHmac(kCCHmacAlgSHA256,key,kl,data,n,out);
}
#include "sae_session.inc"
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
    if(dynamic_cast<Ath10kSAEJob *>(object)){bytes=sizeof(Ath10kSAEJob);++retiredJobs;}
    else if(dynamic_cast<Session *>(object)){bytes=sizeof(Session);++retiredSessions;}
    if(!bytes)return;
    const auto *p=reinterpret_cast<const uint8_t *>(object);
    for(size_t i=0;i+64<=bytes;++i)assert(memcmp(p+i,observedPWE,64));
    for(size_t i=0;i+32<=bytes;++i)assert(memcmp(p+i,observedPMK,32));
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
    auto take=[&](){run(call);auto result=worker->takeCompleted();assert(result);return result;};
    auto submit=[&](Session *s,Kind kind,uint32_t gen,uint64_t now){
        ownerGate=true;assert(s->queue(worker,kind,gen,now)==Submission::Queued);ownerGate=false;
    };
    uint8_t pmk[32],id[16];memset(pmk,0xa5,32);memset(id,0xa5,16);
    { // Reject invalid/double initialization without cryptography or replacement.
      auto bad=new Session;API incomplete{};assert(!bad->initPrepared(incomplete,random,32,g.data(),64,request,local,ap,1,0));
      assert(!bad->initPrepared(api,random,31,g.data(),64,request,local,ap,1,0));bad->release();
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
    auto result=take();auto other=create(11,0);
    assert(other->consume(result,11,2)==Action::Ignore);other->release();
    assert(s->consume(result,12,2)==Action::Ignore);
    ownerGate=true;assert(s->consume(result,11,2)==Action::SendConfirm);ownerGate=false;
    assert(s->consume(result,11,2)==Action::Ignore);result->release();
    assert(s->receive(confirmFrame.data(),confirmFrame.size(),11,3)==Action::VerifyPeer);
    submit(s,Kind::PeerConfirm,11,3);result=take();assert(s->consume(result,11,3)==Action::Ignore);result->release();
    assert(!s->copyPMK(pmk,32,id,16,11,3));for(auto v:pmk)assert(v==0xa5);
    // Provider failure consumes no authentication success; timed retry gets a new job.
    submit(s,Kind::LocalConfirm,11,4);failDigest=true;result=take();failDigest=false;
    assert(s->consume(result,11,4)==Action::Ignore && !s->confirmReady(result,11,4));result->release();
    assert(s->poll(11,753)==Action::Ignore && s->poll(11,754)==Action::SendConfirm);
    submit(s,Kind::LocalConfirm,11,754);auto failedTX=take();
    assert(s->consume(failedTX,11,754)==Action::SendConfirm);
    assert(s->completeConfirm(failedTX,false,11,754)==Action::Ignore && !s->confirmReady(failedTX,11,754));
    assert(s->poll(11,1504)==Action::SendConfirm);submit(s,Kind::LocalConfirm,11,1504);result=take();
    uint8_t frame[128]{};size_t bytes=999;
    assert(s->encodeConfirm(result,3,frame,sizeof(frame),bytes,11,1504) && bytes==64);
    uint16_t accepted=0;
    assert(AthSecurity::verifySAEGroup19PeerConfirm<HMAC>(peerKeys.kck,32,peer.commit,96,request.commit,96,frame+30,34,false,0,accepted));
    ownerGate=true;assert(s->confirmReady(result,11,1504));assert(s->completeConfirm(result,true,11,1504)==Action::Accepted);ownerGate=false;
    assert(s->completeConfirm(failedTX,true,11,754)==Action::Ignore);failedTX->release();
    assert(s->copyPMK(pmk,32,id,16,11,1504) && !memcmp(pmk,expected.data(),32));
    assert(!s->copyPMK(pmk,32,id,16,12,1504));s->cancel();assert(!s->confirmReady(result,11,1505));
    assert(!s->copyPMK(pmk,32,id,16,11,1505));s->release();result->release();assert(objects==1);
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

#include "Ath10kSAESession.hpp"
extern "C" {
#include <corecrypto/cchmac.h>
#include <corecrypto/ccsha2.h>
}
OSDefineMetaClassAndStructors(Ath10kSAESession,OSObject)
OSDefineMetaClassAndStructors(Ath10kSAEJob,Ath10kSAEWorkItem)

struct Ath10kSAEHMAC {
    static bool hmac256(const uint8_t *key,size_t keyBytes,const uint8_t *data,size_t bytes,uint8_t *out){
        const auto digest=ccsha256_di();if(!digest)return false;
        cchmac(digest,keyBytes,key,bytes,data,out);return true;
    }
};
bool Ath10kSAESession::initPrepared(const AthSecurity::P256CoreCryptoAPI &api,const uint8_t *random,size_t randomBytes,
    const uint8_t *pwe,size_t pweBytes,const AthSecurity::SAEGroup19AuthMessage &request,
    const uint8_t *local,const uint8_t *ap,uint32_t generation,uint64_t now){
    if(initialized || !OSObject::init() || !api.complete() || !generation || !random || randomBytes!=32 || !pwe || pweBytes!=64)return false;
    if(!exchange.begin(request,local,ap,now,token))return false;
    context.api=api;AthSecurity::copy(context.random,random,32);AthSecurity::copy(context.pwe,pwe,64);
    connectionGeneration=generation;handoffDeadline=now+AthSecurity::SAEGroup19ClientExchange::DeadlineMs;
    AthSecurity::copy(stationIdentity,local,6);AthSecurity::copy(apIdentity,ap,6);
    closed=false;initialized=true;return true;
}
void Ath10kSAESession::cancel(){
    closed=true;handoffDeadline=0;exchange.cancel();AthSecurity::wipe(&context,sizeof(context));
    AthSecurity::wipe(stationIdentity,sizeof(stationIdentity));AthSecurity::wipe(apIdentity,sizeof(apIdentity));
}
void Ath10kSAESession::free(){
    cancel();AthSecurity::wipe(&context,sizeof(context));token=0;connectionGeneration=0;
    OSObject::free();
}
Ath10kSAESession::Action Ath10kSAESession::poll(uint32_t generation,uint64_t now){
    return current(generation)?exchange.poll(now):Action::Ignore;
}
Ath10kSAESession::Action Ath10kSAESession::receive(const uint8_t *frame,size_t bytes,uint32_t generation,uint64_t now){
    return current(generation)?exchange.receiveFromAP(frame,bytes,now):Action::Ignore;
}
bool Ath10kSAESession::snapshotCommit(AthSecurity::SAEGroup19CommitTx &tx,uint16_t sequence,uint32_t generation,uint64_t now){
    return current(generation) && exchange.snapshotCommit(tx,sequence,now);
}
bool Ath10kSAESession::commitReady(const AthSecurity::SAEGroup19CommitTx &tx,uint32_t generation,uint64_t now){
    return current(generation) && exchange.commitReady(tx,now);
}
bool Ath10kSAESession::completeCommit(const AthSecurity::SAEGroup19CommitTx &tx,bool submitted,uint32_t generation,uint64_t now){
    return current(generation) && exchange.completeCommit(tx,submitted,now);
}
Ath10kSAESession::Submission Ath10kSAESession::queue(Ath10kSAEWorker *worker,Kind kind,uint32_t generation,uint64_t now){
    if(!current(generation) || !worker)return Submission::Aborted;
    // With a single serialized producer, ordinary busy admission consumes no
    // exchange reservation. A terminal cancellation racing submit fails closed.
    if(!worker->available())return Submission::Busy;
    auto job=new Ath10kSAEJob;if(!job)return Submission::NoMemory;
    if(!job->init()){job->release();return Submission::NoMemory;}
    job->session=this;retain();job->kind=kind;job->connectionGeneration=generation;
    bool ready=false;
    if(kind==Kind::Keys){ready=exchange.snapshotKeys(job->key,now);if(ready)job->context=context;}
    else if(kind==Kind::LocalConfirm)ready=exchange.snapshotLocalConfirm(job->confirm,now);
    else if(kind==Kind::PeerConfirm)ready=exchange.snapshotPeerConfirm(job->confirm,job->body,34,now);
    if(!ready){job->release();return Submission::NoWork;}
    const bool submitted=worker->submit(job,this);
    if(submitted && kind==Kind::Keys)AthSecurity::wipe(&context,sizeof(context));
    if(!submitted)cancel(); // Never leave an issued key job or popped confirm stranded.
    job->release();return submitted?Submission::Queued:Submission::Aborted;
}
bool Ath10kSAESession::owns(const Ath10kSAEJob *job,uint32_t generation) const {
    return current(generation) && job && job->session==this && job->connectionGeneration==generation && job->executed;
}
Ath10kSAESession::Action Ath10kSAESession::consume(Ath10kSAEWorkItem *item,uint32_t generation,uint64_t now){
    auto job=OSDynamicCast(Ath10kSAEJob,item);
    if(!owns(job,generation) || job->consumed)return Action::Ignore;
    if(job->kind==Kind::LocalConfirm)return exchange.localConfirmReady(job->confirm,now)?Action::SendConfirm:Action::Ignore;
    job->consumed=true;
    if(job->kind==Kind::Keys)return exchange.completeKeys(job->key,now);
    if(job->kind==Kind::PeerConfirm)return exchange.completePeerConfirm(job->confirm,now);
    return Action::Ignore;
}
bool Ath10kSAESession::encodeConfirm(Ath10kSAEWorkItem *item,uint16_t sequence,uint8_t *frame,size_t capacity,
    size_t &bytes,uint32_t generation,uint64_t now){
    auto job=OSDynamicCast(Ath10kSAEJob,item);
    return owns(job,generation) && !job->consumed && job->kind==Kind::LocalConfirm &&
        exchange.encodeLocalConfirm(job->confirm,sequence,frame,capacity,bytes,now);
}
bool Ath10kSAESession::confirmReady(Ath10kSAEWorkItem *item,uint32_t generation,uint64_t now){
    auto job=OSDynamicCast(Ath10kSAEJob,item);
    return owns(job,generation) && !job->consumed && job->kind==Kind::LocalConfirm && exchange.localConfirmReady(job->confirm,now);
}
Ath10kSAESession::Action Ath10kSAESession::completeConfirm(Ath10kSAEWorkItem *item,bool submitted,uint32_t generation,uint64_t now){
    auto job=OSDynamicCast(Ath10kSAEJob,item);
    if(!owns(job,generation) || job->consumed || job->kind!=Kind::LocalConfirm)return Action::Ignore;
    job->consumed=true;return exchange.completeLocalConfirm(job->confirm,submitted,now);
}
bool Ath10kSAESession::copyPMK(uint8_t *out,size_t bytes,uint8_t *id,size_t idBytes,uint32_t generation,uint64_t now){
    return current(generation) && !eapolStarted && exchange.copyPMK(token,out,bytes,id,idBytes,now);
}
void Ath10kSAEJob::execute(){
    if(executed || !session)return;
    if(kind==Ath10kSAESession::Kind::Keys){
        AthSecurity::P256CoreCryptoCandidate engine(context.api);
        key.compute<Ath10kSAEHMAC>(engine,context.random,32,context.pwe,64,workspace);
    }else if(kind==Ath10kSAESession::Kind::LocalConfirm)confirm.makeLocal<Ath10kSAEHMAC>(body,34);
    else if(kind==Ath10kSAESession::Kind::PeerConfirm)confirm.verifyPeer<Ath10kSAEHMAC>(body,34);
    AthSecurity::wipe(&context,sizeof(context));workspace.clear();
    executed=true;
}
void Ath10kSAEJob::discard(){
    key.retire();confirm.retire();workspace.clear();AthSecurity::wipe(body,sizeof(body));AthSecurity::wipe(&context,sizeof(context));
    executed=consumed=false;kind=Ath10kSAESession::Kind::Empty;connectionGeneration=0;
    auto owner=session;session=nullptr;if(owner)owner->release();
}

OSDefineMetaClassAndStructors(Ath10kSAEPrepareJob,Ath10kSAEWorkItem)

bool Ath10kSAEPrepareJob::initPWE(const AthSecurity::P256CoreCryptoAPI &provider,
    bool (*rng)(uint8_t *,size_t),const uint8_t *point,size_t bytes,bool h2e,
    const uint8_t *station,const uint8_t *bssid,uint32_t connection,uint64_t now){
    if(initialized || consumed || !OSObject::init() || !provider.complete() || !rng || !point || bytes!=64 ||
       !AthSecurity::saeUnicastIdentity(station) || !AthSecurity::saeUnicastIdentity(bssid) ||
       AthSecurity::equal(station,bssid,6) || !connection ||
       now>~uint64_t(0)-AthSecurity::SAEGroup19ClientExchange::DeadlineMs)return false;
    api=provider;randomBytes=rng;AthSecurity::copy(pwe,point,64);
    AthSecurity::copy(local,station,6);AthSecurity::copy(ap,bssid,6);
    generation=connection;started=now;deadline=now+AthSecurity::SAEGroup19ClientExchange::DeadlineMs;
    request.kind=AthSecurity::SAEAuthKind::Commit;request.h2e=h2e;initialized=true;return true;
}
void Ath10kSAEPrepareJob::execute(){
    if(!initialized || executed || consumed)return;
    executed=true;
    AthSecurity::P256CoreCryptoCandidate engine(api);
    uint8_t mask[32]{},scalar[32]{};
    // Reject out-of-range values without modulo bias. A broken RNG cannot
    // monopolize the shared worker: at most 128 complete candidate pairs.
    if(engine.validate(pwe,64,workspace))for(unsigned attempt=0;attempt<128;++attempt){
        AthSecurity::wipe(random,sizeof(random));AthSecurity::wipe(mask,sizeof(mask));
        if(!randomBytes(random,32) || !randomBytes(mask,32))break;
        if(!AthSecurity::saeGroup19CommitScalar(random,mask,32,scalar,32))continue;
        prepared=AthSecurity::saeGroup19Commit(engine,random,mask,32,pwe,64,request.commit,96,workspace);
        break; // Backend failure is terminal, not a reason to reroll secrets.
    }
    AthSecurity::wipe(mask,sizeof(mask));AthSecurity::wipe(scalar,sizeof(scalar));workspace.clear();
    randomBytes=nullptr;
    if(!prepared){AthSecurity::wipe(random,sizeof(random));AthSecurity::wipe(pwe,sizeof(pwe));AthSecurity::wipe(&request,sizeof(request));}
}
Ath10kSAESession *Ath10kSAEPrepareJob::takePrepared(const uint8_t *station,const uint8_t *bssid,
    uint32_t connection,uint64_t now){
    if(!executed || consumed)return nullptr;
    consumed=true;
    Ath10kSAESession *session=nullptr;
    if(prepared && station && bssid && connection==generation && now>=started && now<deadline &&
       AthSecurity::equal(station,local,6) && AthSecurity::equal(bssid,ap,6)){
        session=new Ath10kSAESession;
        if(session && !session->initPrepared(api,random,32,pwe,64,request,local,ap,generation,started)){
            session->release();session=nullptr;
        }
        // Preserve the original preparation deadline; worker latency must not
        // buy a fresh authentication lifetime after completion collection.
        if(session && session->poll(generation,now)!=Ath10kSAESession::Action::SendCommit){
            session->release();session=nullptr;
        }
    }
    discard();return session;
}
void Ath10kSAEPrepareJob::discard(){
    AthSecurity::wipe(&api,sizeof(api));randomBytes=nullptr;workspace.clear();
    AthSecurity::wipe(&request,sizeof(request));AthSecurity::wipe(pwe,sizeof(pwe));
    AthSecurity::wipe(random,sizeof(random));AthSecurity::wipe(local,sizeof(local));AthSecurity::wipe(ap,sizeof(ap));
    generation=0;started=deadline=0;prepared=false;consumed=true;
}

void Ath10kSAERadio::clearTX(){
    if(confirm){confirm->release();confirm=nullptr;}
    commit.retire();AthSecurity::wipe(confirmFrame,sizeof(confirmFrame));tx=TX::None;
}
void Ath10kSAERadio::fail(){
    failed=true;accepted=false;
    if(session){if(worker)worker->cancelFor(session);session->cancel();}
    inFlight=Ath10kSAESession::Kind::Empty;clearTX();
}
void Ath10kSAERadio::cancel(){
    if(session){if(worker)worker->cancelFor(session);session->cancel();}
    clearTX();if(session){session->release();session=nullptr;}
    if(worker){worker->release();worker=nullptr;}
    generation=0;inFlight=Ath10kSAESession::Kind::Empty;failed=accepted=false;
}
bool Ath10kSAERadio::bind(Ath10kSAESession *owner,Ath10kSAEWorker *queue,uint32_t connection,uint64_t now){
    if(session || !owner || !queue || !connection || owner->poll(connection,now)!=Ath10kSAESession::Action::SendCommit)return false;
    session=owner;session->retain();worker=queue;worker->retain();generation=connection;return true;
}
Ath10kSAESession::Action Ath10kSAERadio::receive(const uint8_t *frame,size_t bytes,uint32_t status,uint64_t now){
    using A=Ath10kSAESession::Action;
    if(!session || failed || (status&0x39u) || !frame || bytes<30 || bytes>1536)return A::Ignore;
    const auto action=session->receive(frame,bytes,generation,now);
    if(action==A::Failed)fail();return action;
}
Ath10kSAERadio::State Ath10kSAERadio::service(uint64_t now){
    using K=Ath10kSAESession::Kind;using A=Ath10kSAESession::Action;using S=Ath10kSAESession::Submission;
    if(!session)return State::Idle;if(failed)return State::Failed;
    if(session->activeGeneration()!=generation){fail();return State::Failed;}
    auto action=session->poll(generation,now);
    if(action==A::Failed){fail();return State::Failed;}
    if(inFlight!=K::Empty){
        if(auto item=worker->takeCompletedFor(session)){
            const auto kind=inFlight;inFlight=K::Empty;action=session->consume(item,generation,now);
            if(kind==K::LocalConfirm && action==A::SendConfirm){
                if(confirm){item->release();fail();return State::Failed;}
                confirm=item;
            }else item->release();
            if(action==A::Failed){fail();return State::Failed;}
        }else if(worker->available()){fail();return State::Failed;} // Issued work was cancelled externally.
    }
    action=session->poll(generation,now);
    if(action==A::Failed){fail();return State::Failed;}
    if(action==A::Accepted){
        if(inFlight!=K::Empty)return State::Progress;
        clearTX();accepted=true;return State::Accepted;
    }
    if(inFlight==K::Empty){
        K kind=K::Empty;
        if(action==A::ComputeKeys)kind=K::Keys;
        else if(action==A::VerifyPeer)kind=K::PeerConfirm;
        else if(action==A::SendConfirm && !confirm)kind=K::LocalConfirm;
        if(kind!=K::Empty){
            const auto result=session->queue(worker,kind,generation,now);
            if(result==S::Queued)inFlight=kind;
            else if(result==S::Aborted){fail();return State::Failed;}
        }
    }
    return State::Progress;
}
bool Ath10kSAERadio::prepareTX(uint16_t sequence,uint64_t now,const uint8_t *&frame,size_t &bytes){
    frame=nullptr;bytes=0;
    if(!session || failed || accepted)return false;
    if(session->activeGeneration()!=generation){fail();return false;}
    using A=Ath10kSAESession::Action;
    const auto action=session->poll(generation,now);
    if(action==A::Failed){fail();return false;}
    if(tx==TX::Commit && !session->commitReady(commit,generation,now)){commit.retire();tx=TX::None;}
    if(confirm){
        if(!session->confirmReady(confirm,generation,now)){
            clearTX();return false;
        }
        if(tx!=TX::Confirm && !session->encodeConfirm(confirm,sequence,confirmFrame,sizeof(confirmFrame),bytes,generation,now))return false;
        tx=TX::Confirm;frame=confirmFrame;bytes=sizeof(confirmFrame);return true;
    }
    if(tx!=TX::Commit){
        if(action!=A::SendCommit || !session->snapshotCommit(commit,sequence,generation,now))return false;
        tx=TX::Commit;
    }
    frame=commit.data();bytes=commit.size();return true;
}
bool Ath10kSAERadio::completeTX(bool submitted,uint64_t now){
    if(!session || failed)return false;bool valid=false;
    if(tx==TX::Commit){
        valid=session->completeCommit(commit,submitted,generation,now);
        commit.retire();tx=TX::None;
    }else if(tx==TX::Confirm && confirm){
        valid=session->confirmReady(confirm,generation,now);
        if(valid)session->completeConfirm(confirm,submitted,generation,now);
        clearTX();
    }
    if(session->poll(generation,now)==Ath10kSAESession::Action::Failed)fail();
    return valid;
}

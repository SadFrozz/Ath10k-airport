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
    if(initialized || !OSObject::init() || !api.complete() || !random || randomBytes!=32 || !pwe || pweBytes!=64)return false;
    if(!exchange.begin(request,local,ap,now,token))return false;
    context.api=api;AthSecurity::copy(context.random,random,32);AthSecurity::copy(context.pwe,pwe,64);
    connectionGeneration=generation;closed=false;initialized=true;return true;
}
void Ath10kSAESession::cancel(){closed=true;exchange.cancel();AthSecurity::wipe(&context,sizeof(context));}
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
    const bool submitted=worker->submit(job);
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
    return current(generation) && exchange.copyPMK(token,out,bytes,id,idBytes,now);
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

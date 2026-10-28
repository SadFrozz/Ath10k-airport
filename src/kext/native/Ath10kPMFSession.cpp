#include "Ath10kPMFSession.hpp"
#include "Ath10kKernelCrypto.hpp"
OSDefineMetaClassAndStructors(Ath10kPMFSession,OSObject)
OSDefineMetaClassAndStructors(Ath10kPMFJob,Ath10kSAEWorkItem)
bool Ath10kPMFSession::initConnection(const uint8_t *station,const uint8_t *bssid,uint64_t generation){
    if(initialized || !OSObject::init() || !generation || !AthSecurity::saQueryIdentities(station,bssid))return false;
    AthSecurity::copy(local,station,6);AthSecurity::copy(ap,bssid,6);connection=generation;initialized=true;closed=false;return true;
}
void Ath10kPMFSession::cancel(){
    closed=true;pendingTXPN=0;authorized=havePairwise=haveManagement=false;pairwise.clear();management.clear();
    AthSecurity::wipe(local,sizeof(local));AthSecurity::wipe(ap,sizeof(ap));
}
void Ath10kPMFSession::free(){cancel();connection=0;OSObject::free();}
bool Ath10kPMFSession::acknowledgePairwise(const uint8_t *tk,const uint8_t *station,const uint8_t *bssid){
    if(!current(connection) || !station || !bssid || !AthSecurity::equal(local,station,6) || !AthSecurity::equal(ap,bssid,6))return false;
    AthSecurity::PMFPairwiseEpoch::Snapshot before,after;const bool previous=pairwise.snapshot(before);
    if(!pairwise.activate(tk,local,ap,connection) || !pairwise.snapshot(after))return false;
    if(!previous || before.epoch!=after.epoch){authorized=false;pendingTXPN=0;}
    havePairwise=true;return true;
}
bool Ath10kPMFSession::activateManagement(const AthSecurity::IGTKCMAC128 &key){
    if(!current(connection) || !havePairwise || !management.activate(key))return false;
    haveManagement=true;return true;
}
bool Ath10kPMFSession::authorize(){
    if(!current(connection) || !havePairwise || !haveManagement)return false;
    authorized=true;return true;
}
Ath10kPMFSession::Submission Ath10kPMFSession::queue(Ath10kSAEWorker *worker,const uint8_t *frame,size_t bytes,
    uint32_t status,Layout layout,uint64_t generation){
    if(!current(generation) || !authorized || !worker)return Submission::Aborted;
    if(!frame || bytes<26 || bytes>512 || (status&0x39u) ||
       (layout!=Layout::Ciphertext && layout!=Layout::PlaintextWithEncryptedTag))return Submission::NoWork;
    if(!worker->available())return Submission::Busy;
    auto job=new Ath10kPMFJob;if(!job)return Submission::NoMemory;
    if(!job->init()){job->release();return Submission::NoMemory;}
    job->session=this;retain();job->connection=connection;job->layout=layout;
    if(frame[4]&1){
        if(bytes<44){job->release();return Submission::NoWork;}
        const auto mmie=frame+bytes-18;
        if(mmie[0]!=76 || mmie[1]!=16 || !management.snapshot(AthSecurity::le16(mmie+2),job->management,job->groupEpoch)){
            job->release();return Submission::NoWork;}
        job->kind=Kind::GroupManagement;AthSecurity::copy(job->ap,ap,6);
    }else {
        if(!AthSecurity::pmfCCMPHeader(frame,bytes,local,ap,true) || !pairwise.snapshot(job->pairwise)){
            job->release();return Submission::NoWork;}
        job->kind=Kind::Pairwise;
    }
    AthSecurity::copy(job->frame,frame,bytes);job->bytes=bytes;
    const bool submitted=worker->submit(job);job->release();
    // RX has not reserved any owner mutation. A busy/terminal race drops this
    // frame without retiring a valid association or consuming replay state.
    return submitted?Submission::Queued:Submission::Aborted;
}
bool Ath10kPMFSession::consume(Ath10kSAEWorkItem *item,uint64_t generation,Message &out){
    auto job=OSDynamicCast(Ath10kPMFJob,item);
    if(!current(generation) || !authorized || !job || job->session!=this || job->connection!=generation || !job->executed || job->consumed || job->kind==Kind::ProtectTX)return false;
    job->consumed=true;if(!job->verified)return false;
    AthSecurity::PMFVerifiedRX stamp{};
    if(job->kind==Kind::Pairwise){
        if(!pairwise.commit(job->pairwise,job->result.pn,stamp))return false;
    }else if(job->kind==Kind::GroupManagement){
        if(!management.commitIPN(job->management.keyID,job->groupEpoch,job->acceptedIPN))return false;
    }else return false;
    AthSecurity::wipe(&out,sizeof(out));out.kind=job->kind;
    if(job->kind==Kind::Pairwise){out.bytes=job->result.bytes;AthSecurity::copy(out.frame,job->result.frame,out.bytes);out.pairwise=stamp;}
    else {out.bytes=job->bytes-18;AthSecurity::copy(out.frame,job->frame,out.bytes);out.groupID=job->management.keyID;out.groupEpoch=job->groupEpoch;}
    return true;
}
Ath10kPMFSession::Submission Ath10kPMFSession::queueProtect(Ath10kSAEWorker *worker,const uint8_t *frame,size_t bytes,uint64_t generation){
    if(!current(generation) || !authorized || !worker)return Submission::Aborted;
    if(!frame || bytes<26 || bytes>496 || !AthSecurity::pmfCCMPHeader(frame,bytes,local,ap,false) || !AthSecurity::pmfRobustBody(frame,bytes))return Submission::NoWork;
    if(pendingTXPN || !worker->available())return Submission::Busy;
    auto job=new Ath10kPMFJob;if(!job)return Submission::NoMemory;
    if(!job->init()){job->release();return Submission::NoMemory;}
    if(!pairwise.reserveTX(job->pairwise,job->txPN)){job->release();return Submission::Aborted;}
    job->session=this;retain();job->connection=connection;job->kind=Kind::ProtectTX;
    AthSecurity::copy(job->frame,frame,bytes);job->bytes=bytes;
    const uint64_t reserved=job->txPN;const bool submitted=worker->submit(job);
    // A terminal submit failure burns the reserved PN but no pending lease.
    if(submitted)pendingTXPN=reserved;
    job->release();return submitted?Submission::Queued:Submission::Aborted;
}
bool Ath10kPMFSession::protectedReady(Ath10kSAEWorkItem *item,uint64_t generation) const {
    auto job=OSDynamicCast(Ath10kPMFJob,item);
    return current(generation) && authorized && job && job->session==this && job->connection==generation &&
        job->kind==Kind::ProtectTX && job->executed && !job->consumed && job->verified &&
        pendingTXPN==job->txPN && pairwise.current(job->pairwise);
}
bool Ath10kPMFSession::copyProtected(Ath10kSAEWorkItem *item,uint8_t *frame,size_t capacity,size_t &bytes,uint64_t generation) const {
    auto job=OSDynamicCast(Ath10kPMFJob,item);
    if(!frame || !protectedReady(item,generation) || capacity<job->result.bytes)return false;
    AthSecurity::copy(frame,job->result.frame,job->result.bytes);bytes=job->result.bytes;return true;
}
bool Ath10kPMFSession::retireProtected(Ath10kSAEWorkItem *item,uint64_t generation){
    auto job=OSDynamicCast(Ath10kPMFJob,item);
    if(!current(generation) || !job || job->session!=this || job->connection!=generation || job->kind!=Kind::ProtectTX ||
       !job->executed || job->consumed || pendingTXPN!=job->txPN || !pairwise.current(job->pairwise))return false;
    job->consumed=true;pendingTXPN=0;return true;
}
void Ath10kPMFJob::execute(){
    if(executed || !session)return;
    using C=AthSecurity::PMFCCMP128<Ath10kKernelCrypto>;
    if(kind==Ath10kPMFSession::Kind::Pairwise){
        const auto selected=layout==Ath10kPMFSession::Layout::Ciphertext?C::RXLayout::Ciphertext:C::RXLayout::PlaintextWithEncryptedTag;
        verified=C::receive(frame,bytes,pairwise.key,pairwise.local,pairwise.ap,pairwise.rxPN,selected,result,workspace);
    }else if(kind==Ath10kPMFSession::Kind::ProtectTX){
        verified=C::protect(frame,bytes,pairwise.key,pairwise.local,pairwise.ap,txPN,result,workspace);
    }else if(kind==Ath10kPMFSession::Kind::GroupManagement){
        verified=AthSecurity::verifyBIPManagement<Ath10kKernelCrypto>(frame,bytes,ap,management,management.ipn,acceptedIPN);
    }
    // Keep only lease metadata needed by owner commit; crypto keys retire now.
    AthSecurity::wipe(pairwise.key,sizeof(pairwise.key));AthSecurity::wipe(pairwise.local,sizeof(pairwise.local));AthSecurity::wipe(pairwise.ap,sizeof(pairwise.ap));
    AthSecurity::wipe(management.key,sizeof(management.key));workspace.clear();executed=true;
}
void Ath10kPMFJob::discard(){
    AthSecurity::wipe(&pairwise,sizeof(pairwise));AthSecurity::wipe(&management,sizeof(management));
    AthSecurity::wipe(&result,sizeof(result));AthSecurity::wipe(frame,sizeof(frame));AthSecurity::wipe(ap,sizeof(ap));workspace.clear();
    connection=groupEpoch=acceptedIPN=txPN=bytes=0;executed=consumed=verified=false;kind=Ath10kPMFSession::Kind::Empty;
    auto owner=session;session=nullptr;if(owner)owner->release();
}

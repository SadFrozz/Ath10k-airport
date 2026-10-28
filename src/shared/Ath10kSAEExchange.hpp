#pragma once
#include "Ath10kSAE.hpp"
#include "Ath10kSAEWire.hpp"
#include "Ath10kP256CoreCrypto.hpp"

namespace AthSecurity {
class SAEGroup19ClientExchange;
// Retained, exclusive worker-owned job. Caller supplies random/PWE from the
// same immutable credential/identity generation that produced the local commit.
class SAEGroup19KeyWork {
 friend class SAEGroup19ClientExchange;
 const SAEGroup19ClientExchange *owner=nullptr;
 uint64_t generation=0;
 bool h2e=false,computed=false;
 uint16_t localRejectedBytes=0,peerRejectedBytes=0;
 uint8_t local[96]{},peer[96]{},localMAC[6]{},peerMAC[6]{},localRejected[254]{},peerRejected[254]{};
 SAEGroup19Keys keys{};
 void clear(){wipe(this,sizeof(*this));}
public:
 SAEGroup19KeyWork()=default;
 SAEGroup19KeyWork(const SAEGroup19KeyWork &)=delete;
 SAEGroup19KeyWork &operator=(const SAEGroup19KeyWork &)=delete;
 ~SAEGroup19KeyWork(){clear();}
 void retire(){clear();} // Only after exclusive worker ownership returns.
 template<class Crypto> bool compute(const P256CoreCryptoCandidate &engine,const uint8_t *random,size_t randomBytes,
     const uint8_t *pwe,size_t pweBytes,P256CoreCryptoWorkspace &workspace){
  wipe(&keys,sizeof(keys));computed=false;
  if(!owner || !generation){workspace.clear();return false;}
  computed=saeGroup19ExchangeCandidate<Crypto>(engine,random,randomBytes,local,96,peer,96,pwe,pweBytes,
      h2e,localMAC,peerMAC,localRejected,localRejectedBytes,peerRejected,peerRejectedBytes,keys,workspace);
  return computed;
 }
};
class SAEGroup19CommitTx {
 friend class SAEGroup19ClientExchange;
 const SAEGroup19ClientExchange *owner=nullptr;
 uint64_t generation=0;
 uint32_t revision=0;
 uint8_t frame[1536]{};size_t bytes=0;
 void clear(){wipe(this,sizeof(*this));}
public:
 SAEGroup19CommitTx()=default;
 SAEGroup19CommitTx(const SAEGroup19CommitTx &)=delete;
 SAEGroup19CommitTx &operator=(const SAEGroup19CommitTx &)=delete;
 ~SAEGroup19CommitTx(){clear();}
 const uint8_t *data() const {return frame;}
 size_t size() const {return bytes;}
};
// Client protocol coordinator from an already worker-prepared local commit.
// All methods run under one owner gate; jobs run outside it. This is not wired
// to IOKit/firmware. Retain owner/jobs until drain, check TX admission at actual
// submission, and cancel/revoke downstream keys on leave/sleep/stop.
class SAEGroup19ClientExchange {
public:
 enum class Phase : uint8_t { Idle, Committed, Computing, Confirming, Accepted, Failed };
 enum class Action : uint8_t { Ignore, SendCommit, ComputeKeys, SendConfirm, VerifyPeer, Accepted, Failed };
 enum class Failure : uint8_t { None, InvalidStart, Clock, Timeout, Attempts, TokenChanges, Rejected, Identifier, Mode, Crypto };
 static constexpr uint64_t DeadlineMs=5000,RetryMs=750;
 static constexpr unsigned MaxAttempts=5,MaxTokenChanges=3,MaxPeerVerifications=16;
private:
 struct State {
  SAEGroup19AuthMessage local{},peer{};
  uint8_t localMAC[6]{},apMAC[6]{},confirms[4][34]{};
  uint64_t deadline=0,lastNow=0,lastCommit=0,lastConfirm=0,fenceToken=0;
  uint32_t commitRevision=1;
  uint16_t lastLocalAttempt=0;
  uint8_t commitAttempts=0,confirmAttempts=0,tokenChanges=0,confirmCount=0,verifications=0;
  bool pendingCommit=false,pendingConfirm=false,submittedCommit=false,keyJobIssued=false;
  Phase phase=Phase::Idle;
  Failure failure=Failure::None;
 } state{};
 uint64_t generation=0;
 SAEGroup19Confirmation fence;
 void fail(Failure reason){cancel();state.phase=Phase::Failed;state.failure=reason;}
 bool check(uint64_t now){
  if(state.phase==Phase::Idle || state.phase==Phase::Failed)return false;
  if(now<state.lastNow){fail(Failure::Clock);return false;}
  state.lastNow=now;
  if(state.phase!=Phase::Accepted && now>=state.deadline){fail(Failure::Timeout);return false;}
  return true;
 }
 Action checkedFailure() const {return state.phase==Phase::Failed?Action::Failed:Action::Ignore;}
 Action finishConfirmation(){
  if(fence.accepted(state.fenceToken)){
   state.phase=Phase::Accepted;state.pendingConfirm=false;
   wipe(&state.local,sizeof(state.local));wipe(&state.peer,sizeof(state.peer));
   wipe(state.confirms,sizeof(state.confirms));state.confirmCount=0;
   return Action::Accepted;
  }
  return Action::Ignore;
 }
public:
 SAEGroup19ClientExchange()=default;
 SAEGroup19ClientExchange(const SAEGroup19ClientExchange &)=delete;
 SAEGroup19ClientExchange &operator=(const SAEGroup19ClientExchange &)=delete;
 ~SAEGroup19ClientExchange(){wipe(this,sizeof(*this));}
 void cancel(){fence.cancel();wipe(&state,sizeof(state));}
 Phase phase() const {return state.phase;}
 Failure failure() const {return state.failure;}
 bool begin(const SAEGroup19AuthMessage &local,const uint8_t *localMAC,const uint8_t *ap,
     uint64_t now,uint64_t &token){
  cancel();size_t bytes=0;
  if(local.kind!=SAEAuthKind::Commit || local.tokenBytes || !saeGroup19AuthBodySize(local,bytes) ||
     !saeUnicastIdentity(localMAC) || !saeUnicastIdentity(ap) || equal(localMAC,ap,6) ||
     now>~uint64_t(0)-DeadlineMs || generation==~uint64_t(0)){
   fail(Failure::InvalidStart);return false;
  }
  state.local=local;copy(state.localMAC,localMAC,6);copy(state.apMAC,ap,6);
  state.lastNow=now;state.deadline=now+DeadlineMs;
  state.phase=Phase::Committed;state.pendingCommit=true;state.commitRevision=1;
  token=++generation;return true;
 }
 Action poll(uint64_t now){
  if(!check(now))return checkedFailure();
  if(state.phase==Phase::Accepted)return Action::Accepted;
  if(state.phase==Phase::Computing)return state.keyJobIssued?Action::Ignore:Action::ComputeKeys;
  if(state.phase==Phase::Committed){
   if(!state.pendingCommit && now-state.lastCommit>=RetryMs){
    if(state.commitAttempts>=MaxAttempts){fail(Failure::Attempts);return Action::Failed;}
    state.pendingCommit=true;++state.commitRevision;
   }
   return state.pendingCommit?Action::SendCommit:Action::Ignore;
  }
  if(state.confirmCount && state.verifications<MaxPeerVerifications)return Action::VerifyPeer;
  if(!state.pendingConfirm && now-state.lastConfirm>=RetryMs){
   if(state.confirmAttempts>=MaxAttempts){fail(Failure::Attempts);return Action::Failed;}
   state.pendingConfirm=true;
  }
  return state.pendingConfirm?Action::SendConfirm:Action::Ignore;
 }
 bool snapshotCommit(SAEGroup19CommitTx &job,uint16_t sequence,uint64_t now){
  job.clear();
  if(!check(now) || state.phase!=Phase::Committed || !state.pendingCommit || state.commitAttempts>=MaxAttempts)return false;
  if(!encodeSAEGroup19ToAP(state.local,state.localMAC,state.apMAC,sequence,job.frame,sizeof(job.frame),job.bytes))return false;
  job.owner=this;job.generation=generation;job.revision=state.commitRevision;return true;
 }
 bool commitReady(const SAEGroup19CommitTx &job,uint64_t now){
  if(job.owner!=this || job.generation!=generation || state.phase!=Phase::Committed ||
     !state.pendingCommit || job.revision!=state.commitRevision || !job.bytes)return false;
  return check(now);
 }
 bool completeCommit(const SAEGroup19CommitTx &job,bool submitted,uint64_t now){
  if(!commitReady(job,now))return false;
  ++state.commitAttempts;state.pendingCommit=false;state.lastCommit=now;
  state.submittedCommit|=submitted;return true;
 }
 Action receiveFromAP(const uint8_t *frame,size_t bytes,uint64_t now){
  if(!check(now))return checkedFailure();
  if(state.phase==Phase::Accepted || !state.submittedCommit)return Action::Ignore;
  SAEGroup19AuthMessage message{};
  const auto decoded=decodeSAEGroup19FromAP(frame,bytes,state.localMAC,state.apMAC,state.local.h2e,message);
  if(decoded==SAEWireResult::ModeMismatch){fail(Failure::Mode);return Action::Failed;}
  if(decoded!=SAEWireResult::Valid)return Action::Ignore;
  if(message.kind==SAEAuthKind::Rejected || message.kind==SAEAuthKind::GroupRejected){fail(Failure::Rejected);return Action::Failed;}
  if(message.kind==SAEAuthKind::TokenRequest){
   if(state.phase!=Phase::Committed || (message.tokenBytes==state.local.tokenBytes &&
      equal(message.token,state.local.token,message.tokenBytes)))return Action::Ignore;
   if(state.tokenChanges>=MaxTokenChanges || state.commitAttempts>=MaxAttempts){fail(Failure::TokenChanges);return Action::Failed;}
   ++state.tokenChanges;wipe(state.local.token,sizeof(state.local.token));
   state.local.tokenBytes=message.tokenBytes;copy(state.local.token,message.token,message.tokenBytes);
   state.pendingCommit=true;++state.commitRevision;return Action::SendCommit;
  }
  if(message.kind==SAEAuthKind::Commit){
   if(state.phase!=Phase::Committed || equal(message.commit,state.local.commit,96))return Action::Ignore;
   if(message.identifierPresent!=state.local.identifierPresent || message.identifierBytes!=state.local.identifierBytes ||
      !equal(message.identifier,state.local.identifier,message.identifierBytes)){fail(Failure::Identifier);return Action::Failed;}
   state.peer=message;state.pendingCommit=false;
   if(!fence.begin(state.local.commit,96,message.commit,96,state.fenceToken)){fail(Failure::Crypto);return Action::Failed;}
   state.phase=Phase::Computing;return Action::ComputeKeys;
  }
  if(message.kind==SAEAuthKind::Confirm && (state.phase==Phase::Committed || state.phase==Phase::Computing || state.phase==Phase::Confirming)){
   for(unsigned i=0;i<state.confirmCount;++i)if(equal(state.confirms[i],message.confirm,34))return Action::Ignore;
   if(state.confirmCount>=4 || state.verifications>=MaxPeerVerifications)return Action::Ignore;
   copy(state.confirms[state.confirmCount++],message.confirm,34);
   return state.phase==Phase::Confirming?Action::VerifyPeer:Action::Ignore;
  }
  return Action::Ignore;
 }
 bool snapshotKeys(SAEGroup19KeyWork &job,uint64_t now){
  job.clear();
  if(!check(now) || state.phase!=Phase::Computing || state.keyJobIssued)return false;
  job.owner=this;job.generation=generation;job.h2e=state.local.h2e;
  copy(job.local,state.local.commit,96);copy(job.peer,state.peer.commit,96);
  copy(job.localMAC,state.localMAC,6);copy(job.peerMAC,state.apMAC,6);
  job.localRejectedBytes=state.local.rejectedBytes;job.peerRejectedBytes=state.peer.rejectedBytes;
  copy(job.localRejected,state.local.rejected,job.localRejectedBytes);copy(job.peerRejected,state.peer.rejected,job.peerRejectedBytes);
  state.keyJobIssued=true;return true;
 }
 Action completeKeys(SAEGroup19KeyWork &job,uint64_t now){
  if(job.owner!=this || job.generation!=generation || state.phase!=Phase::Computing){job.clear();return Action::Ignore;}
  if(!check(now)){job.clear();return Action::Failed;}
  const bool ok=fence.completeKeys(state.fenceToken,job.computed,job.keys);job.clear();
  if(!ok){fail(Failure::Crypto);return Action::Failed;}
  state.phase=Phase::Confirming;state.pendingConfirm=true;state.lastConfirm=now;
  return state.confirmCount?Action::VerifyPeer:Action::SendConfirm;
 }
 bool snapshotLocalConfirm(SAEGroup19ConfirmWork &job,uint64_t now){
  if(!check(now) || state.phase!=Phase::Confirming || !state.pendingConfirm || state.confirmAttempts>=MaxAttempts)return false;
  if(!fence.snapshotLocal(state.fenceToken,job))return false;
  ++state.confirmAttempts;state.pendingConfirm=false;state.lastConfirm=now;return true;
 }
 bool localConfirmReady(const SAEGroup19ConfirmWork &job,uint64_t now){
  if(state.phase!=Phase::Confirming || !fence.localReadyToTransmit(job) || job.localSequence()<=state.lastLocalAttempt)return false;
  return check(now);
 }
 bool encodeLocalConfirm(const SAEGroup19ConfirmWork &job,uint16_t sequence,uint8_t *out,
     size_t capacity,size_t &bytes,uint64_t now){
  if(!localConfirmReady(job,now))return false;
  SAEGroup19AuthMessage message{};message.kind=SAEAuthKind::Confirm;message.h2e=state.local.h2e;
  if(!job.copyLocalBody(message.confirm,34))return false;
  return encodeSAEGroup19ToAP(message,state.localMAC,state.apMAC,sequence,out,capacity,bytes);
 }
 Action completeLocalConfirm(const SAEGroup19ConfirmWork &job,bool submitted,uint64_t now){
  if(!localConfirmReady(job,now))return checkedFailure();
  state.lastLocalAttempt=job.localSequence();
  if(!fence.completeLocal(job,submitted))return Action::Ignore;
  return finishConfirmation();
 }
 bool snapshotPeerConfirm(SAEGroup19ConfirmWork &job,uint8_t *body,size_t capacity,uint64_t now){
  if(!body || capacity<34 || !check(now) || state.phase!=Phase::Confirming || !state.confirmCount || state.verifications>=MaxPeerVerifications)return false;
  if(!fence.snapshotPeer(state.fenceToken,job))return false;
  copy(body,state.confirms[0],34);--state.confirmCount;
  for(unsigned i=0;i<state.confirmCount;++i)copy(state.confirms[i],state.confirms[i+1],34);
  wipe(state.confirms[state.confirmCount],34);++state.verifications;return true;
 }
 Action completePeerConfirm(const SAEGroup19ConfirmWork &job,uint64_t now){
  if(state.phase!=Phase::Confirming || !fence.ownsWork(job))return Action::Ignore;
  if(!check(now))return Action::Failed;
  if(!fence.completePeer(job))return Action::Ignore;
  return finishConfirmation();
 }
 bool copyPMK(uint64_t token,uint8_t *pmk,size_t bytes,uint8_t *id,size_t idBytes,uint64_t now){
  if(token!=generation || state.phase!=Phase::Accepted || !check(now))return false;
  return fence.copyPMK(state.fenceToken,pmk,bytes,id,idBytes);
 }
};
static_assert(sizeof(SAEGroup19KeyWork)<=1024,"Bounded SAE key job");
static_assert(sizeof(SAEGroup19ClientExchange)<=4096,"Allocate/retain the exchange off the kernel stack");
}

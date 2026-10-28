#pragma once
#include "Ath10kSHA256.hpp"

namespace AthSecurity {
class SAEGroup19Confirmation;

// Exclusive worker-owned snapshot. It contains KCK/commits, never PMK. Retain
// both job and owner across execution; hand the job back before reusing it.
// No crypto provider may execute while the owner gate is held.
class SAEGroup19ConfirmWork {
 friend class SAEGroup19Confirmation;
 enum class Kind : uint8_t { Empty, Local, Peer } kind=Kind::Empty;
 const SAEGroup19Confirmation *owner=nullptr;
 uint64_t generation=0;
 uint16_t counter=0,previousPeer=0;
 bool peerPreviouslyVerified=false,verified=false;
 uint8_t kck[32]{},local[96]{},peer[96]{},localBody[34]{};
 void clear(){wipe(this,sizeof(*this));}
public:
 SAEGroup19ConfirmWork()=default;
 SAEGroup19ConfirmWork(const SAEGroup19ConfirmWork &)=delete;
 SAEGroup19ConfirmWork &operator=(const SAEGroup19ConfirmWork &)=delete;
 ~SAEGroup19ConfirmWork(){clear();}
 void retire(){clear();} // Only after exclusive worker ownership returns.
 uint16_t localSequence() const {return kind==Kind::Local && verified?counter:0;}
 bool copyLocalBody(uint8_t *out,size_t capacity) const {
  if(!out || capacity<34 || kind!=Kind::Local || !verified)return false;
  copy(out,localBody,34);return true;
 }
 template<class Crypto> bool makeLocal(uint8_t *out,size_t capacity){
  verified=false;wipe(localBody,sizeof(localBody));
  if(kind!=Kind::Local || !out || capacity<34)return false;
  uint8_t body[34]{};body[0]=uint8_t(counter);body[1]=uint8_t(counter>>8);
  verified=saeGroup19Confirm<Crypto>(kck,32,counter,local,96,peer,96,body+2,32);
  if(verified){copy(out,body,34);copy(localBody,body,34);}
  wipe(body,sizeof(body));return verified;
 }
 template<class Crypto> bool verifyPeer(const uint8_t *body,size_t bytes){
  verified=false;
  if(kind!=Kind::Peer)return false;
  verified=verifySAEGroup19PeerConfirm<Crypto>(kck,32,local,96,peer,96,body,bytes,
      peerPreviouslyVerified,previousPeer,counter);
  return verified;
 }
};

// Owner-gate-only confirmation/PMK publication fence, not the complete SAE FSM.
// Begin after commit validation/binding; compute candidate keys on a retained
// worker. All owner methods are non-cryptographic. Cancel on leave, timeout,
// sleep or stop; the owner must stay alive until outstanding jobs are drained.
class SAEGroup19Confirmation {
 enum class Phase : uint8_t { Idle, Computing, Confirming, Accepted };
 struct State {
  SAEGroup19Keys keys{};
  uint8_t local[96]{},peer[96]{};
  uint16_t reservedLocal=0,peerCounter=0;
  bool localSent=false,peerVerified=false;
  Phase phase=Phase::Idle;
 } state{};
 uint64_t generation=0;
 bool current(uint64_t token) const {
  return token && token==generation && state.phase!=Phase::Idle;
 }
 bool confirming(uint64_t token) const {
  return current(token) && (state.phase==Phase::Confirming || state.phase==Phase::Accepted);
 }
 void updateAccepted(){
  if(state.localSent && state.peerVerified)state.phase=Phase::Accepted;
 }
 bool snapshot(uint64_t token,SAEGroup19ConfirmWork &job,bool local){
  job.clear();
  if(!confirming(token) || (local && state.reservedLocal>=0xfffe))return false;
  job.kind=local?SAEGroup19ConfirmWork::Kind::Local:SAEGroup19ConfirmWork::Kind::Peer;
  job.owner=this;job.generation=generation;job.previousPeer=state.peerCounter;
  job.peerPreviouslyVerified=state.peerVerified;
  if(local)job.counter=++state.reservedLocal;
  copy(job.kck,state.keys.kck,32);copy(job.local,state.local,96);copy(job.peer,state.peer,96);
  return true;
 }
public:
 SAEGroup19Confirmation()=default;
 SAEGroup19Confirmation(const SAEGroup19Confirmation &)=delete;
 SAEGroup19Confirmation &operator=(const SAEGroup19Confirmation &)=delete;
 ~SAEGroup19Confirmation(){wipe(this,sizeof(*this));}
 void cancel(){wipe(&state,sizeof(state));} // Preserve monotonic generation.
 bool begin(const uint8_t *local,size_t localBytes,const uint8_t *peer,size_t peerBytes,uint64_t &token){
  cancel();
  if(!local || localBytes!=96 || !peer || peerBytes!=96 || equal(local,peer,96) || generation==~uint64_t(0))return false;
  copy(state.local,local,96);copy(state.peer,peer,96);
  state.phase=Phase::Computing;token=++generation;return true;
 }
 // Consumes and wipes the worker's candidate even when cancelled/stale/failed.
 bool completeKeys(uint64_t token,bool success,SAEGroup19Keys &candidate){
  const bool valid=current(token) && state.phase==Phase::Computing;
  if(valid && success){state.keys=candidate;state.phase=Phase::Confirming;}
  wipe(&candidate,sizeof(candidate));
  if(valid && !success)cancel();
  return valid && success;
 }
 bool snapshotLocal(uint64_t token,SAEGroup19ConfirmWork &job){return snapshot(token,job,true);}
 bool snapshotPeer(uint64_t token,SAEGroup19ConfirmWork &job){return snapshot(token,job,false);}
 bool ownsWork(const SAEGroup19ConfirmWork &job) const {return job.owner==this && confirming(job.generation);}
 bool accepted(uint64_t token) const {return current(token) && state.phase==Phase::Accepted;}
 // Recheck under the owner gate before submitting the frame. A queued TX must
 // retain/recheck this same owner/generation at its actual submission boundary.
 bool localReadyToTransmit(const SAEGroup19ConfirmWork &job) const {
  if(job.owner!=this || !confirming(job.generation) || job.kind!=SAEGroup19ConfirmWork::Kind::Local ||
     !job.verified || !job.counter || job.counter>state.reservedLocal)return false;
  return true;
 }
 // Call after the generated confirm was actually submitted successfully.
 bool completeLocal(const SAEGroup19ConfirmWork &job,bool transmitted){
  if(!transmitted || !localReadyToTransmit(job))return false;
  state.localSent=true;updateAccepted();return true;
 }
 bool completePeer(const SAEGroup19ConfirmWork &job){
  if(job.owner!=this || !confirming(job.generation) || job.kind!=SAEGroup19ConfirmWork::Kind::Peer || !job.verified ||
     (state.peerVerified && (job.counter<=state.peerCounter || job.counter==0xffff)))return false;
  state.peerCounter=job.counter;state.peerVerified=true;updateAccepted();return true;
 }
 bool copyPMK(uint64_t token,uint8_t *pmk,size_t pmkBytes,uint8_t *pmkid,size_t idBytes) const {
  if(!current(token) || state.phase!=Phase::Accepted || !pmk || pmkBytes<32 || !pmkid || idBytes<16)return false;
  copy(pmk,state.keys.pmk,32);copy(pmkid,state.keys.pmkid,16);return true;
 }
};
}

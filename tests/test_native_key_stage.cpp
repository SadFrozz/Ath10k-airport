#define ATH10K_NATIVE_KEY_STAGE_TEST
#include "test_native_pmf_receive.cpp"
#include "sae_eapol_vectors.inc"
#include "native_igtk_vectors.inc"
#include "sha256_vectors.inc"
using S=AthSecurity::Supplicant<Ath10kKernelCrypto,true,true>;
static Ath10kPCIDevice *keyDevice(){
 auto d=new Ath10kPCIDevice;auto &s=d->_connection;s.stage=Ath10k::LinkStage::Connected;
 s.pmfRequired=s.secure=s.pmfQoSTransported=true;s.groupCipher=AthSecurity::cipherCCMP;
 memcpy(s.local,w_sta,6);memcpy(s.bssid,w_ap,6);for(auto &q:d->_wmiRadio)q.completed=q.txConsumed=q.creditReturned=true;
 auto sec=d->_nativeSecurity=new Ath10kPCIDevice::NativeSecurity;assert(sec->prepareSAEWorker());
 sec->pmfSession=new Ath10kPMFSession;assert(sec->pmfSession->initConnection(w_sta,w_ap,91));
 assert(sec->supplicant.begin(w_pmk,w_snonce,w_sta,w_ap,w_rsn,sizeof(w_rsn),8,w_pmkid,16));sec->ready=true;return d;
}
static void clearReply(Ath10kPCIDevice *d){auto sec=d->_nativeSecurity;sec->replyPending=sec->keysPending=sec->authorizePending=false;sec->replyLength=0;AthSecurity::wipe(sec->reply,sizeof(sec->reply));AthSecurity::wipe(sec->keys,sizeof(sec->keys));}
static bool accept(Ath10kPCIDevice *d,unsigned result){ownerGate=true;const bool ok=d->nativeAcceptSecurityResult(result);ownerGate=false;return ok;}
static bool bip(Ath10kPCIDevice *d,const uint8_t *f,size_t n){
 auto sec=d->_nativeSecurity;ownerGate=true;assert(sec->pmfSession->queue(sec->saeWorker,f,n,0,Ath10kPMFSession::Layout::Ciphertext,91)==Ath10kPMFSession::Submission::Queued);ownerGate=false;
 run(latest);ownerGate=true;auto item=sec->saeWorker->takeCompleted();assert(item);Ath10kPMFSession::Message message;
 const bool ok=sec->pmfSession->consume(item,91,message);item->release();ownerGate=false;return ok;
}
static void initial(Ath10kPCIDevice *d){
 auto sec=d->_nativeSecurity;auto &s=d->_connection;
 assert(sec->supplicant.receive(w_m1,sizeof(w_m1))==S::Reply && accept(d,S::Reply));clearReply(d);
 assert(sec->supplicant.receive(w_m3,sizeof(w_m3))==S::Keys && accept(d,S::Keys));
 assert(sec->managementPending && sec->keysPending && sec->replyPending && !memcmp(sec->keys,w_ptk+32,16));
 assert(!d->nativePMFPortReady() && sec->managementPending); // An early query must not consume the staged key.
 s.securityPhase=1;assert(d->nativePMFPairwiseAcknowledged(sec->keys));s.pairInstalled=true;
 s.securityPhase=2;assert(!d->nativePMFPortReady() && sec->managementPending);
 s.securityPhase=3;assert(d->nativePMFPortReady() && !sec->managementPending);
 for(auto b:sec->pendingManagement.key)assert(!b);
 clearReply(d);s.securityPhase=5;s.portAuthorized=true;
}
int main(){
 // Cancellation at every key-install barrier must erase staged secrets and
 // make delayed firmware acknowledgements unable to reopen the PMF port.
 for(unsigned phase: {0u,1u,2u,3u,5u}){
  auto d=keyDevice();auto sec=d->_nativeSecurity;auto &state=d->_connection;
  assert(sec->supplicant.receive(w_m1,sizeof(w_m1))==S::Reply && accept(d,S::Reply));clearReply(d);
  assert(sec->supplicant.receive(w_m3,sizeof(w_m3))==S::Keys && accept(d,S::Keys));
  state.securityPhase=phase;state.pairInstalled=phase>=2;
  if(phase>=2)assert(d->nativePMFPairwiseAcknowledged(sec->keys));
  if(phase>=3)assert(d->nativePMFPortReady());
  state.cancelRequested=true;state.portAuthorized=false;
  ownerGate=true;sec->reset();ownerGate=false;
  assert(!sec->ready && !sec->managementPending && !sec->keysPending && !sec->replyPending);
  assert(!sec->pmfSession && !sec->replyLength && !sec->managementGeneration);
  for(auto byte:sec->keys)assert(!byte);
  for(auto byte:sec->reply)assert(!byte);
  for(auto byte:sec->pendingManagement.key)assert(!byte);
  assert(!accept(d,S::Keys) && !accept(d,S::ManagementKeys));
  assert(!d->nativePMFPairwiseAcknowledged(w_ptk+32) && !d->nativePMFPortReady());
  stop(d);
 }
 // The native SHA256-PSK path still uses its original data-key transaction
 // and never allocates or publishes a PMF owner/management key.
 {auto d=keyDevice();auto sec=d->_nativeSecurity;d->_connection.pmfRequired=false;
  sec->pmfSession->cancel();sec->pmfSession->release();sec->pmfSession=nullptr;
  assert(sec->supplicant.begin(s_pmk,s_snonce,s_sta,s_ap,s_rsn,sizeof(s_rsn),6));
  assert(sec->supplicant.receive(s_m1,sizeof(s_m1))==S::Reply && accept(d,S::Reply));clearReply(d);
  assert(sec->supplicant.receive(s_m3,sizeof(s_m3))==S::Keys && accept(d,S::Keys));
  assert(sec->keysPending && !sec->managementPending && !sec->pmfSession && !memcmp(sec->keys,s_ptk+32,16));
  assert(d->nativePMFPairwiseAcknowledged(sec->keys) && d->nativePMFPortReady());stop(d);}

 {auto d=keyDevice();auto sec=d->_nativeSecurity;
  assert(sec->supplicant.receive(w_m1,sizeof(w_m1))==S::Reply && accept(d,S::Reply));clearReply(d);
  uint8_t bad[sizeof(w_m3)];memcpy(bad,w_m3,sizeof(bad));bad[95]^=1;
  assert(sec->supplicant.receive(bad,sizeof(bad))==S::Fatal);
  assert(!accept(d,S::Fatal) && !sec->managementPending && !sec->keysPending && !sec->replyPending);stop(d);}
 {auto d=keyDevice();auto sec=d->_nativeSecurity;
  sec->supplicant.outputLength=sizeof(sec->reply)+1;assert(!accept(d,S::Reply) && !sec->replyPending);
  AthSecurity::IGTKCMAC128 key{};key.keyID=3;assert(!d->nativeStageManagementKey(key));key.keyID=4;key.ipn=0x1000000000000ull;
  assert(!d->nativeStageManagementKey(key) && !sec->managementPending);stop(d);}

 {auto d=keyDevice();initial(d);auto sec=d->_nativeSecurity;
  assert(bip(d,n_igtk4,sizeof(n_igtk4)) && !bip(d,n_igtk4,sizeof(n_igtk4)));
  assert(sec->supplicant.receive(w_m3,sizeof(w_m3))==S::Reply && accept(d,S::Reply));
  assert(!sec->managementPending && !sec->keysPending && !bip(d,n_igtk4,sizeof(n_igtk4)));clearReply(d);
  const auto phase=d->_connection.securityPhase;
  assert(sec->supplicant.receive(w_mgmt_only,sizeof(w_mgmt_only))==S::ManagementKeys && accept(d,S::ManagementKeys));
  assert(!sec->keysPending && !sec->managementPending && sec->replyPending && d->_connection.securityPhase==phase);
  assert(bip(d,n_igtk5,sizeof(n_igtk5)) && !bip(d,n_igtk4,sizeof(n_igtk4)));clearReply(d);
  assert(sec->supplicant.receive(w_group_both,sizeof(w_group_both))==S::GroupKeys && accept(d,S::GroupKeys));
  assert(!sec->pairUpdateReply);
  assert(sec->managementPending && sec->keysPending);d->_connection.portAuthorized=false;d->_connection.securityPhase=2;
  assert(!d->nativePMFPortReady() && sec->managementPending);
  d->_connection.securityPhase=5;assert(d->nativePMFPortReady() && !sec->managementPending);
  assert(bip(d,n_igtk4_next,sizeof(n_igtk4_next)) && !bip(d,n_igtk5,sizeof(n_igtk5)));clearReply(d);
  d->_connection.portAuthorized=true; // Mock completed group-key firmware/port barrier.
  // A lost group acknowledgement can retransmit the exact authenticated G1.
  // ACK it without a GTK transaction, IGTK publication or replay-floor reset.
  const auto pairEpoch=sec->pmfSession->pairwiseEpoch();
  const auto generation=sec->pmfSession->activeGeneration();
  for(unsigned retry=0;retry<3;++retry){
   assert(sec->supplicant.receive(w_group_both,sizeof(w_group_both))==S::Reply && accept(d,S::Reply));
   assert(sec->replyPending && !sec->keysPending && !sec->managementPending);
   assert(sec->pmfSession->pairwiseEpoch()==pairEpoch && sec->pmfSession->activeGeneration()==generation);
   assert(sec->pmfSession->portReady() && d->_connection.portAuthorized);
   assert(!bip(d,n_igtk4_next,sizeof(n_igtk4_next)));clearReply(d);
  }
  // Old group-key delivery and a changed same-counter G1 must not recover
  // an obsolete key or manufacture a cached acknowledgement.
  assert(sec->supplicant.receive(w_mgmt_only,sizeof(w_mgmt_only))==S::Ignore);
  uint8_t forged[sizeof(w_group_both)];memcpy(forged,w_group_both,sizeof(forged));forged[sizeof(forged)-1]^=1;
  assert(sec->supplicant.receive(forged,sizeof(forged))==S::Ignore);
  assert(!sec->supplicant.outputLength && !sec->replyPending && !sec->keysPending && !sec->managementPending);
  assert(sec->pmfSession->portReady() && !bip(d,n_igtk4_next,sizeof(n_igtk4_next)));stop(d);}
 {auto d=keyDevice();auto sec=d->_nativeSecurity;initial(d);
  assert(sec->supplicant.receive(w_rekey1,sizeof(w_rekey1))==S::Reply && accept(d,S::Reply));clearReply(d);
  assert(sec->supplicant.receive(w_rekey3,sizeof(w_rekey3))==S::PairKeys && accept(d,S::PairKeys));
  assert(sec->pairUpdateReply && sec->ptkUpdateGeneration==d->_connection.securityGeneration);
  assert(!sec->managementPending && sec->keysPending);d->_connection.securityPhase=1;
  assert(d->nativePMFPairwiseAcknowledged(sec->keys));d->_connection.securityPhase=5;assert(d->nativePMFPortReady());
  assert(bip(d,n_igtk4,sizeof(n_igtk4)));stop(d);}
 // Real native receive/service path: an old-key BIP completion waits while
 // authenticated EAPOL stages and publishes a replacement IGTK at its barrier.
 {auto d=keyDevice();initial(d);auto sec=d->_nativeSecurity;auto &state=d->_connection;
  assert(deliver(d,n_igtk4,sizeof(n_igtk4)));service(d,0);assert(sec->pmfRXInFlight);
  run(latest); // Authenticated old-key result has not been committed yet.
  assert(sec->supplicant.receive(w_group_both,sizeof(w_group_both))==S::GroupKeys && accept(d,S::GroupKeys));
  assert(!sec->pairUpdateReply);
  assert(sec->managementPending && sec->keysPending);
  state.portAuthorized=false;state.securityPhase=2;assert(!d->nativePMFPortReady());
  // Mock the completed data-key barrier; this is not a firmware hardware test.
  state.securityPhase=5;assert(d->nativePMFPortReady());state.portAuthorized=true;clearReply(d);
  service(d,1);assert(!sec->pmfRXInFlight && sec->pmfRXDropped==1 && !sec->pmfRXVerified && !state.cancelRequested);
  // The obsolete completion cannot cancel the new association or consume its IPN.
  assert(deliver(d,n_igtk4_next,sizeof(n_igtk4_next)));service(d,2);run(latest);service(d,3);
  assert(sec->pmfRXVerified==1 && state.cancelRequested && !state.portAuthorized && state.apDisconnect.reason==6);stop(d);}
 {auto d=keyDevice();auto sec=d->_nativeSecurity;AthSecurity::IGTKCMAC128 key{};key.keyID=4;memcpy(key.key,w_igtk,16);
  assert(d->nativeStageManagementKey(key));sec->pmfSession->cancel();assert(!d->nativePMFPortReady() && !sec->managementPending);
  for(auto b:sec->pendingManagement.key)assert(!b);stop(d);}
 {auto d=keyDevice();auto sec=d->_nativeSecurity;initial(d);assert(sec->supplicant.receive(w_mgmt_only,sizeof(w_mgmt_only))==S::ManagementKeys);
  d->_connection.pmfRequired=false;assert(!accept(d,S::ManagementKeys) && !sec->replyPending && !sec->managementPending);stop(d);}
}

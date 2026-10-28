#include <cassert>
#include <cstring>
#include <vector>
#include "../src/shared/Ath10kSAEExchange.hpp"
using namespace AthSecurity;
using Exchange=SAEGroup19ClientExchange;
using Action=Exchange::Action;
using Phase=Exchange::Phase;
using Failure=Exchange::Failure;
static const uint8_t local[6]={2,1,2,3,4,5},ap[6]={2,6,7,8,9,10};
static SAEGroup19AuthMessage commit(bool h2e=true){
 SAEGroup19AuthMessage m{};m.kind=SAEAuthKind::Commit;m.h2e=h2e;
 for(unsigned i=0;i<96;++i)m.commit[i]=uint8_t(i+2);return m;
}
static std::vector<uint8_t> response(const SAEGroup19AuthMessage &m){
 std::vector<uint8_t> v(1536);size_t n=0;v[0]=0xb0;
 memcpy(v.data()+4,local,6);memcpy(v.data()+10,ap,6);memcpy(v.data()+16,ap,6);
 assert(encodeSAEGroup19AuthBody(m,v.data()+24,v.size()-24,n));v.resize(n+24);return v;
}
static SAEGroup19AuthMessage challenge(unsigned value,bool h2e=true){
 SAEGroup19AuthMessage m{};m.kind=SAEAuthKind::TokenRequest;m.h2e=h2e;m.tokenBytes=3;
 m.token[0]=uint8_t(value);m.token[1]=8;m.token[2]=9;return m;
}
struct NoCrypto {static bool hmac256(const uint8_t *,size_t,const uint8_t *,size_t,uint8_t *){return false;}};
int main(){
 Exchange e;SAEGroup19CommitTx tx,stale;SAEGroup19KeyWork work,other;
 auto c=commit();uint64_t token=0;
 auto send=[&](uint64_t now,bool success=true){assert(e.snapshotCommit(tx,3,now));assert(e.commitReady(tx,now));assert(e.completeCommit(tx,success,now));};
 assert(e.begin(c,local,ap,10,token));const auto first=token;
 assert(e.poll(10)==Action::SendCommit);
 auto tokenFrame=response(challenge(1));
 assert(e.receiveFromAP(tokenFrame.data(),tokenFrame.size(),11)==Action::Ignore); // No local commit submitted yet.
 assert(e.snapshotCommit(stale,1,12));send(12);
 assert(!e.commitReady(stale,12));assert(!e.completeCommit(stale,true,12));
 assert(e.poll(761)==Action::Ignore && e.poll(762)==Action::SendCommit);
 assert(e.snapshotCommit(stale,2,762));
 assert(e.receiveFromAP(tokenFrame.data(),tokenFrame.size(),763)==Action::SendCommit);
 assert(!e.commitReady(stale,763));
 assert(e.snapshotCommit(tx,3,763));SAEGroup19AuthMessage decoded{};
 assert(decodeSAEGroup19AuthBody(tx.data()+24,tx.size()-24,true,0,decoded)==SAEWireResult::Valid);
 assert(decoded.tokenBytes==3 && decoded.token[0]==1 && !memcmp(decoded.commit,c.commit,96));
 assert(e.receiveFromAP(tokenFrame.data(),tokenFrame.size(),764)==Action::Ignore);
 assert(e.completeCommit(tx,true,764));
 assert(e.receiveFromAP(tokenFrame.data(),tokenFrame.size(),765)==Action::Ignore);
 assert(e.poll(1513)==Action::Ignore && e.poll(1514)==Action::SendCommit);
 // New token revisions invalidate already prepared packets, without extending the deadline.
 for(unsigned value=2;value<=3;++value){
  auto f=response(challenge(value));assert(e.snapshotCommit(stale,4,1514+value));
  assert(e.receiveFromAP(f.data(),f.size(),1514+value)==Action::SendCommit);
  assert(!e.commitReady(stale,1514+value));
 }
 auto excessive=response(challenge(4));assert(e.receiveFromAP(excessive.data(),excessive.size(),1520)==Action::Failed);
 assert(e.failure()==Failure::TokenChanges);
 // An old transport completion must not regress the clock of a replacement exchange.
 assert(e.begin(c,local,ap,2000,token) && token>first);
 assert(!e.completeCommit(stale,true,100));assert(e.phase()==Phase::Committed);
 assert(e.snapshotCommit(tx,1,2000));assert(!e.commitReady(tx,1999));assert(e.failure()==Failure::Clock);
 // Failed submissions consume a finite retry budget too.
 assert(e.begin(c,local,ap,0,token));
 for(unsigned i=0;i<Exchange::MaxAttempts;++i){assert(e.poll(i*750)==Action::SendCommit);send(i*750,false);}
 assert(e.poll(3750)==Action::Failed && e.failure()==Failure::Attempts);
 // RX noise and valid challenges cannot extend the absolute 5000ms deadline.
 assert(e.begin(c,local,ap,100,token));send(100);
 for(unsigned now=101;now<5100;now+=37){
  assert(e.receiveFromAP(nullptr,0,now)==Action::Ignore);
 }
 assert(e.poll(5100)==Action::Failed && e.failure()==Failure::Timeout);
 auto peer=c;peer.commit[95]^=1;auto peerFrame=response(peer);
 assert(e.begin(c,local,ap,6000,token));send(6000);
 auto wrongPeer=peerFrame;wrongPeer[10]^=2;
 assert(e.receiveFromAP(wrongPeer.data(),wrongPeer.size(),6001)==Action::Ignore && e.phase()==Phase::Committed);
 auto reflected=response(c);assert(e.receiveFromAP(reflected.data(),reflected.size(),6002)==Action::Ignore);
 assert(e.receiveFromAP(peerFrame.data(),peerFrame.size(),6003)==Action::ComputeKeys);
 assert(e.snapshotKeys(work,6003));assert(!e.snapshotKeys(other,6003));
 assert(e.receiveFromAP(peerFrame.data(),peerFrame.size(),6004)==Action::Ignore);
 peer.commit[94]^=1;auto changedPeer=response(peer);
 assert(e.receiveFromAP(changedPeer.data(),changedPeer.size(),6005)==Action::Ignore);
 assert(e.poll(6006)==Action::Ignore); // No duplicate key job while computing.
 P256CoreCryptoAPI missing{};P256CoreCryptoCandidate engine(missing);P256CoreCryptoWorkspace workspace;
 uint8_t random[32]{},pwe[64]{};random[31]=7;
 assert(!work.compute<NoCrypto>(engine,random,32,pwe,64,workspace));
 assert(e.completeKeys(work,6007)==Action::Failed && e.failure()==Failure::Crypto);
 // Cancellation rejects a computed/unfinished key callback without touching a newer join.
 assert(e.begin(c,local,ap,7000,token));send(7000);
 assert(e.receiveFromAP(peerFrame.data(),peerFrame.size(),7001)==Action::ComputeKeys);assert(e.snapshotKeys(work,7001));
 e.cancel();assert(e.begin(c,local,ap,8000,token));
 assert(e.completeKeys(work,7002)==Action::Ignore && e.phase()==Phase::Committed);
 assert(e.poll(8000)==Action::SendCommit);
 // Explicit mode/identifier failure; group 19 rejection cannot fall back to open auth.
 send(8000);auto wrongMode=response(commit(false));
 assert(e.receiveFromAP(wrongMode.data(),wrongMode.size(),8001)==Action::Failed && e.failure()==Failure::Mode);
 assert(e.begin(c,local,ap,9000,token));send(9000);
 peer=c;peer.commit[95]^=1;peer.identifierPresent=true;peer.identifierBytes=1;peer.identifier[0]='x';peerFrame=response(peer);
 assert(e.receiveFromAP(peerFrame.data(),peerFrame.size(),9001)==Action::Failed && e.failure()==Failure::Identifier);
 assert(e.begin(c,local,ap,10000,token));send(10000);
 SAEGroup19AuthMessage reject{};reject.kind=SAEAuthKind::GroupRejected;auto rejectFrame=response(reject);
 assert(e.receiveFromAP(rejectFrame.data(),rejectFrame.size(),10001)==Action::Failed && e.failure()==Failure::Rejected);
 uint64_t unchanged=123;auto invalid=c;invalid.tokenBytes=1;
 assert(!e.begin(invalid,local,ap,11000,unchanged) && unchanged==123 && e.failure()==Failure::InvalidStart);
 assert(!e.begin(c,local,local,11000,unchanged));assert(!e.begin(c,local,ap,~uint64_t(0)-1,unchanged));
 uint8_t pmk[32],id[16];memset(pmk,0xa5,32);memset(id,0xa5,16);
 assert(!e.copyPMK(token,pmk,32,id,16,11000));for(auto v:pmk)assert(v==0xa5);for(auto v:id)assert(v==0xa5);
 // Legacy challenge length is retained explicitly in the retransmitted commit.
 c=commit(false);assert(e.begin(c,local,ap,12000,token));send(12000);
 tokenFrame=response(challenge(42,false));assert(e.receiveFromAP(tokenFrame.data(),tokenFrame.size(),12001)==Action::SendCommit);
 assert(e.snapshotCommit(tx,7,12001));
 assert(decodeSAEGroup19AuthBody(tx.data()+24,tx.size()-24,false,3,decoded)==SAEWireResult::Valid);
 assert(decoded.tokenBytes==3 && decoded.token[0]==42 && !memcmp(decoded.commit,c.commit,96));
}

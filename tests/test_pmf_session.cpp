#include "mock_sae_worker.hpp"
#include "../src/shared/Ath10kPMFCCMP.hpp"
#include "../src/shared/Ath10kSHA256.hpp"
#include "common_crypto_personal.hpp"
#include "pmf_ccmp_vectors.inc"
#include <vector>
struct Pause {
 std::mutex mutex;std::condition_variable cv;bool entered=false,go=false;
 void pause(){std::unique_lock<std::mutex> guard(mutex);entered=true;cv.notify_all();assert(cv.wait_for(guard,5s,[&]{return go;}));}
 void wait(){std::unique_lock<std::mutex> guard(mutex);assert(cv.wait_for(guard,5s,[&]{return entered;}));}
 void resume(){std::lock_guard<std::mutex> guard(mutex);go=true;cv.notify_all();}
};
static Pause *pauseAES=nullptr;static bool failAES=false;static unsigned aesCalls=0;
static Ath10kSAEWorker *terminateDuringInit=nullptr;
struct Ath10kKernelCrypto : PersonalTestCrypto {
 static bool encrypt(const uint8_t *k,const uint8_t *in,uint8_t *out){
  assert(!ownerGate && !heldLocks);++aesCalls;if(pauseAES)pauseAES->pause();
  return !failAES && PersonalTestCrypto::encrypt(k,in,out);
 }
};
#include "pmf_session.inc"
using S=Ath10kPMFSession;using Job=Ath10kPMFJob;using Submit=S::Submission;
static void clean(){assert(objects==0 && locks==0 && calls==0);}
static Ath10kSAEWorker *worker(){auto w=new Ath10kSAEWorker;assert(w->init());return w;}
static S *create(uint64_t generation=9,bool ready=true){
 auto s=new S;ownerGate=true;assert(s->initConnection(c_sta,c_ap,generation));
 assert(!s->authorize());AthSecurity::IGTKCMAC128 igtk{};igtk.keyID=4;igtk.ipn=6;memcpy(igtk.key,c_key,16);
 assert(!s->activateManagement(igtk));assert(s->acknowledgePairwise(c_key,c_sta,c_ap));
 if(ready){assert(!s->authorize());assert(s->activateManagement(igtk));assert(s->authorize());}
 ownerGate=false;return s;
}
static Ath10kSAEWorkItem *complete(Ath10kSAEWorker *w){run(latest);auto job=w->takeCompleted();assert(job);return job;}
static Submit queue(S *s,Ath10kSAEWorker *w,const uint8_t *frame=c_query_wire,size_t bytes=sizeof(c_query_wire),
 uint32_t status=0,S::Layout layout=S::Layout::Ciphertext,uint64_t generation=9){
 ownerGate=true;auto result=s->queue(w,frame,bytes,status,layout,generation);ownerGate=false;return result;
}
static bool consume(S *s,Ath10kSAEWorkItem *job,S::Message &out,uint64_t generation=9){ownerGate=true;bool result=s->consume(job,generation,out);ownerGate=false;return result;}
static void stop(S *s,Ath10kSAEWorker *w){ownerGate=true;s->cancel();s->release();w->cancel();ownerGate=false;w->shutdown();w->release();clean();}
static void observeFree(OSObject *object){
 size_t n=0;if(dynamic_cast<Job *>(object))n=sizeof(Job);else if(dynamic_cast<S *>(object))n=sizeof(S);
 auto p=reinterpret_cast<const uint8_t *>(object);for(size_t i=0;i+16<=n;++i)assert(memcmp(p+i,c_key,16));
}
static void lifecycle(){
 failObjectInit=true;auto failed=new S;assert(!failed->initConnection(c_sta,c_ap,9));failed->release();clean();
 auto invalid=new S;assert(!invalid->initConnection(c_sta,c_sta,9));invalid->release();clean();
 auto s=create(9,false);auto w=worker();assert(queue(s,w)==Submit::Aborted);
 ownerGate=true;assert(!s->acknowledgePairwise(c_key,c_ap,c_sta));assert(!s->initConnection(c_sta,c_ap,10));ownerGate=false;
 stop(s,w);
 s=create();w=worker();const unsigned callsBefore=aesCalls;
 assert(queue(s,w)==Submit::Queued && aesCalls==callsBefore);assert(queue(s,w)==Submit::Busy);
 auto item=complete(w);S::Message out;out.bytes=77;assert(!consume(s,item,out,10) && out.bytes==77);
 auto foreign=create();assert(!consume(foreign,item,out));foreign->cancel();foreign->release();
 assert(consume(s,item,out) && out.kind==S::Kind::Pairwise && out.bytes==sizeof(c_query_plain));
 assert(!memcmp(out.frame,c_query_plain,out.bytes) && out.pairwise.integrity && out.pairwise.replay && out.pairwise.connection==9);
 assert(!consume(s,item,out));item->release();
 assert(queue(s,w)==Submit::Queued);item=complete(w);out.bytes=77;assert(!consume(s,item,out) && out.bytes==77);item->release();
 stop(s,w);
}
static void groupAndRotation(){
 auto s=create();auto w=worker();S::Message out;
 assert(queue(s,w,c_bip_disconnect,sizeof(c_bip_disconnect))==Submit::Queued);auto first=complete(w);
 assert(queue(s,w,c_bip_disconnect,sizeof(c_bip_disconnect))==Submit::Queued);auto second=complete(w);
 assert(consume(s,second,out) && out.kind==S::Kind::GroupManagement && out.groupID==4 && out.groupEpoch);
 assert(!out.pairwise.integrity && out.bytes==sizeof(c_bip_disconnect)-18);
 assert(!consume(s,first,out));second->release();first->release();
 assert(queue(s,w)==Submit::Queued);first=complete(w);
 uint8_t next[16];memcpy(next,c_key,16);next[0]^=1;
 ownerGate=true;assert(s->acknowledgePairwise(next,c_sta,c_ap));ownerGate=false;
 assert(queue(s,w)==Submit::Aborted);ownerGate=true;assert(s->authorize());ownerGate=false;
 out.bytes=77;assert(!consume(s,first,out) && out.bytes==77);first->release();
 stop(s,w);
 s=create();w=worker();assert(queue(s,w,c_bip_disconnect,sizeof(c_bip_disconnect))==Submit::Queued);first=complete(w);
 AthSecurity::IGTKCMAC128 key{};key.keyID=4;memcpy(key.key,next,16);
 ownerGate=true;assert(s->activateManagement(key));ownerGate=false;assert(!consume(s,first,out));first->release();stop(s,w);
}
static void admissionAndFailures(){
 auto s=create();auto w=worker();S::Message out;out.bytes=77;
 for(uint32_t error:{1u,8u,16u,32u})assert(queue(s,w,c_query_wire,sizeof(c_query_wire),error)==Submit::NoWork);
 assert(queue(s,w,nullptr)==Submit::NoWork);assert(queue(s,w,c_query_wire,25)==Submit::NoWork);
 assert(queue(s,w,c_query_wire,513)==Submit::NoWork);assert(queue(s,w,c_query_wire,sizeof(c_query_wire),0,S::Layout::Ciphertext,10)==Submit::Aborted);
 failObjectInit=true;assert(queue(s,w)==Submit::NoMemory);assert(queue(s,w)==Submit::Queued);
 failAES=true;auto item=complete(w);failAES=false;assert(!consume(s,item,out) && out.bytes==77);item->release();
 assert(queue(s,w,c_query_decrypted,sizeof(c_query_decrypted),0,S::Layout::PlaintextWithEncryptedTag)==Submit::Queued);
 item=complete(w);assert(consume(s,item,out));item->release();stop(s,w);
 s=create();w=worker();assert(queue(s,w,c_public_wire,sizeof(c_public_wire))==Submit::Queued);item=complete(w);assert(!consume(s,item,out));item->release();stop(s,w);
 s=create();w=worker();auto bad=std::vector<uint8_t>(c_bip_disconnect,c_bip_disconnect+sizeof(c_bip_disconnect));bad.back()^=1;
 assert(queue(s,w,bad.data(),bad.size())==Submit::Queued);item=complete(w);assert(!consume(s,item,out));item->release();stop(s,w);
 s=create();w=worker();terminateDuringInit=w;
 objectInitHook=[](){std::thread stopper([](){terminateDuringInit->shutdown();});stopper.join();};
 assert(queue(s,w)==Submit::Aborted);terminateDuringInit=nullptr;w->release();
 // Terminal queue races do not retire a valid association or consume its PN.
 w=worker();assert(queue(s,w)==Submit::Queued);item=complete(w);assert(consume(s,item,out));item->release();stop(s,w);
}
static void cancelRunning(){
 auto s=create();auto w=worker();Pause paused;pauseAES=&paused;assert(queue(s,w)==Submit::Queued);
 std::thread thread([&]{run(latest);});paused.wait();
 ownerGate=true;s->cancel();s->release();w->cancel();ownerGate=false;
 paused.resume();thread.join();pauseAES=nullptr;assert(!w->takeCompleted());w->shutdown();w->release();clean();
 // Cancellation before dispatch also erases the captured key at disposal.
 s=create();w=worker();assert(queue(s,w)==Submit::Queued);stop(s,w);
}
static Submit queueTX(S *s,Ath10kSAEWorker *w){
 ownerGate=true;auto result=s->queueProtect(w,c_txpn1_plain,sizeof(c_txpn1_plain),9);ownerGate=false;return result;
}
static void protectedTX(){
 auto s=create();auto w=worker();assert(queueTX(s,w)==Submit::Queued);auto item=complete(w);
 assert(queueTX(s,w)==Submit::Busy);uint8_t frame[512]{};size_t bytes=123;S::Message message;
 assert(!consume(s,item,message) && s->protectedReady(item,9));
 assert(!s->copyProtected(item,frame,1,bytes,9) && bytes==123);
 assert(s->copyProtected(item,frame,sizeof(frame),bytes,9) && bytes==sizeof(c_txpn1_wire));
 assert(!memcmp(frame,c_txpn1_wire,bytes));
 assert(s->acknowledgePairwise(c_key,c_sta,c_ap) && s->protectedReady(item,9)); // No same-key PN reset.
 assert(s->retireProtected(item,9) && !s->protectedReady(item,9) && !s->retireProtected(item,9));item->release();
 // A failed crypto result also retires a spent PN, never reallocates it.
 assert(queueTX(s,w)==Submit::Queued);failAES=true;item=complete(w);failAES=false;
 assert(!s->protectedReady(item,9) && s->retireProtected(item,9));item->release();
 assert(queueTX(s,w)==Submit::Queued);item=complete(w);
 assert(s->copyProtected(item,frame,sizeof(frame),bytes,9) && !memcmp(frame,c_txpn3_wire,bytes));
 s->abandonProtected();assert(!s->protectedReady(item,9) && !s->retireProtected(item,9));item->release();stop(s,w);
 // A terminal submit race burns PN1 without blocking the association.
 s=create();w=worker();terminateDuringInit=w;
 objectInitHook=[](){std::thread stopper([](){terminateDuringInit->shutdown();});stopper.join();};
 assert(queueTX(s,w)==Submit::Aborted);terminateDuringInit=nullptr;w->release();w=worker();
 assert(queueTX(s,w)==Submit::Queued);item=complete(w);
 assert(s->copyProtected(item,frame,sizeof(frame),bytes,9) && !memcmp(frame,c_txpn2_wire,bytes));
 uint8_t next[16];memcpy(next,c_key,16);next[0]^=1;
 assert(s->acknowledgePairwise(next,c_sta,c_ap) && s->authorize());
 assert(!s->protectedReady(item,9) && !s->retireProtected(item,9));item->release();stop(s,w);
 // Init failure before nonce reservation does not consume PN1.
 s=create();w=worker();failObjectInit=true;assert(queueTX(s,w)==Submit::NoMemory);
 assert(queueTX(s,w)==Submit::Queued);item=complete(w);
 assert(s->copyProtected(item,frame,sizeof(frame),bytes,9) && !memcmp(frame,c_txpn1_wire,bytes));
 assert(s->retireProtected(item,9));item->release();stop(s,w);
}
static void groupAction(){
 auto s=create();auto w=worker();assert(queue(s,w,c_group_action_wire,sizeof(c_group_action_wire))==Submit::Queued);
 auto item=complete(w);S::Message out;assert(consume(s,item,out) && out.kind==S::Kind::GroupManagement);
 assert(out.bytes==sizeof(c_group_action_plain) && !memcmp(out.frame,c_group_action_plain,out.bytes) && !out.pairwise.integrity);
 item->release();stop(s,w);
}
static void abandonRunningTX(){
 auto s=create();auto w=worker();Pause paused;pauseAES=&paused;assert(queueTX(s,w)==Submit::Queued);
 std::thread thread([&]{run(latest);});paused.wait();
 ownerGate=true;s->abandonProtected();w->cancel();ownerGate=false;
 paused.resume();thread.join();pauseAES=nullptr;assert(!w->takeCompleted());
 assert(queueTX(s,w)==Submit::Queued);auto item=complete(w);uint8_t frame[512]{};size_t bytes=0;
 assert(s->copyProtected(item,frame,sizeof(frame),bytes,9) && !memcmp(frame,c_txpn2_wire,bytes));
 assert(s->retireProtected(item,9));item->release();stop(s,w);
}
int main(){objectFreeObserver=observeFree;lifecycle();groupAndRotation();admissionAndFailures();cancelRunning();protectedTX();groupAction();abandonRunningTX();objectFreeObserver=nullptr;clean();}

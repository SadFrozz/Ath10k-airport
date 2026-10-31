#include "../support/mock_sae_worker.hpp"
#define ATH10K_P256_DIAGNOSTIC_BINDING 1
#define ATH10K_P256_SYMBOLS_TEST 1
#include "../../src/macos/native/Ath10kP256KernelBinding.hpp"
#include "../../src/security/Ath10kP256BackendCheck.hpp"
#include "../../src/security/Ath10kOWEP256.hpp"
#include "../support/common_crypto_personal.hpp"
#include <CommonCrypto/CommonDigest.h>
struct OWECrypto:PersonalTestCrypto {static bool hash256(const uint8_t *p,size_t n,uint8_t *o){return CC_SHA256(p,CC_LONG(n),o)!=nullptr;}};
struct Ath10kKernelCrypto:OWECrypto {
 static bool random(uint8_t *out,size_t n){assert(!ownerGate && !heldLocks);return PersonalTestCrypto::random(out,n);}
};
#include "native_owe_job.inc"
#include <dlfcn.h>
#include <map>
#include <string>
#include <vector>
#include "../../src/security/Ath10kP256DiagnosticPolicy.hpp"
#include "p256_check.inc"
using Report=AthSecurity::P256BackendCheckReport;
using Step=Report::Step;
static const void *(*realCurve)();static unsigned curveCalls=0;
struct Pause {
 std::mutex lock;std::condition_variable cv;bool entered=false,resumed=false;
 void pause(){std::unique_lock<std::mutex> guard(lock);entered=true;cv.notify_all();assert(cv.wait_for(guard,5s,[&]{return resumed;}));}
 void wait(){std::unique_lock<std::mutex> guard(lock);assert(cv.wait_for(guard,5s,[&]{return entered;}));}
 void resume(){std::lock_guard<std::mutex> guard(lock);resumed=true;cv.notify_all();}
};
static Pause *pauseWrites=nullptr;
struct IOService : OSObject {
 std::map<std::string,uint64_t> numbers;std::map<std::string,std::string> strings;
 std::vector<std::string> writes;
 bool setProperty(const char *key,bool value){if(pauseWrites)pauseWrites->pause();numbers[key]=value;writes.emplace_back(key);return true;}
 bool setProperty(const char *key,uint64_t value,unsigned){numbers[key]=value;writes.emplace_back(key);return true;}
 bool setProperty(const char *key,const char *value){strings[key]=value;writes.emplace_back(key);return true;}
};
#include "p256_registry.inc"
static uint64_t timesNS[4]={};static unsigned clockReads=0;
static uint64_t testClock(){assert(clockReads<4);return timesNS[clockReads++];}
static Ath10kP256RegistryJob::Admission nextAdmission;
static unsigned admissionCalls=0;
static Ath10kP256RegistryJob::Admission testAdmission(const AthSecurity::P256DiagnosticPublication &publication){
 assert(!ownerGate && !heldLocks && !publication.cancelled());++admissionCalls;
 return nextAdmission;
}
static Pause *pauseCurve=nullptr;
static const void *curve(){assert(!ownerGate && !heldLocks);++curveCalls;if(pauseCurve)pauseCurve->pause();return realCurve();}
static bool zero(const void *object,size_t bytes){auto p=static_cast<const uint8_t *>(object);uint8_t value=0;for(size_t i=0;i<bytes;++i)value|=p[i];return value==0;}
// Minimal platform shell around the actual native OWE service and job.
using UInt8=uint8_t;using UInt32=uint32_t;using UInt64=uint64_t;
namespace Ath10k {
 enum class LinkStage {Auth,Assoc};enum class DisconnectStage {None,Drain};
 struct OWEState {
  LinkStage stage=LinkStage::Auth;DisconnectStage disconnect=DisconnectStage::None;
  bool cancelRequested=false,secure=true,pmfRequired=true,assocReply=false,oweRequestReady=false,oweResponseReady=false;
  unsigned securityAKM=18;uint8_t local[6]{2,1,2,3,4,5},bssid[6]{2,6,7,8,9,10},oweRequest[37]{},oweResponse[37]{};
  struct {uint8_t bssid[6]{2,6,7,8,9,10},rsn[28]{},rsnxe[18]{};size_t rsnLength=28,rsnxeLength=0;} ap;
 };
}
struct Ath10kNativeSAEKernelBackend {
 static inline AthSecurity::P256CoreCryptoAPI points{};static inline AthSecurity::P256FieldAPI field{};
 static bool providers(AthSecurity::P256CoreCryptoAPI &p,AthSecurity::P256FieldAPI &f){p=points;f=field;return p.complete();}
};
#include "../../src/security/Ath10kSupplicant.hpp"
struct Ath10kPCIDevice {
 struct Security {
  Ath10kSAEWorker *saeWorker=nullptr;Ath10kNativeOWEJob *oweJob=nullptr;
  struct PMF {uint64_t activeGeneration(){return 9;}} pmf,*pmfSession=&pmf;
  uint32_t nextSAEGeneration=9;uint8_t owePhase=0;bool oweSubmitted=false,ready=false;uint64_t oweDeadline=0,oweLastNow=0;
  AthSecurity::Supplicant<OWECrypto,true,true,true,true,true,true> supplicant;
 } security,*_nativeSecurity=&security;
 Ath10k::OWEState _connection;
 bool _nativeJoinPending=true,_nativeStopping=false,_nativeRadioOn=true,_networkEnabled=true,blocked=false;
 bool powerIOBlocked(){return blocked;}bool nativePMFFirmwareReady(){return true;}
 bool serviceNativeOWE(UInt64,const char *&);
};
#include "native_owe_service.inc"
int main(){
 void *lib=dlopen("/usr/lib/system/libcorecrypto.dylib",RTLD_NOW|RTLD_LOCAL);assert(lib);
 using namespace Ath10kP256KernelSymbols;
#define SYMBOL(name) name=reinterpret_cast<decltype(name)>(dlsym(lib,#name));assert(name)
 SYMBOL(ccec_cp_256);SYMBOL(ccec_x963_import_pub);SYMBOL(ccec_validate_pub);SYMBOL(ccec_x963_export);
 SYMBOL(ccec_projectify);SYMBOL(ccec_affinify);SYMBOL(ccec_mult_blinded);SYMBOL(ccec_full_add);SYMBOL(ccec_full_sub);
 SYMBOL(ccn_read_uint);SYMBOL(ccrng);SYMBOL(cczp_n);SYMBOL(cczp_prime);SYMBOL(cczp_mul);SYMBOL(cczp_inv);SYMBOL(cczp_add);SYMBOL(cczp_sub);
#undef SYMBOL
 realCurve=ccec_cp_256;ccec_cp_256=curve;
 const char *testedKernel="Darwin Kernel Version 24.6.0: Mon Jul 14 11:28:17 PDT 2025; root:xnu-11417.140.69~1/RELEASE_X86_64";
 AthSecurity::P256CoreCryptoAPI admittedPoints{};AthSecurity::P256FieldAPI admittedField{};
 assert(Ath10kP256KernelBinding::providersForIdentity(24,6,0,"24G90",testedKernel,admittedPoints,admittedField));
 assert(admittedPoints.complete() && admittedField.multiply && !curveCalls);
 for(unsigned identity=0;identity<6;++identity){
  // Start with valid outputs each time: rejection must erase stale providers.
  assert(Ath10kP256KernelBinding::providersForIdentity(24,6,0,"24G90",testedKernel,admittedPoints,admittedField));
  assert(!Ath10kP256KernelBinding::providersForIdentity(identity==0?25:24,identity==1?5:6,identity==2?1:0,
      identity==3?"24G91":identity==4?nullptr:"24G90",identity==5?"other kernel":testedKernel,admittedPoints,admittedField));
  assert(!admittedPoints.complete() && !admittedPoints.curve && !admittedField.curve && !admittedField.multiply && !curveCalls);
 }
 ownerGate=true;const auto points=Ath10kP256KernelBinding::points();const auto field=Ath10kP256KernelBinding::field();ownerGate=false;
 assert(!curveCalls && points.complete() && points.curve==curve && field.curve==curve);
 // Compact OWE ECDH known points G and 2G, with atomic rejection.
 {
  const uint8_t gx[32]={0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96};
  const uint8_t twice[32]={0x7c,0xf2,0x7b,0x18,0x8d,0x03,0x4f,0x7e,0x8a,0x52,0x38,0x03,0x04,0xb5,0x1a,0xc3,0xc0,0x89,0x69,0xe2,0x77,0xf2,0x1b,0x35,0xa6,0x0b,0x48,0xfc,0x47,0x66,0x99,0x78};
  uint8_t scalar[32]{},out[40];scalar[31]=1;memset(out,0xa5,sizeof(out));
  assert(AthSecurity::oweGroup19SharedSecret(points,field,scalar,32,gx,32,out,sizeof(out)));
  assert(!memcmp(out,gx,32));for(unsigned i=32;i<40;++i)assert(out[i]==0xa5);
  scalar[31]=2;assert(AthSecurity::oweGroup19SharedSecret(points,field,scalar,32,gx,32,out,32));assert(!memcmp(out,twice,32));
  scalar[31]=1;assert(AthSecurity::oweGroup19SharedSecret(points,field,scalar,32,twice,32,out,32));assert(!memcmp(out,twice,32));
  auto rejected=[&](const AthSecurity::P256CoreCryptoAPI &p,const AthSecurity::P256FieldAPI &f,const uint8_t *x,size_t n,size_t cap){
   memset(out,0xa5,sizeof(out));assert(!AthSecurity::oweGroup19SharedSecret(p,f,scalar,32,x,n,out,cap));for(auto v:out)assert(v==0xa5);
  };
  scalar[31]=0;rejected(points,field,gx,32,32);scalar[31]=1;
  uint8_t invalid[32];memset(invalid,0xff,32);rejected(points,field,invalid,32,32);
  rejected(points,field,gx,31,32);rejected(points,field,gx,32,31);
  uint8_t station[6]={2,1,2,3,4,5},ap[6]={2,6,7,8,9,10},ie[37]{},reply[37]{};
  AthSecurity::OWEGroup19Exchange exchange;AthSecurity::OWEGroup19Keys keys{},expected{};
  scalar[31]=2;assert(exchange.begin(points,scalar,32,station,ap,7,100,200,ie,37));
  assert(exchange.active() && !memcmp(ie+5,twice,32));
  assert(AthSecurity::encodeOWEGroup19Parameter(gx,32,reply,37));
  assert(AthSecurity::deriveOWEGroup19Keys<OWECrypto>(twice,32,gx,32,twice,32,expected));
  assert(exchange.finish<OWECrypto>(points,field,reply,37,station,ap,7,150,keys));
  assert(!exchange.active() && !memcmp(&keys,&expected,sizeof(keys)));
  assert(!exchange.finish<OWECrypto>(points,field,reply,37,station,ap,7,151,keys));
  for(unsigned scenario=0;scenario<7;++scenario){
   assert(exchange.begin(points,scalar,32,station,ap,7,100,200,ie,37));
   if(scenario==0)exchange.clear();
   assert(!exchange.finish<OWECrypto>(points,field,reply,scenario==6?36:37,
    scenario==1?ap:station,scenario==2?station:ap,scenario==3?8:7,
    scenario==4?99:scenario==5?200:150,keys));
   assert(!exchange.active() && !memcmp(&keys,&expected,sizeof(keys)));
  }
  scalar[31]=1;
  auto broken=points;broken.validatePoint=[](void *){return false;};rejected(broken,field,gx,32,32);
  auto brokenField=field;brokenField.multiply=[](const void *,uint64_t *,const uint64_t *,const uint64_t *){return -1;};rejected(points,brokenField,gx,32,32);
 }
 // Production two-stage OWE item through the retained worker, including
 // cancellation while crypto is running. No result escapes a retired owner.
 {
  auto queue=new Ath10kSAEWorker;assert(queue->init());auto callback=latest;
  uint8_t sta[6]={2,1,2,3,4,5},ap[6]={2,6,7,8,9,10},request[37],nonce[32];
  for(unsigned scenario=0;scenario<7;++scenario){
   auto job=new Ath10kNativeOWEJob;ownerGate=true;
   assert(job->initExchange(points,field,sta,ap,9,100));assert(queue->submit(job));ownerGate=false;
   if(scenario==0){ownerGate=true;assert(queue->cancelFor(job));ownerGate=false;job->release();assert(objects==1);continue;}
   if(scenario==1){Pause pause;pauseCurve=&pause;std::thread runner([&]{run(callback);});pause.wait();
    ownerGate=true;assert(queue->cancelFor(job));job->release();ownerGate=false;
    pause.resume();runner.join();pauseCurve=nullptr;assert(!queue->takeCompleted() && objects==1);continue;}
   run(callback);auto completed=queue->takeCompletedFor(job);assert(completed==job);completed->release();
   ownerGate=true;
   assert(job->takeRequest(sta,ap,9,110,request,37));assert(!job->takeRequest(sta,ap,9,110,request,37));
   // Synthetic AP echoes a valid point; this is lifecycle evidence, not a radio peer.
   assert(job->setPeer(request,37,sta,ap,9,120));assert(!job->setPeer(request,37,sta,ap,9,120));
   assert(queue->submit(job));ownerGate=false;
   if(scenario==2){ownerGate=true;assert(queue->cancelFor(job));ownerGate=false;job->release();assert(objects==1);continue;}
   if(scenario==3){Pause pause;pauseCurve=&pause;std::thread runner([&]{run(callback);});pause.wait();
    ownerGate=true;assert(queue->cancelFor(job));job->release();ownerGate=false;
    pause.resume();runner.join();pauseCurve=nullptr;assert(!queue->takeCompleted() && objects==1);continue;}
   run(callback);completed=queue->takeCompletedFor(job);assert(completed==job);completed->release();
   AthSecurity::OWEGroup19Keys result;memset(&result,0xa5,sizeof(result));memset(nonce,0xa5,32);ownerGate=true;
   assert(job->takeKeys(sta,ap,scenario==4?10:9,scenario==5?5100:130,result,nonce)==(scenario==6));
   assert(!job->takeKeys(sta,ap,9,131,result,nonce));ownerGate=false;
   if(scenario!=6){for(auto b:result.pmk)assert(b==0xa5);for(auto b:nonce)assert(b==0xa5);}
   job->release();assert(objects==1);
  }
  queue->shutdown();queue->release();assert(objects==0);
 }
 // Controller admission through preparation, association wait and key handoff.
 Ath10kNativeSAEKernelBackend::points=points;Ath10kNativeSAEKernelBackend::field=field;
 for(unsigned scenario=0;scenario<4;++scenario){
  Ath10kPCIDevice device;auto &sec=device.security;auto &state=device._connection;
  assert(AthSecurity::buildOWEStationRSN(state.ap.rsn,28,state.ap.rsnLength));
  sec.saeWorker=new Ath10kSAEWorker;assert(sec.saeWorker->init());auto callback=latest;const char *error=nullptr;
  ownerGate=true;assert(!device.serviceNativeOWE(100,error) && !error);ownerGate=false;
  run(callback);ownerGate=true;assert(device.serviceNativeOWE(110,error) && !error && state.oweRequestReady && !sec.ready);
  state.stage=Ath10k::LinkStage::Assoc;assert(device.serviceNativeOWE(120,error) && !error && !sec.ready);
  state.assocReply=state.oweResponseReady=true;memcpy(state.oweResponse,state.oweRequest,37);
  assert(!device.serviceNativeOWE(130,error) && !error);ownerGate=false;
  run(callback);ownerGate=true;
  if(scenario==1)state.bssid[5]^=1;if(scenario==2)state.cancelRequested=true;
  const bool accepted=device.serviceNativeOWE(scenario==3?5100:140,error);
  assert(accepted==(scenario==0) && sec.ready==(scenario==0));assert(bool(error)==(scenario!=0));
  if(scenario==0){assert(sec.owePhase==4 && !sec.oweJob);assert(device.serviceNativeOWE(150,error));}
  if(sec.oweJob){sec.saeWorker->cancelFor(sec.oweJob);sec.oweJob->release();sec.oweJob=nullptr;}
  ownerGate=false;sec.saeWorker->shutdown();sec.saeWorker->release();assert(objects==0);
 }
 auto workspace=new AthSecurity::P256BackendCheckWorkspace;Report report;
 assert(AthSecurity::checkP256Backend(points,field,*workspace,report));
 assert(report.complete && report.step==Step::Passed && report.passed==0x7ff && zero(workspace,sizeof(*workspace)));
 auto badField=field;badField.multiply=[](const void *,uint64_t *out,const uint64_t *,const uint64_t *){memset(out,0,32);return 0;};
 assert(!AthSecurity::checkP256Backend(points,badField,*workspace,report));
 assert(!report.complete && report.step==Step::FieldMultiply && !report.passed && zero(workspace,sizeof(*workspace)));
 auto badPoints=points;badPoints.validatePoint=[](void *){return false;};
 assert(!AthSecurity::checkP256Backend(badPoints,field,*workspace,report));
 assert(!report.complete && report.step==Step::PointValidate && report.passed==0x3f && zero(workspace,sizeof(*workspace)));
 delete workspace;
 auto worker=new Ath10kSAEWorker;assert(worker->init());auto call=latest;
 for(unsigned scenario=0;scenario<6;++scenario){
  auto job=new Ath10kP256CheckJob;const auto before=curveCalls;ownerGate=true;
  assert(job->initCheck(points,scenario==1?badField:field,31,1000));assert(curveCalls==before);
  Report output;output.complete=true;assert(!job->takeReport(31,1001,output) && !output.complete);
  assert(worker->submit(job));ownerGate=false;job->release();
  if(scenario==2){ownerGate=true;assert(worker->cancelFor(job));ownerGate=false;assert(!worker->takeCompleted() && objects==1);continue;}
  run(call);auto item=worker->takeCompletedFor(job);assert(item==job);const auto after=curveCalls;
  job->execute();assert(curveCalls==after);
  ownerGate=true;const bool collected=job->takeReport(scenario==3?32:31,scenario==4?6000:(scenario==5?999:1001),output);ownerGate=false;
  assert(curveCalls==after);
  if(scenario>=3)assert(!collected && !output.complete && output.step==Step::None && !output.passed);
  else if(scenario==1)assert(collected && !output.complete && output.step==Step::FieldMultiply && !output.passed);
  else assert(collected && output.complete && output.step==Step::Passed && output.passed==0x7ff);
  assert(!job->takeReport(31,1001,output) && !output.complete);job->release();assert(objects==1);
 }
 {auto job=new Ath10kP256CheckJob;auto missing=points;missing.curve=nullptr;
  assert(!job->initCheck(missing,field,31,1000));assert(!job->initCheck(points,field,0,1000));
  assert(!job->initCheck(points,field,31,~uint64_t(0)));job->discard();assert(!job->initCheck(points,field,31,1000));job->release();assert(objects==1);}
 {auto job=new Ath10kP256CheckJob;assert(job->initCheck(points,field,32,1000));assert(worker->submit(job));job->release();
  Pause pause;pauseCurve=&pause;std::thread runner([&]{run(call);});pause.wait();
  ownerGate=true;assert(worker->cancelFor(job));ownerGate=false;assert(!worker->takeCompleted());
  pause.resume();runner.join();pauseCurve=nullptr;assert(!worker->takeCompleted() && objects==1);}
 // Profile admission is intentionally limited to the known device/kernel.
 const char *kernel="Darwin Kernel Version 24.6.0: test; root:xnu-11417.140.69~1/RELEASE_X86_64";
 assert(AthSecurity::p256DiagnosticKernel(24,6,0,"24G90",kernel));
 assert(AthSecurity::p256DiagnosticKernel(24,6,0,"24G90",(std::string(kernel)+"\n").c_str()));
 assert(!AthSecurity::p256DiagnosticKernel(25,6,0,"24G90",kernel));
 assert(!AthSecurity::p256DiagnosticKernel(24,6,0,"24G91",kernel));
 assert(!AthSecurity::p256DiagnosticKernel(24,6,0,"24G90","short"));
 assert(!AthSecurity::p256DiagnosticKernel(24,6,0,"24G90",(std::string(kernel)+" extra").c_str()));
 assert(!AthSecurity::p256DiagnosticKernel(24,6,0,nullptr,kernel));
 assert(AthSecurity::p256DiagnosticDevice(0x168c,0x42,0x1a3b,0x2b51));
 assert(!AthSecurity::p256DiagnosticDevice(0x168c,0x43,0x1a3b,0x2b51));
 for(unsigned i=0;i<100;++i){
  AthSecurity::P256DiagnosticPublication token;bool cancelled=false,writing=false;
  std::thread a([&]{cancelled=token.cancel();}),b([&]{writing=token.beginReport();});a.join();b.join();
  assert(cancelled!=writing);assert(token.finishReport()==writing);assert(!token.cancel() && !token.beginReport());
 }
 for(unsigned scenario=0;scenario<7;++scenario){
  auto target=new IOService;auto job=new Ath10kP256RegistryJob;clockReads=0;
  timesNS[0]=1000000;timesNS[1]=2000000;timesNS[2]=scenario==2?5001000000ull:(scenario==3?1500000:3000000);
  const auto before=curveCalls;ownerGate=true;
  assert(job->initReport(points,scenario==1?badField:field,target,testClock,77));
  assert(curveCalls==before && target->writes.empty());assert(worker->submit(job));ownerGate=false;
  if(scenario==4){
   assert(job->cancelReport());target->setProperty("Ath10kP256CheckState","cancelled");assert(worker->cancelFor(job));assert(!worker->takeCompleted());
  }else if(scenario==5 || scenario==6){
   Pause pause;if(scenario==5)pauseCurve=&pause;else pauseWrites=&pause;
   std::thread runner([&]{run(call);});pause.wait();ownerGate=true;
   const bool won=job->cancelReport();assert(won==(scenario==5));
   if(won)target->setProperty("Ath10kP256CheckState","cancelled");assert(worker->cancelFor(job));ownerGate=false;
   pause.resume();runner.join();pauseCurve=pauseWrites=nullptr;assert(!worker->takeCompleted());
  }else {run(call);auto done=worker->takeCompletedFor(job);assert(done==job);done->release();}
  const auto writes=target->writes.size();job->execute();assert(target->writes.size()==writes);
  if(scenario==4 || scenario==5){assert(target->strings["Ath10kP256CheckState"]=="cancelled" && writes==1);}
  else {
   const char *state=scenario==1?"failed":(scenario==2?"expired":(scenario==3?"clock-error":"passed"));
   assert(target->strings["Ath10kP256CheckState"]==state);
   assert(target->numbers["Ath10kP256CheckPassed"]==uint64_t(scenario==0 || scenario==6));
   assert(target->numbers["Ath10kP256CheckEpoch"]==77 && target->writes.back()=="Ath10kP256CheckState");
   if(scenario==0 || scenario==6)assert(target->numbers["Ath10kP256CheckMask"]==0x7ff && target->numbers["Ath10kP256CheckElapsedNS"]==1000000);
  }
  job->release();target->release();assert(objects==1);
 }
 // Boot identity admission must precede all crypto; waiting for identity must
 // not consume the five-second crypto deadline or renew it after execution.
 for(unsigned scenario=0;scenario<5;++scenario){
  auto target=new IOService;auto job=new Ath10kP256RegistryJob;clockReads=0;admissionCalls=0;
  timesNS[0]=1000000;timesNS[1]=20000000000ull;timesNS[2]=20001000000ull;timesNS[3]=20002000000ull;
  if(scenario==4)timesNS[1]=0;
  nextAdmission=scenario==1?Ath10kP256RegistryJob::Admission::Rejected:
      scenario==2?Ath10kP256RegistryJob::Admission::TimedOut:
      scenario==3?Ath10kP256RegistryJob::Admission::Cancelled:Ath10kP256RegistryJob::Admission::Ready;
  const auto before=curveCalls;
  assert(job->initReport(points,field,target,testClock,88,testAdmission));assert(curveCalls==before);
  assert(worker->submit(job));run(call);auto done=worker->takeCompletedFor(job);assert(done==job);done->release();
  assert(admissionCalls==1);
  const char *state=scenario==0?"passed":scenario==1?"unsupported-kernel":scenario==2?"build-unavailable":scenario==3?"cancelled":"admission-clock-error";
  assert(target->strings["Ath10kP256CheckState"]==state);
  assert(target->numbers["Ath10kP256CheckPassed"]==uint64_t(scenario==0));
  assert(target->writes.back()=="Ath10kP256CheckState");
  if(scenario==0){assert(curveCalls>before && target->numbers["Ath10kP256CheckMask"]==0x7ff);}
  else assert(curveCalls==before);
  job->release();target->release();assert(objects==1);
 }
 worker->shutdown();worker->release();assert(!objects && !locks && !calls && !sleeps);dlclose(lib);
}

#include "mock_sae_worker.hpp"
#define ATH10K_P256_DIAGNOSTIC_BINDING 1
#define ATH10K_P256_SYMBOLS_TEST 1
#include "../src/kext/native/Ath10kP256KernelBinding.hpp"
#include "../src/shared/Ath10kP256BackendCheck.hpp"
#include <dlfcn.h>
#include <map>
#include <string>
#include <vector>
#include "../src/shared/Ath10kP256DiagnosticPolicy.hpp"
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
static uint64_t timesNS[3]={};static unsigned clockReads=0;
static uint64_t testClock(){assert(clockReads<3);return timesNS[clockReads++];}
static Pause *pauseCurve=nullptr;
static const void *curve(){assert(!ownerGate && !heldLocks);++curveCalls;if(pauseCurve)pauseCurve->pause();return realCurve();}
static bool zero(const void *object,size_t bytes){auto p=static_cast<const uint8_t *>(object);uint8_t value=0;for(size_t i=0;i<bytes;++i)value|=p[i];return value==0;}
int main(){
 void *lib=dlopen("/usr/lib/system/libcorecrypto.dylib",RTLD_NOW|RTLD_LOCAL);assert(lib);
 using namespace Ath10kP256KernelSymbols;
#define SYMBOL(name) name=reinterpret_cast<decltype(name)>(dlsym(lib,#name));assert(name)
 SYMBOL(ccec_cp_256);SYMBOL(ccec_x963_import_pub);SYMBOL(ccec_validate_pub);SYMBOL(ccec_x963_export);
 SYMBOL(ccec_projectify);SYMBOL(ccec_affinify);SYMBOL(ccec_mult_blinded);SYMBOL(ccec_full_add);SYMBOL(ccec_full_sub);
 SYMBOL(ccn_read_uint);SYMBOL(ccrng);SYMBOL(cczp_n);SYMBOL(cczp_prime);SYMBOL(cczp_mul);SYMBOL(cczp_inv);SYMBOL(cczp_add);SYMBOL(cczp_sub);
#undef SYMBOL
 realCurve=ccec_cp_256;ccec_cp_256=curve;
 ownerGate=true;const auto points=Ath10kP256KernelBinding::points();const auto field=Ath10kP256KernelBinding::field();ownerGate=false;
 assert(!curveCalls && points.complete() && points.curve==curve && field.curve==curve);
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
 worker->shutdown();worker->release();assert(!objects && !locks && !calls && !sleeps);dlclose(lib);
}

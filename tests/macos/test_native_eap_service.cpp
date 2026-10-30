#include <cassert>
#include <initializer_list>
#include <cstring>
#include <cstdint>
#include "../../src/macos/native/Ath10kNativeEAPOwner.hpp"
using UInt64=uint64_t;using UInt8=uint8_t;
struct Ath10kKernelCrypto {static bool fail;static bool random(UInt8 *p,size_t n){memset(p,0x42,n);return !fail;}};
bool Ath10kKernelCrypto::fail=false;
namespace Ath10k {
struct State {
 UInt64 sinceMs=0;struct {UInt8 rsn[32]{},rsnxe[32]{};unsigned rsnLength=0,rsnxeLength=0;} ap;unsigned securityAKM=1;bool associated=true,cancelRequested=false,portAuthorized=false;
 const char *error=nullptr;uint8_t local[6]={2,1,2,3,4,5},bssid[6]={2,6,7,8,9,10};
 bool txOwned=false,dataPending=false,wmiOwned=false,submitted=false,rekeyKind=false,eapolPause=false;
 unsigned txPauseMask=0;
 struct {unsigned step=0;} maintenance;
 struct {bool blocked=false,powerBlocked=false,appliedPS=false;} radio;
 struct {bool blocked=false;} csa;
 struct Completion {bool complete=false;unsigned status=0;void clear(){complete=false;status=0;}} eapolCompletion;
};
bool connectionAssociated(const State &s){return s.associated;}
}
struct Security {
 AthNative::EAPOwner eapOwner;bool ready=false;bool eapTXInFlight=false,replyPending=false,keysPending=false,authorizePending=false,ptkUpdatePending=false;
 struct {bool pending=false,fail=false;unsigned begins=0,resets=0;bool pairwisePending(){return pending;}
 bool begin(const UInt8 *pmk,const UInt8 *nonce,const UInt8*,const UInt8*,const UInt8*,unsigned,unsigned akm){++begins;assert(pmk[0]==7 && nonce[0]==0x42 && akm==1);return !fail;}
 bool bindRSNXE(const UInt8*,unsigned,bool){return !fail;}void reset(){++resets;}
 } supplicant;
};
struct Ath10kPCIDevice {
 Security security;Security *_nativeSecurity=&security;Ath10k::State _connection;
 struct {bool completed=true,cancelRequested=false;} _wmiScan;
 bool _nativeEAPQueueRunning=false,_networkEnabled=true,_networkLinkUp=false;
 struct {bool active=true;} _wmiLive;
 bool powerBlocked=false;bool powerIOBlocked(){return powerBlocked;}
 void nativeSetEAPQueue(bool);
 struct Queue {unsigned calls=0,starts=0,stops=0,flushes=0;void service(int){++calls;}
 void start(){++starts;}void stop(){++stops;}void flush(){++flushes;}} queue;
 unsigned submits=0;const char *submitError=nullptr;
 Queue *getOutputQueue(){return &queue;}
 const char *submitNetworkPacket(const uint8_t *frame,size_t n,bool,UInt64){assert(n==18 && frame[15]==1);++submits;return submitError;}
 bool nativeEAPWaiting() const;
 const char *serviceEAPDeadline(UInt64);
 void serviceNativeEAP(UInt64 now);
 void begin(){assert(security.eapOwner.begin(_connection.local,_connection.bssid,100,20000));}
 void enqueue(UInt64 now=100){uint8_t f[18]{};memcpy(f,_connection.bssid,6);memcpy(f+6,_connection.local,6);f[12]=0x88;f[13]=0x8e;f[14]=2;f[15]=1;
 assert(security.eapOwner.enqueuePacket(security.eapOwner.generation(),_connection.local,_connection.bssid,f,sizeof(f),now)==AthNative::EAPOwner::Enqueue::Queued);}
};
#include "native_eap_queue.inc"
#include "native_eap_service.inc"
#include "native_eap_timeout.inc"
int main(){
 for(unsigned retired=0;retired<4;++retired)for(bool authorized:{false,true}){
  Ath10kPCIDevice d;d.begin();d.serviceNativeEAP(101);assert(d._nativeEAPQueueRunning);
  d._networkLinkUp=authorized;
  if(retired==0)d.security.eapOwner.clear();
  if(retired==1)d._nativeSecurity=nullptr;
  if(retired==2)d._connection.associated=false;
  if(retired==3)d._connection.securityAKM=8;
  d.serviceNativeEAP(102);assert(!d._nativeEAPQueueRunning);
  assert(d.queue.stops==unsigned(!authorized) && d.queue.flushes==unsigned(!authorized));
  d.serviceNativeEAP(103);assert(d.queue.stops==unsigned(!authorized));
 }

 {Ath10kPCIDevice d;d.begin();d.serviceNativeEAP(101);
  assert(d._nativeEAPQueueRunning && d.queue.starts==1 && !d._networkLinkUp);
  d.serviceNativeEAP(102);assert(d.queue.starts==1);
  d.nativeSetEAPQueue(false);assert(!d._nativeEAPQueueRunning && d.queue.stops==1 && d.queue.flushes==1);
  d.nativeSetEAPQueue(false);assert(d.queue.stops==1);
  d._networkLinkUp=true;d.nativeSetEAPQueue(true);d.nativeSetEAPQueue(false);
  assert(d.queue.starts==1 && d.queue.stops==1); // Data queue ownership survives.
 }
 for(unsigned block=0;block<3;++block){Ath10kPCIDevice d;
  if(block==0)d._networkEnabled=false;if(block==1)d._wmiLive.active=false;if(block==2)d.powerBlocked=true;
  d.begin();d.enqueue();d.serviceNativeEAP(101);
  assert(!d._nativeEAPQueueRunning && !d.queue.starts && !d.submits && d.security.eapOwner.pending());
  d.serviceNativeEAP(20000);assert(d._connection.cancelRequested && !d.security.eapOwner.generation());
 }

 {Ath10kPCIDevice d;d.begin();
  // The ordinary handshake clock cannot expire while the EAP owner is
  // legitimately waiting; the owner's independent budget still must expire.
  d.serviceEAPDeadline(15100);assert(!d._connection.cancelRequested && d.nativeEAPWaiting());
  d.serviceNativeEAP(19999);assert(!d._connection.cancelRequested);
  d.serviceNativeEAP(20000);assert(d._connection.cancelRequested && !d.nativeEAPWaiting());
 }
 {Ath10kPCIDevice d;d.begin();UInt8 key[32]{};key[0]=7;
  assert(d.security.eapOwner.setMSK(d.security.eapOwner.generation(),d._connection.local,d._connection.bssid,9,key,32,19000)==AthNative::EAPOwner::KeyResult::Accepted);
  d.serviceNativeEAP(19001);assert(d.security.ready && !d.nativeEAPWaiting());
  d.serviceEAPDeadline(34000);assert(!d._connection.cancelRequested);
  d.serviceEAPDeadline(34001);assert(d._connection.cancelRequested);
 }
 {Ath10kPCIDevice d;d.begin();d._connection.securityAKM=8;
  d.serviceEAPDeadline(15000);assert(d._connection.cancelRequested && !d.nativeEAPWaiting());
 }

 for(unsigned failure=0;failure<3;++failure){Ath10kPCIDevice d;d.begin();UInt8 key[32]{};key[0]=7;
 assert(d.security.eapOwner.setMSK(d.security.eapOwner.generation(),d._connection.local,d._connection.bssid,9,key,32,101)==AthNative::EAPOwner::KeyResult::Accepted);
 Ath10kKernelCrypto::fail=failure==1;d.security.supplicant.fail=failure==2;
 d.serviceNativeEAP(102);assert(d.security.ready==(failure==0));assert(d._connection.cancelRequested==(failure!=0));
 if(!failure){assert(d._connection.sinceMs==102);d.serviceNativeEAP(103);assert(d.security.supplicant.begins==1 && d._connection.sinceMs==102);}
 else assert(d.security.supplicant.resets==1);
 Ath10kKernelCrypto::fail=false;}

 {Ath10kPCIDevice d;d.begin();d.enqueue();d._wmiScan.completed=false;d.serviceNativeEAP(101);assert(d._wmiScan.cancelRequested && !d.submits && d._connection.eapolPause);
 d._wmiScan.completed=true;d._connection.radio.appliedPS=true;d.serviceNativeEAP(102);assert(!d.submits);
 d._connection.radio.appliedPS=false;d.serviceNativeEAP(103);assert(d.submits==1 && d.security.eapTXInFlight && !d.security.eapOwner.pending() && d.queue.calls==1);
 d.enqueue(104);d.serviceNativeEAP(105);assert(d.submits==1);
 d._connection.eapolCompletion.complete=true;d.serviceNativeEAP(106);assert(d.submits==2 && d.security.eapTXInFlight);
 d._connection.eapolCompletion.complete=true;d.serviceNativeEAP(107);assert(!d.security.eapTXInFlight && !d._connection.eapolPause && !d._connection.cancelRequested);}
 {Ath10kPCIDevice d;d.begin();d.enqueue();d.serviceNativeEAP(101);d._connection.eapolCompletion.complete=true;d._connection.eapolCompletion.status=1;d.serviceNativeEAP(102);assert(d._connection.cancelRequested && !strcmp(d._connection.error,"native-eap-tx-failed"));}
 for(bool reverse:{false,true}){Ath10kPCIDevice d;d.begin();d.enqueue(200);d._connection.txOwned=true;d.serviceNativeEAP(5199);assert(!d._connection.cancelRequested);d.serviceNativeEAP(reverse?199:5200);assert(d._connection.cancelRequested && !strcmp(d._connection.error,"native-eap-queue-timeout"));}
 {Ath10kPCIDevice d;d.begin();d.serviceNativeEAP(20000);assert(d._connection.cancelRequested && !d.security.eapOwner.generation());}
 {Ath10kPCIDevice d;d.begin();d.enqueue();d.submitError="submit-failed";d.serviceNativeEAP(101);assert(d._connection.cancelRequested && d.security.eapOwner.pending() && !d.security.eapTXInFlight);}
 {Ath10kPCIDevice d;d.begin();d.enqueue();d._connection.securityAKM=8;d.serviceNativeEAP(101);assert(!d.submits && !d._connection.cancelRequested);}
}

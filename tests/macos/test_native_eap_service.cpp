#include <cassert>
#include <initializer_list>
#include <cstring>
#include <cstdint>
#include "../../src/macos/native/Ath10kNativeEAPOwner.hpp"
#include "../../src/security/Ath10kTKIPMICOwner.hpp"
#include "../../src/macos/native/Ath10kNativeKeyStart.hpp"
using UInt64=uint64_t;using UInt8=uint8_t;
struct Ath10kKernelCrypto {static bool fail;static bool random(UInt8 *p,size_t n){memset(p,0x42,n);return !fail;}};
bool Ath10kKernelCrypto::fail=false;
namespace Ath10k {
struct State {
 UInt64 sinceMs=0;struct {UInt8 rsn[32]{48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,1,0,0},rsnxe[32]{},wpa[32]{};unsigned rsnLength=22,rsnxeLength=0,wpaLength=0;} ap;unsigned securityAKM=1,securityPhase=0;bool secure=true,pmfRequired=false,wpa1Selected=false;uint8_t pairCipher=4,groupCipher=4;bool associated=true,cancelRequested=false,portAuthorized=false;
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
 AthSecurity::TKIPMICOwner tkipMICOwner;bool tkipDeauthPending=false,tkipDeauthInFlight=false;UInt64 tkipDeauthDeadline=0;bool tkipMICInFlight=false;
 AthNative::EAPOwner eapOwner;bool ready=false;bool eapTXInFlight=false,replyPending=false,keysPending=false,authorizePending=false,ptkUpdatePending=false;
 struct {bool pending=false,fail=false;unsigned begins=0,resets=0,replacements=0;bool pairwisePending(){return pending;}
 bool begin(const UInt8 *pmk,const UInt8 *nonce,const UInt8*,const UInt8*,const UInt8*,unsigned,unsigned akm,const UInt8*,size_t,UInt8 pair){assert(pair==4);++begins;assert(pmk[0]==7 && nonce[0]==0x42 && akm==1);return !fail;}
 bool beginWPA1(const UInt8*,const UInt8*,const UInt8*,const UInt8*,const UInt8*,size_t,uint8_t,uint8_t){assert(false);return false;}
 bool replaceEAPMaster(const UInt8 *pmk,const UInt8*,const UInt8*){++replacements;assert(pmk[0]==7);return !fail;}
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
 for(bool linkUp:{false,true}){
  Ath10kPCIDevice d;auto &s=d._connection;auto &owner=d.security.eapOwner;
  uint8_t key[13]{};assert(owner.beginStaticWEP(s.local,s.bssid,100,1000,key,13,2));
  s.eapolPause=true;d._networkLinkUp=linkUp;d._nativeEAPQueueRunning=true;
  d.serviceNativeEAP(101);
  assert(!d._nativeEAPQueueRunning && !d.queue.starts && !d.submits);
  assert(d.queue.stops==unsigned(!linkUp) && d.queue.flushes==unsigned(!linkUp));
  assert(owner.keyPending() && s.eapolPause && !s.cancelRequested && !d.security.supplicant.begins);
  d.serviceNativeEAP(102);assert(d.queue.stops==unsigned(!linkUp));
  d.serviceNativeEAP(1000);assert(s.cancelRequested && !owner.generation() && !s.portAuthorized);
 }
 // Key-only ownership must pause ordinary traffic and cancel scanning while
 // still allowing system EAP packets and their completion to drain.
 {Ath10kPCIDevice d;auto &s=d._connection;auto &owner=d.security.eapOwner;
  assert(owner.beginDynamicWEP(s.local,s.bssid,100,1000));
  uint8_t key[148]{};key[0]=1;key[4]=5;key[8]=1;key[12]=5;key[16]=7;
  assert(owner.setWEPKey(owner.generation(),s.local,s.bssid,key,sizeof(key),101)==AthNative::EAPOwner::KeyResult::Accepted);
  assert(owner.pending() && owner.keyPending());
  size_t bytes=99;UInt64 since=99;assert(!owner.front(bytes,since) && !bytes && !since);
  d._wmiScan.completed=false;d.serviceNativeEAP(102);
  assert(d._wmiScan.cancelRequested && s.eapolPause && !d.submits && !s.portAuthorized);
  d._wmiScan.completed=true;d.enqueue(103);d.serviceNativeEAP(104);
  assert(d.submits==1 && d.security.eapTXInFlight && owner.keyPending());
  s.eapolCompletion.complete=true;d.serviceNativeEAP(105);
  assert(!d.security.eapTXInFlight && s.eapolPause && owner.pending());
  assert(!d.security.supplicant.begins && !d.security.supplicant.replacements);
  d.serviceNativeEAP(1000);
  assert(s.cancelRequested && !s.portAuthorized && !owner.pending() && !owner.keyPending());
 }

 {Ath10kPCIDevice d;d.begin();d.enqueue();auto &sec=d.security;
  assert(sec.tkipMICOwner.begin(7,0));
  assert(sec.tkipMICOwner.detect({7,1,1,0,16},100)==AthSecurity::TKIPMICOwner::Detection::Report);
  d.serviceNativeEAP(101);assert(!d.submits && sec.eapOwner.pending() && d._connection.eapolPause);
  // Existing EAP receipt must still drain, otherwise MIC and EAP deadlock.
  sec.eapTXInFlight=true;d._connection.eapolCompletion.complete=true;
  d.serviceNativeEAP(102);assert(!sec.eapTXInFlight && !d.submits && sec.eapOwner.pending());
  sec.tkipMICOwner.retire();d.serviceNativeEAP(103);assert(d.submits==1);
 }

 {Ath10kPCIDevice d;d.begin();auto &s=d._connection;auto &sec=d.security;UInt8 key[32]{};key[0]=7;
  auto g=sec.eapOwner.generation();assert(sec.eapOwner.setMSK(g,s.local,s.bssid,9,key,32,101)==AthNative::EAPOwner::KeyResult::Accepted);
  d.serviceNativeEAP(102);d.enqueue(103);
  assert(sec.eapOwner.beginReplacement(g,s.local,s.bssid,104,1000));g=sec.eapOwner.generation();
  assert(sec.eapOwner.setMSK(g,s.local,s.bssid,9,key,32,105)==AthNative::EAPOwner::KeyResult::Accepted);
  d.serviceNativeEAP(106);assert(d.submits==1 && sec.eapTXInFlight && !sec.supplicant.replacements);
  s.eapolCompletion.complete=true;d.serviceNativeEAP(107);
  assert(!sec.eapTXInFlight && !sec.supplicant.replacements);
  d.serviceNativeEAP(108);assert(sec.supplicant.replacements==1 && sec.eapOwner.replacementKeyReady());
 }

 for(unsigned block=0;block<12;++block){
  Ath10kPCIDevice d;d.begin();auto &s=d._connection;auto &sec=d.security;UInt8 key[32]{};key[0]=7;
  auto g=sec.eapOwner.generation();assert(sec.eapOwner.setMSK(g,s.local,s.bssid,9,key,32,101)==AthNative::EAPOwner::KeyResult::Accepted);
  d.serviceNativeEAP(102);assert(sec.ready);
  assert(sec.eapOwner.beginReplacement(g,s.local,s.bssid,103,1000));g=sec.eapOwner.generation();
  assert(sec.eapOwner.setMSK(g,s.local,s.bssid,9,key,32,104)==AthNative::EAPOwner::KeyResult::Accepted);
  bool *guards[]={&sec.eapTXInFlight,&sec.replyPending,&sec.keysPending,&sec.authorizePending,&sec.ptkUpdatePending,&sec.supplicant.pending,&s.txOwned,&s.dataPending,&s.wmiOwned,&s.submitted,&s.rekeyKind,&sec.tkipMICInFlight};
  *guards[block]=true;d.serviceNativeEAP(105);assert(sec.supplicant.replacements==0);
  *guards[block]=false;d.serviceNativeEAP(106);assert(sec.supplicant.replacements==1 && sec.supplicant.begins==1 && !sec.supplicant.resets);
  d.serviceNativeEAP(107);assert(sec.supplicant.replacements==1 && sec.eapOwner.replacementPending());
  d.serviceNativeEAP(1000);assert(s.cancelRequested && !sec.eapOwner.generation());
 }

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

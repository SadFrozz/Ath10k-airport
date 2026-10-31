#include <cassert>
#include <initializer_list>
#include <cstring>
#include <strings.h>
#include "../../src/macos/native/Ath10kNativeEAPOwner.hpp"
using UInt8=uint8_t;using UInt64=uint64_t;using IOReturn=int;
constexpr int kIOReturnSuccess=0,kIOReturnBadArgument=1,kIOReturnUnsupported=2,kIOReturnNotReady=3,kIOReturnBusy=4;
struct apple80211_key {
 uint32_t version=1,key_len=32,key_cipher_type=9;uint16_t key_flags=0,key_index=0;
 uint8_t key[64]{};uint32_t key_rsc_len=0;uint8_t key_rsc[8]{},key_ea[6]{};
 uint32_t wowl_kck_len=0;uint8_t wowl_kck_key[16]{};uint32_t wowl_kek_len=0;uint8_t wowl_kek_key[24]{};
};
namespace Ath10k {
 uint64_t clockMS=100;
 uint64_t uptimeNS(){return clockMS*1000000;}
 template<class S> bool connectionAssociated(const S &s){return s.associated && !s.cancelRequested;}
}
struct Ath10kPCIDevice {
 struct Security {AthNative::EAPOwner eapOwner;
 bool ready=false,eapTXInFlight=false,replyPending=false,keysPending=false,authorizePending=false,ptkUpdatePending=false;
 struct {bool pending=false;bool pairwisePending(){return pending;}} supplicant;
 } security;
 Security *_nativeSecurity=&security;
 struct State {const char *error=nullptr;unsigned securityAKM=1,securityPhase=0,rekeyKind=0;bool txOwned=false,dataPending=false,wmiOwned=false,submitted=false;bool associated=true,cancelRequested=false,portAuthorized=false,eapolPause=false;
   uint8_t local[6]={2,1,2,3,4,5},bssid[6]={2,6,7,8,9,10};} _connection;
 unsigned scheduled=0,discarded=0;
 void requestNativeService(){++scheduled;}
 void discardNativeSecurity(){++discarded;security.eapOwner.clear();}
 IOReturn nativeSetCipherKey(void *);
};
#include "native_eap_callback.inc"
int main(){
 using K=AthNative::EAPOwner::KeyResult;
 for(unsigned length:{5u,13u}){
  Ath10kPCIDevice d;auto &state=d._connection;auto &owner=d.security.eapOwner;
  assert(owner.beginDynamicWEP(state.local,state.bssid,0,1000));const auto generation=owner.generation();
  apple80211_key request{};request.key_len=length;request.key_cipher_type=length==5?1:2;
  for(unsigned i=0;i<length;++i)request.key[i]=uint8_t(i+1);
  for(unsigned index=0;index<4;++index)for(unsigned flags:{2u,5u}){
   request.key_index=index;request.key_flags=flags;
   auto copy=request;assert(d.nativeSetCipherKey(&request)==kIOReturnSuccess);
   assert(!memcmp(&copy,&request,sizeof(request)) && !state.portAuthorized);
  }
  assert(d.scheduled==8 && d.nativeSetCipherKey(&request)==kIOReturnSuccess && d.scheduled==8);
  request.key[0]^=1;assert(d.nativeSetCipherKey(&request)==kIOReturnBusy);request.key[0]^=1;
  uint64_t lastTicket=0;
  for(unsigned index=0;index<4;++index)for(unsigned flags:{2u,5u}){
   const auto *key=owner.frontWEPKey(generation,state.local,state.bssid,100);assert(key);
   assert(key->index==index && key->flags==flags && key->length==length && !memcmp(key->key,request.key,length));
   assert(key->ticket>lastTicket);lastTicket=key->ticket;
   assert(!owner.finishWEPKey(generation+1,state.local,state.bssid,lastTicket,100));
   assert(!owner.finishWEPKey(generation,state.local,state.bssid,lastTicket+1,100));
   assert(owner.finishWEPKey(generation,state.local,state.bssid,lastTicket,100));
   for(auto value:key->key)assert(!value);assert(!key->ticket);
  }
  assert(!owner.frontWEPKey(generation,state.local,state.bssid,100));
  assert(d.nativeSetCipherKey(&request)==kIOReturnSuccess && d.scheduled==8);
  assert(!owner.frontWEPKey(generation,state.local,state.bssid,100));
  const auto *installed=owner.installedWEPKey(generation,state.local,state.bssid,3,false,100);
  assert(installed && installed->length==length && !memcmp(installed->key,request.key,length));
  assert(!owner.installedWEPKey(generation+1,state.local,state.bssid,3,false,100));
  assert(!owner.installedWEPKey(generation,state.local,state.bssid,4,false,100));
  request.key[0]^=1;assert(d.nativeSetCipherKey(&request)==kIOReturnSuccess);
  const auto *retired=owner.frontWEPKey(generation,state.local,state.bssid,100);assert(retired && retired->ticket>lastTicket);
  owner.clear();for(auto value:retired->key)assert(!value);assert(!retired->ticket);
  for(auto value:installed->key)assert(!value);assert(!installed->ticket);
  assert(owner.beginDynamicWEP(state.local,state.bssid,0,1000));
  assert(!owner.finishWEPKey(generation,state.local,state.bssid,lastTicket,100));
  assert(d.nativeSetCipherKey(&request)==kIOReturnSuccess);
  retired=owner.frontWEPKey(owner.generation(),state.local,state.bssid,100);assert(retired);
  Ath10k::clockMS=1000;assert(d.nativeSetCipherKey(&request)==kIOReturnNotReady);
  assert(state.cancelRequested && !state.portAuthorized && d.discarded==1 && !owner.generation());
  for(auto value:retired->key)assert(!value);Ath10k::clockMS=100;
 }


 {Ath10kPCIDevice d;auto &st=d._connection;auto &owner=d.security.eapOwner;
  assert(owner.beginDynamicWEP(st.local,st.bssid,0,1000));const auto generation=owner.generation();
  apple80211_key request{};request.key_len=5;request.key_cipher_type=1;request.key_flags=5;
  for(unsigned value:{1u,2u,1u}){request.key[0]=value;assert(d.nativeSetCipherKey(&request)==kIOReturnSuccess);}
  assert(d.scheduled==3 && d.nativeSetCipherKey(&request)==kIOReturnSuccess && d.scheduled==3);
  for(unsigned value:{1u,2u,1u}){auto key=owner.frontWEPKey(generation,st.local,st.bssid,100);
   assert(key && key->key[0]==value);assert(owner.finishWEPKey(generation,st.local,st.bssid,key->ticket,100));}
 }

 {Ath10kPCIDevice d;auto &st=d._connection;auto &owner=d.security.eapOwner;
  assert(owner.beginDynamicWEP(st.local,st.bssid,0,1000));const auto generation=owner.generation();
  apple80211_key request{};request.key_len=13;request.key_cipher_type=2;request.key_flags=5;request.key[0]=1;
  assert(d.nativeSetCipherKey(&request)==kIOReturnSuccess);
  auto key=owner.frontWEPKey(generation,st.local,st.bssid,100);assert(key);
  assert(owner.finishWEPKey(generation,st.local,st.bssid,key->ticket,100));
  for(unsigned value:{2u,1u}){request.key[0]=value;assert(d.nativeSetCipherKey(&request)==kIOReturnSuccess);}
  assert(d.scheduled==3);
  for(unsigned value:{2u,1u}){key=owner.frontWEPKey(generation,st.local,st.bssid,100);
   assert(key && key->key[0]==value);assert(owner.finishWEPKey(generation,st.local,st.bssid,key->ticket,100));}
  assert(d.nativeSetCipherKey(&request)==kIOReturnSuccess && d.scheduled==3);
  const auto *installed=owner.installedWEPKey(generation,st.local,st.bssid,0,false,100);assert(installed);
  assert(owner.expire(1000));for(auto value:installed->key)assert(!value);assert(!installed->ticket);
 }

 {Ath10kPCIDevice d;auto &st=d._connection;auto &owner=d.security.eapOwner;
  using Action=AthNative::EAPOwner::WEPAction;
  assert(owner.beginDynamicWEP(st.local,st.bssid,0,1000));const auto generation=owner.generation();
  apple80211_key request{};request.key_len=5;request.key_cipher_type=1;request.key_flags=5;request.key[0]=7;
  auto finish=[&](){auto key=owner.frontWEPKey(generation,st.local,st.bssid,100);assert(key);
   assert(owner.finishWEPKey(generation,st.local,st.bssid,key->ticket,100));};
  for(unsigned index:{0u,1u}){request.key_index=index;assert(d.nativeSetCipherKey(&request)==kIOReturnSuccess);
   assert(owner.frontWEPAction(generation,st.local,st.bssid,100)==Action::Install);finish();}
  request.key_index=0;assert(d.nativeSetCipherKey(&request)==kIOReturnSuccess);
  assert(owner.frontWEPAction(generation,st.local,st.bssid,100)==Action::SelectTransmit);finish();
  assert(d.nativeSetCipherKey(&request)==kIOReturnSuccess && !owner.frontWEPKey(generation,st.local,st.bssid,100));
  request.key_flags=9;assert(d.nativeSetCipherKey(&request)==kIOReturnSuccess);
  assert(owner.frontWEPAction(generation,st.local,st.bssid,100)==Action::MetadataOnly);finish();
  // Queued TX choices participate in duplicate detection: A,B,A must finish on A.
  request.key_flags=5;
  for(unsigned index:{0u,1u,0u}){request.key_index=index;assert(d.nativeSetCipherKey(&request)==kIOReturnSuccess);}
  struct Expected{unsigned index;Action action;};
  for(auto expected:{Expected{0,Action::MetadataOnly},Expected{1,Action::SelectTransmit},Expected{0,Action::SelectTransmit}}){
   auto key=owner.frontWEPKey(generation,st.local,st.bssid,100);assert(key && key->index==expected.index);
   assert(owner.frontWEPAction(generation,st.local,st.bssid,100)==expected.action);finish();}
  assert(owner.frontWEPAction(generation,st.local,st.bssid,100)==Action::None);
 }

 {Ath10kPCIDevice d;auto &st=d._connection;auto &owner=d.security.eapOwner;
  using Action=AthNative::EAPOwner::WEPAction;
  assert(owner.beginDynamicWEP(st.local,st.bssid,0,1000));const auto generation=owner.generation();
  apple80211_key request{};request.key_len=5;request.key_cipher_type=1;request.key_flags=5;request.key[0]=1;
  auto submit=[&](Action expected){assert(d.nativeSetCipherKey(&request)==kIOReturnSuccess);
   assert(owner.frontWEPAction(generation,st.local,st.bssid,100)==expected);};
  auto finish=[&](){auto key=owner.frontWEPKey(generation,st.local,st.bssid,100);assert(key);
   assert(owner.finishWEPKey(generation,st.local,st.bssid,key->ticket,100));};
  submit(Action::Install);finish();
  request.key_flags=2;submit(Action::InstallGroupOnly);finish();
  request.key_flags=5;request.key[0]=2;submit(Action::Install);finish();
  request.key_flags=2;request.key[0]=1;submit(Action::RepairPairMirror);finish();
  const auto *pair=owner.installedWEPKey(generation,st.local,st.bssid,0,false,100);
  assert(pair && pair->key[0]==1 && pair->flags==1);
  assert(d.nativeSetCipherKey(&request)==kIOReturnSuccess && !owner.frontWEPKey(generation,st.local,st.bssid,100));
  // A queued individual replacement must prevent suppression of a later
  // group request that restores its required mirror at the same index.
  request.key_flags=5;request.key[0]=2;submit(Action::Install);
  request.key_flags=2;request.key[0]=1;assert(d.nativeSetCipherKey(&request)==kIOReturnSuccess);
  finish();assert(owner.frontWEPAction(generation,st.local,st.bssid,100)==Action::RepairPairMirror);finish();
 }
 // A pending group mirror must also invalidate individual duplicate
 // suppression, for both installed and queued individual history.
 for(bool completed:{false,true})for(unsigned flags:{1u,5u}){
  Ath10kPCIDevice d;auto &st=d._connection;auto &owner=d.security.eapOwner;
  using Action=AthNative::EAPOwner::WEPAction;
  assert(owner.beginDynamicWEP(st.local,st.bssid,0,1000));auto generation=owner.generation();
  apple80211_key request{};request.key_len=5;request.key_cipher_type=1;
  request.key_flags=flags;request.key[0]=1;
  auto finish=[&](unsigned value){const auto *key=owner.frontWEPKey(generation,st.local,st.bssid,100);
   assert(key && key->key[0]==value);
   assert(owner.finishWEPKey(generation,st.local,st.bssid,key->ticket,100));};
  assert(d.nativeSetCipherKey(&request)==kIOReturnSuccess);
  if(completed)finish(1);
  request.key_flags=2;request.key[0]=2;assert(d.nativeSetCipherKey(&request)==kIOReturnSuccess);
  request.key_flags=flags;request.key[0]=1;assert(d.nativeSetCipherKey(&request)==kIOReturnSuccess);
  if(!completed)finish(1);
  finish(2);
  assert(owner.frontWEPAction(generation,st.local,st.bssid,100)==Action::Install);
  finish(1);
  const auto *pair=owner.installedWEPKey(generation,st.local,st.bssid,0,false,100);
  const auto *group=owner.installedWEPKey(generation,st.local,st.bssid,0,true,100);
  assert(pair && group && pair->key[0]==1 && group->key[0]==2);
  assert(!owner.frontWEPKey(generation,st.local,st.bssid,100));
 }
 // The complete firmware plan preserves install/mirror/TX-selection order;
 // changing a default index alone must not reinstall the retained bytes.
 {Ath10kPCIDevice d;auto &st=d._connection;auto &owner=d.security.eapOwner;
  using Write=AthNative::EAPOwner::WEPWrite;
  assert(owner.beginDynamicWEP(st.local,st.bssid,0,1000));auto generation=owner.generation();
  apple80211_key request{};request.key_len=13;request.key_cipher_type=2;request.key_flags=5;request.key[0]=1;
  auto check=[&](std::initializer_list<Write> expected){
   assert(d.nativeSetCipherKey(&request)==kIOReturnSuccess);
   const auto program=owner.frontWEPProgram(generation,st.local,st.bssid,100);
   assert(program.valid && program.generation==generation && program.ticket && program.count==expected.size());
   unsigned i=0;for(auto write:expected)assert(program.writes[i++]==write);
   assert(!owner.frontWEPProgram(generation+1,st.local,st.bssid,100).valid);
   assert(!owner.frontWEPProgram(generation,st.local,st.bssid,1000).valid);
   assert(owner.finishWEPKey(generation,st.local,st.bssid,program.ticket,100));
  };
  check({Write::Pair,Write::SelectTransmit});
  request.key_flags=2;check({Write::Group});
  request.key_index=1;request.key[0]=2;check({Write::Group,Write::Pair});
  request.key_flags=5;check({Write::SelectTransmit});
  request.key_index=0;request.key_flags=5;request.key[0]=1;check({Write::SelectTransmit});
  request.key_flags=1;check({});
  request.key[0]=3;check({Write::Pair});
  request.key_flags=2;request.key[0]=1;check({Write::Pair});
  assert(!owner.frontWEPProgram(generation,st.local,st.bssid,100).valid);
 }
 for(unsigned phase=1;phase<=4;++phase)for(bool rekey:{false,true}){
  Ath10kPCIDevice d;auto &s=d._connection;auto &sec=d.security;uint8_t out[32]{};apple80211_key key;
  assert(sec.eapOwner.begin(s.local,s.bssid,1,1000));auto g=sec.eapOwner.generation();
  assert(sec.eapOwner.setMSK(g,s.local,s.bssid,9,key.key,32,2)==K::Accepted);
  assert(sec.eapOwner.takePMK(g,s.local,s.bssid,3,out));sec.ready=true;
  s.securityPhase=phase;s.rekeyKind=rekey;s.portAuthorized=false;key.key_len=0;Ath10k::clockMS=100;
  assert(d.nativeSetCipherKey(&key)==kIOReturnSuccess);
  assert(!s.portAuthorized); // The restart never skips the firmware authorization barrier.
  if(rekey)assert(!s.cancelRequested && sec.eapOwner.replacementPending() && s.rekeyKind);
  else assert(s.cancelRequested && !sec.eapOwner.generation()); // Initial installation is not reauth.
 }

 for(unsigned block=0;block<12;++block){
  Ath10kPCIDevice d;auto &s=d._connection;auto &sec=d.security;uint8_t out[32]{};apple80211_key key;
  assert(sec.eapOwner.begin(s.local,s.bssid,1,1000));auto old=sec.eapOwner.generation();
  assert(sec.eapOwner.setMSK(old,s.local,s.bssid,9,key.key,32,2)==K::Accepted);
  assert(sec.eapOwner.takePMK(old,s.local,s.bssid,3,out));sec.ready=true;s.portAuthorized=true;s.securityPhase=5;
  bool *guards[]={&sec.eapTXInFlight,&sec.replyPending,&sec.keysPending,&sec.authorizePending,&sec.ptkUpdatePending,&sec.supplicant.pending,&s.txOwned,&s.dataPending,&s.wmiOwned,&s.submitted};
  if(block<10)*guards[block]=true;else if(block==10)s.rekeyKind=1;key.key_len=0;Ath10k::clockMS=100;
  auto result=d.nativeSetCipherKey(&key);
  {
   assert(result==kIOReturnSuccess && !s.cancelRequested && s.portAuthorized && sec.eapOwner.replacementPending());
   auto g=sec.eapOwner.generation();assert(g!=old);
   Ath10k::clockMS=101;assert(d.nativeSetCipherKey(&key)==kIOReturnSuccess && sec.eapOwner.generation()==g);
   assert(sec.eapOwner.expire(30100)); // Repeated empty reset did not extend deadline.
  }
 }

 // A callback may observe expiry before periodic service. It must both reject
 // the key and schedule terminal cleanup, rather than silently erase the timer.
 for(bool clear: {false,true}){
  Ath10kPCIDevice expired;auto &state=expired._connection;
  assert(expired.security.eapOwner.begin(state.local,state.bssid,0,1000));
  apple80211_key request;request.key_len=clear?0:32;state.portAuthorized=true;
  Ath10k::clockMS=1000;assert(expired.nativeSetCipherKey(&request)==kIOReturnNotReady);
  assert(state.cancelRequested && !state.portAuthorized && expired.discarded==1 && expired.scheduled==1);
  assert(!strcmp(state.error,"native-eap-msk-timeout") && !expired.security.eapOwner.generation());
 }
 Ath10k::clockMS=100;

 for(unsigned bad=0;bad<8;++bad){
  Ath10kPCIDevice d;auto &s=d._connection;assert(d.security.eapOwner.begin(s.local,s.bssid,0,1000));
  apple80211_key key;key.key[0]=17;
  switch(bad){case 0:key.version=2;break;case 1:key.key_flags=1;break;case 2:key.key_index=1;break;
   case 3:key.key_rsc_len=1;break;case 4:key.wowl_kck_len=1;break;case 5:key.wowl_kek_len=1;break;
   case 6:key.key_ea[0]=2;break;case 7:key.key_len=64;break;}
  auto copy=key;assert(d.nativeSetCipherKey(&key)==kIOReturnBadArgument);
  assert(!memcmp(&copy,&key,sizeof(key)) && !d.scheduled);
 }
 Ath10kPCIDevice d;auto &s=d._connection;apple80211_key key;key.key[0]=9;
 assert(d.nativeSetCipherKey(nullptr)==kIOReturnBadArgument);
 assert(d.nativeSetCipherKey(&key)==kIOReturnUnsupported);
 assert(d.security.eapOwner.begin(s.local,s.bssid,0,1000));
 for(unsigned personal: {2u,6u,8u}){s.securityAKM=personal;assert(d.nativeSetCipherKey(&key)==kIOReturnUnsupported);}
 s.securityAKM=1;s.associated=false;assert(d.nativeSetCipherKey(&key)==kIOReturnNotReady);s.associated=true;
 const auto owner=d.security.eapOwner.generation();key.key_len=0;
 for(unsigned i=0;i<3;++i)assert(d.nativeSetCipherKey(&key)==kIOReturnSuccess);
 assert(!s.cancelRequested && !s.portAuthorized && !d.discarded && !d.scheduled && d.security.eapOwner.generation()==owner);
 key.key_len=32;
 auto original=key;assert(d.nativeSetCipherKey(&key)==kIOReturnSuccess && d.scheduled==1);
 assert(!memcmp(&key,&original,sizeof(key)));
 assert(d.nativeSetCipherKey(&key)==kIOReturnSuccess && d.scheduled==1);
 key.key[0]^=1;assert(d.nativeSetCipherKey(&key)==kIOReturnBusy);key.key[0]^=1;
 uint8_t pmk[32]{};assert(d.security.eapOwner.takePMK(d.security.eapOwner.generation(),s.local,s.bssid,100,pmk));
 assert(pmk[0]==9);key.key_len=0;s.portAuthorized=true;
 assert(d.nativeSetCipherKey(&key)==kIOReturnSuccess && s.cancelRequested && !s.portAuthorized && d.discarded==1);
 assert(d.nativeSetCipherKey(&key)==kIOReturnUnsupported);
 assert(d.security.eapOwner.setMSK(1,s.local,s.bssid,9,pmk,32,100)==K::Stale);
 AthSecurity::wipe(pmk,sizeof(pmk));
}

#include <cassert>
#include <initializer_list>
#include <cstring>
#include <strings.h>
#include "../../src/macos/native/Ath10kNativeEAPOwner.hpp"
using UInt8=uint8_t;using IOReturn=int;
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
 struct Security {AthNative::EAPOwner eapOwner;} security;
 Security *_nativeSecurity=&security;
 struct State {const char *error=nullptr;unsigned securityAKM=1;bool associated=true,cancelRequested=false,portAuthorized=false;
   uint8_t local[6]={2,1,2,3,4,5},bssid[6]={2,6,7,8,9,10};} _connection;
 unsigned scheduled=0,discarded=0;
 void requestNativeService(){++scheduled;}
 void discardNativeSecurity(){++discarded;security.eapOwner.clear();}
 IOReturn nativeSetCipherKey(void *);
};
#include "native_eap_callback.inc"
int main(){
 using K=AthNative::EAPOwner::KeyResult;
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

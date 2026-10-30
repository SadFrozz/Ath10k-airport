#include <cassert>
#include <array>
#include <cstring>
#include <cstdint>
#include <initializer_list>
#include <type_traits>
#include <algorithm>
#include <new>
#define __MAC_15_2 150200
#define __IO80211_TARGET __MAC_15_2
#include "../../src/macos/native/Ath10kNativeProfile.hpp"
static AirportWCL::JoinRequest profile(unsigned auth){
 AirportWCL::JoinRequest p{};p.lowerAuth=1;p.upperAuth=auth;
 p.ssidLength=4;memcpy(p.ssid,"test",4);p.bssid[0]=2;p.bssid[5]=1;
 p.keyCipher=auth?10:0;p.keyLength=auth?12:0;
 memset(p.key,0xa5,sizeof(p.key));memcpy(p.key,"testpassword",12);
 return p;
}
static void candidateTransaction(){
 const UInt8 local[6]={2,0,0,0,0,1};
 for(unsigned upper:{0u,8u,1024u,4096u}){
  AthNative::ProfileCredentials owner;auto p=profile(upper);
  // Old AP metadata deliberately differs from the selected observation.
  p.channelSpec=0x1001;p.rsnLength=4;memset(p.rsn,0xee,4);
  assert(owner.replace(p,local,true));const auto token=owner.generation();
  Ath10k::ConnectionState live{};memcpy(live.local,local,6);
  live.ssidLength=4;memcpy(live.ssid,p.ssid,4);memcpy(live.bssid,p.bssid,6);
  live.secure=upper!=0;live.securityAKM=upper==4096?8:upper==1024?6:2;live.pmfRequired=upper==4096;
  NativeReassocRequest request{};request.ssidLength=4;memcpy(request.ssid,p.ssid,4);memset(request.bssid,255,6);
  auto cache=new AthNative::CandidateCache;
  Ath10k::WMIBSS ap{};ap.ssidLength=4;memcpy(ap.ssid,p.ssid,4);ap.bssid[0]=2;ap.bssid[5]=9;
  ap.capabilities=1;ap.beaconInterval=100;ap.rateCount=1;ap.rates[0]=0x82;ap.rxChannel=ap.advertisedChannel=6;
  if(upper){
   const UInt8 rsn[]={48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,UInt8(live.securityAKM),0x80,0};
   memcpy(ap.rsn,rsn,sizeof(rsn));ap.rsnLength=sizeof(rsn);ap.privacy=ap.rsnPresent=true;
  }
  cache->add(ap,1000);AirportWCL::JoinRequest next{};Ath10k::CandidateConfiguration candidate{};
  const auto savedLive=live;
  assert(AthNative::prepareRoamJoin(owner,token,live,request,*cache,1100,next,candidate));
  assert(!memcmp(next.key,p.key,p.keyLength) && next.keyLength==p.keyLength);
  assert(next.bssid[5]==9 && next.channelSpec==0x1006);
  assert(next.rsnLength==ap.rsnLength && !memcmp(next.rsn,ap.rsn,ap.rsnLength));
  for(unsigned i=next.rsnLength;i<sizeof(next.rsn);++i)assert(!next.rsn[i]);
  assert(!memcmp(&savedLive,&live,sizeof(live)));
  const auto savedNext=next;const auto savedCandidate=candidate;
  // Preserve the original observation age across a slow teardown; preparation
  // must not make a 29-second-old candidate fresh for another 30 seconds.
  for(unsigned failure=0;failure<8;++failure){
   AthNative::PreparedRoam pending;AthNative::ProfileCredentials current;
   AthNative::ProfileCredentials foreign;const auto *selected=&current;
   assert(current.replace(p,local,true));
   assert(pending.prepare(current,live,request,*cache,30000));
   auto station=std::array<UInt8,6>{};memcpy(station.data(),local,6);UInt64 now=31000;
   switch(failure){
    case 1:current.clear();break;
    case 2:assert(current.replace(p,local,true));break;
    case 3:station[5]^=1;break;
    case 4:now=31001;break;
    case 5:now=29999;break;
    case 6:pending.clear();break;
    case 7:assert(foreign.replace(p,local,true));selected=&foreign;break;
   }
   AirportWCL::JoinRequest taken{};memset(&taken,0x5a,sizeof(taken));const auto unchanged=taken;
   assert(pending.take(*selected,station.data(),now,taken)==(failure==0));
   assert(!pending.generation());
   if(p.keyLength){const auto raw=reinterpret_cast<const UInt8 *>(&pending);
    assert(std::search(raw,raw+sizeof(pending),p.key,p.key+p.keyLength)==raw+sizeof(pending));}

   if(failure)assert(!memcmp(&taken,&unchanged,sizeof(taken)));
   else assert(taken.keyLength==p.keyLength && !memcmp(taken.key,p.key,p.keyLength) && taken.bssid[5]==9);
   const auto consumed=taken;assert(!pending.take(current,local,now,taken));
   assert(!memcmp(&taken,&consumed,sizeof(taken)));AthSecurity::wipe(&taken,sizeof(taken));
  }
  if(p.keyLength){
   alignas(AthNative::PreparedRoam) UInt8 storage[sizeof(AthNative::PreparedRoam)]{};
   auto pending=new(storage) AthNative::PreparedRoam;
   assert(pending->prepare(owner,live,request,*cache,1100));
   assert(std::search(storage,storage+sizeof(storage),p.key,p.key+p.keyLength)!=storage+sizeof(storage));
   pending->~PreparedRoam();
   assert(std::search(storage,storage+sizeof(storage),p.key,p.key+p.keyLength)==storage+sizeof(storage));
  }
  { AthNative::PreparedRoam pending;assert(pending.prepare(owner,live,request,*cache,1100));
    auto invalid=request;invalid.bssidCount=0;
    assert(!pending.prepare(owner,live,invalid,*cache,1101) && !pending.generation());
    AirportWCL::JoinRequest taken{};assert(!pending.take(owner,local,1102,taken));
  }

  for(unsigned fault=0;fault<8;++fault){
   auto changed=live;auto bad=ap;UInt64 generation=token;UInt64 now=1100;
   switch(fault){case 0:++generation;break;case 1:changed.local[5]^=1;break;
    case 2:changed.ssid[0]^=1;break;case 3:changed.secure=!changed.secure;break;
    case 4:now=40000;break;case 5:bad.bssid[0]=1;break;
    case 6:memset(bad.bssid,0,6);break;case 7:bad.powerConstraintDb=255;break;}
   cache->bss.count=0;cache->add(bad,1000);
   assert(!AthNative::prepareRoamJoin(owner,generation,changed,request,*cache,now,next,candidate));
   assert(!memcmp(&savedNext,&next,sizeof(next)) && !memcmp(&savedCandidate,&candidate,sizeof(candidate)));
  }
  cache->bss.count=0;cache->add(ap,1000);owner.clear();
  assert(!AthNative::prepareRoamJoin(owner,token,live,request,*cache,1100,next,candidate));
  AthSecurity::wipe(&next,sizeof(next));delete cache;
 }
}
int main(){
 candidateTransaction();
 static_assert(!std::is_copy_constructible<AthNative::PreparedRoam>::value,"prepared secrets cannot be copied");
 static_assert(!std::is_copy_constructible<AthNative::ProfileCredentials>::value,"secret owner cannot be copied");
 static_assert(!std::is_copy_assignable<AthNative::ProfileCredentials>::value,"secret owner cannot be assigned");
 const UInt8 local[6]={2,0,0,0,0,1},other[6]={2,0,0,0,0,2};
 AthNative::ProfileCredentials owner;UInt64 previous=0;
 for(unsigned upper:{0u,8u,1024u,4096u}){
  auto p=profile(upper);const auto auth=nativeJoinAuth(p,true);
  assert(owner.replace(p,local,true));const auto token=owner.generation();assert(token>previous);
  AirportWCL::JoinRequest out{};
  assert(owner.snapshot(token,local,p.ssid,4,auth,out));
  assert(out.keyLength==p.keyLength && !memcmp(out.key,p.key,p.keyLength));
  for(unsigned i=p.keyLength;i<64;++i)assert(!out.key[i]);
  const auto saved=out;
  assert(!owner.snapshot(previous,local,p.ssid,4,auth,out));
  assert(!owner.snapshot(token,other,p.ssid,4,auth,out));
  assert(!owner.snapshot(token,local,p.ssid,3,auth,out));
  assert(!owner.snapshot(token,local,p.ssid,33,auth,out));
  assert(!owner.snapshot(token,local,p.ssid,4,NativeJoinAuth::Unsupported,out));
  auto wrong=p;wrong.ssid[0]^=1;assert(!owner.snapshot(token,local,wrong.ssid,4,auth,out));
  assert(!memcmp(&out,&saved,sizeof(out)));
  owner.clear();assert(!owner.generation());
  assert(!owner.snapshot(token,local,p.ssid,4,auth,out));
  assert(!memcmp(&out,&saved,sizeof(out)));previous=token;
  AthSecurity::wipe(&out,sizeof(out));
 }
 // Invalid profile replacement retires the former generation, including
 // identity, bounds and authentication failures; it cannot revive old access.
 for(unsigned failure=0;failure<7;++failure){
  auto p=profile(4096);assert(owner.replace(p,local,true));auto token=owner.generation();
  auto bad=p;
  switch(failure){case 0:bad.ssidLength=33;break;case 1:bad.keyLength=65;break;
   case 2:bad.bssid[0]=1;break;case 3:bad.rsnLength=258;break;
   case 4:bad.upperAuth=8192;break;case 5:bad.transitionDisable=2;break;default:break;}
  assert(!owner.replace(bad,local,failure!=6));assert(!owner.generation());
  AirportWCL::JoinRequest out{};assert(!owner.snapshot(token,local,p.ssid,4,NativeJoinAuth::SAE,out));
  assert(owner.replace(p,local,true));assert(owner.generation()>token);
 }
 // PMK profiles retain the exact binary PMK rather than treating it as text.
 auto p=profile(8);p.keyCipher=6;p.keyLength=32;p.key[7]=0;
 assert(owner.replace(p,local,false));AirportWCL::JoinRequest out{};
 assert(owner.snapshot(owner.generation(),local,p.ssid,4,NativeJoinAuth::PSK,out));
 assert(!memcmp(out.key,p.key,32));AthSecurity::wipe(&out,sizeof(out));
 owner.clear();
 // Authenticated transition-disable must retire pre-policy jobs, never
 // downgrade protection, and never let an old notification clear a new profile.
 p=profile(4096);assert(owner.replace(p,local,true));auto before=owner.generation();
 assert(owner.restrictPolicy(before,NativeTransitionDisable::Personal));
 const auto restricted=owner.generation();assert(restricted>before);
 assert(!owner.snapshot(before,local,p.ssid,4,NativeJoinAuth::SAE,out));
 assert(owner.snapshot(restricted,local,p.ssid,4,NativeJoinAuth::SAE,out));
 assert(out.transitionDisable==NativeTransitionDisable::Personal);
 assert(owner.restrictPolicy(restricted,0) && owner.generation()==restricted);
 assert(!owner.restrictPolicy(before,255) && owner.generation()==restricted);
 assert(!owner.restrictPolicy(restricted,NativeTransitionDisable::SAEPK) && !owner.generation());
 p=profile(8);assert(owner.replace(p,local,false));
 assert(!owner.restrictPolicy(owner.generation(),NativeTransitionDisable::Personal));
 assert(!owner.generation());
 p=profile(4096);assert(owner.replace(p,local,true));
 assert(!owner.restrictPolicy(owner.generation(),16) && !owner.generation());
 AthSecurity::wipe(&out,sizeof(out));
 // Inspect backing storage after clear and destruction: invalidating a token
 // alone is insufficient if password octets remain resident.
 alignas(AthNative::ProfileCredentials) unsigned char storage[sizeof(AthNative::ProfileCredentials)]{};
 auto *placed=new(storage) AthNative::ProfileCredentials;
 auto password=profile(4096);
 assert(placed->replace(password,local,true));
 auto contains=[&](){return std::search(storage,storage+sizeof(storage),password.key,password.key+password.keyLength)!=storage+sizeof(storage);};
 assert(contains());placed->clear();assert(!contains());
 assert(placed->replace(password,local,true));assert(contains());
 placed->~ProfileCredentials();assert(!contains());
}

#include <cassert>
#include <array>
#include <vector>
#include <cstring>
#include <cstdint>
#include <initializer_list>
#define __MAC_15_2 150200
#define __IO80211_TARGET __MAC_15_2
#include "../../src/macos/native/Ath10kNativeWire.hpp"
#include "../../src/macos/native/Ath10kNativeCandidates.hpp"
#include "../../src/macos/native/Ath10kNativeMAC.hpp"
#include "../../src/macos/native/Ath10kNativeRoamEvents.hpp"
#include "../../src/macos/native/Ath10kNativeRoamCache.hpp"
int main(){
 {using namespace AthNative::RoamEvents;
  const uint8_t target[]={2,1,2,3,4,5};
  for(unsigned failureStage=0;failureStage<4;++failureStage){
   Delivery delivery;uint64_t generation=0;std::vector<uint32_t> accepted;bool reject=true;
   auto post=[&](uint32_t id,void *payload,size_t bytes){
    assert(bytes==(id==CompleteID?168u:id==ReassocID?8u:12u));
    // Mutation of a rejected payload cannot damage later retry metadata.
    if(reject){memset(payload,0xcc,bytes);return false;}
    const auto p=static_cast<const uint8_t *>(payload);
    if(id==PrepID){assert(!memcmp(p+4,target,6));assert(AirportWCL::read32(p)==7);}
    if(id==CompleteID)assert(AirportWCL::read32(p)==(failureStage?1u:0u));
    accepted.push_back(id);return true;
   };
   assert(!delivery.sendPrep(generation,post) && !delivery.sendReassoc(generation,post));
   assert(!delivery.sendComplete(generation,1,false,post));
   assert(delivery.begin(7,target) && !delivery.begin(7,target));
   generation=delivery.generation();assert(generation);
   assert(!delivery.sendStart(generation,post));reject=false;
   assert(delivery.sendStart(generation,post) && !delivery.sendStart(generation,post));
   assert(!delivery.sendComplete(generation,0,true,post));
   if(failureStage!=1){
    reject=true;assert(!delivery.sendPrep(generation,post));reject=false;
    assert(delivery.sendPrep(generation,post) && !delivery.sendPrep(generation,post));
    assert(!delivery.sendComplete(generation,0,true,post));
    if(failureStage!=2){
     reject=true;assert(!delivery.sendReassoc(generation,post));reject=false;
     assert(delivery.sendReassoc(generation,post) && !delivery.sendReassoc(generation,post));
     assert(!delivery.sendComplete(generation,0,false,post));
    }
   }
   reject=true;assert(!delivery.sendComplete(generation,failureStage?1:0,true,post));reject=false;
   assert(delivery.sendComplete(generation,failureStage?1:0,true,post));
   assert(!delivery.sendComplete(generation,1,true,post) && !delivery.sendPrep(generation,post));
   assert(accepted.front()==StartID && accepted.back()==CompleteID);
   assert(accepted.size()==(failureStage==1?2u:failureStage==2?3u:4u));
   const uint8_t invalid[]={1,1,2,3,4,5};assert(!delivery.begin(7,invalid));
   assert(delivery.phase()==Delivery::Phase::Completed && delivery.begin(7,target));
   const auto current=delivery.generation();assert(current!=generation);
   assert(!delivery.sendStart(generation,post));
   assert(delivery.sendStart(current,post));
   assert(!delivery.sendPrep(generation,post) && !delivery.sendComplete(generation,1,false,post));
   assert(delivery.sendPrep(current,post));
   assert(!delivery.sendReassoc(generation,post));
   assert(delivery.sendReassoc(current,post));
   assert(!delivery.sendComplete(generation,0,true,post));
   assert(delivery.sendComplete(current,failureStage?1:0,true,post));
  }
 }

 { UInt8 wire[128]{};wire[0x7b]=wire[0x7c]=1;AthNative::RoamCacheRequest request{};
   assert(AthNative::decodeRoamCache(wire,sizeof(wire),request));
   assert(!request.count && request.clear && request.updateOverride && !request.overrideEnabled);
   AthNative::UserRoamCache cache;
   auto valid=[](const AthNative::RoamCacheChannel &c){return c.version==1 && c.channel==6 && c.flags==10;};
   assert(cache.apply(request,valid));
   Ath10k::htcWriteLE32(wire,1);Ath10k::htcWriteLE32(wire+4,6);Ath10k::htcWriteLE32(wire+8,10);
   wire[0x78]=1;wire[0x7a]=1;assert(AthNative::decodeRoamCache(wire,128,request));
   assert(cache.apply(request,valid) && cache.count==1 && cache.overrideEnabled && cache.channels[0].channel==6);
   const auto saved=request;const auto oldCache=cache;
   for(size_t length=0;length<128;++length){assert(!AthNative::decodeRoamCache(wire,length,request));assert(!memcmp(&request,&saved,sizeof(saved)));}
   for(unsigned fault=0;fault<8;++fault){auto bad=std::array<UInt8,128>{};memcpy(bad.data(),wire,128);
     if(fault==0)bad[0x78]=11;else if(fault==1)bad[0x79]=0xff;else if(fault==2)bad[0x7f]=1;else bad[0x7a+fault-3]=2;
     assert(!AthNative::decodeRoamCache(bad.data(),128,request));assert(!memcmp(&request,&saved,sizeof(saved)));
   }
   request.channels[0].channel=0;assert(!cache.apply(request,valid));assert(!memcmp(&cache,&oldCache,sizeof(cache)));
   request={};request.updateOverride=true;assert(cache.apply(request,valid) && cache.count==1 && !cache.overrideEnabled);
   request={};request.readChannels=true;assert(cache.apply(request,valid) && cache.count==1);
   request={};request.clear=true;assert(cache.apply(request,valid) && !cache.count && !cache.overrideEnabled);
   for(const auto &c:cache.channels)assert(!c.version && !c.channel && !c.flags);
   request={};assert(!cache.apply(request,valid));request.count=11;assert(!cache.apply(request,valid));
   Ath10k::RegulatoryPolicy policy;
   auto realValid=[&](const AthNative::RoamCacheChannel &c){return AthNative::validRoamCacheChannel(policy,c);};
   assert(realValid({1,6,10}));
   for(auto c:{AthNative::RoamCacheChannel{2,6,10},{1,6,18},{1,6,0x4000000a},{1,6,11},{1,6,14},{1,6,0x20a},{1,0,10}})assert(!realValid(c));
   auto restricted=policy;restricted.high2=2410;assert(!AthNative::validRoamCacheChannel(restricted,{1,6,10}));
   UInt8 command[128]{};Ath10k::htcWriteLE32(command,1);Ath10k::htcWriteLE32(command+4,6);Ath10k::htcWriteLE32(command+8,10);
   command[0x78]=1;command[0x7a]=command[0x7c]=command[0x7d]=command[0x7e]=1;
   assert(cache.exchange(command,128,realValid) && cache.count==1 && cache.overrideEnabled);
   memset(command,0xa5,120);memset(command+120,0,8);command[0x7d]=command[0x7e]=1;
   assert(cache.exchange(command,128,realValid));
   assert(Ath10k::wmiReadLE32(command)==1 && Ath10k::wmiReadLE32(command+4)==6 && command[0x78]==1 && command[0x7a]==1);
   for(unsigned i=12;i<120;++i)assert(!command[i]);
   const auto beforeCache=cache;command[0x7b]=1;command[4]=0;
   UInt8 beforeCommand[128];memcpy(beforeCommand,command,128);
   assert(!cache.exchange(command,128,realValid));assert(!memcmp(command,beforeCommand,128) && !memcmp(&cache,&beforeCache,sizeof(cache)));
   assert(!cache.exchange(command,127,realValid));assert(!memcmp(command,beforeCommand,128));
   memset(command,0,128);command[0x7b]=command[0x7c]=command[0x7d]=command[0x7e]=1;
   assert(cache.exchange(command,128,realValid) && !cache.count && !cache.overrideEnabled && !command[0x78] && !command[0x7a]);
 }

 { namespace R=AthNative::RoamEvents;
   static_assert(R::StartID==137 && R::PrepID==139 && R::ReassocID==73 && R::CompleteID==80,"stock controller event IDs");
   const UInt8 startBytes[12]={0x78,0x56,0x34,0x12,0xef,0xcd,0xab,0x90,0xc0,0xff,0,0};
   auto start=R::start(0x12345678,0x90abcdef,-64);assert(!memcmp(start.bytes,startBytes,12));
   const UInt8 address[6]={2,3,4,5,6,7};R::Prep prep{};
   const UInt8 prepBytes[12]={0x78,0x56,0x34,0x12,2,3,4,5,6,7,0xc0,0xff};
   assert(R::prep(0x12345678,address,prep,-64) && !memcmp(prep.bytes,prepBytes,12));
   const auto saved=prep;UInt8 invalid[6]{};
   assert(!R::prep(0,nullptr,prep) && !memcmp(prep.bytes,saved.bytes,12));
   assert(!R::prep(0,invalid,prep) && !memcmp(prep.bytes,saved.bytes,12));
   invalid[0]=1;assert(!R::prep(0,invalid,prep) && !memcmp(prep.bytes,saved.bytes,12));
   auto reassoc=R::reassoc(0x12345678,0x90abcdef);assert(!memcmp(reassoc.bytes,startBytes,8));
   for(UInt32 status:{0u,0xe00002ebu,0xe00002bcu}){
     auto done=R::completion(status);assert(Ath10k::wmiReadLE32(done.bytes)==status);
     for(size_t i=4;i<sizeof(done.bytes);++i)assert(!done.bytes[i]);
     // Consumer owns mutable storage and may replace the first 0x68 bytes.
     memset(done.bytes,0xa5,0x68);for(size_t i=0x68;i<sizeof(done.bytes);++i)assert(!done.bytes[i]);
   }
 }

 { AirportWCL::ScanRequest scan{};Ath10k::WMIBSS b{};
   b.rxChannel=6;b.ssidLength=3;memcpy(b.ssid,"two",3);
   scan.ssids.count=2;
   for(auto &entry:scan.ssids.entries){entry.version=1;entry.length=3;}
   memcpy(scan.ssids.entries[0].bytes,"one",3);memcpy(scan.ssids.entries[1].bytes,"two",3);
   assert(nativeScanMatches(scan,b));b.ssid[0]='x';assert(!nativeScanMatches(scan,b));
   scan.ssids.entries[1]={};assert(nativeScanMatches(scan,b));
   scan.channelCount=1;scan.channels[1]=1;assert(!nativeScanMatches(scan,b));
   scan.channels[0]=1<<6;assert(nativeScanMatches(scan,b));
   scan.bssid[0]=2;assert(!nativeScanMatches(scan,b));
   b.bssid[0]=2;assert(nativeScanMatches(scan,b));
   scan.ssids.count=11;assert(!nativeScanMatches(scan,b));
 }

 { Ath10k::ConnectionState live{};live.ssidLength=4;memcpy(live.ssid,"test",4);
   Ath10k::WMIBSS ap{};ap.ssidLength=4;memcpy(ap.ssid,"test",4);
   ap.bssid[0]=2;ap.bssid[5]=7;ap.hidden=false;ap.capabilities=1;
   ap.beaconInterval=100;ap.rateCount=1;ap.rates[0]=0x82;ap.rxChannel=ap.advertisedChannel=6;
   NativeReassocRequest request{};request.ssidLength=4;memcpy(request.ssid,"test",4);memset(request.bssid,255,6);
   const auto saved=live;Ath10k::CandidateConfiguration prepared{};
   { auto cache=new AthNative::CandidateCache;
     auto weaker=ap;weaker.snr=20;cache->add(weaker,1000);
     auto stronger=ap;stronger.bssid[5]=8;stronger.snr=50;cache->add(stronger,1100);
     auto wrong=stronger;wrong.bssid[5]=9;wrong.ssid[0]^=1;wrong.snr=80;cache->add(wrong,1200);
     assert(AthNative::chooseRoamCandidate(live,request,*cache,1300,prepared));
     assert(prepared.ap.bssid[5]==8);
     cache->observed[1]=0; // Stronger observation expires, weaker remains usable.
     assert(AthNative::chooseRoamCandidate(live,request,*cache,30500,prepared));
     assert(prepared.ap.bssid[5]==7);
     const auto previous=prepared;
     assert(!AthNative::chooseRoamCandidate(live,request,*cache,40000,prepared));
     assert(!memcmp(&previous,&prepared,sizeof(prepared)));
     cache->observed[1]=1100;
     assert(!AthNative::chooseRoamCandidate(live,request,*cache,500,prepared));
     assert(!memcmp(&saved,&live,sizeof(live)));delete cache;
   }

   { auto cache=new AthNative::CandidateCache;
     auto first=ap;first.snr=40;first.bssid[5]=9;
     auto second=first;second.bssid[5]=7;
     for(bool reverse:{false,true}){
       cache->bss.count=0;
       cache->add(reverse?second:first,1000);cache->add(reverse?first:second,1000);
       assert(AthNative::chooseRoamCandidate(live,request,*cache,2000,prepared));
       assert(prepared.ap.bssid[5]==7); // Stable tie break regardless of cache order.
     }
     cache->add(first,1500);
     assert(AthNative::chooseRoamCandidate(live,request,*cache,2000,prepared));
     assert(prepared.ap.bssid[5]==9); // Freshness breaks equal-signal ties first.
     memcpy(request.bssid,second.bssid,6);
     assert(AthNative::chooseRoamCandidate(live,request,*cache,2000,prepared));
     assert(prepared.ap.bssid[5]==7); // Explicit target outranks signal/freshness.
     // Multi-target filtering must retain ranking while excluding other APs.
     request.bssidCount=2;memcpy(request.additionalBSSIDs[0],first.bssid,6);
     assert(AthNative::chooseRoamCandidate(live,request,*cache,2000,prepared));
     assert(prepared.ap.bssid[5]==9);
     request.additionalBSSIDs[0][5]=10;
     assert(AthNative::chooseRoamCandidate(live,request,*cache,2000,prepared));
     assert(prepared.ap.bssid[5]==7);
     const auto valid=prepared;
     for(unsigned bad: {0u,1u,255u}){
       memset(request.additionalBSSIDs[0],bad,6);
       assert(!AthNative::chooseRoamCandidate(live,request,*cache,2000,prepared));
       assert(!memcmp(&valid,&prepared,sizeof(prepared)));
     }
     request.bssidCount=1;memset(request.bssid,255,6);
     const auto previous=prepared;cache->bss.count=65;
     assert(!AthNative::chooseRoamCandidate(live,request,*cache,2000,prepared));
     assert(!memcmp(&previous,&prepared,sizeof(prepared)));
     delete cache;
   }
   assert(!AthNative::prepareRoamCandidate(live,request,ap,prepared));
   memcpy(request.bssid,ap.bssid,6);request.channelCount=1;request.channels[0]=0x1006;
   assert(!AthNative::prepareRoamCandidate(live,request,ap,prepared));
   request.channels[0]=0x5006;
   assert(!strcmp(AthNative::prepareRoamCandidate(live,request,ap,prepared),"roam-channel-mismatch"));
   request.channels[0]=0x1006;request.bssid[5]^=1;
   assert(!strcmp(AthNative::prepareRoamCandidate(live,request,ap,prepared),"roam-target-mismatch"));
   memset(request.bssid,0,6);
   assert(!strcmp(AthNative::prepareRoamCandidate(live,request,ap,prepared),"roam-target-invalid"));
   memset(request.bssid,255,6);request.ssid[0]^=1;
   assert(!strcmp(AthNative::prepareRoamCandidate(live,request,ap,prepared),"roam-request-ssid-mismatch"));
   assert(!memcmp(&saved,&live,sizeof(live)));
 }

 assert(nativePrimaryChannel(0x1006)==6 && nativePrimaryChannel(0xd024)==36);
 for(unsigned side=0;side<2;++side)
   assert(nativePrimaryChannel(UInt16(0xd826|(side<<8)))==36+4*side);
 for(unsigned side=0;side<4;++side)
   assert(nativePrimaryChannel(UInt16(0xe02a|(side<<8)))==36+4*side);
 for(unsigned side=0;side<8;++side)
   assert(nativePrimaryChannel(UInt16(0xe832|(side<<8)))==36+4*side);
 assert(nativeChannelSpecsMatch(0xd024,0xe02a));
 assert(!nativeChannelSpecsMatch(0xd028,0xe02a));
 assert(!nativeChannelSpecsMatch(0xd024,0x5024)); // Equal number, different band.
 assert(nativePrimaryChannel(0xf001)==52 && nativePrimaryChannel(0xf000)==0);
 assert(nativePrimaryChannel(0xe801)==0 && nativePrimaryChannel(0xefff)==0);
 { NativeReassocRequest request{};
   assert(nativeReassocChannelMatches(request,0xe02a));
   request.channelCount=1;request.channels[0]=0xd024;
   assert(nativeReassocChannelMatches(request,0xe02a));
   assert(!nativeReassocChannelMatches(request,0x5024));
   request.channelCount=51;assert(!nativeReassocChannelMatches(request,0xe02a));
 }

 { UInt8 wire[0xbc]{};Ath10k::htcWriteLE32(wire+0x90,1);
   memset(wire+0x64,255,6);wire[0xb9]=4;memcpy(wire+0x99,"test",4);
   NativeReassocRequest decoded{};
   assert(nativeDecodeReassoc(wire,sizeof(wire),decoded));
   assert(!decoded.channelCount && decoded.bssid[0]==255 && decoded.ssidLength==4);
   Ath10k::htcWriteLE32(wire+0x94,50);wire[0x98]=1;
   for(unsigned i=0;i<50;++i)Ath10k::htcWriteLE16(wire+2*i,0xd024+i);
   assert(nativeDecodeReassoc(wire,sizeof(wire),decoded));
   assert(decoded.channelCount==50 && decoded.channels[49]==0xd055 && decoded.flags==1);
   for(unsigned count=2;count<=7;++count){
     Ath10k::htcWriteLE32(wire+0x90,count);
     for(unsigned target=0;target<count;++target){memset(wire+0x64+6*target,0,6);wire[0x64+6*target]=2;wire[0x69+6*target]=target+1;}
     assert(nativeDecodeReassoc(wire,sizeof(wire),decoded) && decoded.bssidCount==count);
     assert(decoded.bssid[5]==1 && decoded.additionalBSSIDs[count-2][5]==count);
     assert(decoded.channels[49]==0xd055 && decoded.ssidLength==4);
   }
   const auto saved=decoded;
   for(unsigned n=0;n<sizeof(wire);++n){
     assert(!nativeDecodeReassoc(wire,n,decoded));assert(!memcmp(&saved,&decoded,sizeof(saved)));
   }
   assert(!nativeDecodeReassoc(nullptr,sizeof(wire),decoded));
   assert(!nativeDecodeReassoc(wire,sizeof(wire)+1,decoded));
   for(unsigned offset: {0x90u,0x94u,0x98u,0xb9u}){
     UInt8 bad[sizeof(wire)];memcpy(bad,wire,sizeof(wire));bad[offset]=255;
     assert(!nativeDecodeReassoc(bad,sizeof(bad),decoded));
     assert(!memcmp(&saved,&decoded,sizeof(saved)));
   }
 }

 UInt8 privateMAC[]={2,0x11,0x22,0x33,0x44,0x55},invalidMAC[]={1,0,0,0,0,1},zeroMAC[6]{};
 assert(AthNative::validMAC(privateMAC) && !AthNative::validMAC(invalidMAC) && !AthNative::validMAC(zeroMAC) && !AthNative::validMAC(nullptr));
 UInt8 mf[48];memset(mf,0xa5,sizeof(mf));
 assert(!AthNative::macFrame(mf,19,2,1,privateMAC,0x1234));assert(mf[0]==0xa5);
 assert(AthNative::macFrame(mf,sizeof(mf),2,1,privateMAC,0x1234)==20);
 assert(Ath10k::htcReadLE16(mf+2)==12 && Ath10k::wmiReadLE32(mf+8)==0x5002 && Ath10k::htcReadLE16(mf+14)==87 && Ath10k::wmiReadLE32(mf+16)==0);
 assert(mf[20]==0xa5);
 assert(AthNative::macFrame(mf,sizeof(mf),2,2,privateMAC,0x1234)==20 && Ath10k::wmiReadLE32(mf+8)==0x1d001 && Ath10k::wmiReadLE32(mf+16)==0x1234);
 assert(!AthNative::macFrame(mf,35,2,3,privateMAC,0));
 assert(AthNative::macFrame(mf,sizeof(mf),2,3,privateMAC,0)==36);
 assert(Ath10k::wmiReadLE32(mf+8)==0x5001 && Ath10k::wmiReadLE32(mf+16)==0 && Ath10k::wmiReadLE32(mf+20)==2 && !memcmp(mf+28,privateMAC,6));
 assert(mf[34]==0 && mf[35]==0 && mf[36]==0xa5);
 assert(AthNative::macFrame(mf,sizeof(mf),2,4,privateMAC,0x5678)==20 && Ath10k::wmiReadLE32(mf+16)==0x5678);
 assert(!AthNative::macFrame(mf,sizeof(mf),2,5,privateMAC,0));
 assert(!AthNative::macFrame(mf,sizeof(mf),0,1,privateMAC,0));
 assert(!AthNative::macFrame(mf,sizeof(mf),2,1,invalidMAC,0));

 assert(nativeScanDwellBudget(0)==120 && nativeScanDwellBudget(1)==1);
 assert(nativeScanDwellBudget(100)==100 && nativeScanDwellBudget(10000)==120);

 auto candidates=new AthNative::CandidateCache;Ath10k::WMIBSS candidate{};
 candidate.bssid[0]=2;candidate.bssid[5]=1;candidates->add(candidate,1000);
 candidate.snr=42;candidates->add(candidate,2000);assert(candidates->bss.count==1 && candidates->bss.entries[0].snr==42);
 for(unsigned i=2;i<70;++i){candidate.bssid[5]=i;candidates->add(candidate,2000+i);}
 assert(candidates->bss.count==64);candidates->expire(40000);assert(!candidates->bss.count);
 candidates->add(candidate,5000);candidates->expire(4000);assert(!candidates->bss.count);delete candidates;

 UInt8 latency[8];memset(latency,0xa5,sizeof(latency));
 assert(!nativeLowLatencySessions(nullptr,4));assert(!nativeLowLatencySessions(latency,3));
 assert(nativeLowLatencySessions(latency,4));
 for(unsigned i=0;i<4;++i)assert(latency[i]==0);
 for(unsigned i=4;i<8;++i)assert(latency[i]==0xa5);

 Ath10k::RegulatoryPolicy policy;AirportWCL::ChannelInfo channels{};
 assert(nativeWCLChannels(policy,channels));
 assert(channels.count==Ath10k::kWMIScanChannelCount && !channels.supports6GHz);
 bool seen52=false,seen149=false,seen165=false;
 for(unsigned i=0;i<channels.count;++i){auto &c=channels.channels[i];
  assert(Ath10k::wmiScanChannelAllowed(c.channel));assert(c.flags&4);
  if(c.channel==52){seen52=true;assert(c.flags&2);}
  if(c.channel==149)seen149=true;if(c.channel==165)seen165=true;
 }
 assert(seen52 && seen149 && seen165);
 policy.high5=5200;assert(nativeWCLChannels(policy,channels));
 for(unsigned i=0;i<channels.count;++i)assert(channels.channels[i].channel<=40);

 Ath10k::WMIBSS b{};b.hidden=false;b.ssidLength=4;memcpy(b.ssid,"test",4);b.rateCount=1;b.rates[0]=12;b.rxChannel=6;b.bssid[0]=2;b.snr=40;
 AirportWCL::ScanRequest scan{};
 assert(nativeScanMatches(scan,b));memset(scan.bssid,255,6);assert(nativeScanMatches(scan,b));
 scan.bssid[0]=2;assert(!nativeScanMatches(scan,b));memcpy(scan.bssid,b.bssid,6);assert(nativeScanMatches(scan,b));
 scan.channelCount=1;scan.channels[6/8]|=1<<(6%8);assert(nativeScanMatches(scan,b));scan.channels[0]=0;assert(!nativeScanMatches(scan,b));
 scan.channelCount=0;scan.ssidLength=4;memcpy(scan.ssid,"nope",4);assert(!nativeScanMatches(scan,b));memcpy(scan.ssid,"test",4);assert(nativeScanMatches(scan,b));
 alignas(AirportWCL::BeaconMetadata) UInt8 bytes[1700];memset(bytes,0x5a,sizeof(bytes));auto n=nativeBSSMessage(b,bytes,1600);assert(n>sizeof(AirportWCL::BeaconMetadata));
 auto m=reinterpret_cast<AirportWCL::BeaconMetadata *>(bytes);assert(m->channel==6 && m->ssidLength==4 && m->rssi==-55);
 assert(m->flags==AirportWCL::RSSIValid);
 // The production buffer can have any byte alignment. Compare exact wire
 // bytes and decode into an aligned object rather than casting that buffer.
 alignas(AirportWCL::BeaconMetadata) UInt8 unaligned[1704];
 for(unsigned offset=0;offset<alignof(AirportWCL::BeaconMetadata);++offset){
  memset(unaligned,0x5a,sizeof(unaligned));assert(nativeBSSMessage(b,unaligned+offset,1600)==n);
  assert(!memcmp(unaligned+offset,bytes,n));AirportWCL::BeaconMetadata decoded{};
  memcpy(&decoded,unaligned+offset,sizeof(decoded));assert(decoded.channel==6 && decoded.rssi==-55);
  assert(unaligned[offset+1600]==0x5a);
 }
 b.hidden=true;assert(nativeBSSMessage(b,bytes,1600)==n);assert(m->flags==(AirportWCL::RSSIValid|AirportWCL::SSIDPresent));
 b.hidden=false;assert(nativeBSSMessage(b,bytes,1600)==n);assert(m->flags==AirportWCL::RSSIValid);
 assert(AirportWCL::validIEs(bytes+sizeof(*m),m->ieLength));assert(n==sizeof(*m)+m->ieLength);assert(bytes[1600]==0x5a);
 // Preserve every standard RSNXE capability byte in the complete beacon IE
 // message; the fixed extended-BSS RSNE slot has no invented RSNXE offset.
 for(unsigned body=1;body<=16;++body){auto extended=b;
  extended.rsnxeLength=UInt8(body+2);extended.rsnxe[0]=244;extended.rsnxe[1]=UInt8(body);extended.rsnxe[2]=UInt8(0x20|(body-1));
  for(unsigned j=3;j<body+2;++j)extended.rsnxe[j]=UInt8(0x80+j);
  auto length=nativeBSSMessage(extended,bytes,1600);assert(length==n+body+2);
  bool found=false;for(size_t at=sizeof(*m);at<length;at+=size_t(bytes[at+1])+2)if(bytes[at]==244){
   assert(!found && !memcmp(bytes+at,extended.rsnxe,body+2));found=true;
  }assert(found && bytes[1600]==0x5a);
  extended.rsnxeLength=19;assert(!nativeBSSMessage(extended,bytes,1600));
  extended.rsnxeLength=UInt8(body+2);extended.rsnxe[2]^=1;assert(!nativeBSSMessage(extended,bytes,1600));
 }
 {auto maximum=b;maximum.ssidLength=32;maximum.rateCount=32;maximum.countryPresent=true;maximum.countryLength=254;
  maximum.rsnLength=257;maximum.rsn[0]=48;maximum.rsn[1]=255;
  maximum.htPresent=maximum.htOperation=maximum.vhtPresent=maximum.vhtOperation=true;
  maximum.rsnxeLength=18;maximum.rsnxe[0]=244;maximum.rsnxe[1]=16;maximum.rsnxe[2]=0x2f;
  const auto cap=sizeof(*m)+800;memset(bytes,0x5a,sizeof(bytes));auto length=nativeBSSMessage(maximum,bytes,cap);
  assert(length && length<=cap && bytes[cap]==0x5a);
 }
 assert(nativeBSSMessage(b,bytes,1600)==n);
 assert(!nativeBSSMessage(b,bytes,30));b.rateCount=33;assert(!nativeBSSMessage(b,bytes,1600));b.rateCount=32;
 b.rsnLength=258;assert(!nativeBSSMessage(b,bytes,1600));b.rsnLength=3;b.rsn[0]=48;b.rsn[1]=100;assert(!nativeBSSMessage(b,bytes,1600));
 b.rsnLength=0;b.ssidLength=33;assert(!nativeBSSMessage(b,bytes,1600));
}

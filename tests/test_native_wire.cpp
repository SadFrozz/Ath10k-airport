#include <cassert>
#include <cstring>
#include <cstdint>
#include <initializer_list>
#define __MAC_15_2 150200
#define __IO80211_TARGET __MAC_15_2
#include "../src/kext/native/Ath10kNativeWire.hpp"
#include "../src/kext/native/Ath10kNativeCandidates.hpp"
#include "../src/kext/native/Ath10kNativeMAC.hpp"
int main(){
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
     memset(request.bssid,255,6);
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

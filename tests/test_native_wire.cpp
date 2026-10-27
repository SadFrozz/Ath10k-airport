#include <cassert>
#include <cstring>
#include <cstdint>
#define __MAC_15_2 150200
#define __IO80211_TARGET __MAC_15_2
#include "../src/kext/native/Ath10kNativeWire.hpp"
#include "../src/kext/native/Ath10kNativeCandidates.hpp"
int main(){
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

 Ath10k::WMIBSS b{};b.ssidLength=4;memcpy(b.ssid,"test",4);b.rateCount=1;b.rates[0]=12;b.rxChannel=6;b.bssid[0]=2;b.snr=40;
 AirportWCL::ScanRequest scan{};
 assert(nativeScanMatches(scan,b));memset(scan.bssid,255,6);assert(nativeScanMatches(scan,b));
 scan.bssid[0]=2;assert(!nativeScanMatches(scan,b));memcpy(scan.bssid,b.bssid,6);assert(nativeScanMatches(scan,b));
 scan.channelCount=1;scan.channels[6/8]|=1<<(6%8);assert(nativeScanMatches(scan,b));scan.channels[0]=0;assert(!nativeScanMatches(scan,b));
 scan.channelCount=0;scan.ssidLength=4;memcpy(scan.ssid,"nope",4);assert(!nativeScanMatches(scan,b));memcpy(scan.ssid,"test",4);assert(nativeScanMatches(scan,b));
 UInt8 bytes[1700];memset(bytes,0x5a,sizeof(bytes));auto n=nativeBSSMessage(b,bytes,1600);assert(n>sizeof(AirportWCL::BeaconMetadata));
 auto m=reinterpret_cast<AirportWCL::BeaconMetadata *>(bytes);assert(m->channel==6 && m->ssidLength==4 && m->rssi==-55);
 assert(AirportWCL::validIEs(bytes+sizeof(*m),m->ieLength));assert(n==sizeof(*m)+m->ieLength);assert(bytes[1600]==0x5a);
 assert(!nativeBSSMessage(b,bytes,30));b.rateCount=33;assert(!nativeBSSMessage(b,bytes,1600));b.rateCount=32;
 b.rsnLength=258;assert(!nativeBSSMessage(b,bytes,1600));b.rsnLength=3;b.rsn[0]=48;b.rsn[1]=100;assert(!nativeBSSMessage(b,bytes,1600));
 b.rsnLength=0;b.ssidLength=33;assert(!nativeBSSMessage(b,bytes,1600));
}

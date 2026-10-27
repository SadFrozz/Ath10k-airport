#include <cassert>
#include <cstring>
#include <cstdint>
#define __MAC_15_2 150200
#define __IO80211_TARGET __MAC_15_2
#include "../src/kext/native/Ath10kNativeWire.hpp"
int main(){
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

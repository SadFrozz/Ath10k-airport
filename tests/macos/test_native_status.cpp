#include <cassert>
#include <cstring>
#include <cstdint>
#define __MAC_15_2 150200
#define __IO80211_TARGET __MAC_15_2
#include "../../src/core/Ath10kConnection.hpp"
#include "../../src/macos/native/Ath10kNativeWire.hpp"
int main(){
    {auto station=new Ath10k::ConnectionState;
     station->stage=Ath10k::LinkStage::Assoc;station->secure=true;station->securityAKM=6;
     station->groupCipher=4;station->nss=1;station->ssidLength=1;station->ssid[0]='x';
     station->ap.rateCount=1;station->ap.rates[0]=12;UInt8 association[256]{};
     auto length=Ath10k::buildStationManagement(association,sizeof(association),*station);assert(length>28);
     bool found=false;for(unsigned at=28;at+2<=length;){unsigned n=association[at+1]+2;assert(at+n<=length);
      if(association[at]==48){AthSecurity::RSNInfo info{};assert(AthSecurity::parseRSN(association+at,n,info));
       assert(info.akmHas(6) && !info.akmHas(2) && !info.mfpc() && !info.mfpr());found=true;}
      at+=n;
     }assert(found);
     station->securityAKM=8;assert(!Ath10k::buildStationManagement(association,sizeof(association),*station));
     delete station;}

    auto s=new Ath10k::ConnectionState;
    s->stage=Ath10k::LinkStage::Connected;s->operatingChannel=6;
    const UInt8 peer[6]={2,1,2,3,4,5};memcpy(s->bssid,peer,6);
    UInt8 frame[36]{};frame[0]=0x80;memset(frame+4,255,6);
    memcpy(frame+10,peer,6);memcpy(frame+16,peer,6);frame[24]=123;frame[32]=100;frame[34]=1;
    Ath10k::receiveStationManagement(*s,frame,sizeof(frame),0,6);
    assert(s->beaconFrameBytes==36 && s->beaconFrameSerial==1 && s->beaconFrame[24]==123);
    UInt8 output[0x810];memset(output,0x5a,sizeof(output));
    assert(nativeBeaconInfo(s->beaconFrame,s->beaconFrameBytes,output,0x808));
    assert(AirportWCL::read32(output)==36 && output[28]==123 && output[0x808]==0x5a);
    frame[24]=124;Ath10k::receiveStationManagement(*s,frame,sizeof(frame),0,6);
    assert(s->beaconFrameSerial==2 && s->beaconFrame[24]==124);
    Ath10k::receiveStationManagement(*s,frame,sizeof(frame),1,6);assert(s->beaconFrameSerial==2);
    Ath10k::receiveStationManagement(*s,frame,sizeof(frame),0,11);assert(s->beaconFrameSerial==2);
    frame[10]^=1;Ath10k::receiveStationManagement(*s,frame,sizeof(frame),0,6);assert(s->beaconFrameSerial==2);frame[10]^=1;
    frame[0]=0x50;Ath10k::receiveStationManagement(*s,frame,sizeof(frame),0,6);assert(s->beaconFrameSerial==2);
    assert(!nativeBeaconInfo(frame,36,output,0x808));frame[0]=0x80;
    assert(!nativeBeaconInfo(frame,35,output,0x808));assert(!nativeBeaconInfo(frame,36,output,0x807));
    assert(!nativeBeaconInfo(nullptr,36,output,0x808));assert(!nativeBeaconInfo(frame,0x801,output,0x808));
    Ath10k::resetDisconnected(*s);assert(s->beaconFrameBytes==0 && s->beaconFrameSerial==0);delete s;
    UInt8 rates[32]={0x82,0x84,12,24},ht[3]={0,7,15},rsn[4]={48,2,1,0};
    NativeExtendedBSSInput in{};in.rates=rates;in.rateCount=4;in.htRates=ht;in.htRateCount=3;in.vhtMap=0xfffe;in.rsn=rsn;in.rsnLength=4;
    memset(output,0x5a,sizeof(output));assert(nativeExtendedBSS(in,output,0x1e0));
    assert(AirportWCL::read32(output)==1 && output[4]==4 && AirportWCL::read32(output+12)==0x82);
    assert(output[0xc0]==0x81 && output[0xc1]==0x80 && output[0xd0]==0xfe && output[0xd1]==0xff);
    assert(output[0xd8]==255 && output[0xd9]==255 && !memcmp(output+0xdd,rsn,4));assert(output[0x1e0]==0x5a);
    in.rateCount=32;assert(nativeExtendedBSS(in,output,0x1e0));assert(output[4]==15);
    in.rateCount=33;assert(!nativeExtendedBSS(in,output,0x1e0));in.rateCount=4;
    ht[0]=96;assert(!nativeExtendedBSS(in,output,0x1e0));ht[0]=0;
    assert(!nativeExtendedBSS(in,output,0x1df));in.rsnLength=258;assert(!nativeExtendedBSS(in,output,0x1e0));
    in.rsnLength=3;assert(!nativeExtendedBSS(in,output,0x1e0));in.rsnLength=4;rsn[0]=221;assert(!nativeExtendedBSS(in,output,0x1e0));
    in.rsnLength=0;in.htRateCount=0;in.vhtMap=0xffff;
    assert(nativeExtendedBSS(in,output,0x1e0));assert(!output[0xc0] && output[0xd0]==255 && output[0xdd]==0);
}

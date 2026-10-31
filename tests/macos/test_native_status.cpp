#include <cassert>
#include <cstring>
#include <cstdint>
#include <initializer_list>
#define __MAC_15_2 150200
#define __IO80211_TARGET __MAC_15_2
#include "../../src/core/Ath10kConnection.hpp"
#include "../../src/macos/native/Ath10kNativeWire.hpp"
static void associationSnapshot(){
 for(unsigned akm:{1u,2u,5u,6u,8u,18u}){
  auto p=new Ath10k::ConnectionState;auto &s=*p;
  s.stage=Ath10k::LinkStage::Assoc;s.secure=true;s.securityAKM=akm;
  s.pairCipher=s.groupCipher=4;s.pmfRequired=akm==5 || akm==8 || akm==18;
  s.local[0]=s.bssid[0]=2;s.local[5]=1;s.bssid[5]=2;
  UInt8 frame[128]{};memcpy(frame+4,s.bssid,6);memcpy(frame+10,s.local,6);memcpy(frame+16,s.bssid,6);
  size_t n=0;UInt8 id[16]{};
  if(akm==8)assert(AthSecurity::buildSAEStationRSN(id,sizeof(id),frame+28,100,n));
  else if(akm==18)assert(AthSecurity::buildOWEStationRSN(frame+28,100,n));
  else if(akm==5)assert(AthSecurity::buildEAPSHA256StationRSN(frame+28,100,n));
  else assert(AthSecurity::buildSelectedStationRSN(4,4,akm,frame+28,100,n));
  assert(Ath10k::retainAssociationRSN(s,frame,28+n));
  assert(s.associationRSNValid && s.associationRSNLength==n && !memcmp(s.associationRSN,frame+28,n));
  UInt8 previous[257];memcpy(previous,s.associationRSN,257);
  frame[28+n]=48;frame[29+n]=0;assert(!Ath10k::retainAssociationRSN(s,frame,30+n));
  assert(!memcmp(previous,s.associationRSN,257));
  assert(!Ath10k::retainAssociationRSN(s,frame,27+n));
  frame[4]^=2;assert(!Ath10k::retainAssociationRSN(s,frame,28+n));frame[4]^=2;
  s.securityAKM=31;assert(!Ath10k::retainAssociationRSN(s,frame,28+n));s.securityAKM=akm;
  s.cancelRequested=true;assert(!Ath10k::retainAssociationRSN(s,frame,28+n));
  Ath10k::resetDisconnected(s);assert(!s.associationRSNValid && !s.associationRSNLength);
  for(auto b:s.associationRSN)assert(!b);delete p;
 }
}
int main(){
 associationSnapshot();
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

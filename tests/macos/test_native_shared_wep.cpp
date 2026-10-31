#define ATH10K_NATIVE_KEY_STAGE_TEST
#include "test_native_pmf_receive.cpp"
static Ath10kPCIDevice *setup(){
 auto d=new Ath10kPCIDevice;auto &s=d->_connection;d->_nativeSecurity=new Ath10kPCIDevice::NativeSecurity;
 s.stage=Ath10k::LinkStage::Auth;s.secure=s.sharedKeyAuth=true;s.pairCipher=1;s.operatingChannel=36;
 memcpy(s.local,c_sta,6);memcpy(s.bssid,c_ap,6);d->_nativeJoinPending=true;
 UInt8 key[5]{},iv[3]={1,2,3};auto sec=d->_nativeSecurity;sec->sharedWEPGeneration=8;
 assert(sec->sharedWEP.begin(8,s.local,s.bssid,key,5,0,iv,100,10000));return d;
}
static const char *tick(Ath10kPCIDevice *d,UInt64 now){ownerGate=true;auto e=d->serviceNativeSharedWEP(now);ownerGate=false;return e;}
static std::vector<UInt8> reply(Ath10kPCIDevice *d,bool final){
 std::vector<UInt8> f(final?30:287);f[0]=0xb0;auto &s=d->_connection;
 memcpy(f.data()+4,s.local,6);memcpy(f.data()+10,s.bssid,6);memcpy(f.data()+16,s.bssid,6);
 f[24]=1;f[26]=final?4:2;if(!final){f[30]=16;f[31]=255;}return f;
}
int main(){
 {auto d=setup();auto &s=d->_connection;
  d->_wmiScan.txOwned=true;assert(!tick(d,100) && d->transmitted.empty());d->_wmiScan.txOwned=false;
  assert(!tick(d,101) && d->transmitted.size()==1 && d->transmitted[0][24]==1);
  auto challenge=reply(d,false);nativeSAEClockMS=102;assert(deliver(d,challenge.data(),challenge.size()));
  assert(!tick(d,103) && d->transmitted.size()==1); // prior DMA still owns request1
  s.txOwned=false;s.txComplete=true;
  assert(!tick(d,104) && d->transmitted.size()==2 && d->transmitted[1].size()==295 && d->transmitted[1][1]==0x40);
  auto done=reply(d,true);nativeSAEClockMS=105;assert(deliver(d,done.data(),done.size()));
  assert(!tick(d,106) && !s.authReply);s.txOwned=false;s.txComplete=true;
  assert(!tick(d,107) && s.authReply && !s.portAuthorized);stop(d);
 }
 {auto d=setup();auto &s=d->_connection;assert(!tick(d,101));
  auto challenge=reply(d,false);challenge[10]^=1;nativeSAEClockMS=102;assert(deliver(d,challenge.data(),challenge.size()));
  assert(d->_nativeSecurity->sharedWEP.state()==AthSecurity::WEPSharedAuthentication::State::Challenge);
  s.txOwned=false;s.txComplete=true;assert(!tick(d,500) && d->transmitted.size()==1);
  assert(!tick(d,1101) && d->transmitted.size()==2);s.txOwned=false;s.txComplete=true;
  assert(!tick(d,2101) && d->transmitted.size()==3);s.txOwned=false;s.txComplete=true;
  assert(tick(d,3101) && d->transmitted.size()==3);stop(d);
 }
 {auto d=setup();d->_connection.cancelRequested=true;assert(tick(d,101) && d->transmitted.empty());stop(d);}
 {auto d=setup();auto &s=d->_connection;UInt8 frame[320]{};
  assert(!Ath10k::buildStationManagement(frame,sizeof(frame),s));
  auto open=reply(d,true);open[24]=0;open[26]=2;s.submitted=true;
  Ath10k::receiveStationManagement(s,open.data(),open.size(),0,36);assert(!s.authReply);stop(d);
 }
}

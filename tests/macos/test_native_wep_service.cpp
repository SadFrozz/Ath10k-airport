#include <cassert>
#include <cstring>
#include <vector>
#include "Ath10kWMI.hpp"
#include "Ath10kCE.hpp"
#include "../../src/macos/native/Ath10kNativeWEPExecution.hpp"
namespace Ath10k {
 static CESnapshot testCE{};
 inline bool readCESnapshot(int,unsigned,CESnapshot &out){out=testCE;return true;}
}
class Ath10kPCIDevice {
public:
 struct Security {AthNative::EAPOwner eapOwner;AthNative::WEPExecution wepExecution;
  UInt32 wepEchoSerial=0;bool eapTXInFlight=false;} security;
 Security *_nativeSecurity=&security;
 Ath10k::ConnectionState _connection{};
 Ath10k::WMIEchoState _connectionEcho{};
 struct {bool completed=true,cancelRequested=false;} _wmiScan;
 struct {bool active=true;} _wmiLive;
 struct {Ath10k::HTCCreditState credits{};} _wmi;
 struct {unsigned pendingMPDUs=0;} _rxSetup;
 struct {UInt8 endpoint=2;} _htcWMIControl;
 bool _networkEnabled=true,blocked=false;int _regs=0;
 struct Buffer {UInt8 bytes[256]{};void *virtualAddress(){return bytes;}bool syncFromDevice(){return true;}} _connectionCommand,_ceSrcRings[4];
 std::vector<std::vector<UInt8>> sent;
 bool powerIOBlocked(){return blocked;}
 bool validateBMIPipeStructure(unsigned,const Ath10k::CESnapshot &){return true;}
 const char *submitNetworkCE(unsigned,Buffer &b,UInt32 n,UInt32 &next){
  sent.emplace_back(b.bytes,b.bytes+n);++next;_connection.wmiOwned=true;
  Ath10k::testCE.srcWriteIndex=next;return nullptr;
 }
 void serviceNativeWEP(UInt64);
 void setup(){
  auto &s=_connection;s.stage=Ath10k::LinkStage::Connected;s.vdevUp=true;
  s.secure=true;s.securityAKM=1;s.pairCipher=1;s.groupCipher=1;s.peerId=7;s.peerCount=1;s.peerIDs[0]=1u<<7;
  s.local[0]=2;s.local[5]=1;s.bssid[0]=2;s.bssid[5]=2;
  assert(security.eapOwner.beginDynamicWEP(s.local,s.bssid,0,10000));
  UInt8 key[148]{};key[0]=1;key[4]=5;key[8]=1;key[12]=2;key[16]=7;
  assert(security.eapOwner.setWEPKey(security.eapOwner.generation(),s.local,s.bssid,key,sizeof(key),1)==AthNative::EAPOwner::KeyResult::Accepted);
  Ath10k::testCE={};
 }
 void retireCE(){Ath10k::testCE.currentSrcRead=_connection.wmiNext;}
 void ack(){UInt8 frame[36]{};frame[8]=0xb;frame[9]=_connection.wepKeyReceipt.expected;frame[10]=7;
  assert(!Ath10k::validateConnectionHTT(_connection,frame,sizeof(frame)));Ath10k::commitConnectionHTT(_connection,frame);}
};
#include "native_wep_service.inc"
int main(){
 {Ath10kPCIDevice d;d.setup();auto &s=d._connection;auto &owner=d.security.eapOwner;
  UInt8 key[13]{};assert(owner.beginStaticWEP(s.local,s.bssid,0,1000,key,13,2));
  s.pairCipher=s.groupCipher=5;s.wepSelected=true;
  for(UInt64 now=2;now<100 && s.securityPhase!=3;++now){
   d.serviceNativeWEP(now);
   assert(!s.portAuthorized);
   if(s.wmiOwned)d.retireCE();
   if(s.wepKeyReceipt.active && !s.wepKeyReceipt.received)d.ack();
   if(s.wepEchoPending)d._connectionEcho.replyReceived=true;
  }
  assert(s.securityPhase==3 && s.authorizeRequested && !s.portAuthorized);
  assert(owner.staticWEPReady(owner.generation(),s.local,s.bssid,100));
  assert(!owner.validAt(1001)); // key programming alone cannot retire auth deadline
  s.securityPhase=5;s.portAuthorized=true;d.serviceNativeWEP(101);
  assert(owner.validAt(1001) && !s.cancelRequested);
 }

 {Ath10kPCIDevice d;d.setup();auto &s=d._connection;
  for(unsigned op=0;op<2;++op){
   d.serviceNativeWEP(2+op*10);assert(d.sent.size()==1+op*2 && s.wmiOwned);
   d.serviceNativeWEP(3+op*10);assert(d.sent.size()==1+op*2 && s.wmiOwned);
   d.retireCE();d.serviceNativeWEP(4+op*10);assert(!s.wmiOwned && !s.wepEchoPending);
   d.ack();d.serviceNativeWEP(5+op*10);assert(d.sent.size()==2+op*2 && s.wepEchoPending && s.wmiOwned);
   assert(Ath10k::connLE32(d.sent.back().data()+8)==0x1d001);
   d.retireCE();d._connectionEcho.replyReceived=true;d._rxSetup.pendingMPDUs=1;
   d.serviceNativeWEP(6+op*10);assert(s.wepEchoPending && s.wepKeyReceipt.active);
   d._rxSetup.pendingMPDUs=0;d.serviceNativeWEP(7+op*10);
   assert(!s.wepEchoPending && !s.wepKeyReceipt.active && s.wepIOActive);
  }
  d.serviceNativeWEP(30);assert(s.wepInstalledLengths[0][0]==5 && s.wepInstalledLengths[1][0]==5 && s.securityGeneration==1);assert(!s.wepIOActive && !d.security.eapOwner.pending() && !s.portAuthorized && !s.securityAck);
 }
 for(bool timeout:{false,true}){
  Ath10kPCIDevice d;d.setup();auto &s=d._connection;d.serviceNativeWEP(2);
  assert(s.wmiOwned && s.wepIOActive);
  if(!timeout)s.cancelRequested=true;
  d.serviceNativeWEP(timeout?6000:3);
  assert(s.cancelRequested && s.wmiOwned && s.wepIOActive && !s.portAuthorized);
  d.security.eapOwner.clear();d.serviceNativeWEP(6001);assert(s.wmiOwned);
  // Late key indication is consumed without acknowledging a teardown command.
  d.ack();assert(!s.securityAck && !s.wepKeyReceipt.received);
 }
}

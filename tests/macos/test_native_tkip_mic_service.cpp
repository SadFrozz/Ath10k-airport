#include <cassert>
#include <cstring>
#include "../../src/core/Ath10kRX.hpp"
#include "../../src/security/Ath10kTKIPMICOwner.hpp"
class Ath10kPCIDevice {
public:
 struct Security {
 UInt8 tkipMICNoticeBSSID[6]{};UInt32 tkipMICNoticeGeneration=0;unsigned tkipMICNotices=0;UInt8 tkipMICNoticeKinds[2]{6,6};
  AthSecurity::TKIPMICOwner tkipMICOwner;
  AthSecurity::TKIPMICOwner::Ticket tkipMICTicket{};
  bool tkipDeauthPending=false,tkipDeauthInFlight=false;UInt64 tkipDeauthDeadline=0;bool tkipMICInFlight=false,ready=true,keysPending=false,replyPending=false,authorizePending=false,ptkUpdatePending=false,eapTXInFlight=false;
  struct {UInt64 generation()const{return 7;}}profile;
  struct {bool fail=false,lastPairwise=false;bool pairwisePending()const{return false;}
   bool buildMICFailureReport(UInt8 *p,size_t n,size_t &bytes,bool pairwise){lastPairwise=pairwise;assert(n==113);memset(p,0xab,n);bytes=n;return !fail;}
  }supplicant;
 } sec;
 Security *_nativeSecurity=&sec;Ath10k::ConnectionState _connection{};
 struct {bool completed=true,cancelRequested=false;}_wmiScan;
 bool _nativeRadioOn=true,_networkEnabled=true;unsigned submitted=0;bool submitFail=false;
 bool powerIOBlocked()const{return false;}
 const char *submitNetworkPacket(const UInt8 *p,UInt32 n,bool mgmt,UInt64,AthSecurity::ManagementTX mode,Ath10k::ConnectionState::EAPOLPurpose purpose){
  assert(mode==AthSecurity::ManagementTX::Plain);
  if(mgmt){assert(n==26 && p[0]==0xc0 && Ath10k::htcReadLE16(p+24)==14);
   assert(purpose==Ath10k::ConnectionState::EAPOLPurpose::MICDeauth);
  }else {assert(n==113 && p[0]==0xab && purpose==Ath10k::ConnectionState::EAPOLPurpose::MICReport);}
  ++submitted;
  if(submitFail)return "submission-failed";
  _connection.micReportCompletion.begin(12);return nullptr;
 }
 bool nativeRecordTKIPMIC(const Ath10k::GroupTKIPMICFailure &,UInt64);
 void serviceNativeTKIPMIC(UInt64);
 Ath10kPCIDevice(){auto &s=_connection;s.stage=Ath10k::LinkStage::Connected;s.secure=s.portAuthorized=s.pairInstalled=true;
  s.groupCipher=AthSecurity::cipherTKIP;s.securityPhase=5;s.groupInstalled[2]=true;s.groupKeyEpoch[2]=19;
  assert(sec.tkipMICOwner.begin(7,0));assert(sec.tkipMICOwner.detect({7,19,1,2,16},100)==AthSecurity::TKIPMICOwner::Detection::Report);
 }
};
#include "native_tkip_mic_service.inc"
int main(){
 {Ath10kPCIDevice d;auto &s=d._connection;d.sec.tkipMICOwner.retire();
  s.peerId=7;s.peerCount=1;s.peerIDs[0]=1u<<7;s.securityGeneration=42;
  s.pairCipher=AthSecurity::cipherTKIP;s.groupCipher=AthSecurity::cipherCCMP;s.pairKeyEpoch=33;
  Ath10k::GroupTKIPMICFailure e{10,33,42,7,0,16,true,true};
  assert(d.nativeRecordTKIPMIC(e,70000));assert(d.sec.tkipMICNoticeKinds[0]==5);
  d.serviceNativeTKIPMIC(70001);assert(d.submitted==1 && d.sec.supplicant.lastPairwise);
  s.micReportCompletion.retire(12,0);d.serviceNativeTKIPMIC(70002);
  assert(!s.cancelRequested && !d.sec.tkipMICOwner.pending());
  ++e.tsc;e.keyEpoch=32;assert(!d.nativeRecordTKIPMIC(e,70003));
  e.keyEpoch=33;assert(d.nativeRecordTKIPMIC(e,70003) && s.tkipDataBlocked);
 }

 {Ath10kPCIDevice d;auto &s=d._connection;d.sec.tkipMICOwner.retire();
  s.peerId=7;s.peerCount=1;s.peerIDs[0]=1u<<7;s.securityGeneration=42;
  Ath10k::GroupTKIPMICFailure e{10,19,42,7,2,16,true};
  // Constructor seeded a first failure. Use a later window for a fresh report.
  assert(d.nativeRecordTKIPMIC(e,70000) && d.sec.tkipMICOwner.pending()==1);
  assert(!d.nativeRecordTKIPMIC(e,70001) && d.sec.tkipMICOwner.pending()==1);
  e.generation=41;++e.tsc;assert(!d.nativeRecordTKIPMIC(e,70002));e.generation=42;
  e.keyEpoch=18;assert(!d.nativeRecordTKIPMIC(e,70002));e.keyEpoch=19;
  assert(d.nativeRecordTKIPMIC(e,70003) && s.tkipDataBlocked && s.eapolPause);
  assert(d.sec.tkipMICOwner.blocked(130002));
  d.serviceNativeTKIPMIC(70004);assert(d.submitted==1);
 }

 {Ath10kPCIDevice d;d.serviceNativeTKIPMIC(101);assert(d.submitted==1 && d.sec.tkipMICInFlight);
  d._connection.micReportCompletion.retire(12,0);d.serviceNativeTKIPMIC(102);
  assert(!d.sec.tkipMICOwner.pending() && !d._connection.authorizeRequested && !d._connection.cancelRequested);}
 {Ath10kPCIDevice d;assert(d.sec.tkipMICOwner.detect({7,19,2,2,16},101)==AthSecurity::TKIPMICOwner::Detection::Countermeasures);
  d._connection.tkipDataBlocked=true;d.sec.tkipDeauthPending=true;d.sec.tkipDeauthDeadline=6101;d.serviceNativeTKIPMIC(102);d._connection.micReportCompletion.retire(12,0);
  d.serviceNativeTKIPMIC(103);assert(d.submitted==2 && !d._connection.cancelRequested);
  d._connection.micReportCompletion.retire(12,0);d.serviceNativeTKIPMIC(104);assert(d.submitted==3 && d.sec.tkipDeauthInFlight && !d._connection.cancelRequested);
  d._connection.micReportCompletion.retire(12,0);d.serviceNativeTKIPMIC(105);
  assert(d._connection.cancelRequested && d._connection.tkipDataBlocked);}
 for(unsigned failure=0;failure<2;++failure){Ath10kPCIDevice d;
  d._connection.tkipDataBlocked=true;d.sec.tkipDeauthPending=true;d.sec.tkipDeauthDeadline=6100;
  d.serviceNativeTKIPMIC(101);assert(d.submitted==1);
  if(failure==0){d._connection.micReportCompletion.retire(12,1);d.serviceNativeTKIPMIC(102);}
  else {d._connection.txOwned=true;d.serviceNativeTKIPMIC(5100);assert(d.submitted==1 && !d._connection.cancelRequested);
   d._connection.txOwned=false;d.serviceNativeTKIPMIC(5101);}
  assert(d.submitted==2 && d.sec.tkipDeauthInFlight && !d._connection.cancelRequested);
  d._connection.micReportCompletion.retire(12,0);d.serviceNativeTKIPMIC(failure?5102:103);
  assert(d._connection.cancelRequested && d._connection.tkipDataBlocked);
 }
 for(unsigned failure=0;failure<2;++failure){Ath10kPCIDevice d;
  d._connection.tkipDataBlocked=true;d.sec.tkipDeauthPending=true;d.sec.tkipDeauthDeadline=6100;
  d.submitFail=failure==0;d.sec.supplicant.fail=failure==1;
  d.serviceNativeTKIPMIC(101);assert(!d._connection.cancelRequested && !d.sec.tkipMICOwner.pending());
  d.submitFail=false;d.sec.supplicant.fail=false;d.serviceNativeTKIPMIC(102);
  assert(d.sec.tkipDeauthInFlight && !d._connection.cancelRequested);
 }
 for(unsigned failure=0;failure<3;++failure){Ath10kPCIDevice d;
  d.sec.tkipMICOwner.retire();d.sec.tkipDeauthPending=true;d.sec.tkipDeauthDeadline=6100;d._connection.tkipDataBlocked=true;
  if(failure==0){d._connection.txOwned=true;d.serviceNativeTKIPMIC(6100);}
  if(failure==1){d.submitFail=true;d.serviceNativeTKIPMIC(101);}
  if(failure==2){d.serviceNativeTKIPMIC(101);d._connection.micReportCompletion.retire(12,1);d.serviceNativeTKIPMIC(102);}
  assert(d._connection.cancelRequested && !d._connection.authorizeRequested);
 }
 for(unsigned failure=0;failure<4;++failure){Ath10kPCIDevice d;
  if(failure==0)d._connection.groupKeyEpoch[2]=20;
  if(failure==1)d.sec.supplicant.fail=true;
  if(failure==2)d.submitFail=true;
  if(failure==3)d._connection.txOwned=true;
  d.serviceNativeTKIPMIC(failure==3?5100:101);assert(d._connection.cancelRequested && !d._connection.authorizeRequested);}
 {Ath10kPCIDevice d;d._connection.radio.appliedPS=true;d._wmiScan.completed=false;
  d.serviceNativeTKIPMIC(101);assert(!d.submitted && d._connection.eapolPause);
  assert(d._wmiScan.cancelRequested && d._connection.radio.txWakeRequested && d._connection.radio.txWakeRequests==1);
  d.serviceNativeTKIPMIC(102);assert(d._connection.radio.txWakeRequests==1);
  d._wmiScan.completed=true;d._connection.radio.appliedPS=false;d.serviceNativeTKIPMIC(103);assert(d.submitted==1);}
 {Ath10kPCIDevice d;d._connection.dataPending=1;d.serviceNativeTKIPMIC(101);assert(!d.submitted && !d._connection.cancelRequested);
  d._connection.dataPending=0;d.serviceNativeTKIPMIC(102);assert(d.submitted==1);}
}

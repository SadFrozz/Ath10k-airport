#include <cassert>
#include <initializer_list>
#include <cstring>
#include "../../src/macos/native/Ath10kNativeWEPExecution.hpp"
using O=AthNative::EAPOwner;
using E=AthNative::WEPExecution;
static void staticProfiles(){
 uint8_t station[6]={2,0,0,0,0,1},peer[6]={2,0,0,0,0,2},key[13]{};
 for(unsigned length:{5u,13u})for(unsigned index=0;index<4;++index){
  O owner;E engine;assert(owner.beginStaticWEP(station,peer,0,1000,key,length,index));
  const auto generation=owner.generation();assert(owner.staticWEP() && !owner.dynamicWEP());
  assert(!owner.finishStaticWEP(generation,station,peer,1));
  unsigned commands=0,installs=0,selections=0;
  while(owner.keyPending()){
   assert(engine.begin(owner,station,peer,7,2,100));
   while(engine.state()!=E::State::Complete){
    uint8_t command[256]{};assert(engine.build(owner,station,peer,3,command,sizeof(command),2,1));
    assert(engine.submitted(owner,station,peer,4));++commands;
    if(engine.expectedReceipt()!=255){++installs;assert(engine.acknowledge(7,engine.expectedReceipt()));}
    else ++selections;
    assert(engine.transportRetired(owner,station,peer,5));assert(engine.fenceRetired(owner,station,peer,6));
   }
   assert(engine.commit(owner,station,peer,7));
  }
  assert(commands==3 && installs==2 && selections==1); // no reinstall for TX selection
  uint8_t record[148]{};assert(owner.setWEPKey(generation,station,peer,record,sizeof(record),8)==O::KeyResult::Invalid);
  assert(!owner.finishStaticWEP(generation+1,station,peer,9));
  assert(owner.finishStaticWEP(generation,station,peer,9));assert(owner.validAt(1001));
  assert(!owner.beginReplacement(generation,station,peer,10,100));
  owner.clear();assert(!owner.wep() && !owner.staticWEP());
 }
}
// Reconnect to the same BSSID must not let a late old completion publish
// new-session keys, including after the final fence but before host commit.
static void replacementOwnership(){
 uint8_t station[6]={2,0,0,0,0,1},peer[6]={2,0,0,0,0,2};
 for(unsigned length:{5u,13u})for(unsigned flags:{2u,5u})for(unsigned phase=0;phase<5;++phase){
  O owner;E engine;uint8_t record[148]{};
  auto seed=[&](uint64_t now){
   assert(owner.beginDynamicWEP(station,peer,now,now+1000));
   record[0]=1;record[4]=length;record[8]=length==5?1:2;record[12]=flags;record[16]++;
   assert(owner.setWEPKey(owner.generation(),station,peer,record,sizeof(record),now+1)==O::KeyResult::Accepted);
  };
  seed(0);const auto retiredGeneration=owner.generation();
  assert(engine.begin(owner,station,peer,7,2,100));const auto retiredTicket=engine.ticket();
  if(phase>=1)assert(engine.submitted(owner,station,peer,3));
  if(phase>=2){assert(engine.acknowledge(7,engine.expectedReceipt()));assert(engine.transportRetired(owner,station,peer,4));}
  if(phase>=3)assert(engine.fenceRetired(owner,station,peer,5));
  if(phase==4){
   assert(engine.submitted(owner,station,peer,6));
   if(engine.expectedReceipt()!=255)assert(engine.acknowledge(7,engine.expectedReceipt()));
   assert(engine.transportRetired(owner,station,peer,7));assert(engine.fenceRetired(owner,station,peer,8));
   assert(engine.state()==E::State::Complete);
  }
  seed(20);assert(owner.generation()!=retiredGeneration);
  const auto *pending=owner.frontWEPKey(owner.generation(),station,peer,22);
  assert(pending && pending->ticket!=retiredTicket);const auto newTicket=pending->ticket;
  assert(!engine.commit(owner,station,peer,22));
  assert(engine.state()==E::State::Uncertain && !engine.acknowledge(7,3));
  assert(!engine.begin(owner,station,peer,7,23,200));
  assert(!owner.installedWEPKey(owner.generation(),station,peer,0,false,23));
  assert(owner.frontWEPKey(owner.generation(),station,peer,23)->ticket==newTicket);
  assert(!owner.finishWEPKey(retiredGeneration,station,peer,retiredTicket,23));
  engine.firmwareRetired();assert(engine.begin(owner,station,peer,7,24,200));
  engine.cancel();assert(!engine.commit(owner,station,peer,25));
  assert(engine.state()==E::State::Uncertain && owner.keyPending());
 }
}
int main(){
 staticProfiles();replacementOwnership();
 // Exercise the production HTT validator/dispatcher, not a simulated ACK.
 for(uint8_t cipher:{uint8_t(1),uint8_t(5)})for(bool pair:{false,true}){
  Ath10k::ConnectionState s{};s.secure=true;s.securityAKM=1;s.pairCipher=cipher;
  s.stage=Ath10k::LinkStage::Connected;s.peerIDs[0]=1u<<7;
  const uint8_t expected=(cipher==1?3:2)|(pair?0x80:0);
  assert(Ath10k::armWEPKeyReceipt(s,1,9,7,expected));
  assert(!Ath10k::armWEPKeyReceipt(s,1,10,7,expected));
  uint8_t frame[36]{};frame[8]=0xb;frame[9]=expected;frame[10]=7;
  assert(!Ath10k::retireWEPKeyReceiptAfterFence(s,1,9));
  for(unsigned bad=0;bad<4;++bad){auto copy=s;
   if(bad==0)copy.submitted=true;
   if(bad==1)copy.securityPhase=1;
   if(bad==2)copy.wepKeyReceipt.peer=8;
   if(bad==3)copy.pairCipher=4;
   assert(!Ath10k::validateConnectionHTT(copy,frame,sizeof(frame)));
   Ath10k::commitConnectionHTT(copy,frame);
   assert(copy.securityReceiptRejected && copy.cancelRequested && !copy.portAuthorized);
   assert(!copy.wepKeyReceipt.received && !copy.securityAck && copy.wepKeyReceipt.active);
   assert(copy.securityInd.rejected==1 && copy.securityInd.firstRejectPeer==7);
  }
  assert(!Ath10k::validateConnectionHTT(s,frame,sizeof(frame)));
  Ath10k::commitConnectionHTT(s,frame);
  assert(s.wepKeyReceipt.received && !s.securityAck && !s.portAuthorized);
  assert(!Ath10k::validateConnectionHTT(s,frame,sizeof(frame)));
  Ath10k::commitConnectionHTT(s,frame);assert(s.securityInd.ignored==1 && !s.securityAck);
  assert(!Ath10k::retireWEPKeyReceiptAfterFence(s,2,9));
  assert(!Ath10k::retireWEPKeyReceiptAfterFence(s,1,10));
  assert(Ath10k::retireWEPKeyReceiptAfterFence(s,1,9));
  assert(!s.wepKeyReceipt.active && !s.securityAck);
  assert(!Ath10k::validateConnectionHTT(s,frame,sizeof(frame)));
  Ath10k::commitConnectionHTT(s,frame);assert(s.securityReceiptRejected && !s.securityAck);
 }

 uint8_t station[6]{2,1,2,3,4,5},peer[6]{2,6,7,8,9,10};
 for(unsigned length:{5u,13u})for(unsigned flags:{2u,5u}){
  O owner;E engine;uint8_t record[148]{};
  assert(owner.beginDynamicWEP(station,peer,0,1000));
  record[0]=1;record[4]=length;record[8]=length==5?1:2;record[12]=flags;record[14]=3;record[16]=0x42;
  assert(owner.setWEPKey(owner.generation(),station,peer,record,sizeof(record),1)==O::KeyResult::Accepted);
  assert(engine.begin(owner,station,peer,7,2,900));
  assert(!engine.begin(owner,station,peer,7,2,900));
  for(unsigned op=0;op<2;++op){
   assert(!engine.commit(owner,station,peer,3));
   uint8_t command[160];memset(command,0x55,sizeof(command));
   assert(!engine.build(owner,station,peer,3,command,1,2,1));
   for(auto b:command)assert(b==0x55);
   const auto bytes=engine.build(owner,station,peer,3,command,sizeof(command),2,1);
   const bool select=flags==5 && op==1;
   assert(bytes==(select?28:112+((length+3)&~3u)));
   assert(Ath10k::connLE32(command+8)==(select?0x5008u:0x5009u));
   assert(Ath10k::connLE32(command+(select?24:28))==3);
   if(!select){assert(command[112]==0x42);assert(Ath10k::connLE32(command+32)==(flags==2 && op==0?1u:0u));}
   assert(!engine.fenceRetired(owner,station,peer,3));
   assert(engine.submitted(owner,station,peer,4));
   assert(!engine.build(owner,station,peer,4,command,sizeof(command),2,1));
   if(!select){
    assert(!engine.transportRetired(owner,station,peer,5));
    auto expected=engine.expectedReceipt();
    assert(!engine.acknowledge(8,expected));assert(!engine.acknowledge(7,expected^0x80));
    assert(engine.acknowledge(7,expected));assert(!engine.acknowledge(7,expected));
   }else assert(!engine.acknowledge(7,0xff));
   assert(engine.transportRetired(owner,station,peer,5));
   assert(!engine.commit(owner,station,peer,5));
   assert(engine.fenceRetired(owner,station,peer,6));
  }
  assert(engine.commit(owner,station,peer,7));
  assert(engine.state()==E::State::Idle && !owner.keyPending());
  uint8_t txIndex=99;
  assert(owner.confirmedWEPTransmitIndex(owner.generation(),station,peer,7,txIndex)==(flags==5));
  assert(txIndex==(flags==5?3:0));
  Ath10k::ConnectionState tx{};tx.secure=true;tx.pairCipher=length==5?1:5;
  tx.stage=Ath10k::LinkStage::Connected;tx.portAuthorized=true;
  assert(!Ath10k::dataTXAdmissionOpen(tx));
  tx.wepInstalledLengths[0][3]=length;assert(!Ath10k::dataTXAdmissionOpen(tx));
  tx.wepTransmitValid=true;tx.wepTransmitIndex=3;assert(Ath10k::dataTXAdmissionOpen(tx));
  tx.wepIOActive=true;assert(!Ath10k::dataTXAdmissionOpen(tx));
  tx.wepIOActive=false;Ath10k::wipeConnectionSecrets(tx);
  assert(!tx.wepTransmitValid && !tx.wepInstalledLengths[0][3]);

 }
 // Cancel/timeout never permit the next request to borrow old receipts.
 for(unsigned phase=0;phase<4;++phase){
  O owner;E engine;uint8_t record[148]{};
  assert(owner.beginDynamicWEP(station,peer,0,1000));
  record[0]=1;record[4]=5;record[8]=1;record[12]=2;record[16]=7;
  assert(owner.setWEPKey(owner.generation(),station,peer,record,sizeof(record),1)==O::KeyResult::Accepted);
  assert(engine.begin(owner,station,peer,7,2,100));
  if(phase){assert(engine.submitted(owner,station,peer,3));
   if(phase>=2){assert(engine.acknowledge(7,3));assert(engine.transportRetired(owner,station,peer,4));}
   if(phase>=3)assert(engine.fenceRetired(owner,station,peer,5));
  }
  assert(!engine.poll(owner,station,peer,100));
  assert(engine.state()==E::State::Uncertain && owner.keyPending());
  assert(!engine.commit(owner,station,peer,101) && !engine.acknowledge(7,3));
  assert(!engine.begin(owner,station,peer,7,101,200));
  engine.firmwareRetired();assert(engine.begin(owner,station,peer,7,101,200));
  owner.clear();assert(!engine.poll(owner,station,peer,102));
  assert(engine.state()==E::State::Uncertain);
 }
}

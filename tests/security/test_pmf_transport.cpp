#include <cassert>
#include <cstring>
#include <array>
#include <initializer_list>
#include "Ath10kConnection.hpp"
#include "../fixtures/pmf_ccmp_vectors.inc"
using Mode=AthSecurity::ManagementTX;
static void sharedWEPTransport(){
 Ath10k::ConnectionState s{};s.stage=Ath10k::LinkStage::Auth;s.secure=s.sharedKeyAuth=true;s.pairCipher=1;
 s.local[0]=s.bssid[0]=2;s.local[5]=1;s.bssid[5]=2;
 AthSecurity::WEPSharedAuthentication owner;uint8_t key[5]{},iv[3]={1,2,3};
 uint8_t challenge[263]={1,0,2,0,0,0,16,255};
 assert(owner.begin(8,s.local,s.bssid,key,5,0,iv,100,1000));assert(owner.requestSubmitted());
 assert(owner.receive(8,s.local,s.bssid,challenge,sizeof(challenge),110));
 uint8_t frame[296]{},cmd[256]{};
 assert(!owner.buildResponseFrame(8,s.local,s.bssid,111,1,frame,256));
 const auto n=owner.buildResponseFrame(8,s.local,s.bssid,111,4095,frame,sizeof(frame));assert(n==295);
 Ath10k::WEPAuthenticationTX proof{&owner,8,111};
 auto build=[&](){return Ath10k::buildHTTPacket(cmd,sizeof(cmd),frame,n,0x1000,0x2000,5,s,true,Mode::SoftwareWEPAuthentication,255,&proof);};
 assert(build() && cmd[9]==0x65); // explicit NO_ENCRYPT, no firmware CCMP/WEP rewrite
 assert(!Ath10k::buildHTTPacket(cmd,sizeof(cmd),frame,n,0x1000,0x2000,5,s,true,Mode::SoftwareWEPAuthentication));
 for(unsigned at:{0u,1u,2u,4u,10u,16u,22u,24u,27u,294u}){frame[at]^=1;assert(!build());frame[at]^=1;}
 proof.generation=7;assert(!build());proof.generation=8;
 proof.now=1000;assert(!build());proof.now=111;
 s.cancelRequested=true;assert(!build());s.cancelRequested=false;
 s.stage=Ath10k::LinkStage::Connected;assert(!build());s.stage=Ath10k::LinkStage::Auth;
 s.portAuthorized=true;assert(!build());s.portAuthorized=false;
 s.pairCipher=4;assert(!build());s.pairCipher=5;assert(!build());s.pairCipher=1;
 s.pmfRequired=true;assert(!build());s.pmfRequired=false;
 s.sharedKeyAuth=false;assert(!build());s.sharedKeyAuth=true;
 assert(build());owner.cancel();assert(!build());
}
int main(){
 sharedWEPTransport();
 Ath10k::ConnectionState s{};s.stage=Ath10k::LinkStage::Connected;s.secure=true;s.pairInstalled=true;s.pmfRequired=true;
 memcpy(s.local,c_sta,6);memcpy(s.bssid,c_ap,6);s.txId=19;s.httSequence=7;
 AthSecurity::PMFCCMPResult result;assert(AthSecurity::PMFHardwareCCMP::prepare(c_txpn1_plain,sizeof(c_txpn1_plain),c_sta,c_ap,1,result));
 assert(result.bytes==sizeof(c_txpn1_hardware) && !memcmp(result.frame,c_txpn1_hardware,result.bytes));
 UInt8 cmd[256]{};
 assert(Ath10k::buildHTTPacket(cmd,sizeof(cmd),result.frame,result.bytes,0x12345678,0x22334455,5,s,true,Mode::HardwareCCMP)==68);
 const UInt8 expected[]={5,0,60,0,0,7,0,0,1,0x61,0x40,0x0c,44,0,19,0,0x78,0x56,0x34,0x12,0xff,0xff,0,0};
 assert(!memcmp(cmd,expected,sizeof(expected)) && !memcmp(cmd+24,c_txpn1_hardware,sizeof(c_txpn1_hardware)));
 auto reject=[&](const UInt8 *p,UInt32 n,bool management,Mode mode){
  memset(cmd,0xa5,sizeof(cmd));assert(!Ath10k::buildHTTPacket(cmd,sizeof(cmd),p,n,0x12345678,0x22334455,5,s,management,mode));
  for(auto v:cmd)assert(v==0xa5);
 };
 reject(result.frame,result.bytes,true,Mode::Plain);reject(result.frame,result.bytes,true,Mode::SoftwareCCMP);
 reject(result.frame,result.bytes,false,Mode::HardwareCCMP);reject(result.frame,result.bytes,true,static_cast<Mode>(99));
 reject(c_txpn1_wire,sizeof(c_txpn1_wire),true,Mode::HardwareCCMP);
 s.pairInstalled=false;reject(result.frame,result.bytes,true,Mode::HardwareCCMP);s.pairInstalled=true;
 s.secure=false;reject(result.frame,result.bytes,true,Mode::HardwareCCMP);s.secure=true;
 s.stage=Ath10k::LinkStage::Auth;reject(result.frame,result.bytes,true,Mode::HardwareCCMP);s.stage=Ath10k::LinkStage::Connected;
 s.disconnect=Ath10k::DisconnectStage::Down;reject(result.frame,result.bytes,true,Mode::HardwareCCMP);s.disconnect=Ath10k::DisconnectStage::None;
 for(unsigned index:{4u,10u,16u,26u,27u,43u}){
  auto bad=std::array<UInt8,sizeof(c_txpn1_hardware)>{};memcpy(bad.data(),c_txpn1_hardware,bad.size());bad[index]^=1;
  reject(bad.data(),bad.size(),true,Mode::HardwareCCMP);
 }
 auto zeroPN=std::array<UInt8,sizeof(c_txpn1_hardware)>{};memcpy(zeroPN.data(),c_txpn1_hardware,zeroPN.size());zeroPN[24]=0;
 reject(zeroPN.data(),zeroPN.size(),true,Mode::HardwareCCMP);
 s.pmfRequired=false;reject(result.frame,result.bytes,true,Mode::HardwareCCMP);s.pmfRequired=true;
 UInt8 unprotected[28];memcpy(unprotected,c_txpn1_plain,sizeof(unprotected));unprotected[1]&=~0x40;
 reject(unprotected,sizeof(unprotected),true,Mode::Plain);
 s.pairInstalled=false;assert(Ath10k::packetProtectionAllowed(unprotected,sizeof(unprotected),s,true,Mode::Plain));s.pairInstalled=true;
 // An unverified raw disconnect is blocked after PMF keys exist, but legacy
 // pre-key rejection still reaches association failure handling.
 UInt8 deauth[26]{};deauth[0]=0xc0;memcpy(deauth+4,s.local,6);memcpy(deauth+10,s.bssid,6);memcpy(deauth+16,s.bssid,6);deauth[24]=6;
 Ath10k::receiveStationManagement(s,deauth,sizeof(deauth),0);assert(!s.cancelRequested);
 s.pairInstalled=false;Ath10k::receiveStationManagement(s,deauth,sizeof(deauth),0);assert(s.cancelRequested);
 s.cancelRequested=false;s.stage=Ath10k::LinkStage::Connected;s.pairInstalled=true;
 UInt8 probe[24]{};probe[0]=0x40;
 assert(Ath10k::buildHTTPacket(cmd,sizeof(cmd),probe,sizeof(probe),0x1000,0x2000,1,s,true) && cmd[9]==0x65);
 reject(probe,23,true,Mode::Plain);
 // Max payload and maximum nonzero PN retain exactly one eight-byte MIC slot.
 UInt8 large[496]{};memcpy(large,c_txpn1_plain,24);large[24]=10;large[25]=1;
 assert(AthSecurity::PMFHardwareCCMP::prepare(large,sizeof(large),c_sta,c_ap,0xffffffffffffull,result) && result.bytes==512);
 assert(Ath10k::buildHTTPacket(cmd,sizeof(cmd),result.frame,result.bytes,0x1000,0x2000,1,s,true,Mode::HardwareCCMP)==76);
 assert(Ath10k::htcReadLE16(cmd+12)==512 && cmd[9]==0x61 && !memcmp(cmd+24,result.frame,50));
 result.bytes=77;result.pn=88;memset(result.frame,0xa5,512);
 for(uint64_t pn:{uint64_t(0),uint64_t(0x1000000000000ull)}){
  assert(!AthSecurity::PMFHardwareCCMP::prepare(c_txpn1_plain,sizeof(c_txpn1_plain),c_sta,c_ap,pn,result));
  assert(result.bytes==77 && result.pn==88);for(auto v:result.frame)assert(v==0xa5);
 }
 assert(!AthSecurity::PMFHardwareCCMP::prepare(result.frame,28,c_sta,c_ap,1,result));
}

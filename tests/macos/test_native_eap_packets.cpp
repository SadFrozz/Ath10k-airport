#include <cassert>
#include <cstring>
#include <vector>
#include <cstdint>
#include "../../src/macos/native/Ath10kNativeEAPOwner.hpp"
using UInt8=uint8_t;using UInt32=uint32_t;
struct Packet {std::vector<UInt8> bytes;bool copyFail=false;};using mbuf_t=Packet*;
size_t mbuf_pkthdr_len(mbuf_t p){return p->bytes.size();}
int mbuf_copydata(mbuf_t p,size_t off,size_t n,void *out){if(p->copyFail)return 1;memcpy(out,p->bytes.data()+off,n);return 0;}
int mbuf_copyback(mbuf_t p,size_t,size_t n,const void *in,int){if(p->copyFail)return 1;p->bytes.resize(n);memcpy(p->bytes.data(),in,n);return 0;}
constexpr int MBUF_DONTWAIT=0,kIOReturnOutputDropped=1,kIOReturnOutputStall=2,kIOReturnOutputSuccess=0;
namespace Ath10k {
constexpr size_t kEthernetFrameMax=1522;uint64_t clockMS=200;uint64_t uptimeNS(){return clockMS*1000000;}
struct ConnectionState {enum Drop{EAPOL,Allocation,Plaintext};bool secure=true;unsigned eapolCount=0;unsigned securityAKM=1;bool associated=true,eapolPause=false;uint8_t local[6]={2,1,2,3,4,5},bssid[6]={2,6,7,8,9,10};unsigned rxPackets=0,rxBytes=0,drops[3]{};};
struct RXBatch {unsigned count=1;UInt8 data[1600]{};unsigned offsets[1]{},lengths[1]{};UInt8 descriptor[16]{};};
bool sameMAC(const UInt8 *a,const UInt8 *b){return !memcmp(a,b,6);}
UInt32 connLE32(const UInt8 *p){return UInt32(p[0])|(UInt32(p[1])<<8)|(UInt32(p[2])<<16)|(UInt32(p[3])<<24);}
bool connectionAssociated(const ConnectionState &s){return s.associated;}void rxDrop(ConnectionState &s,ConnectionState::Drop why){++s.drops[why];}
}
struct Ath10kPCIDevice {
 struct Security{AthNative::EAPOwner eapOwner;} security;Security *_nativeSecurity=&security;
 Ath10k::ConnectionState _connection;struct {bool completed=false,cancelRequested=false;} _wmiScan;
 unsigned frees=0,requests=0;bool allocationFail=false,copybackFail=false;
 struct Interface {unsigned received=0;std::vector<UInt8> last;void inputPacket(mbuf_t p,size_t n){assert(n==p->bytes.size());++received;last=p->bytes;delete p;}} interface;
 Interface *_networkInterface=&interface;
 void freePacket(mbuf_t p){++frees;delete p;}void requestNativeService(){++requests;}
 mbuf_t takeRXPacket(size_t n){if(allocationFail)return nullptr;auto p=new Packet;p->bytes.resize(n);p->copyFail=copybackFail;return p;}
 bool preflight(Ath10k::RXBatch &);bool nativeEAPSystemFrame(const UInt8*,UInt32);UInt32 nativeEAPOutput(mbuf_t);bool nativeEAPReceive(const UInt8*,UInt32);
 Ath10kPCIDevice(){assert(security.eapOwner.begin(_connection.local,_connection.bssid,100,1000));}
 std::vector<UInt8> frame(bool tx){std::vector<UInt8> f(60);memcpy(f.data(),tx?_connection.bssid:_connection.local,6);memcpy(f.data()+6,tx?_connection.local:_connection.bssid,6);f[12]=0x88;f[13]=0x8e;f[14]=2;
 if(tx)f[15]=1;else{f[17]=5;f[18]=1;f[21]=5;f[22]=1;}return f;}
};
#include "native_eap_packets.inc"
#define ATH10K_NATIVE 1
#include "native_eap_preflight.inc"
int main(){
 // Exercise the gap before asynchronous service retires an expired owner.
 for(unsigned boundary=0;boundary<4;++boundary){
  Ath10kPCIDevice d;auto f=d.frame(false);
  Ath10k::clockMS=boundary==0?1000:boundary==1?99:200;
  if(boundary==2)d._connection.associated=false;
  if(boundary==3)d._networkInterface=nullptr;
  if(boundary!=3)assert(!d.nativeEAPSystemFrame(f.data(),f.size()));
  assert(d.nativeEAPReceive(f.data(),f.size()) && !d.interface.received && d._connection.drops[0]==1);
  if(boundary<3)assert(d.nativeEAPOutput(new Packet{d.frame(true)})==kIOReturnOutputDropped && d.frees==1);
 }
 Ath10k::clockMS=200;

 {Ath10kPCIDevice d;auto f=d.frame(false);f.resize(1024);const unsigned body=1024-18;
 f[16]=body>>8;f[17]=UInt8(body);f[20]=body>>8;f[21]=UInt8(body);
 assert(d.nativeEAPSystemFrame(f.data(),f.size()));
 Ath10k::RXBatch batch;memcpy(batch.data,f.data(),f.size());batch.lengths[0]=f.size();
 d._connection.eapolCount=4;assert(d.preflight(batch));
 d._connection.securityAKM=8;assert(!d.preflight(batch));d._connection.securityAKM=1;
 assert(d.nativeEAPReceive(f.data(),f.size()) && d.interface.last.size()==1024);
 d._connection.securityAKM=8;assert(!d.nativeEAPSystemFrame(f.data(),f.size()));
 d._connection.securityAKM=1;f[6]^=2;assert(!d.nativeEAPSystemFrame(f.data(),f.size()));}

 {Ath10kPCIDevice d;for(unsigned i=0;i<4;++i)assert(d.nativeEAPOutput(new Packet{d.frame(true)})==kIOReturnOutputSuccess);
 auto retry=new Packet{d.frame(true)};assert(d.nativeEAPOutput(retry)==kIOReturnOutputStall && d.frees==4);assert(retry->bytes.size()==60);
 d.security.eapOwner.pop();assert(d.nativeEAPOutput(retry)==kIOReturnOutputSuccess && d.frees==5 && d.requests==5 && d._wmiScan.cancelRequested);
 auto bad=new Packet{d.frame(true)};bad->copyFail=true;assert(d.nativeEAPOutput(bad)==kIOReturnOutputDropped && d.frees==6);}
 {Ath10kPCIDevice d;auto f=d.frame(false);assert(d.nativeEAPReceive(f.data(),f.size()));assert(d.interface.received==1 && d.interface.last.size()==23 && d._connection.rxBytes==23);
 f[6]^=2;assert(d.nativeEAPReceive(f.data(),f.size()) && d._connection.drops[0]==1 && d.interface.received==1);}
 {Ath10kPCIDevice d;auto f=d.frame(false);d.allocationFail=true;assert(d.nativeEAPReceive(f.data(),f.size()) && d._connection.drops[1]==1 && !d.frees);
 d.allocationFail=false;d.copybackFail=true;assert(d.nativeEAPReceive(f.data(),f.size()) && d._connection.drops[1]==2 && d.frees==1 && !d.interface.received);}
 {Ath10kPCIDevice d;auto f=d.frame(false);f.resize(113);f[15]=3;f[17]=95;f[18]=2;f[21]=f[22]=0;assert(!d.nativeEAPReceive(f.data(),f.size()) && !d.interface.received);
 d._connection.securityAKM=8;assert(!d.nativeEAPReceive(f.data(),f.size()));}
 {Ath10kPCIDevice d;d.security.eapOwner.clear();assert(d.nativeEAPOutput(new Packet{d.frame(true)})==kIOReturnOutputDropped && d.frees==1);}
}

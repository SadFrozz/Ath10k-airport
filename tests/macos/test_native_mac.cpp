#include <cassert>
#include <cstring>
#include <vector>
#include <memory>
#include "../../src/macos/native/Ath10kNativeMAC.hpp"
using IOReturn=int;
static constexpr IOReturn kIOReturnSuccess=0;
static const char *kIOMACAddress="IOMACAddress";
// The hardware seam exposes only the two ring indices consumed by this method.
namespace Ath10k {struct CESnapshot {UInt32 srcWriteIndex=0,currentSrcRead=0;};}
struct MACRegs {Ath10k::CESnapshot state{};bool valid=true;};
namespace Ath10k {inline bool readCESnapshot(MACRegs &r,UInt32,CESnapshot &s){s=r.state;return r.valid;}}
static UInt8 bsdAddress[6]{};static int bsdError=0;
static int ifnet_set_lladdr(void *,const void *address,unsigned n){assert(n==6);if(bsdError)return bsdError;memcpy(bsdAddress,address,6);return 0;}
struct MACBuffer {UInt8 data[256]{};bool valid=true;void *virtualAddress(){return data;}bool syncFromDevice(){return valid;}};
struct MACInterface {void *getIfnet(){return this;}void setProperty(const char *,const UInt8 *,unsigned){}};
struct MACGate {unsigned wakes=0;void commandWakeup(void *){++wakes;}};
class Ath10kPCIDevice {
public:
 bool _nativeMACActive=true,_nativeMACSubmitted=false,structureValid=true;
 UInt32 _nativeMACStep=1,_nativeMACNext=0,_nativeMACGeneration=1;
 UInt64 _nativeMACSince=1000;
 UInt8 _nativeMACRequested[6]={2,1,2,3,4,5},_nativeMACCurrent[6]={2,5,4,3,2,1};
 IOReturn _nativeMACResult=-1;
 Ath10k::WMIEchoState _nativeMACEcho{};
 struct {Ath10k::HTCCreditState credits;} _wmi;
 struct {UInt8 endpoint=2;} _htcWMIControl;
 Ath10k::ConnectionState _connection{};
 MACBuffer _connectionCommand,_ceSrcRings[4];MACRegs _regs;
 MACInterface iface;MACInterface *_networkInterface=&iface;
 MACGate gate;MACGate *_nativeGate=&gate;
 std::vector<std::vector<UInt8>> frames;
 Ath10kPCIDevice(){_wmi.credits.initialize(2,256,2);}
 bool validateBMIPipeStructure(UInt32,const Ath10k::CESnapshot &){return structureValid;}
 const char *submitNetworkCE(UInt32,MACBuffer &b,UInt32 bytes,UInt32 &next){
  assert(!_connection.wmiOwned && !_wmi.credits.outstanding);
  assert(_wmi.credits.reserve(bytes));_connection.wmiOwned=true;
  frames.emplace_back(b.data,b.data+bytes);next=++_regs.state.srcWriteIndex;return nullptr;
 }
 void completeDMA(){_regs.state.currentSrcRead=_nativeMACNext;_wmi.credits.outstanding=0;_wmi.credits.available=2;}
 void setProperty(const char *,const char *){}void setProperty(const char *,UInt64,unsigned){}
 const char *serviceNativeMAC(UInt64);
};
#include "native_mac_method.inc"
int main(){
 auto d=std::make_unique<Ath10kPCIDevice>();const UInt8 old[]={2,5,4,3,2,1};
 for(unsigned step=1;step<=4;++step){
  assert(!d->serviceNativeMAC(1010+step));assert(d->_nativeMACStep==step && d->frames.size()==step);
  assert(!d->serviceNativeMAC(1020+step));assert(d->frames.size()==step && d->_connection.wmiOwned);
  assert(!memcmp(old,d->_nativeMACCurrent,6) && d->gate.wakes==0);
  d->completeDMA();
  if(step==2 || step==4){
   // Returned DMA/credits cannot satisfy an ECHO semantic barrier.
   assert(!d->serviceNativeMAC(1030+step));assert(d->_nativeMACStep==step && d->_nativeMACActive);
   UInt8 reply[20]{};reply[0]=2;Ath10k::htcWriteLE16(reply+2,12);
   Ath10k::htcWriteLE32(reply+8,0x1d001);Ath10k::htcWriteLE16(reply+12,4);Ath10k::htcWriteLE16(reply+14,54);
   Ath10k::htcWriteLE32(reply+16,d->_nativeMACEcho.cookie+1);
   Ath10k::WMIInitState events{};
   assert(Ath10k::parseWMIInitResponse(reply,20,2,d->_wmi.credits,events,&d->_nativeMACEcho));
   assert(!d->_nativeMACEcho.replyReceived);
   Ath10k::htcWriteLE32(reply+16,d->_nativeMACEcho.cookie);
   assert(!Ath10k::parseWMIInitResponse(reply,20,2,d->_wmi.credits,events,&d->_nativeMACEcho));
  }
  assert(!d->serviceNativeMAC(1040+step));
 }
 assert(!d->_nativeMACActive && d->_nativeMACResult==0 && d->gate.wakes==1);
 assert(!memcmp(d->_nativeMACCurrent,d->_nativeMACRequested,6) && !memcmp(bsdAddress,d->_nativeMACRequested,6));
 assert(Ath10k::wmiReadLE32(d->frames[0].data()+8)==0x5002 && Ath10k::wmiReadLE32(d->frames[2].data()+8)==0x5001);
 assert(!memcmp(d->frames[2].data()+28,d->_nativeMACRequested,6));
 assert(d->frames[1]!=d->frames[3]); // Distinct cookies for the two barriers.
 auto timeout=std::make_unique<Ath10kPCIDevice>();assert(timeout->serviceNativeMAC(6000));assert(timeout->gate.wakes==0 && timeout->frames.empty());
 auto backwards=std::make_unique<Ath10kPCIDevice>();assert(backwards->serviceNativeMAC(999));
 auto bad=std::make_unique<Ath10kPCIDevice>();assert(!bad->serviceNativeMAC(1001));bad->_regs.valid=false;
 assert(bad->serviceNativeMAC(1002) && bad->gate.wakes==0 && !memcmp(old,bad->_nativeMACCurrent,6));
 auto sync=std::make_unique<Ath10kPCIDevice>();assert(!sync->serviceNativeMAC(1001));sync->completeDMA();sync->_connectionCommand.valid=false;
 assert(sync->serviceNativeMAC(1002) && sync->gate.wakes==0 && !memcmp(old,sync->_nativeMACCurrent,6));
 auto bsd=std::make_unique<Ath10kPCIDevice>();bsd->_nativeMACStep=4;assert(!bsd->serviceNativeMAC(1001));bsd->completeDMA();bsd->_nativeMACEcho.replyReceived=true;bsdError=1;
 assert(bsd->serviceNativeMAC(1002) && bsd->gate.wakes==0 && !memcmp(old,bsd->_nativeMACCurrent,6));
}

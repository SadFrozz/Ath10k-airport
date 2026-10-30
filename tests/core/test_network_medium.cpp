// Execute the production selector for both personalities. This models the
// BSD media-type consumer, not a live IONetworkController or ioctl call.
#include <cassert>
#include <initializer_list>
using IOMediumType=unsigned;
using IOReturn=int;
constexpr unsigned kIOMediumEthernetAuto=0x20,kIOMediumIEEE80211Auto=0x80;
constexpr int kIOReturnSuccess=0,kIOReturnUnsupported=1,kIOReturnError=2;
struct IONetworkMedium {
    unsigned type;
    unsigned getType() const {return type;}
};
struct Selector {
    bool accept=true;unsigned calls=0;const IONetworkMedium *selected=nullptr;
    bool setSelectedMedium(const IONetworkMedium *medium) {
        ++calls;if(!accept)return false;selected=medium;return true;
    }
};
namespace Native {
struct Ath10kPCIDevice:Selector {IOReturn selectMedium(const IONetworkMedium *);};
#define ATH10K_NATIVE 1
#include "network_medium.inc"
#undef ATH10K_NATIVE
}
namespace Diagnostic {
struct Ath10kPCIDevice:Selector {IOReturn selectMedium(const IONetworkMedium *);};
#include "network_medium.inc"
}
template<class Driver> void verify(unsigned wanted,unsigned wrong) {
    Driver driver;IONetworkMedium valid{wanted},invalid{wrong};
    assert(driver.selectMedium(nullptr)==kIOReturnUnsupported);
    assert(driver.selectMedium(&invalid)==kIOReturnUnsupported);
    assert(driver.calls==0 && !driver.selected);
    driver.accept=false;
    assert(driver.selectMedium(&valid)==kIOReturnError);
    assert(!driver.selected);
    driver.accept=true;
    assert(driver.selectMedium(&valid)==kIOReturnSuccess);
    assert(driver.selected==&valid && driver.calls==2);
}
namespace Carrier {
namespace Ath10k {enum class DisconnectStage {None,Drain};struct RXBatch {};}
constexpr unsigned kIONetworkLinkValid=1,kIONetworkLinkActive=2;
void IOFree(void *,unsigned){}
struct Ath10kPCIDevice {
 bool _nativeEAPQueueRunning=false;
 bool _networkEnabled=true,_networkLinkUp=true,_nativeDeferredLinkDown=false,_dataTXStalled=false,hold=true;
 struct {bool active=true;} _wmiLive;struct {Ath10k::DisconnectStage disconnect=Ath10k::DisconnectStage::None;} _connection;
 struct Reorder {template<class F>void reset(F){}} _rxReorder;
 struct Reset {void reset(){}} _rxDefrag,_rxBatch;
 struct Queue {unsigned stops=0,flushes=0,starts=0;void stop(){++stops;}void flush(){++flushes;}void start(){++starts;}} queue;
 unsigned reports=0,last=3;
 bool nativeRetainSystemLink(){return hold;}
 Queue *getOutputQueue(){return &queue;}
 void flushNetworkRX(){}
 void setLinkStatus(unsigned flags){++reports;last=flags;}
 void networkLink(bool);
};
#define ATH10K_NATIVE 1
#include "network_carrier.inc"
#undef ATH10K_NATIVE
void verify(){
 {Ath10kPCIDevice d;d._networkLinkUp=false;d.hold=false;d._nativeEAPQueueRunning=true;
  d.networkLink(false);assert(!d._nativeEAPQueueRunning && d.queue.stops==1 && d.queue.flushes==1);
  d.networkLink(false);assert(d.queue.stops==1);
 }
 for(bool success:{false,true}){
  Ath10kPCIDevice d;d.networkLink(false);assert(!d._networkLinkUp && d._nativeDeferredLinkDown && !d.reports);
  d.networkLink(false);assert(!d.reports);
  d.hold=false;d.networkLink(success);assert(d.reports==1 && d.last==(success?3u:1u) && !d._nativeDeferredLinkDown);
  d.networkLink(success);assert(d.reports==1);
 }
}
}
int main() {
    Carrier::verify();
    assert((Native::kAth10kAutoMedium&0xe0)==0x80);
    assert((Diagnostic::kAth10kAutoMedium&0xe0)==0x20);
    verify<Native::Ath10kPCIDevice>(0x80,0x20);
    verify<Diagnostic::Ath10kPCIDevice>(0x20,0x80);
}

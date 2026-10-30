#include <cassert>
#include <cstdint>
#include <initializer_list>
using UInt64=uint64_t;using IOReturn=int;
constexpr IOReturn kIOReturnSuccess=0,kIOReturnNotReady=1,kIOReturnBadArgument=2;
struct OSObject{};
#define OSDynamicCast(type,obj) static_cast<type *>(obj)
#include "../../src/macos/native/Ath10kNativeOps.hpp"
using Action=IOReturn(*)(OSObject *,void *,void *,void *,void *);
class Ath10kPCIDevice;
struct Gate {
    Ath10kPCIDevice *owner;
    bool blockAtEntry=false,stopAtEntry=false,inactivateAtEntry=false;
    unsigned entries=0;
    IOReturn runAction(Action,void *,void *);
};
class Ath10kPCIDevice:public OSObject {
public:
    Gate gate{this};Gate *_nativeGate=&gate;
    bool _nativeStopping=false,blocked=false;unsigned accepted=0;
    struct {bool active=true;} _wmiLive;
    bool powerIOBlocked(){return blocked;}
    template<class... T> void setProperty(T...){}
    IOReturn nativeRequest(AthNativeOp,void *);
    IOReturn nativeRequestGated(AthNativeOp,void *);
    static IOReturn nativeAction(OSObject *,void *,void *,void *,void *);
};
IOReturn Gate::runAction(Action action,void *op,void *data){
    ++entries;if(blockAtEntry)owner->blocked=true;
    if(stopAtEntry)owner->_nativeStopping=true;
    if(inactivateAtEntry)owner->_wmiLive.active=false;
    return action(owner,op,data,nullptr,nullptr);
}
// Exact production public dispatcher/action and the admission prefix of the
// gated handler. The test seam counts acceptance, not firmware side effects.
#include "native_request_admission.inc"
int main(){
    for(auto op:{AthNativeOp::setWCL_SCAN_REQ,AthNativeOp::setWCL_ASSOCIATE,AthNativeOp::MACSet,AthNativeOp::PowerGet,
        AthNativeOp::setIPV4_PARAMS,AthNativeOp::setIPV6_PARAMS,AthNativeOp::setOFFLOAD_ARP,AthNativeOp::setOFFLOAD_NDP}){
        int payload=0;
        Ath10kPCIDevice ready;assert(ready.nativeRequest(op,&payload)==0 && ready.accepted==1 && ready.gate.entries==1);
        Ath10kPCIDevice sleep;sleep.blocked=true;
        assert(sleep.nativeRequest(op,&payload)==kIOReturnNotReady && !sleep.accepted && !sleep.gate.entries);
        // The power intent may arrive after the fast-path check, while a WCL
        // request is waiting for the radio gate. Recheck inside that gate.
        Ath10kPCIDevice queued;queued.gate.blockAtEntry=true;
        assert(queued.nativeRequest(op,&payload)==kIOReturnNotReady && !queued.accepted && queued.gate.entries==1);
        Ath10kPCIDevice stopping;stopping.gate.stopAtEntry=true;
        assert(stopping.nativeRequest(op,&payload)==kIOReturnNotReady && !stopping.accepted);
        Ath10kPCIDevice ended;ended.gate.inactivateAtEntry=true;
        assert(ended.nativeRequest(op,&payload)==kIOReturnNotReady && !ended.accepted);
        Ath10kPCIDevice detached;detached._nativeGate=nullptr;
        assert(detached.nativeRequest(op,&payload)==kIOReturnNotReady && !detached.accepted);
    }
    assert(Ath10kPCIDevice::nativeAction(nullptr,nullptr,nullptr,nullptr,nullptr)==kIOReturnBadArgument);
}

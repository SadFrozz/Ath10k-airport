#include <cassert>
using UInt8=unsigned char;using IOReturn=int;
constexpr int kIOReturnSuccess=0,kIOReturnNotAttached=1,kIOReturnNotPermitted=2,kIOReturnNotReady=3,kIOReturnUnsupported=4,kIOReturnBadArgument=5;
enum class AthNativeOp {setWCL_FAST_LANE,setWCL_LINK_STATE_UPDATE,Other};
struct Loop {bool held=false;bool inGate(){return held;}};
IOReturn validate(AthNativeOp op,void *data){
 if(!data)return kIOReturnBadArgument;using N=AthNativeOp;
 switch(op){
#include "native_policy_admission.inc"
 default:return 0;
 }
}
struct Controller {
 Loop radio;int calls=0,result=0;
 Loop *getWorkLoop(){return &radio;}
 IOReturn nativeRequest(AthNativeOp op,void *data){++calls;assert(!radio.held);radio.held=true;auto r=result?result:validate(op,data);radio.held=false;return r;}
};
struct Ath10kNativeInterface {
 Controller *controller=nullptr;Loop wcl;bool bound=true;int applied=0;bool enabled=false;
 Loop *getWorkLoop(){return &wcl;}void *getBSDInterface(){return bound?this:nullptr;}
 IOReturn perform(AthNativeOp,void *);
};
void ath10kSetFastlaneCapable(Ath10kNativeInterface *p,bool enable){
 assert(p->wcl.held && !p->controller->radio.held && p->bound);++p->applied;p->enabled=enable;
}
#include "native_policy_dispatch.inc"
int main(){
 Controller c;Ath10kNativeInterface p;p.controller=&c;UInt8 data[16]{};data[0]=1;
 assert(p.perform(AthNativeOp::setWCL_FAST_LANE,data)==kIOReturnNotPermitted && !c.calls);
 p.wcl.held=true;c.radio.held=true;
 assert(p.perform(AthNativeOp::setWCL_FAST_LANE,data)==kIOReturnNotPermitted && !c.calls);
 c.radio.held=false;p.bound=false;
 assert(p.perform(AthNativeOp::setWCL_FAST_LANE,data)==kIOReturnNotReady && !c.calls);
 p.bound=true;c.result=kIOReturnUnsupported;
 assert(p.perform(AthNativeOp::setWCL_FAST_LANE,data)==kIOReturnUnsupported && !p.applied);
 c.result=0;assert(!p.perform(AthNativeOp::setWCL_FAST_LANE,data) && p.enabled);
 assert(!p.perform(AthNativeOp::setWCL_LINK_STATE_UPDATE,data) && !p.enabled);
 data[6]=1;int count=p.applied;assert(!p.perform(AthNativeOp::setWCL_LINK_STATE_UPDATE,data) && count==p.applied);
 data[0]=data[1]=1;count=p.applied;
 assert(p.perform(AthNativeOp::setWCL_FAST_LANE,data)==kIOReturnUnsupported && count==p.applied);
 data[0]=0;assert(!p.perform(AthNativeOp::setWCL_FAST_LANE,data) && !p.enabled);
 assert(p.perform(AthNativeOp::setWCL_FAST_LANE,nullptr)==kIOReturnBadArgument);
 p.controller=nullptr;assert(p.perform(AthNativeOp::setWCL_FAST_LANE,data)==kIOReturnNotAttached);
}

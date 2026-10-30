#include <cassert>
#include <cstring>
#include <initializer_list>
namespace Ath10k {enum class LinkStage {Disabled,Scan,Connected}; enum class DisconnectStage {None,Drain,DeletePeer};}
namespace AthSecurity {inline void wipe(void *p,unsigned n){memset(p,0,n);}}
enum class N {setWCL_JOIN_ABORT,setWCL_LEAVE_NETWORK};
constexpr int kIOReturnSuccess=0;
struct Driver {
    struct {Ath10k::LinkStage stage=Ath10k::LinkStage::Disabled;
        Ath10k::DisconnectStage disconnect=Ath10k::DisconnectStage::None;
        bool cancelRequested=false,portAuthorized=false;} s;
    struct {bool completed=true,cancelRequested=false;} _wmiScan;
    struct Security {unsigned resets=0;void reset(){++resets;}} security;
    Security *_nativeSecurity=&security;
    bool _nativeJoinPending=false,_nativeAbortRequested=false,_nativeJoinFailed=false;
    unsigned _nativeRoamJoinGeneration=0;
    unsigned _nativeJoin=123,services=0,links=0;
    void networkLink(bool up){assert(!up);++links;}
    void requestNativeService(){++services;}
    int leave(N op){switch(op){
#include "native_leave.inc"
    }return -1;}
};
int main(){
    for(auto op:{N::setWCL_LEAVE_NETWORK,N::setWCL_JOIN_ABORT}){
        Driver idle;
        assert(idle.leave(op)==0);
        assert(!idle.s.cancelRequested); // Idle leave must not poison the next join.
        assert(!idle.s.portAuthorized && idle.security.resets==1);
        assert(idle.leave(op)==0 && !idle.s.cancelRequested);
        if(op==N::setWCL_JOIN_ABORT)assert(idle._nativeAbortRequested && idle.services==2 && !idle._nativeJoin);
        for(auto stage:{Ath10k::LinkStage::Scan,Ath10k::LinkStage::Connected}){
            Driver active;active.s.stage=stage;active.s.portAuthorized=true;active._wmiScan.completed=false;
            assert(active.leave(op)==0 && active.s.cancelRequested && !active.s.portAuthorized);
            assert(active._wmiScan.cancelRequested && active.security.resets==1);
        }
        // The radio may already be disabled while WCL still owns a join.
        Driver retired;retired._nativeJoinPending=true;
        assert(retired.leave(op)==0 && retired._nativeJoinFailed);
        assert(!retired.s.cancelRequested); // Do not poison the next radio owner.
        if(op==N::setWCL_LEAVE_NETWORK)assert(retired._nativeJoinPending);
        else assert(!retired._nativeJoinPending && retired._nativeAbortRequested);
        Driver roaming;roaming._nativeRoamJoinGeneration=7;roaming._nativeJoinPending=true;
        assert(roaming.leave(op)==0 && roaming._nativeJoinPending && roaming._nativeJoinFailed && roaming._nativeRoamJoinGeneration==7);
        Driver teardown;teardown.s.disconnect=Ath10k::DisconnectStage::DeletePeer;
        assert(teardown.leave(op)==0 && teardown.s.cancelRequested);
    }
}

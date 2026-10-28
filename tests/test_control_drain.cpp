#include <cassert>
#define ATH10K_NATIVE 1
class Ath10kPCIDevice {
public:
    bool powerDrained=false;
    struct Native {bool *done;void drainPowerCalls(){*done=true;}} native{&powerDrained};Native *_nativeInterface=&native;
    bool probePending=false,nativePending=false,nativeAllocated=false;
    bool nativeStopping=false,resourcesLive=true;
    unsigned probeCancels=0,nativeDrains=0;unsigned gateDepth=0;
    void blockPowerIOForTermination(){}
    void drainControlWorkers();
    void cancelDeferredProbe(){
        assert(!gateDepth && resourcesLive);++probeCancels;
        // Model the important race: an already running probe completes by
        // creating a new native worker while cancellation waits for it.
        if(probePending){nativeAllocated=nativePending=true;nativeStopping=false;}
        probePending=false;
    }
    void stopNativeRequests(){
        assert(!gateDepth && resourcesLive && !probePending && powerDrained);
        ++nativeDrains;nativeStopping=true;nativePending=nativeAllocated=false;
    }
    void releaseRadio(){assert(!probePending && !nativePending && nativeStopping);resourcesLive=false;}
};
#include "control_drain_method.inc"
int main(){
    for(unsigned mode=0;mode<4;++mode){
        Ath10kPCIDevice d;
        d.probePending=mode&1;d.nativeAllocated=d.nativePending=mode&2;
        d.drainControlWorkers();
        assert(!d.probePending && !d.nativePending && !d.nativeAllocated && d.nativeStopping);
        assert(d.probeCancels==1 && d.nativeDrains==1);
        d.drainControlWorkers();assert(d.probeCancels==2 && d.nativeDrains==2);
        d.releaseRadio();
    }
}

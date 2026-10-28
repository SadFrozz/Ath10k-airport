#include <cassert>
#include <cstdint>
#include <vector>
#include <algorithm>
static std::vector<unsigned> events;
static void IOLockFree(void *){assert(false);}
#define OSSafeReleaseNULL(p) do{if(p){(p)->release();(p)=nullptr;}}while(0)
namespace AthSecurity {static void wipe(void *p,unsigned n){auto *b=static_cast<volatile uint8_t *>(p);while(n--)*b++=0;}}
struct Native {
    void *provider=nullptr;unsigned stops=0,detaches=0,releases=0;
    void *getProvider(){return provider;}
    void stop(void *owner){assert(provider==owner && !stops);++stops;events.push_back(3);}
    void detach(void *owner){assert(provider==owner);provider=nullptr;++detaches;events.push_back(5);}
    void release(){++releases;events.push_back(6);}
};
struct BSD {unsigned releases=0;void release(){++releases;events.push_back(2);}};
struct IO80211Controller {
    unsigned controllerDetaches=0;
    void detachInterface(Native *,bool synchronous){assert(synchronous);++controllerDetaches;events.push_back(4);}
};
struct IONetworkController {
    unsigned bsdDetaches=0;
    void detachInterface(BSD *,bool synchronous){assert(synchronous);++bsdDetaches;events.push_back(1);}
};
struct Gate;
struct Loop {unsigned removals=0;void removeEventSource(Gate *){++removals;events.push_back(8);}};
struct Gate {
    Loop *loop;unsigned releases=0;Loop *getWorkLoop(){return loop;}
    void release(){++releases;events.push_back(9);}
};
static unsigned securityDeletes=0;
struct Security {~Security(){++securityDeletes;events.push_back(7);}};
class Ath10kPCIDevice:public IO80211Controller,public IONetworkController {
public:
    unsigned drains=0;void *_nativeServiceLock=nullptr;
    bool _nativeStarted=false,_nativeAttached=false,_nativeControllerAttached=false,_nativeReadyPublished=true;
    Native *_nativeInterface=nullptr;BSD *_networkInterface=nullptr;Security *_nativeSecurity=nullptr;
    uint8_t _nativeJoin[48]{};
    Loop radio,wcl;Gate *_nativeGate=nullptr,*_nativeBSDGate=nullptr;
    void stopNativeRequests(){++drains;events.push_back(0);}
    Loop *getWorkLoop(){return &radio;}
    void releaseNativeInterface();
};
#include "native_release_method.inc"
int main(){
    for(unsigned mode=0;mode<6;++mode){
        events.clear();Ath10kPCIDevice d;Native native;BSD bsd;Gate radio{&d.radio},wcl{&d.wcl};
        d._nativeInterface=&native;d._networkInterface=&bsd;d._nativeGate=&radio;d._nativeBSDGate=&wcl;
        d._nativeSecurity=new Security;std::fill(std::begin(d._nativeJoin),std::end(d._nativeJoin),0xa5);
        d._nativeStarted=mode!=2 && mode!=3;d._nativeAttached=mode!=3;
        d._nativeControllerAttached=mode!=3;native.provider=mode==3?nullptr:&d;
        if(mode==1){ // Framework actionStop already did stop + detach, flags remain stale.
            native.stop(&d);native.detach(&d);events.clear();
        }
        int foreign=0;
        if(mode==4)native.provider=&foreign; // Never stop/detach a different provider's child.
        if(mode==5){native.detach(&d);events.clear();} // Detached without completed startup ownership.
        d.releaseNativeInterface();
        const unsigned expectedStops=(mode==0 || mode==1)?1:0;
        const unsigned expectedDetaches=(mode==0 || mode==1 || mode==2 || mode==5)?1:0;
        assert(native.stops==expectedStops && native.detaches==expectedDetaches && native.releases==1);
        assert(mode!=4 || native.provider==&foreign);
        assert(d.drains==1 && bsd.releases==1 && d.bsdDetaches==1);
        assert(d.controllerDetaches==(mode==3?0u:1u));
        assert(d.radio.removals==1 && d.wcl.removals==1 && radio.releases==1 && wcl.releases==1);
        assert(!d._nativeInterface && !d._networkInterface && !d._nativeGate && !d._nativeBSDGate && !d._nativeSecurity);
        assert(!d._nativeStarted && !d._nativeAttached && !d._nativeControllerAttached && !d._nativeReadyPublished);
        for(auto v:d._nativeJoin)assert(!v);
        assert(events.front()==0 && events[1]==1 && events[2]==2);
        auto release=std::find(events.begin(),events.end(),6),remove=std::find(events.begin(),events.end(),8);
        assert(release<remove);
        // Repeated controller cleanup must not repeat the child's stock stop.
        d.releaseNativeInterface();assert(native.stops==expectedStops && native.releases==1 && d.drains==2);
    }
    assert(securityDeletes==6);
    Ath10kPCIDevice empty;empty.releaseNativeInterface();empty.releaseNativeInterface();
    assert(empty.drains==2 && !empty.controllerDetaches && !empty.bsdDetaches);
}

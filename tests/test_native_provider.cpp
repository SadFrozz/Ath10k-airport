#include <cassert>
struct IOWorkLoop {};
using IO80211WorkQueue=IOWorkLoop;
class Ath10kPCIDevice {
public:
    IOWorkLoop radio,wcl;
    IOWorkLoop *getWorkLoop() const {return const_cast<IOWorkLoop *>(&radio);}
    IO80211WorkQueue *getWorkQueue() const {return const_cast<IOWorkLoop *>(&wcl);}
};
class Ath10kNativeInterface {
public:
    Ath10kPCIDevice *controller=nullptr;
    IOWorkLoop *getWorkLoop() const;
};
class Ath10kBSDInterface {
public:
    Ath10kNativeInterface *wifi=nullptr;
    IOWorkLoop *getWorkLoop() const;
};
// Exact implementation bodies, extracted from the compiled driver's source.
#include "native_provider_methods.inc"
int main(){
    Ath10kPCIDevice owner;
    Ath10kNativeInterface protocol;Ath10kBSDInterface bsd;
    assert(!protocol.getWorkLoop() && !bsd.getWorkLoop());
    bsd.wifi=&protocol;assert(!bsd.getWorkLoop());
    protocol.controller=&owner;
    // IOService/API clients inherit the native provider's workloop, whereas
    // the BSD data interface must preserve the threaded controller workloop.
    assert(protocol.getWorkLoop()==&owner.wcl);
    assert(bsd.getWorkLoop()==&owner.radio);
    assert(protocol.getWorkLoop()!=bsd.getWorkLoop());
    protocol.controller=nullptr;
    assert(!protocol.getWorkLoop() && !bsd.getWorkLoop());
}

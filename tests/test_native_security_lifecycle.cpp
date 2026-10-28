#include <cassert>
#include <cstring>
#include <vector>
#include "../src/kext/native/Ath10kNativeCandidates.hpp"
#include "../src/kext/native/Ath10kNativeWire.hpp"
#include "../src/shared/Ath10kSupplicant.hpp"
#include "sha256_vectors.inc"
// No crypto operation is invoked: begin stores the fixture and reset must
// wipe it. Definitions are deliberately absent to catch accidental operations.
struct Ath10kKernelCrypto {};
static std::vector<unsigned> cleanup;
struct Ath10kSAESession {
    void cancel(){cleanup.push_back(1);}
    void release(){cleanup.push_back(4);delete this;}
};
struct Ath10kSAEWorkItem {
    void discard(){cleanup.push_back(2);}
    void release(){cleanup.push_back(3);delete this;}
};
struct Ath10kSAEWorker {
    static inline unsigned created=0,cancelled=0,drained=0,released=0;
    static inline bool failInit=false;
    bool init(){++created;return !failInit;}
    void cancel(){++cancelled;cleanup.push_back(5);}
    void shutdown(){++drained;}
    void release(){++released;delete this;}
};
class Ath10kPCIDevice {
public:
    class NativeSecurity;
    NativeSecurity *_nativeSecurity=nullptr;
    AirportWCL::JoinRequest _nativeJoin{};
    void discardNativeSecurity();
};
#include "native_security_class.inc"
#include "native_security_discard.inc"
int main(){
    { auto s=new Ath10kPCIDevice::NativeSecurity;
      Ath10kSAEWorker::failInit=true;assert(!s->prepareSAEWorker() && !s->saeWorker);
      assert(Ath10kSAEWorker::created==1 && Ath10kSAEWorker::released==1);
      Ath10kSAEWorker::failInit=false;assert(s->prepareSAEWorker());assert(s->prepareSAEWorker());
      assert(Ath10kSAEWorker::created==2);
      s->saeSession=new Ath10kSAESession;s->saePendingTX=new Ath10kSAEWorkItem;
      s->reset();assert(Ath10kSAEWorker::cancelled==1 && !Ath10kSAEWorker::drained);
      assert(!s->saeSession && !s->saePendingTX && cleanup==std::vector<unsigned>({1,2,3,4,5}));
      s->drainSAEWorker();assert(Ath10kSAEWorker::drained==1);delete s;
      assert(Ath10kSAEWorker::released==2 && Ath10kSAEWorker::cancelled==2);
    }
    Ath10kPCIDevice d;Ath10kPCIDevice::NativeSecurity security;
    d._nativeSecurity=&security;
    assert(security.supplicant.begin(s_pmk,s_snonce,s_sta,s_ap,s_rsn,sizeof(s_rsn),6));
    memset(security.reply,0xa5,sizeof(security.reply));memset(security.keys,0x5a,sizeof(security.keys));
    memset(security.supplicant.output,0x3c,sizeof(security.supplicant.output));
    memset(security.supplicant.keys,0x4b,sizeof(security.supplicant.keys));
    security.supplicant.outputLength=123;
    security.ready=security.replyPending=security.keysPending=security.authorizePending=true;
    security.replyLength=120;security.keyOperation=3;security.pairDeadline=5000;
    security.cachedGeneration=12;
    memset(d._nativeJoin.key,0x7d,sizeof(d._nativeJoin.key));
    memcpy(d._nativeJoin.bssid,s_ap,6);
    security.cancelPairwiseAttempt();
    assert(!security.replyPending && !security.replyLength && !security.pairDeadline);
    for(auto byte:security.reply)assert(!byte);
    // Cancellation only removes the candidate response, not pending committed
    // key operations or readiness. Full teardown below still retires everything.
    assert(security.ready && security.keysPending && security.authorizePending);
    d.discardNativeSecurity();
    AthSecurity::Supplicant<Ath10kKernelCrypto,true> pristine;pristine.reset();
    assert(!memcmp(&security.supplicant,&pristine,sizeof(pristine)));
    for(auto v:security.reply)assert(!v);
    for(auto v:security.keys)assert(!v);
    for(auto v:d._nativeJoin.key)assert(!v);
    assert(!security.ready && !security.replyPending && !security.keysPending && !security.authorizePending);
    assert(!security.replyLength && !security.keyOperation && !security.pairDeadline);
    // Nonsecret association metadata survives until terminal event acceptance.
    assert(!memcmp(d._nativeJoin.bssid,s_ap,6) && security.cachedGeneration==12);
    d.discardNativeSecurity();
    assert(!memcmp(&security.supplicant,&pristine,sizeof(pristine)));
    d._nativeSecurity=nullptr;d.discardNativeSecurity();
}

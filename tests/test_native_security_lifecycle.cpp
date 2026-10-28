#include <cassert>
#include <cstring>
#include <vector>
#include "../src/kext/native/Ath10kNativeCandidates.hpp"
#include "../src/kext/native/Ath10kNativePMFInbox.hpp"
#include "../src/kext/native/Ath10kNativeWire.hpp"
#include "../src/shared/Ath10kSupplicant.hpp"
#include "sha256_vectors.inc"
// No crypto operation is invoked: begin stores the fixture and reset must
// wipe it. Definitions are deliberately absent to catch accidental operations.
struct Ath10kKernelCrypto {};
static std::vector<unsigned> cleanup;
struct Ath10kPMFSession {
    bool keyResult=true,portResult=true;unsigned keyCalls=0,portCalls=0;
    bool acknowledgePairwise(const UInt8 *,const UInt8 *,const UInt8 *){++keyCalls;return keyResult;}
    bool authorize(){++portCalls;return portResult;}
    void cancel(){cleanup.push_back(6);}
    void release(){cleanup.push_back(7);delete this;}
};
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
    struct {UInt8 local[6]{},bssid[6]{};Ath10k::LinkStage stage=Ath10k::LinkStage::Connected;
        Ath10k::DisconnectStage disconnect=Ath10k::DisconnectStage::None;bool cancelRequested=false,pmfRequired=false;} _connection;
    void discardIfStopped();
    void discardNativeSecurity();
    bool nativePMFPairwiseAcknowledged(const UInt8 *);
    bool nativePMFPortReady();
    const char *beforeFirmwareAuthorization(unsigned);
};
#include "native_security_class.inc"
#include "native_security_discard.inc"
#include "native_pmf_key_hooks.inc"
#include "native_pmf_firmware_guard.inc"
#include "native_security_terminal_cleanup.inc"
int main(){
    { Ath10kPCIDevice d;UInt8 key[16]{};d._connection.pmfRequired=true;
      assert(!d.nativePMFPairwiseAcknowledged(key) && !d.nativePMFPortReady() && d.beforeFirmwareAuthorization(3));
      d._nativeSecurity=new Ath10kPCIDevice::NativeSecurity;
      assert(!d.nativePMFPairwiseAcknowledged(key) && !d.nativePMFPortReady());delete d._nativeSecurity;
    }

    { Ath10kPCIDevice d;assert(!d.beforeFirmwareAuthorization(3));
      d._nativeSecurity=new Ath10kPCIDevice::NativeSecurity;auto pmf=new Ath10kPMFSession;
      d._nativeSecurity->pmfSession=pmf;pmf->portResult=false;
      assert(!d.beforeFirmwareAuthorization(1) && !d.beforeFirmwareAuthorization(2) && !pmf->portCalls);
      assert(d.beforeFirmwareAuthorization(3) && pmf->portCalls==1);
      pmf->portResult=true;assert(!d.beforeFirmwareAuthorization(3) && pmf->portCalls==2);
      delete d._nativeSecurity;cleanup.clear();
    }

    // Authentication can fail before the EAPOL ready/reply/key flags exist.
    for(unsigned reason=0;reason<4;++reason)for(unsigned resource=0;resource<3;++resource){
      Ath10kPCIDevice d;d._nativeSecurity=new Ath10kPCIDevice::NativeSecurity;
      if(resource==0)d._nativeSecurity->pmfSession=new Ath10kPMFSession;
      if(resource==1)d._nativeSecurity->saeSession=new Ath10kSAESession;
      if(resource==2)d._nativeSecurity->saePendingTX=new Ath10kSAEWorkItem;
      if(reason==0)d._connection.stage=Ath10k::LinkStage::Failed;
      if(reason==1)d._connection.stage=Ath10k::LinkStage::Disabled;
      if(reason==2)d._connection.cancelRequested=true;
      if(reason==3)d._connection.disconnect=Ath10k::DisconnectStage::Down;
      d.discardIfStopped();assert(!d._nativeSecurity->pmfSession && !d._nativeSecurity->saeSession && !d._nativeSecurity->saePendingTX);
      assert(cleanup==std::vector<unsigned>(resource==0?std::initializer_list<unsigned>{6,7}:
          (resource==1?std::initializer_list<unsigned>{1,4}:std::initializer_list<unsigned>{2,3})));
      delete d._nativeSecurity;cleanup.clear();
    }
    { Ath10kPCIDevice d;d._nativeSecurity=new Ath10kPCIDevice::NativeSecurity;
      d._nativeSecurity->pmfSession=new Ath10kPMFSession;d.discardIfStopped();
      assert(d._nativeSecurity->pmfSession && cleanup.empty());delete d._nativeSecurity;cleanup.clear();
    }

    { Ath10kPCIDevice d;UInt8 key[16]{};
      assert(d.nativePMFPairwiseAcknowledged(key) && d.nativePMFPortReady());
      d._nativeSecurity=new Ath10kPCIDevice::NativeSecurity;
      assert(d.nativePMFPairwiseAcknowledged(key) && d.nativePMFPortReady());
      auto pmf=new Ath10kPMFSession;d._nativeSecurity->pmfSession=pmf;
      assert(d.nativePMFPairwiseAcknowledged(key) && pmf->keyCalls==1);
      pmf->keyResult=false;assert(!d.nativePMFPairwiseAcknowledged(key));
      pmf->portResult=false;assert(!d.nativePMFPortReady());
      pmf->portResult=true;assert(d.nativePMFPortReady() && pmf->portCalls==2);
      delete d._nativeSecurity;cleanup.clear();
    }

    { auto s=new Ath10kPCIDevice::NativeSecurity;s->pmfSession=new Ath10kPMFSession;
      s->reset();assert(!s->pmfSession && cleanup==std::vector<unsigned>({6,7}));
      s->reset();assert(cleanup==std::vector<unsigned>({6,7}));delete s;cleanup.clear();
    }
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

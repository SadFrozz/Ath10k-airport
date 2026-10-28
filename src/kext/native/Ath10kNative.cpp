// Sequoia WCL adapter for the Ath10k radio core. Experimental, x86_64 only.
// ABI definitions and message layouts are pinned in vendor/itlwm/SOURCE.json.
#include "../Ath10kPCIDevice.hpp"
#include "../../shared/Ath10kSupplicant.hpp"
#include "Ath10kNativeWire.hpp"
#include "Ath10kNativeCapture.hpp"
#include "Ath10kNativeCandidates.hpp"
#include "Ath10kNativeMAC.hpp"
#include <kern/clock.h>
#include <net/kpi_interface.h>
#include <IOKit/IOLib.h>
#include <IOKit/IONotifier.h>
#include <IOKit/network/IONetworkMedium.h>
#include <sys/kpi_mbuf.h>
#include <sys/random.h>
extern "C" {
#include <corecrypto/cchmac.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode.h>
}

OSDefineMetaClassAndStructors(Ath10kNativeInterface,IO80211InfraProtocol)

// The BSD data path remains mbuf-based, as in the reference WCL adapter.
// Subtype 3 and prepareBSDInterface attach it to the real Wi-Fi protocol.
class Ath10kBSDInterface : public IOEthernetInterface {
    OSDeclareDefaultStructors(Ath10kBSDInterface)
    Ath10kNativeInterface *wifi=nullptr;
    bool attached=false;
public:
    bool initWithController(Ath10kPCIDevice *owner,Ath10kNativeInterface *protocol) {
        wifi=protocol;return IOEthernetInterface::init(owner);
    }
    IOWorkLoop *getWorkLoop() const override {
        // getProvider() presents the Wi-Fi protocol after BSD attachment.
        // Do not inherit its threadless WCL queue for Ethernet operations.
        return wifi && wifi->controller?wifi->controller->getWorkLoop():nullptr;
    }
    static IOReturn prepare(OSObject *,void *arg,void *,void *,void *) {
        auto self=static_cast<Ath10kBSDInterface *>(arg);
        auto owner=self->wifi->controller;
        auto queue=owner->getWorkQueue();
        if(!queue || !queue->inGate() || queue->onThread())return kIOReturnNotPermitted;
        return self->wifi->prepareBSDInterface(self->getIfnet(),0);
    }
    IOReturn attachToDataLinkLayer(IOOptionBits options,void *parameter) override {
        if(!setInterfaceSubType(3))return kIOReturnNotReady;
        auto result=IOEthernetInterface::attachToDataLinkLayer(options,parameter);
        if(result!=kIOReturnSuccess)return result;
        char name[IFNAMSIZ];
        snprintf(name,sizeof(name),"%s%u",ifnet_name(getIfnet()),ifnet_unit(getIfnet()));
        wifi->setProperty("IOInterfaceName",name);
        wifi->setProperty(kIOInterfaceNamePrefix,ifnet_name(getIfnet()));
        wifi->setProperty(kIOInterfaceUnit,UInt64(ifnet_unit(getIfnet())),32);
        UInt8 builtin=1;wifi->setProperty("built-in",&builtin,sizeof(builtin));
        result=wifi->controller->_nativeBSDGate->runAction(prepare,this);
        if(result!=kIOReturnSuccess){
            IOEthernetInterface::detachFromDataLinkLayer(options,parameter);return result;
        }
        attached=true;wifi->registerService();
        // Firmware was initialized before the WCL interface existed. Publish
        // its readiness only after the BSD/Wi-Fi binding is actually usable.
        ownerReady();return result;
    }
    void detachFromDataLinkLayer(IOOptionBits options,void *parameter) override {
        IOEthernetInterface::detachFromDataLinkLayer(options,parameter);attached=false;
    }
    IOService *getProvider() const override {
        return attached?static_cast<IOService *>(wifi):IOEthernetInterface::getProvider();
    }
    void ownerReady(){wifi->controller->nativeRequest(AthNativeOp::NativeReady,nullptr);}
};
OSDefineMetaClassAndStructors(Ath10kBSDInterface,IOEthernetInterface)

struct Ath10kKernelCrypto {
    static bool hmac256(const UInt8 *key,size_t keyLength,const UInt8 *data,size_t length,UInt8 *out) {
        const auto di=ccsha256_di();if(!di)return false;
        cchmac(di,keyLength,key,length,data,out);return true;
    }
    static bool encrypt(const UInt8 *key,const UInt8 *data,UInt8 *out) {
        auto mode=ccaes_ecb_encrypt_mode();if(!mode || mode->size>1024)return false;
        alignas(16) UInt8 context[1024]{};auto ctx=reinterpret_cast<ccecb_ctx *>(context);
        bool ok=mode->init(mode,ctx,16,key)==0 && mode->ecb(ctx,1,data,out)==0;
        AthSecurity::wipe(context,sizeof(context));return ok;
    }
    static bool hmac(const UInt8 *key,size_t keyLength,const UInt8 *data,size_t length,UInt8 *out) {
        const auto di=ccsha1_di();if(!di)return false;
        cchmac(di,keyLength,key,length,data,out);return true;
    }
    static bool decrypt(const UInt8 *key,const UInt8 *data,UInt8 *out) {
        auto mode=ccaes_ecb_decrypt_mode();if(!mode || mode->size>1024)return false;
        // Fixed upper bound: no variable-sized kernel stack allocation.
        alignas(16) UInt8 context[1024]{};
        auto ctx=reinterpret_cast<ccecb_ctx *>(context);
        bool ok=mode->init(mode,ctx,16,key)==0 && mode->ecb(ctx,1,data,out)==0;
        AthSecurity::wipe(context,sizeof(context));return ok;
    }
    static bool random(UInt8 *out,size_t length) {read_random(out,length);return true;}
};
class Ath10kPCIDevice::NativeSecurity {
public:
    AthSecurity::Supplicant<Ath10kKernelCrypto,true> supplicant;
    AthNative::CandidateCache candidates;
    UInt32 cachedGeneration=~0u;
    bool ready=false,replyPending=false,keysPending=false,authorizePending=false;
    unsigned keyOperation=0;
    UInt8 reply[160]{},keys[56]{};
    UInt32 replyLength=0;
    UInt64 pairDeadline=0;
    void reset(){supplicant.reset();AthSecurity::wipe(reply,sizeof(reply));AthSecurity::wipe(keys,sizeof(keys));
        ready=replyPending=keysPending=authorizePending=false;replyLength=keyOperation=0;pairDeadline=0;}
    ~NativeSecurity(){reset();}
};

IO80211WorkQueue *Ath10kPCIDevice::getWorkQueue() const {
    return _nativeWorkQueue;
}
bool Ath10kPCIDevice::getLogPipes(CCPipe **a,CCPipe **b,CCPipe **c) {
    if(!a || !b || !c)return false;*a=_nativePipes[0];*b=_nativePipes[1];*c=_nativePipes[2];
    return *a && *b && *c;
}
void Ath10kPCIDevice::nativeStartupPhase(const char *phase) {
    setProperty("Ath10kNativeStartupPhase",phase);
    if(auto provider=getProvider())provider->setProperty("Ath10kNativeStartupPhase",phase);
    IOLog("Ath10kMac: native startup phase=%s\n",phase);
}
bool Ath10kPCIDevice::prepareNativeLogs() {
    if(!getWorkLoop())return false;
    static const char *names[]={"DriverLogs","DatapathEvents","StateSnapshots"};
    static const char *createPhases[]={"log-pipe-create","datapath-pipe-create","snapshot-pipe-create"};
    static const char *startPhases[]={"log-pipe-start","datapath-pipe-start","snapshot-pipe-start"};
    for(unsigned i=0;i<3;++i){
        CCPipeOptions options{};if(!nativeCaptureOptions(i,options))return false;
        strlcpy(options.file_name,names[i],sizeof(options.file_name));
        if(i!=1)strlcpy(options.name,i==0?"wlan0":"0",sizeof(options.name));
        strlcpy(options.directory_name,"WiFi",sizeof(options.directory_name));
        nativeStartupPhase(createPhases[i]);
        _nativePipes[i]=CCPipe::withOwnerNameCapacity(this,"br.com.jonasw8.driver.ath10kmac",names[i],&options);
        if(!_nativePipes[i])return false;
        nativeStartupPhase(startPhases[i]);
        if(!(_nativePipesStarted[i]=_nativePipes[i]->CCPipe::startPipe()))return false;
        if(i==0){
            // The owner logger must exist before creating dependent pipes.
            nativeStartupPhase("logger-create");
            CCStreamOptions loggerOptions{};
            CCStream *logger=CCStream::withPipeAndName(_nativePipes[0],"Ath10kMac",&loggerOptions);
            _nativeLogger=OSDynamicCast(CCLogStream,logger);
            if(!_nativeLogger){OSSafeReleaseNULL(logger);return false;}
        }
    }
    nativeStartupPhase("fault-stream-create");
    CCStreamOptions faultOptions{};faultOptions.stream_type=1;faultOptions.console_level=~0ULL;
    _nativeFaultStream=CCStream::withPipeAndName(_nativePipes[2],"FaultReporter",&faultOptions);
    auto data=OSDynamicCast(CCDataStream,_nativeFaultStream);if(!data)return false;
    nativeStartupPhase("core-fault-reporter-create");
    _nativeCoreFault=CCFaultReporter::withStreamWorkloop(data,getWorkLoop());if(!_nativeCoreFault)return false;
    nativeStartupPhase("wifi-fault-reporter-create");
    _nativeFault=IO80211FaultReporter::allocWithParams(_nativeCoreFault);
    return OSDynamicCast(CommonFaultReporter,_nativeFault)!=nullptr;
}
void Ath10kPCIDevice::releaseNativeLogs() {
    OSSafeReleaseNULL(_nativeFault);OSSafeReleaseNULL(_nativeCoreFault);
    OSSafeReleaseNULL(_nativeFaultStream);OSSafeReleaseNULL(_nativeLogger);
    for(unsigned i=0;i<3;++i){
        if(_nativePipesStarted[i] && _nativePipes[i])_nativePipes[i]->CCPipe::stopPipe();
        _nativePipesStarted[i]=false;OSSafeReleaseNULL(_nativePipes[i]);
    }
}
static IOReturn nativeVersion(apple80211_version_data *data,const char *value) {
    if(!data)return kIOReturnBadArgument;bzero(data,sizeof(*data));data->version=APPLE80211_VERSION;
    data->string_len=strlcpy(data->string,value,sizeof(data->string));return kIOReturnSuccess;
}
IOReturn Ath10kPCIDevice::getDRIVER_VERSION(IO80211SkywalkInterface *,apple80211_version_data *data) {
    return nativeVersion(data,"Ath10kMac Sequoia WCL experimental");
}
IOReturn Ath10kPCIDevice::getHARDWARE_VERSION(IO80211SkywalkInterface *,apple80211_version_data *data) {
    return nativeVersion(data,"Qualcomm Atheros QCA9377 Lunnen 1a3b:2b51");
}
IOReturn Ath10kPCIDevice::getCARD_CAPABILITIES(IO80211SkywalkInterface *,apple80211_capability_data *data) {
    if(!data)return kIOReturnBadArgument;bzero(data,sizeof(*data));data->version=APPLE80211_VERSION;
    data->capabilities[0]=(1<<APPLE80211_CAP_AES_CCM)|(1<<APPLE80211_CAP_TKIP);
    data->capabilities[1]=(1<<(APPLE80211_CAP_WPA2-8))|(1<<(APPLE80211_CAP_TKIPMIC-8));
    data->capabilities[2]=(1<<(APPLE80211_CAP_WME-16));data->capabilities[5]=0x40;
    return kIOReturnSuccess;
}
IOReturn Ath10kPCIDevice::getPOWER(IO80211SkywalkInterface *,apple80211_power_data *data){return nativeRequest(AthNativeOp::PowerGet,data);}
IOReturn Ath10kPCIDevice::setPOWER(IO80211SkywalkInterface *,apple80211_power_data *data){return nativeRequest(AthNativeOp::PowerSet,data);}
IOReturn Ath10kPCIDevice::getCOUNTRY_CODE(IO80211SkywalkInterface *,apple80211_country_code_data *data){return nativeRequest(AthNativeOp::CountryGet,data);}
IOReturn Ath10kPCIDevice::setCOUNTRY_CODE(IO80211SkywalkInterface *,apple80211_country_code_data *data){return nativeRequest(AthNativeOp::CountrySet,data);}

bool Ath10kNativeInterface::initWithController(Ath10kPCIDevice *owner) {
    controller=owner;IOEthernetAddress address{};
    return IO80211InfraInterface::init() && owner->getHardwareAddress(&address)==kIOReturnSuccess &&
        IO80211SkywalkInterface::init(owner,reinterpret_cast<ether_addr *>(&address)) &&
        prepareTerminationNotification();
}
IOReturn Ath10kNativeInterface::prepareBSDInterface(ifnet_t interface,unsigned int options) {
    if(!interface)return kIOReturnBadArgument;
    // Stock Skywalk stores this borrowed pointer without taking a reference.
    // Legacy BSD detach/free can precede the native object's final cleanup.
    // Keep the resource through parent free, including failed preparation.
    if(_nativeBSDReference || _nativeBSDOwner)return kIOReturnBusy;
    // ifnet's softc callbacks dereference the legacy IONetworkInterface too.
    // An ifnet reference alone does not retain that callback context.
    auto owner=controller?controller->_networkInterface:nullptr;
    if(!owner || owner->getIfnet()!=interface)return kIOReturnNotAttached;
    owner->retain();
    if(ifnet_reference(interface)!=0){owner->release();return kIOReturnError;}
    _nativeBSDOwner=owner;_nativeBSDReference=interface;
    return IO80211InfraProtocol::prepareBSDInterface(interface,options);
}
bool Ath10kNativeInterface::prepareTerminationNotification() {
    if(_terminationNotifier)return true;
    if(!_terminationLock)_terminationLock=IOLockAlloc();
    if(!_terminationLock)return false;
    if(!_terminationCall)_terminationCall=thread_call_allocate_with_options(terminationThread,this,
        THREAD_CALL_PRIORITY_KERNEL,THREAD_CALL_OPTIONS_ONCE);
    if(!_terminationCall)return false;
    // A newly initialized entry gets its registry ID only when attached. Use
    // the class match before attachment, and filter this exact object below.
    auto *matching=IOService::serviceMatching("Ath10kNativeInterface");
    if(!matching)return false;
    _terminationNotifier=IOService::addMatchingNotification(gIOWillTerminateNotification,matching,
        willTerminateNotification,this);
    matching->release();
    return _terminationNotifier!=nullptr;
}
void Ath10kNativeInterface::releaseTerminationNotification() {
    // Final-free/failed-init only. A deferred termination owns a self-reference
    // until its last worker access, so it cannot reach here while queued.
    if(_terminationNotifier){_terminationNotifier->remove();_terminationNotifier=nullptr;}
    if(_terminationCall){thread_call_free(_terminationCall);_terminationCall=nullptr;}
    if(_terminationLock){IOLockFree(_terminationLock);_terminationLock=nullptr;}
}
void Ath10kNativeInterface::closePowerAdmission() {
    if(!_terminationLock)return;
    IOLockLock(_terminationLock);_powerAdmissionClosed=true;IOLockUnlock(_terminationLock);
}
IOReturn Ath10kNativeInterface::setPowerState(unsigned long ordinal,IOService *device) {
    if(!_terminationLock)return kIOReturnNotReady;
    IOLockLock(_terminationLock);
    if(_powerAdmissionClosed){IOLockUnlock(_terminationLock);return kIOReturnAborted;}
    ++_nativePowerCalls;IOLockUnlock(_terminationLock);
    // Preserve the stock body/return value and its WCL ordering. Never hold our
    // short bookkeeping lock across a framework call or a command gate.
    const IOReturn result=IO80211InfraProtocol::setPowerState(ordinal,device);
    IOLockLock(_terminationLock);
    --_nativePowerCalls;
    if(!_nativePowerCalls){
        IOLockWakeup(_terminationLock,&_nativePowerCalls,false);
        if(_terminationRequested && _terminationPMStopped && !_terminationScheduled && !_terminationCompleted){
            _terminationScheduled=true;thread_call_enter(_terminationCall);
        }
    }
    IOLockUnlock(_terminationLock);
    return result;
}
void Ath10kNativeInterface::drainPowerCalls() {
    // Controller stop/free call this after the probe, outside WCL/radio. The
    // normal framework route has already completed deferred didTerminate.
    // This also covers direct cleanup after a partially successful start.
    if(!_terminationLock)return;
    closePowerAdmission();
    if(controller)controller->nativeInterfaceWillStop(this);
    PMstop();
    IOLockLock(_terminationLock);
    while(_nativePowerCalls)IOLockSleep(_terminationLock,&_nativePowerCalls,THREAD_UNINT);
    IOLockUnlock(_terminationLock);
    if(auto loop=getWorkLoop())loop->runAction(finalizeBSDAction,this);
}
bool Ath10kNativeInterface::didTerminate(IOService *provider,IOOptionBits options,bool *defer) {
    if(!provider || !defer)return false;
    if(!_terminationLock || !_terminationCall)
        return IO80211InfraProtocol::didTerminate(provider,options,defer);
    IOLockLock(_terminationLock);_powerAdmissionClosed=true;
    if(_terminationCompleted){*defer=false;IOLockUnlock(_terminationLock);return true;}
    // Explicitly hold the inherited completion/close handshake until pending
    // power I/O exits. Do not take provider arbitration from this workloop.
    *defer=true;
    if(!_terminationRequested){
        _terminationRequested=true;_terminationProvider=provider;_terminationOptions=options;
        retain();provider->retain(); // Keep the pending notification/job alive.
        _terminationScheduled=true;thread_call_enter(_terminationCall);
    }else if(_terminationPMStopped && !_terminationScheduled && !_nativePowerCalls){
        _terminationScheduled=true;thread_call_enter(_terminationCall);
    }
    IOLockUnlock(_terminationLock);
    // Do not invoke the inherited didTerminate yet: it schedules stop/detach.
    // Leaving this child attached also holds off controller finalization/stop,
    // preserving its command gates, WMI state and the native managers together.
    return true;
}
bool Ath10kNativeInterface::finalize(IOOptionBits options) {
    if(!_terminationLock)return IO80211InfraProtocol::finalize(options);
    IOLockLock(_terminationLock);
    if(_terminationCompleted){IOLockUnlock(_terminationLock);return IO80211InfraProtocol::finalize(options);}
    _terminationFinalizePending=true;_terminationFinalizeOptions=options;
    IOLockUnlock(_terminationLock);
    // IOService::finalize can schedule stop independently when the provider is
    // still active (termination of this interface alone). Defer that path too.
    if(auto provider=getProvider()){
        bool defer=false;didTerminate(provider,options,&defer);return true;
    }
    return IO80211InfraProtocol::finalize(options); // Unattached partial init.
}
void Ath10kNativeInterface::terminationThread(thread_call_param_t context,thread_call_param_t) {
    auto self=static_cast<Ath10kNativeInterface *>(context);
    IOLockLock(self->_terminationLock);
    const bool stopPower=!self->_terminationPMStopped;
    IOLockUnlock(self->_terminationLock);
    if(stopPower)self->PMstop(); // Outside all driver/framework workloop gates.
    IOLockLock(self->_terminationLock);self->_terminationPMStopped=true;
    if(self->_nativePowerCalls){
        // Platform PMstop can time out. Keep the child attached and all owned
        // resources alive; the last admitted call queues us again on real exit.
        self->_terminationScheduled=false;IOLockUnlock(self->_terminationLock);return;
    }
    auto provider=self->_terminationProvider;
    IOLockUnlock(self->_terminationLock);
    // Fence previously admitted WCL callers before scheduling provider-gated
    // stop. Keep completion false until that fence and BSD cleanup actually run.
    IOReturn result;
    if(auto loop=self->getWorkLoop())result=loop->runAction(resumeTerminationAction,self);
    else result=resumeTerminationAction(self,nullptr,nullptr,nullptr,nullptr);
    if(result!=kIOReturnSuccess){
        IOLockLock(self->_terminationLock);self->_terminationScheduled=false;IOLockUnlock(self->_terminationLock);
        self->setProperty("Ath10kNativeTerminationPhase","bsd-binding-mismatch");
        return; // Keep the child/job references; never clean up an unknown binding.
    }
    provider->release();
    self->release(); // May free this object and our own thread call. No later access.
}
IOReturn Ath10kNativeInterface::finalizeBSDAction(OSObject *owner,void *,void *,void *,void *) {
    auto self=static_cast<Ath10kNativeInterface *>(owner);
    // Called only behind the WCL fence after admitted stock power bodies exit.
    if(auto interface=self->getBSDInterface()){
        if(interface!=self->_nativeBSDReference)return kIOReturnBadArgument;
        self->IO80211InfraProtocol::finalizeBSDInterface(interface,0);
    }
    return kIOReturnSuccess;
}
IOReturn Ath10kNativeInterface::resumeTerminationAction(OSObject *owner,void *,void *,void *,void *) {
    auto self=static_cast<Ath10kNativeInterface *>(owner);
    const auto result=finalizeBSDAction(owner,nullptr,nullptr,nullptr,nullptr);
    if(result!=kIOReturnSuccess)return result;
    // Capture finalize requests only after entering WCL: finalize() may have
    // arrived while the worker was waiting for the fence.
    IOLockLock(self->_terminationLock);
    auto provider=self->_terminationProvider;const auto options=self->_terminationOptions;
    const bool finalize=self->_terminationFinalizePending;
    const auto finalizeOptions=self->_terminationFinalizeOptions;
    self->_terminationFinalizePending=false;self->_terminationProvider=nullptr;
    self->_terminationCompleted=true;self->_terminationScheduled=false;
    IOLockUnlock(self->_terminationLock);
    bool defer=false;
    if(finalize)self->IO80211InfraProtocol::finalize(finalizeOptions);
    self->IO80211InfraProtocol::didTerminate(provider,options,&defer);
    return kIOReturnSuccess;
}
bool Ath10kNativeInterface::willTerminateNotification(void *target,void *,IOService *service,IONotifier *) {
    auto *self=static_cast<Ath10kNativeInterface *>(target);
    if(!self || service!=self)return true;
    // XNU invokes this identity-filtered notification outside workloop gates
    // and the global notification lock, before leaf/provider stop is queued.
    self->closePowerAdmission();
    if(self->controller)self->controller->prepareNativeInterfaceTermination(self);
    self->setProperty("Ath10kNativeTerminationPhase","power-admission-closed");
    // didTerminate defers the framework stop; no PM wait on this global worker.
    return true;
}
bool Ath10kNativeInterface::prepareRegistrationInfo(const IOSkywalkEthernetInterface::RegistrationInfo &registration) {
    if(!mExpansionData || !mExpansionData2 || _registrationLoan ||
       mExpansionData->fRegistrationInfo || mExpansionData2->fRegistrationInfo)return false;
    // Stock copyRegistrationInfo owns allocation, copy, MAC publication and
    // typed destruction. Never put a generic IOMalloc buffer into its slots.
    if(copyRegistrationInfo(&registration)!=kIOReturnSuccess)return false;
    auto *owned=mExpansionData2->fRegistrationInfo;
    if(!owned)return false;
    static_assert(sizeof(IOSkywalkNetworkInterface::RegistrationInfo)==0x108,"network registration prefix");
    static_assert(sizeof(IOSkywalkEthernetInterface::RegistrationInfo)==0x130,"Ethernet registration size");
    _registrationLoan=reinterpret_cast<IOSkywalkNetworkInterface::RegistrationInfo *>(owned);
    mExpansionData->fRegistrationInfo=_registrationLoan;
    return true;
}
void Ath10kNativeInterface::detachRegistrationLoan() {
    // A reader which already loaded this prefix still has valid storage until
    // the interface's final base free. Only remove our loan, never another owner.
    if(mExpansionData && _registrationLoan && mExpansionData->fRegistrationInfo==_registrationLoan)
        mExpansionData->fRegistrationInfo=nullptr;
    _registrationLoan=nullptr;
}
void Ath10kNativeInterface::stop(IOService *provider) {
    if(controller)controller->nativeInterfaceWillStop(this);
    detachRegistrationLoan();
    if(_baseStarted){_baseStarted=false;IO80211InfraProtocol::stop(provider);}
}
void Ath10kNativeInterface::free() {
    // Includes partial initialization and a release without a preceding stop.
    releaseTerminationNotification();
    detachRegistrationLoan();
    auto interface=_nativeBSDReference;_nativeBSDReference=nullptr;
    auto owner=_nativeBSDOwner;_nativeBSDOwner=nullptr;
    IO80211InfraProtocol::free();
    // Parent free can read the borrowed pointer. Release only after it returns;
    // never dereference this after the parent has destroyed its storage.
    if(interface)ifnet_release(interface);
    if(owner)owner->release();
}
IOReturn Ath10kNativeInterface::deregisterLogicalLink() {
    detachRegistrationLoan();
    return IO80211InfraProtocol::deregisterLogicalLink();
}
IOWorkLoop *Ath10kNativeInterface::getWorkLoop() const {
    // API user clients inherit their provider's workloop. Their stop path
    // must enter WCL directly, rather than hold the BSD/radio gate and
    // then synchronously enter WCL while another WCL command needs radio.
    // The BSD controller retains its separate, thread-backed workloop.
    return controller?controller->getWorkQueue():nullptr;
}
IOReturn Ath10kNativeInterface::perform(AthNativeOp op,void *data){return controller?controller->nativeRequest(op,data):kIOReturnNotAttached;}
IOReturn Ath10kNativeInterface::setMacAddress(ether_addr &address) {
    return controller?controller->nativeRequest(AthNativeOp::MACSet,&address):kIOReturnNotAttached;
}
IONetworkInterface *Ath10kPCIDevice::createInterface() {
    auto interface=new Ath10kBSDInterface;
    if(interface && interface->initWithController(this,_nativeInterface))return interface;
    OSSafeReleaseNULL(interface);return nullptr;
}
bool Ath10kPCIDevice::prepareNativeInterface() {
    _nativeStopping=false;_nativeReadyRequested=_nativeAbortRequested=_nativeReadyResetSent=false;
    _nativeAssocSent=_nativeBeaconSent=_nativeJoinBSSSent=_nativeLinkUpSent=false;
    _nativeWasUp=_nativeDeauthSent=_nativeJoinFailed=false;
    _nativeScanResultIndex=_nativeScanResultsEmitted=0;_nativePostError=kIOReturnSuccess;
    bzero(_nativeLastBSSID,sizeof(_nativeLastBSSID));
    _nativeServiceLock=IOLockAlloc();
    if(!_nativeServiceLock)return false;
    _nativeServiceStopping=false;_nativeServiceQueued=_nativeServiceRunning=false;
    _nativeServiceCall=thread_call_allocate_with_options(nativeServiceThread,this,THREAD_CALL_PRIORITY_KERNEL,THREAD_CALL_OPTIONS_ONCE);
    if(!_nativeServiceCall)return false;
    bcopy(_wmiInit.mac,_nativeMACCurrent,6);_nativeMACValid=true;
    // Strict profile/OS guard; unrelated adapters must not enter the WCL path.
    if(_vendorId!=0x168c || _deviceId!=0x42 || _subsystemVendorId!=0x1a3b || _subsystemId!=0x2b51)return false;
    _nativeGate=IOCommandGate::commandGate(this);
    if(!_nativeGate || getWorkLoop()->addEventSource(_nativeGate)!=kIOReturnSuccess)return false;
    // BSD preparation is a WCL operation and requires the IO80211 queue gate.
    // Radio state requests remain serialized with WMI on the legacy workloop.
    _nativeBSDGate=IOCommandGate::commandGate(this);
    if(!_nativeBSDGate || !getWorkQueue() ||
       getWorkQueue()->addEventSource(_nativeBSDGate)!=kIOReturnSuccess)return false;
    _nativeSecurity=new NativeSecurity;if(!_nativeSecurity)return false;
    _nativeInterface=new Ath10kNativeInterface;
    if(!_nativeInterface || !_nativeInterface->initWithController(this))return false;
    _nativeInterface->setInterfaceRole(1);_nativeInterface->setInterfaceId(1);
    if(!_nativeInterface->attach(this))return false;
    _nativeAttached=true;
    if(!IO80211Controller::attachInterface(_nativeInterface,this))return false;
    _nativeControllerAttached=true;
    if(!IONetworkController::attachInterface(&_networkInterface,false))return false;
    IOSkywalkEthernetInterface::RegistrationInfo registration{};
    if(!_nativeInterface->initRegistrationInfo(&registration,1,sizeof(registration)))return false;
    if(!_nativeInterface->prepareRegistrationInfo(registration))return false;
    _nativeInterface->deferBSDAttach(true);
    if(!_nativeInterface->start(this))return false;
    _nativeInterface->_baseStarted=true;
    _nativeStarted=true;_networkEnabled=true;
    _networkInterface->registerService();
    setProperty("Ath10kNativeABI","Sequoia-15.2-WCL-experimental");
    return true;
}
// Radio-gated terminal cleanup. Event metadata and the last BSSID survive
// until macOS accepts the terminal notifications; cryptographic material does not.
void Ath10kPCIDevice::discardNativeSecurity() {
    if(_nativeSecurity)_nativeSecurity->reset();
    AthSecurity::wipe(_nativeJoin.key,sizeof(_nativeJoin.key));
}
IOReturn Ath10kPCIDevice::nativeStopAction(OSObject *owner,void *,void *,void *,void *) {
    auto self=OSDynamicCast(Ath10kPCIDevice,owner);
    if(!self)return kIOReturnBadArgument;
    self->_nativeStopping=true;self->discardNativeSecurity();
    if(self->_nativeMACWaiting){self->_nativeMACResult=kIOReturnAborted;self->_nativeGate->commandWakeup(&self->_nativeMACResult);}
    return kIOReturnSuccess;
}
IOReturn Ath10kPCIDevice::nativeInterfaceStopAction(OSObject *owner,void *interface,void *,void *,void *) {
    auto self=OSDynamicCast(Ath10kPCIDevice,owner);
    if(!self || !interface || self->_nativeInterface!=interface)return kIOReturnNotAttached;
    // IOService can stop this leaf before it stops our controller. Exclude all
    // protocol work before the base interface destroys its managers/context.
    nativeStopAction(owner,nullptr,nullptr,nullptr,nullptr);
    self->_nativeStarted=false;
    self->endWMIRuntime("native-interface-stopped");
    return kIOReturnSuccess;
}
void Ath10kPCIDevice::nativeInterfaceWillStop(Ath10kNativeInterface *interface) {
    if(_nativeGate && _nativeGate->getWorkLoop())
        _nativeGate->runAction(nativeInterfaceStopAction,interface);
    else if(interface && _nativeInterface==interface){
        // Interface construction follows gate installation; only a partial
        // teardown can reach this fallback. Do not schedule or touch hardware.
        _nativeStopping=true;_nativeStarted=false;discardNativeSecurity();
    }
    // Do not wait for the service thread here: IOService may hold the radio
    // gate. Controller stop/free later drain it outside that gate.
}
void Ath10kPCIDevice::prepareNativeInterfaceTermination(Ath10kNativeInterface *interface) {
    if(!interface || _nativeInterface!=interface)return;
    // This entry is only called from the outside-gate will-terminate notifier.
    // Block new work before waiting for a probe which can still construct/start
    // the interface. Never take this barrier from the provider-gated stop hook.
    blockPowerIOForTermination();
    if(_probePowerLock)IOLockLock(_probePowerLock);
    nativeInterfaceWillStop(interface);
    if(_probePowerLock)IOLockUnlock(_probePowerLock);
    // Return with both initialization and radio gates released before PMstop.
}
void Ath10kPCIDevice::stopNativeRequests() {
    if(_nativeGate && _nativeGate->getWorkLoop())_nativeGate->runAction(nativeStopAction);
    else _nativeStopping=true;
    // stop/free call this outside both workloop gates. The stop flag prevents
    // new scheduling; wait before removing gates, interface or radio resources.
    if(_nativeServiceLock){
        IOLockLock(_nativeServiceLock);
        _nativeServiceStopping=true;
        if(_nativeServiceCall && thread_call_cancel(_nativeServiceCall))_nativeServiceQueued=false;
        // A false cancel may mean dispatch has begun before callback entry.
        // Keep queued true until that callback claims it under this lock.
        while(_nativeServiceQueued || _nativeServiceRunning)
            IOLockSleep(_nativeServiceLock,&_nativeServiceRunning,THREAD_UNINT);
        auto call=_nativeServiceCall;_nativeServiceCall=nullptr;
        IOLockUnlock(_nativeServiceLock);
        if(call)thread_call_free(call);
        // Keep the lock until final interface cleanup: repeated stop is valid.
    }
    _nativeServicePending=false;
}
void Ath10kPCIDevice::releaseNativeInterface() {
    // stop() has already cancelled the runtime worker under its workloop.
    stopNativeRequests();
    if(_networkInterface){
        IONetworkController::detachInterface(_networkInterface,true);
        OSSafeReleaseNULL(_networkInterface);
    }
    if(_nativeInterface){
        // Normal IOService termination has already stopped and detached its
        // leaf clients before this controller stops. The cached startup flags
        // do not imply that our interface is still attached or needs stop().
        const bool stillAttached=_nativeAttached && _nativeInterface->getProvider()==this;
        if(_nativeInterface->_baseStarted && stillAttached)_nativeInterface->stop(this);
        if(_nativeControllerAttached)IO80211Controller::detachInterface(_nativeInterface,true);
        if(stillAttached)_nativeInterface->detach(this);
        OSSafeReleaseNULL(_nativeInterface);
    }
    _nativeStarted=_nativeAttached=_nativeControllerAttached=_nativeReadyPublished=false;
    if(_nativeServiceLock){IOLockFree(_nativeServiceLock);_nativeServiceLock=nullptr;}
    if(_nativeSecurity){delete _nativeSecurity;_nativeSecurity=nullptr;}
    AthSecurity::wipe(&_nativeJoin,sizeof(_nativeJoin));
    if(_nativeGate){getWorkLoop()->removeEventSource(_nativeGate);OSSafeReleaseNULL(_nativeGate);}
    if(_nativeBSDGate){
        if(auto loop=_nativeBSDGate->getWorkLoop())loop->removeEventSource(_nativeBSDGate);
        OSSafeReleaseNULL(_nativeBSDGate);
    }
}
IOReturn Ath10kPCIDevice::nativeRequest(AthNativeOp op,void *data) {
    const bool scan=op==AthNativeOp::setWCL_SCAN_REQ;
    const bool joinRequest=op==AthNativeOp::setWCL_ASSOCIATE;
    if(joinRequest)setProperty("Ath10kNativeJoinDispatchSeen",true);
    if(scan)setProperty("Ath10kNativeScanDispatchSeen",true);
    if(!_nativeGate || _nativeStopping || powerIOBlocked() || !_wmiLive.active){
        if(scan)setProperty("Ath10kNativeScanReturn",UInt64(kIOReturnNotReady),32);
        return kIOReturnNotReady;
    }
    IOReturn result=_nativeGate->runAction(nativeAction,reinterpret_cast<void *>(uintptr_t(op)),data);
    if(scan)setProperty("Ath10kNativeScanReturn",UInt64(result),32);
    if(joinRequest)setProperty("Ath10kNativeJoinReturn",UInt64(result),32);
    if(op==AthNativeOp::MACSet)setProperty("Ath10kNativeMACReturn",UInt64(result),32);
    return result;
}
IOReturn Ath10kPCIDevice::nativeAction(OSObject *target,void *op,void *data,void *,void *) {
    auto self=OSDynamicCast(Ath10kPCIDevice,target);
    return self?self->nativeRequestGated(static_cast<AthNativeOp>(uintptr_t(op)),data):kIOReturnBadArgument;
}
IOReturn Ath10kPCIDevice::nativeCurrentAPInfo(AthNativeOp op,void *data) {
    if(!data)return kIOReturnBadArgument;
    auto &s=_connection;using N=AthNativeOp;
    if(!Ath10k::connectionAssociated(s))return kIOReturnNotReady;
    switch(op){
    case N::getWCL_BSS_INFO:{
        if(!s.beaconFrameBytes)return kIOReturnNotReady;
        // Background scan notifications reuse the scratch buffer. Rebuild
        // from the associated AP rather than returning another scan result.
        const size_t length=nativeBSSMessage(s.ap,_nativeBSSMessage,sizeof(_nativeBSSMessage));
        if(!length)return kIOReturnNotReady;
        bcopy(_nativeBSSMessage,data,length);return kIOReturnSuccess;}
    case N::getBEACON_INFO:{
        return nativeBeaconInfo(s.beaconFrame,s.beaconFrameBytes,data,0x808)?kIOReturnSuccess:kIOReturnNotReady;}
    case N::getWCL_EXTENDED_BSS_INFO:{
        NativeExtendedBSSInput input{};input.rates=s.ap.rates;input.rateCount=s.ap.rateCount;
        input.htRates=s.htRates;input.htRateCount=s.htEnabled?s.htRateCount:0;
        input.vhtMap=s.vhtEnabled?s.vhtTxMap:0xffff;
        if(s.secure){input.rsn=s.ap.rsn;input.rsnLength=s.ap.rsnLength;}
        return nativeExtendedBSS(input,data,0x1e0)?kIOReturnSuccess:kIOReturnBadArgument;}
    default:return kIOReturnUnsupported;
    }
}
IOReturn Ath10kPCIDevice::nativeLinkStateUpdate(void *data) {
    if(!data)return kIOReturnBadArgument;
    if(!_nativeInterface)return kIOReturnNotReady;
    auto bytes=static_cast<const UInt8 *>(data);
    if(bytes[6]){
        // A WCL event can outlive the association it describes. Never revive
        // its AP/link after cancel or teardown; key replacement is still associated.
        if(!Ath10k::connectionAssociated(_connection))return kIOReturnNotReady;
        if(!Ath10k::sameMAC(bytes,_connection.bssid))return kIOReturnBadArgument;
        if(bytes[8])_nativeInterface->setCurrentApAddress(reinterpret_cast<ether_addr *>(data));
        if(bytes[7])_nativeInterface->setLinkState(kIO80211NetworkLinkUp,0,false,0);
    }else{
        // WCL deliberately sends an all-zero BSSID for down. Keep this
        // idempotent during/after teardown and preserve its debounce interval.
        _nativeInterface->setCurrentApAddress(nullptr);
        UInt32 debounce=AirportWCL::read32(bytes+12);
        _nativeInterface->setLinkState(kIO80211NetworkLinkDown,0,debounce!=0,debounce);
    }
    return kIOReturnSuccess;
}
static UInt32 channelFlags(UInt32 channel){return nativeChannelFlags(channel,channel,20);}
static_assert(sizeof(apple80211_channel_data)==16,"Sequoia channel reply size");
static_assert(offsetof(apple80211_channel_data,channel)==4,"Sequoia channel reply offset");
static_assert(APPLE80211_C_FLAG_20MHZ==0x2 && APPLE80211_C_FLAG_40MHZ==0x4 &&
    APPLE80211_C_FLAG_80MHZ==0x400 && APPLE80211_C_FLAG_EXT_ABV==0x200 &&
    APPLE80211_C_FLAG_DFS==0x100,"Sequoia channel flags");
IOReturn Ath10kPCIDevice::nativeLinkMetrics(AthNativeOp op,void *data) {
    if(!data)return kIOReturnBadArgument;
    auto &s=_connection;using N=AthNativeOp;
    if(s.cancelRequested || s.disconnect!=Ath10k::DisconnectStage::None ||
       s.stage==Ath10k::LinkStage::Disabled || s.stage==Ath10k::LinkStage::Failed)return kIOReturnNotReady;
    switch(op){
    case N::getCHANNEL:{
        // During join, this is the selected home definition, not instantaneous
        // off-channel scan RF. Do not advertise a width whose geometry is invalid.
        const UInt32 flags=nativeChannelFlags(s.operatingChannel,s.centerChannel,s.width);
        if(!flags)return kIOReturnNotReady;
        auto d=static_cast<apple80211_channel_data *>(data);bzero(d,sizeof(*d));d->version=1;
        d->channel.version=1;d->channel.channel=s.operatingChannel;d->channel.flags=flags;
        return kIOReturnSuccess;}
    case N::getRSSI:{
        if(!Ath10k::connectionAssociated(s) || s.signalDbm==INT32_MIN)return kIOReturnNotReady;
        auto d=static_cast<apple80211_rssi_data *>(data);bzero(d,sizeof(*d));d->version=1;
        d->num_radios=1;d->rssi_unit=APPLE80211_UNIT_DBM;d->rssi[0]=d->aggregate_rssi=s.signalDbm;
        return kIOReturnSuccess;}
    case N::getRATE:{
        if(!Ath10k::connectionAssociated(s) || !s.fwStats.rateValid || s.fwStats.txKbps<500 || s.fwStats.txKbps>2000000)return kIOReturnNotReady;
        auto d=static_cast<apple80211_rate_data *>(data);bzero(d,sizeof(*d));d->version=1;
        d->num_radios=1;d->rate[0]=s.fwStats.txKbps/500;return kIOReturnSuccess;}
    default:return kIOReturnUnsupported;
    }
}
IOReturn Ath10kPCIDevice::nativeRequestGated(AthNativeOp op,void *data) {
    if(_nativeStopping || powerIOBlocked() || !_wmiLive.active)return kIOReturnNotReady;
    auto &s=_connection;using N=AthNativeOp;
    if(!data && op!=N::setCLEAR_PMKSA_CACHE && op!=N::setWCL_SCAN_ABORT &&
       op!=N::setWCL_JOIN_ABORT && op!=N::setWCL_LEAVE_NETWORK && op!=N::setWCL_LINK_UP_DONE &&
       op!=N::NativeReady)return kIOReturnBadArgument;
    if((_nativeMACActive || _nativeMACWaiting) && op!=N::MACSet && op!=N::PowerGet && op!=N::getHW_ADDR)return kIOReturnBusy;
    switch(op){
    case N::MACSet:{
        const auto address=static_cast<const UInt8 *>(data);
        if(!AthNative::validMAC(address))return kIOReturnBadArgument;
        if(_nativeMACWaiting || _nativeMACActive)return kIOReturnBusy;
        const bool same=!bcmp(_nativeMACCurrent,address,6);
        setProperty("Ath10kNativeMACChangeRequested",!same);
        if(same)return kIOReturnSuccess;
        if(!_nativeMACValid || !_nativeGate || getWorkLoop()->onThread())return kIOReturnNotReady;
        if(!_networkInterface || !_networkInterface->getIfnet() || !_wmiScanChannels.completed || !_wmiScan.completed ||
           _nativeScanPending || _nativeJoinPending || _nativeAbortRequested || _nativeWasUp || _nativeLinkUpSent || s.stage!=Ath10k::LinkStage::Disabled ||
           s.disconnect!=Ath10k::DisconnectStage::None || s.peerCount || s.wmiOwned || s.txOwned || _wmi.credits.outstanding)return kIOReturnBusy;
        if(!_connectionCommand.allocated() && !_connectionCommand.allocate(256,128,_dmaMapper))return kIOReturnNoMemory;
        bcopy(address,_nativeMACRequested,6);_nativeMACResult=kIOReturnNotReady;
        _nativeMACStep=1;_nativeMACSubmitted=false;_nativeMACActive=_nativeMACWaiting=true;
        _nativeMACSince=Ath10k::uptimeNS()/1000000u;++_nativeMACGeneration;
        setProperty("Ath10kNativeMACStatus","recreating-vdev");
        // This callback runs on the separate WCL queue. Sleep releases the
        // network gate so the runtime timer can drain DMA and ECHO responses.
        AbsoluteTime deadline;clock_interval_to_deadline(6000,kMillisecondScale,&deadline);
        while(_nativeMACActive && !_nativeStopping && _wmiLive.active){
            IOReturn wake=_nativeGate->commandSleep(&_nativeMACResult,deadline,THREAD_UNINT);
            if(wake!=THREAD_AWAKENED)break;
        }
        if(_nativeMACActive){
            endWMIRuntime("native-mac-transaction-interrupted");
            _nativeMACResult=kIOReturnTimeout;_nativeMACActive=false;
        }
        _nativeMACWaiting=false;if(!_wmiLive.active)requestNativeService();return _nativeMACResult;}

    case N::NativeReady:{
        if(!_nativeStarted || !_nativeInterface || !_networkInterface)return kIOReturnNotReady;
        if(_nativeReadyPublished)return kIOReturnSuccess;
        _nativeReadyRequested=true;requestNativeService();return kIOReturnSuccess;}
    case N::PowerGet:{auto d=static_cast<apple80211_power_data *>(data);bzero(d,sizeof(*d));d->version=1;d->num_radios=1;d->power_state[0]=_nativeRadioOn?1:0;return kIOReturnSuccess;}
    case N::PowerSet:{auto d=static_cast<apple80211_power_data *>(data);if(d->num_radios!=1 || d->power_state[0]>1)return kIOReturnBadArgument;
        _nativeRadioOn=d->power_state[0];if(!_nativeRadioOn){_wmiScan.cancelRequested=true;s.cancelRequested=true;s.portAuthorized=false;discardNativeSecurity();networkLink(false);}
        return kIOReturnSuccess;}
    case N::CountryGet:{auto d=static_cast<apple80211_country_code_data *>(data);bzero(d,sizeof(*d));d->version=1;
        if(_regulatory.country)bcopy(_regulatory.country->alpha2,d->cc,2);return kIOReturnSuccess;}
    case N::CountrySet:{auto d=static_cast<apple80211_country_code_data *>(data);
        return _regulatory.country && !bcmp(d->cc,_regulatory.country->alpha2,2)?kIOReturnSuccess:kIOReturnUnsupported;}
    case N::getHW_ADDR:{AirportWCL::HardwareAddress address{};
        if(!AirportWCL::copyHardwareAddress(_nativeMACCurrent,address))return kIOReturnNotReady;bcopy(&address,data,sizeof(address));return kIOReturnSuccess;}
    case N::getCHANNEL:case N::getRSSI:case N::getRATE:return nativeLinkMetrics(op,data);
    case N::getOP_MODE:{auto d=static_cast<apple80211_opmode_data *>(data);bzero(d,sizeof(*d));d->version=1;d->op_mode=APPLE80211_M_STA;return kIOReturnSuccess;}
    case N::getNSS:{auto d=static_cast<apple80211_nss_data *>(data);bzero(d,sizeof(*d));d->version=1;d->nss=1;return kIOReturnSuccess;}
    case N::getTXPOWER:{auto d=static_cast<apple80211_txpower_data *>(data);bzero(d,sizeof(*d));d->version=1;d->txpower_unit=APPLE80211_UNIT_DBM;d->txpower=s.txPowerHalfDbm/2;return kIOReturnSuccess;}
    case N::getPOWERSAVE:{auto d=static_cast<apple80211_powersave_data *>(data);bzero(d,sizeof(*d));d->version=1;d->powersave_level=s.radio.appliedPS?1:0;return kIOReturnSuccess;}
    case N::setPOWERSAVE:{auto d=static_cast<apple80211_powersave_data *>(data);if(d->powersave_level>1)return kIOReturnUnsupported;s.radio.requestedPS=d->powersave_level;return kIOReturnSuccess;}
    case N::getSUPPORTED_CHANNELS:case N::getHW_SUPPORTED_CHANNELS:{auto d=static_cast<apple80211_sup_channel_data *>(data);bzero(d,sizeof(*d));d->version=1;
        for(const auto &physical:Ath10k::kWMIScanPlan){
            const unsigned ch=physical.channel;
            if(d->num_channels>=APPLE80211_MAX_CHANNELS)break;
            if(!Ath10k::regulatoryPower(_regulatory,ch,ch,20,false))continue;
            auto &c=d->supported_channels[d->num_channels++];c.version=1;c.channel=ch;c.flags=channelFlags(ch);
        }return kIOReturnSuccess;}
    case N::getWCL_LOW_LATENCY_INFO:
        setProperty("Ath10kNativeLowLatencyQuerySeen",true);
        return nativeLowLatencySessions(data,4)?kIOReturnSuccess:kIOReturnBadArgument;
    case N::getWCL_CHANNELS_INFO:{
        auto &channels=*static_cast<AirportWCL::ChannelInfo *>(data);
        bool ok=nativeWCLChannels(_regulatory,channels);
        setProperty("Ath10kNativeWCLChannelCount",UInt64(channels.count),32);
        return ok?kIOReturnSuccess:kIOReturnNotReady;}
    case N::getCHANNELS_INFO:case N::getCOUNTRY_CHANNELS_INFO:{auto d=static_cast<AirportWCL::NativeChannelInfo *>(data);bzero(d,sizeof(*d));
        if(_regulatory.country)bcopy(_regulatory.country->alpha2,d->country,2);
        for(const auto &physical:Ath10k::kWMIScanPlan){const unsigned ch=physical.channel;
            if(!Ath10k::regulatoryPower(_regulatory,ch,ch,20,false))continue;
            AirportWCL::appendChannel(*d,ch,ch>14,ch>=52 && ch<=144,true,false,false);
        }return kIOReturnSuccess;}
    case N::getWCL_TRAFFIC_COUNTERS:{AirportWCL::TrafficCounters counters{};counters.infraTx=s.txPackets;counters.infraRx=s.rxPackets;counters.timestampNanoseconds=Ath10k::uptimeNS();bcopy(&counters,data,sizeof(counters));return kIOReturnSuccess;}
    case N::getWCL_BSS_INFO:case N::getBEACON_INFO:case N::getWCL_EXTENDED_BSS_INFO:
        return nativeCurrentAPInfo(op,data);
    case N::setWCL_SCAN_TIMING:{
        UInt32 milliseconds=AirportWCL::read32(static_cast<const UInt8 *>(data));
        _nativeScanDwellMs=nativeScanDwellBudget(milliseconds);
        setProperty("Ath10kNativeScanTimingRequested",UInt64(milliseconds),32);
        setProperty("Ath10kNativeScanDwellMs",UInt64(_nativeScanDwellMs),32);
        return kIOReturnSuccess;}
    case N::setWCL_FAST_LANE:{
        const auto bytes=static_cast<const UInt8 *>(data);
        return (bytes[0] || bytes[1])?kIOReturnUnsupported:kIOReturnSuccess;}
    case N::setWCL_SCAN_REQ:{AirportWCL::ScanRequest scan{};
        // The native ABI owns a fixed request containing at most 400 channels.
        if(!AirportWCL::decodeScan(data,0x1318,scan))return kIOReturnBadArgument;
        if(!_nativeRadioOn || powerIOBlocked() || _wmiEvents.rfKill)return kIOReturnNotReady;
        UInt32 busy=(_nativeScanPending?1u:0u)|(_nativeJoinPending?2u:0u)|(!_wmiScan.completed?4u:0u)|
            (s.wmiOwned?8u:0u)|(s.txOwned?16u:0u)|(_wmi.credits.outstanding?32u:0u)|
            ((s.stage!=Ath10k::LinkStage::Disabled && (!s.portAuthorized || s.stage!=Ath10k::LinkStage::Connected))?64u:0u)|
            ((_nativeWasUp || _nativeLinkUpSent) && s.stage==Ath10k::LinkStage::Disabled?128u:0u)|
            (_nativeAbortRequested?256u:0u);
        setProperty("Ath10kNativeScanBusyMask",UInt64(busy),32);
        if(busy)return kIOReturnBusy;
        const UInt64 requested=Ath10k::wmiRequestedScanMask(scan.channelCount?scan.channels:nullptr,sizeof(scan.channels));
        const UInt32 channelCount=Ath10k::regulatoryScanCount(&_regulatory,requested);
        setProperty("Ath10kNativeScanRequestedChannelCount",UInt64(channelCount),32);
        if(!channelCount)return kIOReturnUnsupported;
        // Restrict the firmware scan itself as well as delivered results.
        // DFS remains passive and every channel still intersects the domain.
        UInt32 generation=_wmiScan.generation+1;Ath10k::resetInPlace(_wmiScan);_wmiScan.generation=generation;
        _wmiScan.id=0xa000|((0x36+generation)&0xfff);Ath10k::resetInPlace(_wmiBSS);_nativeScan=scan;_nativeScanPending=true;
        _nativeScanResultIndex=_nativeScanResultsEmitted=0;
        return kIOReturnSuccess;}
    case N::setWCL_SCAN_ABORT:{if(_nativeScanPending)_wmiScan.cancelRequested=true;return kIOReturnSuccess;}
    case N::setWCL_ASSOCIATE:{AirportWCL::JoinRequest join{};
        setProperty("Ath10kNativeJoinReason","decode-request");
        if(!AirportWCL::decodeJoin(data,0x2cc,join))return kIOReturnBadArgument;
        setProperty("Ath10kNativeJoinAuth",UInt64(join.upperAuth),32);
        setProperty("Ath10kNativeJoinChannel",UInt64(join.channelSpec&0xff),32);
        const UInt8 selectedAKM=join.upperAuth==APPLE80211_AUTHTYPE_SHA256_PSK?6:2;
        bool personal=join.upperAuth==APPLE80211_AUTHTYPE_WPA2_PSK || join.upperAuth==APPLE80211_AUTHTYPE_SHA256_PSK;
        bool open=join.upperAuth==0 && join.keyLength==0 && join.lowerAuth==1;
        if((!personal && !open) || (personal && (join.lowerAuth!=1 || join.keyLength!=32 || (join.keyCipher!=6 && join.keyCipher!=7)))){
            setProperty("Ath10kNativeJoinReason","unsupported-authentication");
            AthSecurity::wipe(&join,sizeof(join));return kIOReturnUnsupported;}
        if(!_nativeRadioOn || powerIOBlocked() || _wmiEvents.rfKill || !_networkEnabled){AthSecurity::wipe(&join,sizeof(join));return kIOReturnNotReady;}
        if(_nativeJoinPending || _nativeScanPending || _nativeAbortRequested || _nativeWasUp || _nativeLinkUpSent || !_wmiScan.completed || s.stage!=Ath10k::LinkStage::Disabled || s.disconnect!=Ath10k::DisconnectStage::None){AthSecurity::wipe(&join,sizeof(join));return kIOReturnBusy;}
        s.regulatory=_regulatory;s.hiddenSSID=true;s.securityAKM=selectedAKM;s.secure=personal;s.ssidLength=join.ssidLength;
        bcopy(join.ssid,s.ssid,join.ssidLength);bcopy(join.bssid,s.bssid,6);bcopy(_nativeMACCurrent,s.local,6);
        s.firmwareHT=_wmi.htCapability;s.firmwareVHT=_wmi.vhtCapability;s.rfChains=1;
        _nativeSecurity->candidates.expire(Ath10k::uptimeNS()/1000000u);
        const char *error=Ath10k::selectOpenBSS(s,_nativeSecurity->candidates.bss);
        if(error){setProperty("Ath10kNativeJoinReason",error);AthSecurity::wipe(&join,sizeof(join));Ath10k::resetDisconnected(s);return kIOReturnUnsupported;}
        s.hiddenSSID=s.ap.hidden;
        if(personal){UInt8 nonce[32]{};Ath10kKernelCrypto::random(nonce,sizeof(nonce));
            bool ok=_nativeSecurity->supplicant.begin(join.key,nonce,s.local,s.bssid,s.ap.rsn,s.ap.rsnLength,selectedAKM);
            AthSecurity::wipe(nonce,sizeof(nonce));if(!ok){setProperty("Ath10kNativeJoinReason","supplicant-initialization-failed");AthSecurity::wipe(&join,sizeof(join));Ath10k::resetDisconnected(s);return kIOReturnUnsupported;}
            _nativeSecurity->ready=true;}
        _nativeJoin=join;AthSecurity::wipe(_nativeJoin.key,sizeof(_nativeJoin.key));AthSecurity::wipe(&join,sizeof(join));
        setProperty("Ath10kNativeJoinReason","accepted");
        _nativeJoinPending=true;_nativeAssocSent=_nativeBeaconSent=_nativeJoinBSSSent=_nativeLinkUpSent=_nativeJoinFailed=false;_nativeJoinDeadline=Ath10k::uptimeNS()/1000000u+30000;
        s.error="none";s.stage=Ath10k::LinkStage::Scan;return kIOReturnSuccess;}
    case N::setWCL_JOIN_ABORT:case N::setWCL_LEAVE_NETWORK:{
        s.cancelRequested=true;s.portAuthorized=false;if(!_wmiScan.completed)_wmiScan.cancelRequested=true;networkLink(false);
        if(_nativeSecurity)_nativeSecurity->reset();
        if(op==N::setWCL_JOIN_ABORT){
            _nativeJoinPending=false;AthSecurity::wipe(&_nativeJoin,sizeof(_nativeJoin));
            _nativeAbortRequested=true;requestNativeService();
        }
        return kIOReturnSuccess;}
    case N::setCLEAR_PMKSA_CACHE:return kIOReturnSuccess; // No PMKSA cache is retained.
    case N::setWCL_LINK_UP_DONE:return Ath10k::connectionAssociated(s) && s.portAuthorized?kIOReturnSuccess:kIOReturnNotReady;
    case N::setWCL_LINK_STATE_UPDATE:return nativeLinkStateUpdate(data);

    default:return kIOReturnUnsupported;
    }
}

// Radio code never enters WCL synchronously. One coalesced thread call enters
// WCL first, then the network gate. PostOffice and interface callbacks therefore
// use the same WCL -> network order as reportDataPathEvents and native IOCTLs.
void Ath10kPCIDevice::requestNativeService() {
    // Callers hold radio. Never wait for a callback while holding that gate.
    if(_nativeStopping || !_nativeStarted || (!_nativeReadyRequested && !_nativeReadyPublished) || !_nativeServiceLock || _nativeServicePending)return;
    IOLockLock(_nativeServiceLock);
    if(!_nativeServiceStopping && _nativeServiceCall){
        _nativeServicePending=true;
        if(!_nativeServiceQueued){_nativeServiceQueued=true;thread_call_enter(_nativeServiceCall);}
    }
    IOLockUnlock(_nativeServiceLock);
}
void Ath10kPCIDevice::nativeServiceThread(thread_call_param_t context,thread_call_param_t) {
    auto self=static_cast<Ath10kPCIDevice *>(context);
    auto lock=self->_nativeServiceLock;
    IOLockLock(lock);
    self->_nativeServiceQueued=false;self->_nativeServiceRunning=true;
    const bool stopping=self->_nativeServiceStopping;
    IOLockUnlock(lock);
    // Do not hold the bookkeeping lock while attempting either workloop.
    IOReturn result=kIOReturnNotReady;
    if(!stopping && self->_nativeBSDGate)
        result=self->_nativeBSDGate->attemptAction(nativeServiceWCLAction);
    IOLockLock(lock);
    if(!self->_nativeServiceStopping && !self->_nativeServiceQueued &&
       (result==kIOReturnCannotLock || result==kIOReturnNoMemory)){
        AbsoluteTime deadline;clock_interval_to_deadline(10,kMillisecondScale,&deadline);
        self->_nativeServiceQueued=true;
        thread_call_enter_delayed(self->_nativeServiceCall,deadline);
    }
    self->_nativeServiceRunning=false;
    IOLockWakeup(lock,&self->_nativeServiceRunning,false);
    IOLockUnlock(lock);
    // No access to self after publishing completion: stop may release it now.
}
IOReturn Ath10kPCIDevice::nativeServiceWCLAction(OSObject *owner,void *,void *,void *,void *) {
    auto self=OSDynamicCast(Ath10kPCIDevice,owner);
    if(!self || !self->_nativeGate)return kIOReturnNotReady;
    return self->_nativeGate->attemptAction(nativeServiceRadioAction);
}
IOReturn Ath10kPCIDevice::nativeServiceRadioAction(OSObject *owner,void *,void *,void *,void *) {
    auto self=OSDynamicCast(Ath10kPCIDevice,owner);
    if(!self)return kIOReturnBadArgument;
    self->_nativeServicePending=false;
    // The sleep caller raises the atomic block before it can acquire radio.
    // Do not progress crypto or publish join success in that handoff window.
    // Once radio quiescence completes, inactive-runtime terminal events still run.
    if(self->powerIOBlocked() && self->_wmiLive.active)return kIOReturnNotReady;
    if(self->_nativeStopping || (!self->_wmiLive.active && !self->_nativeWasUp && !self->_nativeJoinPending && !self->_nativeScanPending && !self->_nativeLinkUpSent && !self->_nativeAbortRequested))return kIOReturnNotReady;
    self->serviceNative(Ath10k::uptimeNS()/1000000u);
    if(self->_nativePostError!=kIOReturnSuccess){
        self->_nativeServicePending=true;return kIOReturnNoMemory;
    }
    return kIOReturnSuccess;
}

void Ath10kPCIDevice::serviceNative(UInt64 now) {
    _nativePostError=kIOReturnSuccess;
    if(!_nativeInterface || _nativeStopping || !_nativeStarted || _nativeMACActive || _nativeMACWaiting)return;
    auto &s=_connection;auto sec=_nativeSecurity;
    if(sec && _wmiScan.completed && !_wmiScan.failed && !_wmiScan.cancelRequested &&
       sec->cachedGeneration!=_wmiScan.generation){
        for(UInt32 i=0;i<_wmiBSS.count;++i)sec->candidates.add(_wmiBSS.entries[i],now);
        sec->cachedGeneration=_wmiScan.generation;
    }
    const bool associated=Ath10k::connectionAssociated(s);
    // A completed radio-side teardown must not retain PMK/PTK/replies merely
    // because WCL cannot yet allocate Deauth or LinkDown notifications.
    if(sec && (sec->ready || sec->replyPending || sec->keysPending || sec->authorizePending || sec->pairDeadline) &&
       (s.cancelRequested || s.stage==Ath10k::LinkStage::Disabled || s.stage==Ath10k::LinkStage::Failed ||
        s.disconnect!=Ath10k::DisconnectStage::None))discardNativeSecurity();
    // Crypto/radio progress must not wait for WCL event allocation to recover.
    if(sec && sec->ready && associated && s.secure){
        if(sec->authorizePending && !s.txOwned && s.txComplete){
            if(s.txStatus || s.eapolTxFailed){s.error="native-eapol-tx-failed";s.cancelRequested=true;}
            else if(s.securityPhase==3)s.authorizeRequested=true;
            sec->authorizePending=false;
        }
        if(sec->keysPending && !s.wmiOwned && !s.submitted && !s.txOwned && !s.dataPending &&
           !s.stats.step && !s.maintenance.step && !s.radio.step && _wmiScan.completed && !_wmi.credits.outstanding){
            const bool initial=sec->keyOperation==AthSecurity::Supplicant<Ath10kKernelCrypto,true>::Keys;
            const bool pair=sec->keyOperation==AthSecurity::Supplicant<Ath10kKernelCrypto,true>::PairKeys;
            if((initial && !s.securityPhase) || (!initial && s.securityPhase==5 && s.portAuthorized)){
                const unsigned keyBytes=s.groupCipher==AthSecurity::cipherTKIP?32:16;
                bool sameGroup=s.groupInstalled[sec->keys[49]] && AthSecurity::equal(sec->keys+16,s.installedGroups[sec->keys[49]],keyBytes);
                bcopy(sec->keys,s.temporalKey,16);bcopy(sec->keys+16,s.groupKey,32);
                s.groupIndex=sec->keys[49];bcopy(sec->keys+50,s.groupRSC,6);
                if(initial){UInt64 pn=0;for(unsigned i=0;i<6;++i)pn|=UInt64(s.groupRSC[i])<<(8*i);for(auto &v:s.groupPN)v=pn;}
                s.rekeyKind=initial?0:(pair?2:1);s.rekeySkipGroup=pair && sameGroup;
                s.securityPhase=initial || pair?1:2;s.submitted=false;s.securityAck=false;s.authorizeRequested=false;
                s.portAuthorized=false;s.sinceMs=now;sec->keysPending=false;AthSecurity::wipe(sec->keys,sizeof(sec->keys));
            }
        }
        if(sec->replyPending && !sec->keysPending && !s.txOwned && !s.dataPending && !s.wmiOwned &&
           !s.maintenance.step && !s.radio.blocked && !s.radio.powerBlocked && !s.radio.appliedPS && !s.csa.blocked && !s.txPauseMask &&
           (!s.securityPhase || s.securityPhase==3 || s.securityPhase==5)){
            const char *error=submitNetworkPacket(sec->reply,sec->replyLength,false,now);
            if(error){s.error=error;s.cancelRequested=true;}
            else {sec->replyPending=false;sec->authorizePending=s.securityPhase==3;
                AthSecurity::wipe(sec->reply,sizeof(sec->reply));sec->replyLength=0;}
        }
        if(!sec->replyPending && !sec->keysPending && !sec->authorizePending && s.eapolCount && !s.rekeyKind){
            auto result=sec->supplicant.receive(s.eapolFrames[s.eapolRead],s.eapolLength[s.eapolRead]);
            AthSecurity::wipe(s.eapolFrames[s.eapolRead],512);s.eapolRead=(s.eapolRead+1)%4;--s.eapolCount;
            using Supplicant=AthSecurity::Supplicant<Ath10kKernelCrypto,true>;
            if(result==Supplicant::Fatal){s.error="native-wpa2-handshake-failed";s.cancelRequested=true;}
            else if(result!=Supplicant::Ignore){
                if(sec->supplicant.outputLength && sec->supplicant.outputLength<=sizeof(sec->reply)){
                    bcopy(sec->supplicant.output,sec->reply,sec->supplicant.outputLength);sec->replyLength=sec->supplicant.outputLength;sec->replyPending=true;}
                if(result==Supplicant::Keys || result==Supplicant::GroupKeys || result==Supplicant::PairKeys){
                    bcopy(sec->supplicant.keys,sec->keys,sizeof(sec->keys));sec->keysPending=true;sec->keyOperation=result;
                }
            }
        }
        if(sec->supplicant.pairwisePending()){
            s.eapolPause=true;if(!sec->pairDeadline)sec->pairDeadline=now+5000;
            if(now>=sec->pairDeadline){sec->supplicant.cancelPairwiseAttempt();sec->pairDeadline=0;s.eapolPause=false;}
        }else {sec->pairDeadline=0;s.eapolPause=sec->replyPending || sec->keysPending || sec->authorizePending;}
    }
    serviceNativeNotifications(now);
}

// Called only with WCL and radio gates held, in that order. PostOffice copies
// each payload before returning, but a failed enqueue has not delivered anything.
void Ath10kPCIDevice::serviceNativeNotifications(UInt64 now) {
    _nativePostError=kIOReturnSuccess;
    if(!_nativeInterface || _nativeStopping || !_nativeStarted || _nativeMACActive || _nativeMACWaiting)return;
    auto &s=_connection;auto sec=_nativeSecurity;
    auto post=[&](UInt32 id,void *payload,size_t bytes){
        if(_nativePostError!=kIOReturnSuccess)return false;
        const IOReturn result=postMessage(_nativeInterface,id,payload,bytes,true);
        if(result==kIOReturnSuccess)return true;
        _nativePostError=result;++_nativePostFailures;
        // Bound allocation-heavy telemetry while the system is short on memory.
        if(_nativePostFailures==1 || _nativePostFailures%100==0){
            setProperty("Ath10kNativeEventEnqueueFailures",_nativePostFailures,64);
            setProperty("Ath10kNativeEventEnqueueLastError",UInt64(result),32);
            setProperty("Ath10kNativeEventEnqueueLastID",UInt64(id),32);
        }
        return false;
    };
    if(_nativeReadyRequested && !_nativeReadyPublished && _wmiLive.active){
        if(!_nativeReadyResetSent){
            UInt32 reset=1;
            if(post(AirportWCL::ResetInterface,&reset,sizeof(reset)))_nativeReadyResetSent=true;
        }
        if(_nativeReadyResetSent){
            AirportWCL::DriverAvailability ready{};ready.version=3;ready.available=1;ready.reason=0xe0821803;
            if(post(AirportWCL::DriverAvailable,&ready,sizeof(ready))){
                _nativeReadyPublished=true;_nativeReadyRequested=false;
            }
        }
    }
    if(_nativeAbortRequested && post(AirportWCL::JoinAbortComplete,nullptr,0))_nativeAbortRequested=false;

    if(_nativeScanPending && _wmiScan.completed){
        if(!_wmiScan.failed && !_wmiScan.cancelRequested){
            while(_nativeScanResultIndex<_wmiBSS.count){
                const auto &b=_wmiBSS.entries[_nativeScanResultIndex];
                if(nativeScanMatches(_nativeScan,b)){
                    const size_t length=nativeBSSMessage(b,_nativeBSSMessage,sizeof(_nativeBSSMessage));
                    if(length){
                        if(!post(AirportWCL::ScanResult,_nativeBSSMessage,length))break;
                        ++_nativeScanResultsEmitted;
                    }
                }
                ++_nativeScanResultIndex;
            }
        }
        if(_wmiScan.failed || _wmiScan.cancelRequested || _nativeScanResultIndex>=_wmiBSS.count){
            UInt32 status=_wmiScan.cancelRequested?kIOReturnAborted:(_wmiScan.failed?kIOReturnError:kIOReturnSuccess);
            if(post(AirportWCL::ScanDone,&status,sizeof(status))){
                setProperty("Ath10kNativeScanResultsEmitted",UInt64(_nativeScanResultsEmitted),32);
                setProperty("Ath10kNativeScanDoneStatus",UInt64(status),32);
                setProperty("Ath10kNativeScanDoneGeneration",UInt64(_wmiScan.generation),32);
                _nativeScanPending=false;_nativeBSSBytes=0;
            }
        }
    }
    const bool associated=Ath10k::connectionAssociated(s);
    const bool joinFailed=_nativeJoinPending && (_nativeJoinFailed || s.cancelRequested ||
        s.stage==Ath10k::LinkStage::Failed || s.disconnect!=Ath10k::DisconnectStage::None || now>=_nativeJoinDeadline);
    if(_nativeJoinPending && !joinFailed && associated && !_nativeAssocSent){
        AirportWCL::AssociationEvent event{};bcopy(s.bssid,event.bssid,6);event.status=s.associationStatus;
        event.driverStatus=event.status?kIOReturnError:kIOReturnSuccess;
        if(post(AirportWCL::AssocComplete,&event,sizeof(event)))_nativeAssocSent=event.status==0;
    }
    if(_nativeJoinPending && !joinFailed && associated && _nativeAssocSent && s.beaconFrameBytes && !_nativeBeaconSent){
        if(!_nativeJoinBSSSent){
            _nativeBSSBytes=nativeBSSMessage(s.ap,_nativeBSSMessage,sizeof(_nativeBSSMessage));
            if(_nativeBSSBytes && post(AirportWCL::ScanResult,_nativeBSSMessage,_nativeBSSBytes))_nativeJoinBSSSent=true;
        }
        if(_nativeJoinBSSSent && !_nativeLinkUpSent){
            AirportWCL::LinkStatusEvent link{};bcopy(s.bssid,link.bssid,6);link.up=1;link.reason=255;
            if(post(AirportWCL::LinkStatus,&link,sizeof(link))){
                _nativeLinkUpSent=true;bcopy(s.bssid,_nativeLastBSSID,6);
            }
        }
        if(_nativeLinkUpSent){
            AirportWCL::FirstBeaconEvent beacon{};bcopy(s.bssid,beacon.peer.bssid,6);
            if(post(AirportWCL::FirstBeacon,&beacon,sizeof(beacon)))_nativeBeaconSent=true;
        }
    }
    if(_nativeJoinPending){
        const bool success=!joinFailed && associated && s.portAuthorized && _nativeBeaconSent;
        if(success || joinFailed){
            // A timeout/failure closes the data port even if its notification
            // must wait for memory. Do not reset crypto repeatedly on retries.
            if(joinFailed && !_nativeJoinFailed){
                _nativeJoinFailed=true;s.cancelRequested=true;s.portAuthorized=false;
                AthSecurity::wipe(_nativeJoin.key,sizeof(_nativeJoin.key));
                networkLink(false);if(sec)sec->reset();
            }
            AirportWCL::ConnectionEvent event{};event.status=success?0:1;
            bcopy(_nativeJoin.bssid,event.peers[0].bssid,6);event.peers[0].driverStatus=success?kIOReturnSuccess:kIOReturnError;
            if(post(AirportWCL::ConnectComplete,&event,sizeof(event))){
                _nativeJoinPending=false;AthSecurity::wipe(&_nativeJoin,sizeof(_nativeJoin));
            }
        }
    }
    // Key replacement temporarily closes the controlled port; this is not a
    // new association and must not generate Deauth/LinkDown for a healthy AP.
    const bool up=associated && _networkLinkUp && (s.portAuthorized || (_nativeWasUp && s.rekeyKind));
    const int quality=up && s.signalDbm!=INT32_MIN?(s.signalDbm>=-70?100:(s.signalDbm>=-85?50:20)):-2;
    if(quality!=_nativeReportedQuality){
        setProperty("Ath10kNativeLinkQuality",UInt64(static_cast<SInt64>(quality)),64);
        _nativeReportedQuality=quality;
    }
    if(up && s.signalDbm!=INT32_MIN && s.beaconFrameSerial!=_nativeReportedBeacon &&
       UInt32(s.beaconFrameSerial-_nativeReportedBeacon)>=8){
        AirportWCL::SequoiaLqmUpdate update{};update.rssiValid=1;update.rssi=s.signalDbm;
        if(post(AirportWCL::LqmUpdate,&update,sizeof(update)))_nativeReportedBeacon=s.beaconFrameSerial;
    }
    if((_nativeWasUp || (_nativeLinkUpSent && !_nativeJoinPending)) && !up){
        if(!_nativeDeauthSent){
            AirportWCL::DeauthEvent event{};bcopy(_nativeLastBSSID,event.bssid,6);event.reason=3;event.deauthentication=1;
            if(s.apDisconnect.valid && Ath10k::sameMAC(s.apDisconnect.bssid,_nativeLastBSSID)){
                event.reason=s.apDisconnect.reason;event.deauthentication=!s.apDisconnect.disassociation;
            }
            if(post(AirportWCL::Deauth,&event,sizeof(event)))_nativeDeauthSent=true;
        }
        if(_nativeDeauthSent){
            AirportWCL::LinkStatusEvent link{};bcopy(_nativeLastBSSID,link.bssid,6);
            if(post(AirportWCL::LinkStatus,&link,sizeof(link))){
                _nativeWasUp=_nativeLinkUpSent=_nativeDeauthSent=false;
                _nativeBSSBytes=0;_nativeReportedBeacon=0;
                bzero(_nativeLastBSSID,sizeof(_nativeLastBSSID));if(sec)sec->reset();
            }
        }
    }
    if(up){_nativeWasUp=true;bcopy(s.bssid,_nativeLastBSSID,6);}
}

// Runs under the network workloop gate; no radio commands run concurrently.
const char *Ath10kPCIDevice::serviceNativeMAC(UInt64 now) {
    if(!_nativeMACActive)return nullptr;
    if(now<_nativeMACSince || now-_nativeMACSince>=5000)return "native-mac-transaction-timeout";
    if(!_nativeMACSubmitted){
        if(_wmi.credits.outstanding)return nullptr;
        const bool barrier=_nativeMACStep==2 || _nativeMACStep==4;
        if(barrier){
            Ath10k::resetInPlace(_nativeMACEcho);
            _nativeMACEcho.cookie=0xa7c00000u|((_nativeMACGeneration&0xfffu)<<4)|_nativeMACStep;
            _nativeMACEcho.submitted=true;
        }
        const UInt32 bytes=AthNative::macFrame(static_cast<UInt8 *>(_connectionCommand.virtualAddress()),256,
            _htcWMIControl.endpoint,_nativeMACStep,_nativeMACRequested,_nativeMACEcho.cookie);
        if(!bytes)return "native-mac-frame";
        const char *error=submitNetworkCE(3,_connectionCommand,bytes,_nativeMACNext);
        if(error)return error;
        _nativeMACSubmitted=true;return nullptr;
    }
    Ath10k::CESnapshot snap{};
    if(!Ath10k::readCESnapshot(_regs,3,snap) || !validateBMIPipeStructure(3,snap) || snap.srcWriteIndex!=_nativeMACNext)return "native-mac-ce-state";
    if(snap.currentSrcRead!=_nativeMACNext || _wmi.credits.outstanding)return nullptr;
    if(!_connectionCommand.syncFromDevice() || !_ceSrcRings[3].syncFromDevice())return "native-mac-ce-sync";
    _connection.wmiOwned=false;
    if((_nativeMACStep==2 || _nativeMACStep==4) && !_nativeMACEcho.replyReceived)return nullptr;
    if(_nativeMACStep<4){++_nativeMACStep;_nativeMACSubmitted=false;return nullptr;}
    // Firmware now has the requested address. Publish only after both barriers.
    if(!_networkInterface || !_networkInterface->getIfnet() ||
       ifnet_set_lladdr(_networkInterface->getIfnet(),_nativeMACRequested,6))return "native-mac-bsd-address";
    bcopy(_nativeMACRequested,_nativeMACCurrent,6);
    _networkInterface->setProperty(kIOMACAddress,_nativeMACCurrent,6);
    setProperty("Ath10kNativeMACStatus","applied");
    setProperty("Ath10kNativeMACGeneration",UInt64(_nativeMACGeneration),32);
    _nativeMACResult=kIOReturnSuccess;_nativeMACActive=false;
    _nativeGate->commandWakeup(&_nativeMACResult);return nullptr;
}

const char *Ath10kPCIDevice::nativeSelectBSS(UInt64 now) {
    if(!_nativeSecurity || !_nativeJoinPending)return "native-candidate-not-ready";
    _nativeSecurity->candidates.expire(now);
    return Ath10k::selectOpenBSS(_connection,_nativeSecurity->candidates.bss);
}

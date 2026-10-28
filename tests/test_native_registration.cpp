#include <cassert>
#include <cstring>
#include <cstdint>
using IOReturn=int;
constexpr IOReturn kIOReturnSuccess=0,kIOReturnNoMemory=1,kIOReturnError=2,kIOReturnBadArgument=3;
struct IOService{};
struct IOSkywalkNetworkInterface {struct RegistrationInfo {uint8_t bytes[0x108];};};
struct IOSkywalkEthernetInterface:IOSkywalkNetworkInterface {struct RegistrationInfo {uint8_t bytes[0x130];};};
class IO80211InfraProtocol:public IOSkywalkEthernetInterface {
public:
    struct NetworkExpansion {IOSkywalkNetworkInterface::RegistrationInfo *fRegistrationInfo=nullptr;} network;
    struct EthernetExpansion {IOSkywalkEthernetInterface::RegistrationInfo *fRegistrationInfo=nullptr;} ethernet;
    NetworkExpansion *mExpansionData=&network;EthernetExpansion *mExpansionData2=&ethernet;
    unsigned copies=0,ethernetFrees=0,networkFrees=0,stops=0,frees=0,deregisters=0;
    unsigned factoryFailure=0;IOReturn deregisterResult=kIOReturnSuccess;
    IOReturn copyRegistrationInfo(const IOSkywalkEthernetInterface::RegistrationInfo *registration){
        ++copies;assert(mExpansionData2 && !mExpansionData2->fRegistrationInfo);
        uint32_t version=0,length=0;memcpy(&version,registration->bytes,4);memcpy(&length,registration->bytes+4,4);
        if(version!=1 || length<sizeof(*registration))return kIOReturnBadArgument;
        if(factoryFailure==1)return kIOReturnNoMemory;
        if(factoryFailure==3)return kIOReturnSuccess; // Defensive missing-output seam.
        mExpansionData2->fRegistrationInfo=new IOSkywalkEthernetInterface::RegistrationInfo(*registration);
        // Stock factory can fail MAC property publication after allocation.
        return factoryFailure==2?kIOReturnError:kIOReturnSuccess;
    }
    void freeNetwork(){
        if(!mExpansionData || !mExpansionData->fRegistrationInfo)return;
        // A network typed free must never receive the Ethernet typed object.
        assert(!mExpansionData2 || reinterpret_cast<void *>(mExpansionData->fRegistrationInfo)!=mExpansionData2->fRegistrationInfo);
        delete mExpansionData->fRegistrationInfo;mExpansionData->fRegistrationInfo=nullptr;++networkFrees;
    }
    virtual void stop(IOService *){++stops;freeNetwork();}
    virtual void free(){
        ++frees;
        // Real Ethernet base free precedes Network base free. A surviving
        // borrowed alias would be both a wrong-type free and a double free.
        assert(!mExpansionData || !mExpansionData2 || !mExpansionData->fRegistrationInfo ||
            reinterpret_cast<void *>(mExpansionData->fRegistrationInfo)!=mExpansionData2->fRegistrationInfo);
        if(mExpansionData2 && mExpansionData2->fRegistrationInfo){
            delete mExpansionData2->fRegistrationInfo;mExpansionData2->fRegistrationInfo=nullptr;++ethernetFrees;
        }
        freeNetwork();
    }
    virtual IOReturn deregisterLogicalLink(){++deregisters;freeNetwork();return deregisterResult;}
    virtual ~IO80211InfraProtocol(){assert(!network.fRegistrationInfo && !ethernet.fRegistrationInfo);}
};
struct Controller {unsigned interfaceStops=0;void nativeInterfaceWillStop(void *){++interfaceStops;}};
static void ifnet_release(void *){assert(false);}
class Ath10kNativeInterface:public IO80211InfraProtocol {
public:
    void *_nativeBSDReference=nullptr;
    Controller *controller=nullptr;
    void releaseTerminationNotification(){}
    IOSkywalkNetworkInterface::RegistrationInfo *_registrationLoan=nullptr;
    bool prepareRegistrationInfo(const IOSkywalkEthernetInterface::RegistrationInfo &);
    void detachRegistrationLoan();void stop(IOService *) override;void free() override;
    IOReturn deregisterLogicalLink() override;
};
#include "native_registration_methods.inc"
int main(){
    IOSkywalkEthernetInterface::RegistrationInfo registration{};
    for(unsigned i=0;i<sizeof(registration);++i)registration.bytes[i]=uint8_t(i);
    uint32_t version=1,length=sizeof(registration);
    memcpy(registration.bytes,&version,4);memcpy(registration.bytes+4,&length,4);
    for(unsigned route=0;route<3;++route){
        Ath10kNativeInterface d;Controller controller;d.controller=&controller;assert(d.prepareRegistrationInfo(registration));
        assert(d.copies==1 && d.network.fRegistrationInfo==d._registrationLoan);
        assert(reinterpret_cast<void *>(d.network.fRegistrationInfo)==d.ethernet.fRegistrationInfo);
        auto *reader=d.network.fRegistrationInfo;auto *owned=d.ethernet.fRegistrationInfo;
        assert(!memcmp(reader,&registration,sizeof(*reader)));
        assert(!d.prepareRegistrationInfo(registration) && d.copies==1);
        if(route==0){
            d.stop(nullptr);d.stop(nullptr); // Checks our detach; mock base is intentionally repeatable.
            assert(controller.interfaceStops==2);
            assert(!d.network.fRegistrationInfo && !d._registrationLoan && d.ethernet.fRegistrationInfo==owned);
            assert(!memcmp(reader,&registration,sizeof(*reader))); // Old reader storage remains live.
        }else if(route==1){
            d.deregisterResult=kIOReturnError;
            assert(d.deregisterLogicalLink()==kIOReturnError);
            assert(!d.network.fRegistrationInfo && d.ethernet.fRegistrationInfo==owned);
            assert(!memcmp(reader,&registration,sizeof(*reader)));
        }
        d.free();assert(!d.network.fRegistrationInfo && !d.ethernet.fRegistrationInfo);
        assert(d.ethernetFrees==1 && d.networkFrees==0 && d.frees==1);
    }
    for(unsigned failure=1;failure<=3;++failure){
        Ath10kNativeInterface d;d.factoryFailure=failure;
        assert(!d.prepareRegistrationInfo(registration) && !d._registrationLoan && !d.network.fRegistrationInfo);
        d.free();assert(d.ethernetFrees==(failure==2?1u:0u) && !d.networkFrees);
    }
    { // Never overwrite registration already owned by a framework path.
        Ath10kNativeInterface d;
        d.network.fRegistrationInfo=new IOSkywalkNetworkInterface::RegistrationInfo{};
        auto *existing=d.network.fRegistrationInfo;
        assert(!d.prepareRegistrationInfo(registration) && !d.copies && d.network.fRegistrationInfo==existing);
        d.free();assert(d.networkFrees==1 && !d.ethernetFrees);
    }
    {
        Ath10kNativeInterface d;
        d.ethernet.fRegistrationInfo=new IOSkywalkEthernetInterface::RegistrationInfo{};
        auto *existing=d.ethernet.fRegistrationInfo;
        assert(!d.prepareRegistrationInfo(registration) && !d.copies && d.ethernet.fRegistrationInfo==existing);
        d.free();assert(d.ethernetFrees==1 && !d.networkFrees);
    }
    { // Another owner replacing the loan remains responsible for its own slot.
        Ath10kNativeInterface d;assert(d.prepareRegistrationInfo(registration));
        d.network.fRegistrationInfo=new IOSkywalkNetworkInterface::RegistrationInfo{};
        d.stop(nullptr);assert(d.networkFrees==1 && !d._registrationLoan);
        d.free();assert(d.ethernetFrees==1 && d.networkFrees==1);
    }
    for(unsigned field=0;field<2;++field){
        Ath10kNativeInterface d;auto invalid=registration;uint32_t bad=0;
        memcpy(invalid.bytes+4*field,&bad,4);
        assert(!d.prepareRegistrationInfo(invalid) && !d.network.fRegistrationInfo && !d.ethernet.fRegistrationInfo);
        d.free();assert(!d.networkFrees && !d.ethernetFrees);
    }
    for(unsigned missing=0;missing<2;++missing){
        Ath10kNativeInterface d;
        if(missing)d.mExpansionData2=nullptr;else d.mExpansionData=nullptr;
        assert(!d.prepareRegistrationInfo(registration) && !d.copies);
        d.free();assert(!d.ethernetFrees && !d.networkFrees);
    }
}

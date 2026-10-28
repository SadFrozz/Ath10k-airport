#if !ATH10K_P256_DIAGNOSTIC
#error "The diagnostic service must only be compiled for diagnostic stage 4"
#endif
#define ATH10K_P256_DIAGNOSTIC_BINDING 1
#include "Ath10kP256KernelBinding.hpp"
#include "Ath10kP256RegistryJob.hpp"
#include <IOKit/pci/IOPCIDevice.h>
#include <libkern/c++/OSBoolean.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSString.h>
#include <libkern/version.h>
#include <kern/clock.h>
static uint64_t diagnosticClockNS(){uint64_t absolute=0,ns=0;clock_get_uptime(&absolute);absolutetime_to_nanoseconds(absolute,&ns);return ns;}

// No IO80211 inheritance, workloop, CoreCapture, power plane, PCI-open or DMA.
class Ath10kP256DiagnosticService : public IOService {
    OSDeclareDefaultStructors(Ath10kP256DiagnosticService)
    Ath10kSAEWorker *worker=nullptr;
    Ath10kP256RegistryJob *job=nullptr;
    bool started=false;
    static bool registryID(IOService *entry,const char *key,UInt16 &out){
        auto property=entry->copyProperty(key);bool valid=false;UInt64 value=0;
        if(auto data=OSDynamicCast(OSData,property)){
            if(data->getLength()==4 && data->getBytesNoCopy()){
                auto p=static_cast<const UInt8 *>(data->getBytesNoCopy());
                value=UInt32(p[0])|(UInt32(p[1])<<8)|(UInt32(p[2])<<16)|(UInt32(p[3])<<24);valid=value<=0xffff;
            }
        }else if(auto number=OSDynamicCast(OSNumber,property)){value=number->unsigned64BitValue();valid=value<=0xffff;}
        if(property)property->release();if(valid)out=static_cast<UInt16>(value);return valid;
    }
    bool allowed(IOService *provider){
        auto enabled=OSDynamicCast(OSBoolean,getProperty("Ath10kP256SelfTest"));
        auto stage=OSDynamicCast(OSNumber,getProperty("Ath10kDiagnosticStage"));
        if(!enabled || !enabled->isTrue() || !stage || stage->unsigned32BitValue()!=4 || !OSDynamicCast(IOPCIDevice,provider))return false;
        UInt16 vendor=0,device=0,subvendor=0,subsystem=0;
        if(!registryID(provider,"vendor-id",vendor) || !registryID(provider,"device-id",device) ||
           !registryID(provider,"subsystem-vendor-id",subvendor) || !registryID(provider,"subsystem-id",subsystem) ||
           !AthSecurity::p256DiagnosticDevice(vendor,device,subvendor,subsystem))return false;
        // osversion is declared by the SDK but is not a supported kext export.
        // Read the same build identity through the retained registry property.
        auto root=IORegistryEntry::getRegistryRoot();
        auto property=root?root->copyProperty("OS Build Version"):nullptr;
        auto build=OSDynamicCast(OSString,property);
        const bool supported=build && AthSecurity::p256DiagnosticKernel(version_major,version_minor,version_revision,build->getCStringNoCopy(),version);
        if(property)property->release();if(supported)return true;
        provider->setProperty("Ath10kP256CheckPassed",false);
        provider->setProperty("Ath10kP256CheckKernel",version);
        provider->setProperty("Ath10kP256CheckState","unsupported-kernel");return false;
    }
    void cleanup(IOService *provider){
        // No owned driver gate exists. The worker never calls back into this
        // service; drain before dropping either retained object.
        if(job && job->cancelReport() && provider){
            provider->setProperty("Ath10kP256CheckPassed",false);
            provider->setProperty("Ath10kP256CheckState","cancelled");
        }
        if(worker)worker->shutdown();
        OSSafeReleaseNULL(worker);OSSafeReleaseNULL(job);
    }
    void free() override {cleanup(nullptr);IOService::free();}
public:
    IOService *probe(IOService *provider,SInt32 *score) override {
        if(!allowed(provider))return nullptr;return IOService::probe(provider,score);
    }
    bool start(IOService *provider) override {
        if(!allowed(provider) || !IOService::start(provider))return false;started=true;
        provider->setProperty("Ath10kP256CheckState","initializing");
        provider->setProperty("Ath10kP256CheckPassed",false);
        provider->setProperty("Ath10kP256CheckMask",UInt64(0),32);
        provider->setProperty("Ath10kP256CheckStep",UInt64(0),32);
        provider->setProperty("Ath10kP256CheckEpoch",UInt64(1),32);
        provider->setProperty("Ath10kP256CheckElapsedNS",UInt64(0),64);
        provider->setProperty("Ath10kP256CheckQueueNS",UInt64(0),64);
        provider->setProperty("Ath10kP256CheckKernel",version);
        provider->setProperty("Ath10kP256CheckState","pending");
        worker=new Ath10kSAEWorker;job=new Ath10kP256RegistryJob;
        if(!worker || !job || !worker->init() ||
           !job->initReport(Ath10kP256KernelBinding::points(),Ath10kP256KernelBinding::field(),provider,diagnosticClockNS,1) ||
           !worker->submit(job)){
            provider->setProperty("Ath10kP256CheckState","allocation-failed");cleanup(nullptr);
            IOService::stop(provider);started=false;return false;
        }
        return true;
    }
    void stop(IOService *provider) override {
        cleanup(provider);if(started){started=false;IOService::stop(provider);}
    }
};
OSDefineMetaClassAndStructors(Ath10kP256DiagnosticService,IOService)

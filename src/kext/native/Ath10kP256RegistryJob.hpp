#pragma once
#include <IOKit/IOService.h>
#include "Ath10kP256CheckJob.hpp"
#include "../../shared/Ath10kP256DiagnosticPolicy.hpp"
// Diagnostic-only registry reporter. Holds a PCI registry entry, never the
// controller/NativeSecurity; no callback or computation enters an owner gate.
class Ath10kP256RegistryJob : public Ath10kSAEWorkItem {
    OSDeclareDefaultStructors(Ath10kP256RegistryJob)
    Ath10kP256CheckJob *check=nullptr;
    IOService *target=nullptr;
    uint64_t (*clockNS)()=nullptr;
    uint32_t epoch=0;uint64_t submitted=0;
    bool executed=false,consumed=false;
    AthSecurity::P256DiagnosticPublication publication;
public:
    enum class Admission {Ready,Rejected,TimedOut,Cancelled};
    using AdmissionCheck=Admission (*)(const AthSecurity::P256DiagnosticPublication &);
private:
    AdmissionCheck admission=nullptr;
    AthSecurity::P256CoreCryptoAPI points{};
    AthSecurity::P256FieldAPI field{};
public:
    bool initReport(const AthSecurity::P256CoreCryptoAPI &,const AthSecurity::P256FieldAPI &,
        IOService *,uint64_t (*)(),uint32_t,AdmissionCheck=nullptr);
    bool cancelReport(){return publication.cancel();} // Caller retains the job.
    void execute() override;
    void discard() override;
};

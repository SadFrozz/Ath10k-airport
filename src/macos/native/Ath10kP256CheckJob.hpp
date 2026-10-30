#pragma once
#include "Ath10kSAEWorker.hpp"
#include "../../security/Ath10kP256BackendCheck.hpp"
// Diagnostic only: no password, radio, NativeSecurity or IO80211 ownership.
// Submission/collection use the existing retained worker protocol. A passing
// report never enables SAE admission or proves another OS's private ABI.
class Ath10kP256CheckJob : public Ath10kSAEWorkItem {
    OSDeclareDefaultStructors(Ath10kP256CheckJob)
    AthSecurity::P256CoreCryptoAPI points{};
    AthSecurity::P256FieldAPI field{};
    AthSecurity::P256BackendCheckWorkspace workspace{};
    AthSecurity::P256BackendCheckReport report{};
    uint32_t epoch=0;uint64_t started=0,deadline=0;
    bool initialized=false,executed=false,consumed=false;
public:
    static constexpr uint64_t DeadlineMs=5000;
    bool initCheck(const AthSecurity::P256CoreCryptoAPI &,const AthSecurity::P256FieldAPI &,uint32_t,uint64_t);
    void execute() override;
    void discard() override;
    // True means a current report was collected; inspect report.complete for
    // the test result. Collection success is never crypto/admission approval.
    bool takeReport(uint32_t,uint64_t,AthSecurity::P256BackendCheckReport &);
};
static_assert(sizeof(Ath10kP256CheckJob)<=2048,"Heap-owned bounded public backend check");

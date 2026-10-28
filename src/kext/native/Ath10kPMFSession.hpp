#pragma once
#include "Ath10kSAEWorker.hpp"
#include "../../shared/Ath10kPMFTransport.hpp"
#include "../../shared/Ath10kSHA256.hpp"
class Ath10kPMFJob;
// One negotiated PMF association. All owner methods require the radio gate.
// Native RX/TX dispatch and WPA3 admission are not enabled by this object.
class Ath10kPMFSession : public OSObject {
    OSDeclareDefaultStructors(Ath10kPMFSession)
    friend class Ath10kPMFJob;
    AthSecurity::PMFPairwiseEpoch pairwise;
    AthSecurity::PMFKeyEpochs management;
    uint8_t local[6]{},ap[6]{};
    uint64_t connection=0,pendingTXPN=0;
    bool initialized=false,closed=true,havePairwise=false,haveManagement=false,authorized=false;
    void free() override;
    bool current(uint64_t generation) const {return initialized && !closed && generation==connection;}
public:
    enum class Submission : uint8_t {Queued,Busy,NoMemory,NoWork,Aborted};
    enum class Kind : uint8_t {Empty,Pairwise,GroupManagement,ProtectTX};
    using Layout=AthSecurity::PMFCCMPRXLayout;
    struct Message {
        uint8_t frame[512]{};size_t bytes=0;Kind kind=Kind::Empty;
        AthSecurity::PMFVerifiedRX pairwise{};uint16_t groupID=0;uint64_t groupEpoch=0;
        ~Message(){AthSecurity::wipe(this,sizeof(*this));}
    };
    bool initConnection(const uint8_t *station,const uint8_t *bssid,uint64_t generation);
    // Call only at HTT PTK acknowledgement and authenticated IGTK publication.
    bool acknowledgePairwise(const uint8_t *tk,const uint8_t *station,const uint8_t *bssid);
    bool activateManagement(const AthSecurity::IGTKCMAC128 &);
    // Called after the data-key transaction/barrier, before controlled port up.
    bool authorize();
    void cancel(); // Independent running snapshots stay retained until drained.
    uint64_t activeGeneration() const {return current(connection)?connection:0;}
    uint64_t pairwiseEpoch() const {return current(connection)?pairwise.currentEpoch():0;}
    Submission queue(Ath10kSAEWorker *,const uint8_t *,size_t,uint32_t status,Layout,uint64_t generation);
    bool consume(Ath10kSAEWorkItem *,uint64_t generation,Message &);
    Submission queueProtect(Ath10kSAEWorker *,const uint8_t *,size_t,uint64_t generation,AthSecurity::ManagementTX=AthSecurity::ManagementTX::SoftwareCCMP);
    bool protectedReady(Ath10kSAEWorkItem *,uint64_t generation) const;
    bool copyProtected(Ath10kSAEWorkItem *,uint8_t *,size_t,size_t &,uint64_t generation) const;
    bool copyForTransport(Ath10kSAEWorkItem *,uint8_t *,size_t,size_t &,AthSecurity::ManagementTX &,uint64_t generation) const;
    // Consume on either accepted or failed transport handoff; PN stays spent.
    bool retireProtected(Ath10kSAEWorkItem *,uint64_t generation);
    // Cancel only this TX lease; a running job owns independent snapshots.
    void abandonProtected(){pendingTXPN=0;}
};
class Ath10kPMFJob : public Ath10kSAEWorkItem {
    OSDeclareDefaultStructors(Ath10kPMFJob)
    friend class Ath10kPMFSession;
    Ath10kPMFSession *session=nullptr;
    uint64_t connection=0,groupEpoch=0,acceptedIPN=0,txPN=0;
    Ath10kPMFSession::Kind kind=Ath10kPMFSession::Kind::Empty;
    Ath10kPMFSession::Layout layout=Ath10kPMFSession::Layout::Ciphertext;
    AthSecurity::ManagementTX txMode=AthSecurity::ManagementTX::SoftwareCCMP;
    bool executed=false,consumed=false,verified=false;
    uint8_t frame[512]{},ap[6]{};size_t bytes=0;
    AthSecurity::PMFPairwiseEpoch::Snapshot pairwise;
    AthSecurity::IGTKCMAC128 management{};
    AthSecurity::PMFCCMPResult result;
    AthSecurity::PMFCCMPWorkspace workspace;
public:
    void execute() override;
    void discard() override;
};
static_assert(sizeof(Ath10kPMFJob)<=4096,"Bounded heap-owned management crypto job");

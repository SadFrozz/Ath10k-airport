#pragma once
#include "Ath10kSAEWorker.hpp"
#include "../../shared/Ath10kSAEExchange.hpp"

class Ath10kSAEJob;
// Owner methods require the same radio gate. Jobs get independent context
// snapshots, so cancellation can immediately erase the owner's prepared secrets.
// This does not bind/validate the kernel P-256 ABI or admit native SAE joins.
class Ath10kSAESession : public OSObject {
    OSDeclareDefaultStructors(Ath10kSAESession)
    friend class Ath10kSAEJob;
    struct Context {
        AthSecurity::P256CoreCryptoAPI api{};
        uint8_t random[32]{},pwe[64]{};
    } context{};
    AthSecurity::SAEGroup19ClientExchange exchange;
    uint64_t token=0;
    uint32_t connectionGeneration=0;
    bool closed=true,initialized=false;
    void free() override;
    bool current(uint32_t generation) const {return initialized && !closed && generation==connectionGeneration;}
    bool owns(const Ath10kSAEJob *,uint32_t) const;
public:
    using Action=AthSecurity::SAEGroup19ClientExchange::Action;
    using Phase=AthSecurity::SAEGroup19ClientExchange::Phase;
    enum class Kind : uint8_t { Empty, Keys, LocalConfirm, PeerConfirm };
    enum class Submission : uint8_t { Queued, Busy, NoMemory, NoWork, Aborted };
    // Caller already prepared/validated the commit/random/PWE on a worker and
    // proved the backend callable. Key admission consumes the prepared context.
    bool initPrepared(const AthSecurity::P256CoreCryptoAPI &,const uint8_t *random,size_t randomBytes,
        const uint8_t *pwe,size_t pweBytes,const AthSecurity::SAEGroup19AuthMessage &,
        const uint8_t *local,const uint8_t *ap,uint32_t generation,uint64_t now);
    void cancel(); // Worker snapshots are independent; owner secrets retire now.
    Action poll(uint32_t generation,uint64_t now);
    Action receive(const uint8_t *,size_t,uint32_t generation,uint64_t now);
    bool snapshotCommit(AthSecurity::SAEGroup19CommitTx &,uint16_t,uint32_t,uint64_t);
    bool commitReady(const AthSecurity::SAEGroup19CommitTx &,uint32_t,uint64_t);
    bool completeCommit(const AthSecurity::SAEGroup19CommitTx &,bool,uint32_t,uint64_t);
    Submission queue(Ath10kSAEWorker *,Kind,uint32_t generation,uint64_t now);
    Action consume(Ath10kSAEWorkItem *,uint32_t generation,uint64_t now);
    bool encodeConfirm(Ath10kSAEWorkItem *,uint16_t,uint8_t *,size_t,size_t &,uint32_t,uint64_t);
    bool confirmReady(Ath10kSAEWorkItem *,uint32_t,uint64_t);
    Action completeConfirm(Ath10kSAEWorkItem *,bool,uint32_t,uint64_t);
    bool copyPMK(uint8_t *,size_t,uint8_t *,size_t,uint32_t,uint64_t);
};

// Filled under the owner gate, executed exactly once by Ath10kSAEWorker, then
// handed back before owner consumption. Does not hold NativeSecurity/IO80211.
class Ath10kSAEJob : public Ath10kSAEWorkItem {
    OSDeclareDefaultStructors(Ath10kSAEJob)
    friend class Ath10kSAESession;
    Ath10kSAESession *session=nullptr;
    Ath10kSAESession::Kind kind=Ath10kSAESession::Kind::Empty;
    uint32_t connectionGeneration=0;
    bool executed=false,consumed=false;
    Ath10kSAESession::Context context{};
    AthSecurity::SAEGroup19KeyWork key;
    AthSecurity::SAEGroup19ConfirmWork confirm;
    AthSecurity::P256CoreCryptoWorkspace workspace{};
    uint8_t body[34]{};
public:
    void execute() override;
    void discard() override;
};
static_assert(sizeof(Ath10kSAEJob)<=4096,"Bounded heap-owned SAE job");
static_assert(sizeof(Ath10kSAESession)<=8192,"Allocate the SAE owner off the kernel stack");

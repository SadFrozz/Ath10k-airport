#pragma once
#include "Ath10kSAEWorker.hpp"
#include "../../security/Ath10kSAEExchange.hpp"
#include "../../security/Ath10kSAEPassword.hpp"

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
    uint8_t stationIdentity[6]{},apIdentity[6]{};
    bool eapolStarted=false,hashToElement=false;
    uint64_t handoffDeadline=0;
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
    bool usingH2E() const {return initialized && !closed && hashToElement;}
    uint32_t activeGeneration() const {return initialized && !closed?connectionGeneration:0;}
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
    // Owner-gated transfer into AKM8, after both SAE confirmations. This binds
    // the original identities and generation without exposing temporary keys
    // to native request storage. Native admission/PMF checks remain the caller's.
    template<class EAPOL> bool beginEAPOL(EAPOL &eapol,const uint8_t *nonce,
        const uint8_t *station,const uint8_t *ap,const uint8_t *rsn,size_t rsnBytes,
        uint32_t generation,uint64_t now){
        if(!nonce || !station || !ap || !current(generation) || eapolStarted ||
           !AthSecurity::equal(station,stationIdentity,6) || !AthSecurity::equal(ap,apIdentity,6))return false;
        if(now>=handoffDeadline){cancel();return false;}
        struct Keys {
            uint8_t pmk[32]{},id[16]{};
            ~Keys(){AthSecurity::wipe(this,sizeof(*this));}
        } keys;
        if(!exchange.copyPMK(token,keys.pmk,32,keys.id,16,now))return false;
        eapolStarted=true;
        const bool ok=eapol.begin(keys.pmk,nonce,stationIdentity,apIdentity,rsn,rsnBytes,8,keys.id,16);
        if(!ok)cancel(); // A failed target initialization cannot reuse this PMK.
        return ok;
    }

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

// One-shot preparation from a derived PWE or an experimental retained H2E/legacy
// credential snapshot. Native admission and kernel backend validation remain
// caller prerequisites.
// Inputs are immutable after init; execute is worker-only; takePrepared is owner-
// gated only after taking the completed job. No callback enters an owner gate.
class Ath10kSAEPrepareJob : public Ath10kSAEWorkItem {
    OSDeclareDefaultStructors(Ath10kSAEPrepareJob)
    AthSecurity::P256CoreCryptoAPI api{};
    bool (*randomBytes)(uint8_t *,size_t)=nullptr;
    AthSecurity::P256CoreCryptoWorkspace workspace{};
    AthSecurity::SAEGroup19AuthMessage request{};
    uint8_t pwe[64]{},random[32]{},local[6]{},ap[6]{};
    uint32_t generation=0;
    uint64_t started=0,deadline=0;
    bool initialized=false,executed=false,prepared=false,consumed=false;
    AthSecurity::P256FieldAPI fieldAPI{};
    AthSecurity::P256FieldWorkspace fieldWorkspace{};
    uint8_t password[64]{},ssid[32]{},pt[64]{};
    size_t passwordBytes=0,ssidBytes=0;
    bool credentialBound=false;
    bool initPassword(const AthSecurity::P256CoreCryptoAPI &,const AthSecurity::P256FieldAPI &,
        bool (*)(uint8_t *,size_t),bool,const uint8_t *,size_t,const uint8_t *,size_t,
        const uint8_t *,size_t,const uint8_t *,const uint8_t *,uint32_t,uint64_t);
    bool initBinding(const AthSecurity::P256CoreCryptoAPI &,bool (*)(uint8_t *,size_t),
        bool,const uint8_t *,const uint8_t *,uint32_t,uint64_t);
    Ath10kSAESession *takePreparedBound(const uint8_t *,const uint8_t *,const uint8_t *,size_t,uint32_t,uint64_t);
public:
    bool initPWE(const AthSecurity::P256CoreCryptoAPI &,bool (*)(uint8_t *,size_t),
        const uint8_t *,size_t,bool,const uint8_t *,const uint8_t *,uint32_t,uint64_t);
    // Experimental retained H2E password derivation. Provider ABI/timing and
    // native credential admission must be validated before native use.
    bool initH2E(const AthSecurity::P256CoreCryptoAPI &,const AthSecurity::P256FieldAPI &,
        bool (*)(uint8_t *,size_t),const uint8_t *,size_t,const uint8_t *,size_t,
        const uint8_t *,size_t,const uint8_t *,const uint8_t *,uint32_t,uint64_t);
    void execute() override;
    void discard() override;
    // Legacy SAE has no password identifier. Selection must come from the
    // negotiated mode, never an automatic fallback after H2E/backend failure.
    bool initLegacyPassword(const AthSecurity::P256CoreCryptoAPI &,const AthSecurity::P256FieldAPI &,
        bool (*)(uint8_t *,size_t),const uint8_t *,size_t,const uint8_t *,size_t,
        const uint8_t *,const uint8_t *,uint32_t,uint64_t);
    // Both password modes require exact SSID, identities, generation and deadline.
    Ath10kSAESession *takePreparedPassword(const uint8_t *,size_t,const uint8_t *,const uint8_t *,uint32_t,uint64_t);
    Ath10kSAESession *takePreparedH2E(const uint8_t *,size_t,const uint8_t *,const uint8_t *,uint32_t,uint64_t);
    // Transfers a newly retained owner once, only to the exact admitted attempt.
    Ath10kSAESession *takePrepared(const uint8_t *,const uint8_t *,uint32_t,uint64_t);
};
static_assert(sizeof(Ath10kSAEPrepareJob)<=4096,"Bounded heap-owned SAE preparation");

// Owner-gated bridge from retained SAE work to a serialized management TX
// channel. No OS/WCL callbacks or crypto execute here. bind requires a freshly
// prepared session; native credential/profile admission remains separate.
class Ath10kSAERadio {
    Ath10kSAESession *session=nullptr;
    Ath10kSAEWorker *worker=nullptr;
    uint32_t generation=0;
    Ath10kSAESession::Kind inFlight=Ath10kSAESession::Kind::Empty;
    Ath10kSAEWorkItem *confirm=nullptr;
    AthSecurity::SAEGroup19CommitTx commit;
    enum class TX { None,Commit,Confirm } tx=TX::None;
    uint8_t confirmFrame[64]{};
    bool failed=false,accepted=false;
    void clearTX();
    void fail();
public:
    enum class State {Idle,Progress,Accepted,Failed};
    Ath10kSAERadio()=default;
    Ath10kSAERadio(const Ath10kSAERadio &)=delete;
    Ath10kSAERadio &operator=(const Ath10kSAERadio &)=delete;
    ~Ath10kSAERadio(){cancel();}
    bool bind(Ath10kSAESession *,Ath10kSAEWorker *,uint32_t,uint64_t);
    void cancel(); // Nonblocking, including during a running retained job.
    bool boundTo(const Ath10kSAESession *owner,uint32_t connection) const {
        return session==owner && generation==connection && !failed && session && session->activeGeneration()==connection;
    }
    State service(uint64_t);
    Ath10kSAESession::Action receive(const uint8_t *,size_t,uint32_t,uint64_t);
    // Returned bytes are borrowed until the next owner method. Prepare,
    // actual channel admission/copy, and complete must share the owner gate.
    bool prepareTX(uint16_t,uint64_t,const uint8_t *&,size_t &);
    bool completeTX(bool,uint64_t); // True only for a current TX reservation.
    template<class EAPOL> bool beginEAPOL(EAPOL &eapol,const uint8_t *nonce,
        const uint8_t *station,const uint8_t *ap,const uint8_t *rsn,size_t bytes,uint64_t now){
        return session && accepted && !failed && inFlight==Ath10kSAESession::Kind::Empty &&
            session->beginEAPOL(eapol,nonce,station,ap,rsn,bytes,generation,now);
    }
};
static_assert(sizeof(Ath10kSAERadio)<=2048,"Bounded owner-side management transport");

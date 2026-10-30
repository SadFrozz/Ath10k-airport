#pragma once
#include "Ath10kNativeSAEJoin.hpp"
#include "Ath10kSAESession.hpp"

// Serialized by the connection owner. Crypto runs only on the retained worker;
// cancellation never waits for it. This does not enable native SAE admission.
class Ath10kNativeSAEPreparation {
    Ath10kSAEWorker *worker=nullptr;
    Ath10kSAEPrepareJob *job=nullptr;
    bool submitted=false;
    struct Profile {
        uint8_t station[6]{},bssid[6]{},ssid[32]{},rsn[257]{},rsnxe[18]{};
        size_t ssidBytes=0,rsnBytes=0,rsnxeBytes=0;
        NativeSAEPasswordMode mode=NativeSAEPasswordMode::Unsupported;
        uint32_t generation=0;
        uint64_t lastNow=0,deadline=0;
    } profile;
    static_assert(sizeof(Profile)<=512,"Bounded credential-free preparation snapshot");
public:
    enum class State {Idle,Pending,Ready,Changed,Expired,ClockError,Failed};
    struct Result {State state;Ath10kSAESession *session=nullptr;}; // Ready transfers one reference.
    Ath10kNativeSAEPreparation()=default;
    Ath10kNativeSAEPreparation(const Ath10kNativeSAEPreparation &)=delete;
    Ath10kNativeSAEPreparation &operator=(const Ath10kNativeSAEPreparation &)=delete;
    ~Ath10kNativeSAEPreparation(){cancel();}
    bool active() const {return job!=nullptr;}
    bool begin(Ath10kSAEWorker *,const AirportWCL::JoinRequest &,const Ath10k::WMIBSS &,
        const AthSecurity::P256CoreCryptoAPI &,const AthSecurity::P256FieldAPI &,
        bool (*)(uint8_t *,size_t),const uint8_t *,uint32_t,uint64_t);
    Result collect(const uint8_t *,size_t,const Ath10k::WMIBSS &,const uint8_t *,uint32_t,uint64_t);
    void cancel();
};

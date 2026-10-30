#pragma once
#include "Ath10kSAEWorker.hpp"
#include "../../core/Ath10kConnection.hpp"
#include "../../security/Ath10kSAQuery.hpp"
#include "Ath10kNativeWire.hpp"
#include "../../security/Ath10kPSKPassword.hpp"
class Ath10kNativePSKJob : public Ath10kSAEWorkItem {
 OSDeclareDefaultStructors(Ath10kNativePSKJob)
 uint8_t password[64]{},ssid[32]{},pmk[32]{},nonce[32]{};
 size_t passwordBytes=0,ssidBytes=0;
 bool initialized=false,executed=false,valid=false,consumed=false;
public:
 bool initPassword(const uint8_t *,size_t,const uint8_t *,size_t);
 void execute() override;
 void discard() override;
 bool take(uint8_t *,uint8_t *);
};
static_assert(sizeof(Ath10kNativePSKJob)<=1024,"Bounded password work item");
// All owner methods are nonblocking. Cancellation drops the owner's reference;
// a dispatched worker retains its immutable secret until execute has returned.
class Ath10kNativePSKPreparation {
 Ath10kSAEWorker *worker=nullptr;Ath10kNativePSKJob *job=nullptr;bool submitted=false;
 struct Profile {
  uint8_t ssid[32]{},station[6]{},bssid[6]{},rsn[257]{},rsnxe[18]{};
  size_t ssidBytes=0,rsnBytes=0,rsnxeBytes=0;uint8_t akm=0;
  uint32_t generation=0;uint64_t lastNow=0,deadline=0;
 } profile;
public:
 enum class State {Idle,Pending,Ready,Changed,Expired,ClockError,Failed};
 struct Result {State state;uint8_t pmk[32]{},nonce[32]{};~Result(){AthSecurity::wipe(pmk,sizeof(pmk));AthSecurity::wipe(nonce,sizeof(nonce));}};
 Ath10kNativePSKPreparation()=default;
 Ath10kNativePSKPreparation(const Ath10kNativePSKPreparation &)=delete;
 Ath10kNativePSKPreparation &operator=(const Ath10kNativePSKPreparation &)=delete;
 ~Ath10kNativePSKPreparation(){cancel();}
 bool active() const {return job!=nullptr;}
 bool begin(Ath10kSAEWorker *,const AirportWCL::JoinRequest &,const Ath10k::WMIBSS &,const uint8_t *,uint32_t,uint64_t);
 Result collect(const Ath10k::ConnectionState &,uint32_t,uint64_t);
 void cancel();
};

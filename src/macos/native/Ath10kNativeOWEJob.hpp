#pragma once
#include "Ath10kSAEWorker.hpp"
#include "../../security/Ath10kOWEP256.hpp"
// Retained worker item across the association request/response. Owner mutates
// only after takeCompletedFor transfers completion; never while queued/running.
class Ath10kNativeOWEJob : public Ath10kSAEWorkItem {
 OSDeclareDefaultStructors(Ath10kNativeOWEJob)
 enum class Phase {Idle,Prepare,Request,AwaitPeer,Derive,Keys,Dead};
 Phase phase=Phase::Idle;
 AthSecurity::P256CoreCryptoAPI points{};AthSecurity::P256FieldAPI field{};
 AthSecurity::OWEGroup19Exchange exchange{};AthSecurity::OWEGroup19Keys keys{};
 uint8_t station[6]{},peer[6]{},element[37]{},nonce[32]{};
 uint32_t epoch=0;uint64_t started=0,deadline=0,lastNow=0;
 bool current(const uint8_t *,const uint8_t *,uint32_t,uint64_t) const;
public:
 bool initExchange(const AthSecurity::P256CoreCryptoAPI &,const AthSecurity::P256FieldAPI &,
  const uint8_t *,const uint8_t *,uint32_t,uint64_t);
 void execute() override;
 void discard() override;
 bool takeRequest(const uint8_t *,const uint8_t *,uint32_t,uint64_t,uint8_t *,size_t);
 bool setPeer(const uint8_t *,size_t,const uint8_t *,const uint8_t *,uint32_t,uint64_t);
 bool takeKeys(const uint8_t *,const uint8_t *,uint32_t,uint64_t,AthSecurity::OWEGroup19Keys &,uint8_t *);
};
static_assert(sizeof(Ath10kNativeOWEJob)<=2048,"Bounded OWE worker ownership");

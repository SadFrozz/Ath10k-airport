#include "Ath10kNativeOWEJob.hpp"
#include "Ath10kKernelCrypto.hpp"
OSDefineMetaClassAndStructors(Ath10kNativeOWEJob,Ath10kSAEWorkItem)
bool Ath10kNativeOWEJob::current(const uint8_t *local,const uint8_t *remote,uint32_t generation,uint64_t now) const {
 return local && remote && generation==epoch && now>=lastNow && now>=started && now<deadline &&
  AthSecurity::equal(local,station,6) && AthSecurity::equal(remote,peer,6);
}
bool Ath10kNativeOWEJob::initExchange(const AthSecurity::P256CoreCryptoAPI &p,const AthSecurity::P256FieldAPI &f,
 const uint8_t *local,const uint8_t *remote,uint32_t generation,uint64_t now){
 if(phase!=Phase::Idle || !local || !remote || !generation || now>~uint64_t(0)-5000 ||
  !p.complete() || !f.curve || !f.units || !f.prime || !f.multiply || !f.inverse || !f.add || !f.subtract || !OSObject::init())return false;
 uint8_t a=0,b=0;for(unsigned i=0;i<6;++i){a|=local[i];b|=remote[i];}
 if(!a || !b || (local[0]&1) || (remote[0]&1) || AthSecurity::equal(local,remote,6))return false;
 points=p;field=f;AthSecurity::copy(station,local,6);AthSecurity::copy(peer,remote,6);
 epoch=generation;started=lastNow=now;deadline=now+5000;phase=Phase::Prepare;return true;
}
void Ath10kNativeOWEJob::execute(){
 if(phase==Phase::Prepare){
  struct Secret {uint8_t scalar[32]{};~Secret(){AthSecurity::wipe(scalar,sizeof(scalar));}} secret;
  bool ready=false;
  // Rejection sampling; no biased reduction and no reuse from a failed job.
  for(unsigned attempt=0;attempt<16 && !ready;++attempt){
   if(!Ath10kKernelCrypto::random(secret.scalar,32))break;
   ready=exchange.begin(points,secret.scalar,32,station,peer,epoch,started,deadline,element,sizeof(element));
  }
  if(ready && Ath10kKernelCrypto::random(nonce,sizeof(nonce)))phase=Phase::Request;
  else discard();
 }else if(phase==Phase::Derive){
  if(exchange.finish<Ath10kKernelCrypto>(points,field,element,sizeof(element),station,peer,epoch,lastNow,keys))phase=Phase::Keys;
  else discard();
 }
}
bool Ath10kNativeOWEJob::takeRequest(const uint8_t *local,const uint8_t *remote,uint32_t generation,uint64_t now,uint8_t *out,size_t capacity){
 if(phase!=Phase::Request)return false;
 if(!out || capacity<sizeof(element) || !current(local,remote,generation,now)){discard();return false;}
 AthSecurity::copy(out,element,sizeof(element));AthSecurity::wipe(element,sizeof(element));lastNow=now;phase=Phase::AwaitPeer;return true;
}
bool Ath10kNativeOWEJob::setPeer(const uint8_t *ie,size_t bytes,const uint8_t *local,const uint8_t *remote,uint32_t generation,uint64_t now){
 if(phase!=Phase::AwaitPeer)return false;
 AthSecurity::OWEGroup19Parameter view{};
 if(!current(local,remote,generation,now) || !AthSecurity::decodeOWEGroup19Parameter(ie,bytes,view)){discard();return false;}
 AthSecurity::copy(element,ie,bytes);lastNow=now;phase=Phase::Derive;return true;
}
bool Ath10kNativeOWEJob::takeKeys(const uint8_t *local,const uint8_t *remote,uint32_t generation,uint64_t now,AthSecurity::OWEGroup19Keys &out,uint8_t *snonce){
 if(phase!=Phase::Keys)return false;
 if(!snonce || !current(local,remote,generation,now)){discard();return false;}
 out=keys;AthSecurity::copy(snonce,nonce,32);discard();return true;
}
void Ath10kNativeOWEJob::discard(){
 exchange.clear();AthSecurity::wipe(&keys,sizeof(keys));AthSecurity::wipe(nonce,sizeof(nonce));
 AthSecurity::wipe(element,sizeof(element));AthSecurity::wipe(station,sizeof(station));AthSecurity::wipe(peer,sizeof(peer));
 points={};field={};epoch=0;started=deadline=lastNow=0;phase=Phase::Dead;
}

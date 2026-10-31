#pragma once
#include "Ath10kOWE.hpp"
#include "Ath10kP256CoreCrypto.hpp"
namespace AthSecurity {
// RFC6090 compact ECDH: either square root produces the same shared x.
// Execute on the crypto worker, never while holding the radio/owner gate.
// Caller binds the scalar and peer element to one association generation.
inline bool oweGroup19SharedSecret(const P256CoreCryptoAPI &pointAPI,
 const P256FieldAPI &fieldAPI,const uint8_t *scalar,size_t scalarBytes,
 const uint8_t *peerX,size_t peerBytes,uint8_t *out,size_t capacity){
 if(!scalar || scalarBytes!=32 || !peerX || peerBytes!=32 || !out || capacity<32)return false;
 struct Temporary {
  P256CoreCryptoWorkspace point{};P256FieldWorkspace field{};
  uint8_t peer[64]{},square[32]{},cube[32]{},threeX[32]{},rhs[32]{},shared[64]{};
  ~Temporary(){wipe(this,sizeof(*this));}
 } t;
 static constexpr uint8_t b[32]={
  0x5a,0xc6,0x35,0xd8,0xaa,0x3a,0x93,0xe7,0xb3,0xeb,0xbd,0x55,0x76,0x98,0x86,0xbc,
  0x65,0x1d,0x06,0xb0,0xcc,0x53,0xb0,0xf6,0x3b,0xce,0x3c,0x3e,0x27,0xd2,0x60,0x4b};
 copy(t.peer,peerX,32);
 P256FieldCandidate field(fieldAPI);P256CoreCryptoCandidate points(pointAPI);
 // Field import rejects noncanonical x >= p. Square root verifies y*y == rhs.
 if(!field.multiply(t.peer,32,t.peer,32,t.square,32,t.field) ||
    !field.multiply(t.square,32,t.peer,32,t.cube,32,t.field) ||
    !field.add(t.peer,t.peer,32,t.threeX,32,t.field) ||
    !field.add(t.threeX,t.peer,32,t.threeX,32,t.field) ||
    !field.subtract(t.cube,t.threeX,32,t.rhs,32,t.field) ||
    !field.add(t.rhs,b,32,t.rhs,32,t.field) ||
    field.squareRootStatus(t.rhs,32,t.peer+32,32,t.field)!=P256FieldResult::Success ||
    !points.validate(t.peer,64,t.point) ||
    !points.multiply(scalar,32,t.peer,64,t.shared,64,t.point))return false;
 copy(out,t.shared,32);return true;
}
// One worker-owned exchange. The owner cancels publication through its existing
// worker fence; never mutate this object concurrently with execute/finish.
class OWEGroup19Exchange {
 uint8_t scalar[32]{},client[32]{},station[6]{},peer[6]{};
 uint32_t generation=0;uint64_t started=0,deadline=0;bool pending=false;
public:
 OWEGroup19Exchange()=default;
 OWEGroup19Exchange(const OWEGroup19Exchange &)=delete;
 OWEGroup19Exchange &operator=(const OWEGroup19Exchange &)=delete;
 ~OWEGroup19Exchange(){clear();}
 void clear(){wipe(scalar,32);wipe(client,32);wipe(station,6);wipe(peer,6);generation=0;started=deadline=0;pending=false;}
 bool active() const {return pending;}
 // Entropy provider must supply a fresh uniformly random scalar; out-of-range
 // candidates are rejected, not reduced modulo n. No scalar reuse after failure.
 bool begin(const P256CoreCryptoAPI &points,const uint8_t *privateScalar,size_t bytes,
  const uint8_t *local,const uint8_t *remote,uint32_t epoch,uint64_t now,uint64_t expires,
  uint8_t *element,size_t capacity){
  clear();
  if(!privateScalar || bytes!=32 || !local || !remote || !epoch || expires<=now ||
     !element || capacity<37 || (local[0]&1) || (remote[0]&1) || equal(local,remote,6))return false;
  uint8_t localBits=0,peerBits=0;for(unsigned i=0;i<6;++i){localBits|=local[i];peerBits|=remote[i];}
  if(!localBits || !peerBits)return false;
  static constexpr uint8_t generator[64]={
   0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
   0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96,
   0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
   0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5};
  struct Temporary {P256CoreCryptoWorkspace workspace{};uint8_t point[64]{};~Temporary(){wipe(this,sizeof(*this));}} t;
  if(!P256CoreCryptoCandidate(points).multiply(privateScalar,32,generator,64,t.point,64,t.workspace))return false;
  copy(scalar,privateScalar,32);copy(client,t.point,32);copy(station,local,6);copy(peer,remote,6);
  generation=epoch;started=now;deadline=expires;pending=true;
  return encodeOWEGroup19Parameter(client,32,element,capacity);
 }
 template<class Crypto> bool finish(const P256CoreCryptoAPI &points,const P256FieldAPI &field,
  const uint8_t *element,size_t bytes,const uint8_t *local,const uint8_t *remote,
  uint32_t epoch,uint64_t now,OWEGroup19Keys &out){
  struct Cleanup {OWEGroup19Exchange &exchange;~Cleanup(){exchange.clear();}} cleanup{*this};
  if(!pending || !local || !remote || epoch!=generation || now<started || now>=deadline ||
     !equal(local,station,6) || !equal(remote,peer,6))return false;
  OWEGroup19Parameter parameter{};
  if(!decodeOWEGroup19Parameter(element,bytes,parameter))return false;
  struct Temporary {uint8_t z[32]{};~Temporary(){wipe(z,sizeof(z));}} t;
  return oweGroup19SharedSecret(points,field,scalar,32,parameter.x,32,t.z,32) &&
   deriveOWEGroup19Keys<Crypto>(client,32,parameter.x,32,t.z,32,out);
 }
};

}

#pragma once
#include "Ath10kSecurity.hpp"
namespace AthSecurity {
// RFC8110 group19 wire/KDF boundary. A decoded x coordinate is NOT a
// validated curve point. The exchange worker must validate it and derive z.
struct OWEGroup19Parameter {const uint8_t *x=nullptr;};
inline bool decodeOWEGroup19Parameter(const uint8_t *ie,size_t bytes,OWEGroup19Parameter &out){
 out={};
 if(!ie || bytes!=37 || ie[0]!=255 || ie[1]!=35 || ie[2]!=32 || le16(ie+3)!=19)return false;
 out.x=ie+5;return true;
}
inline bool encodeOWEGroup19Parameter(const uint8_t *x,size_t bytes,uint8_t *out,size_t capacity){
 if(!x || bytes!=32 || !out || capacity<37)return false;
 uint8_t ie[37]={255,35,32,19,0};copy(ie+5,x,32);copy(out,ie,sizeof(ie));return true;
}
struct OWEGroup19Keys {uint8_t pmk[32]{},pmkid[16]{};};
// Input z must come from validated ECDH for these exact public keys.
// C/A order is station/AP, never sorted by MAC or public value. No PMK cache.
// All provider failures preserve the caller's output; intermediate secrets wipe.
template<class Crypto> inline bool deriveOWEGroup19Keys(
 const uint8_t *client,size_t clientBytes,const uint8_t *ap,size_t apBytes,
 const uint8_t *secret,size_t secretBytes,OWEGroup19Keys &out){
 if(!client || !ap || !secret || clientBytes!=32 || apBytes!=32 || secretBytes!=32)return false;
 struct Temporary {
  uint8_t salt[66]{},prk[32]{},digest[32]{},input[19]{};
  OWEGroup19Keys keys{};
  ~Temporary(){wipe(this,sizeof(*this));}
 } t;
 static constexpr char label[]="OWE Key Generation";
 static_assert(sizeof(label)==19,"OWE HKDF label plus counter");
 copy(t.salt,client,32);copy(t.salt+32,ap,32);t.salt[64]=19;
 copy(t.input,reinterpret_cast<const uint8_t *>(label),sizeof(label)-1);
 t.input[sizeof(t.input)-1]=1; // HKDF expand block1, no NUL in label.
 if(!Crypto::hmac256(t.salt,sizeof(t.salt),secret,32,t.prk) ||
    !Crypto::hmac256(t.prk,sizeof(t.prk),t.input,sizeof(t.input),t.keys.pmk) ||
    !Crypto::hash256(t.salt,64,t.digest))return false;
 copy(t.keys.pmkid,t.digest,16);out=t.keys;return true;
}
}

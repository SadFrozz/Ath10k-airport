#pragma once
#include "Ath10kP256CoreCrypto.hpp"

namespace AthSecurity {
// Experimental group-19 hunting-and-pecking. Exclusive worker only. This
// implements the protocol derivation, not approval of provider timing/ABI.
// The caller retains the original authentication deadline across this work.
template<class Crypto> inline bool saeGroup19LegacyPWE(const P256FieldCandidate &field,
 const P256CoreCryptoCandidate &points,bool (*rng)(uint8_t *,size_t),
 const uint8_t *password,size_t passwordBytes,const uint8_t *station,const uint8_t *ap,
 uint8_t *out,size_t capacity,P256FieldWorkspace &fw,P256CoreCryptoWorkspace &pw){
 struct Scratch {
  uint8_t dummy[64]{},material[65]{},addresses[12]{},seed[32]{},candidate[32]{},x[32]{},y[32]{},negative[32]{},
   r[32]{},qr[32]{},qnr[32]{},factor[32]{},square[32]{},blind[32]{},temporary[32]{},root[32]{},point[64]{},kdf[59]{};
  P256FieldWorkspace &f;P256CoreCryptoWorkspace &p;
  Scratch(P256FieldWorkspace &a,P256CoreCryptoWorkspace &b):f(a),p(b){}
  ~Scratch(){
   wipe(dummy,sizeof(dummy));wipe(material,sizeof(material));wipe(addresses,sizeof(addresses));wipe(seed,sizeof(seed));
   wipe(candidate,sizeof(candidate));wipe(x,sizeof(x));wipe(y,sizeof(y));wipe(negative,sizeof(negative));
   wipe(r,sizeof(r));wipe(qr,sizeof(qr));wipe(qnr,sizeof(qnr));wipe(factor,sizeof(factor));
   wipe(square,sizeof(square));wipe(blind,sizeof(blind));wipe(temporary,sizeof(temporary));wipe(root,sizeof(root));wipe(point,sizeof(point));wipe(kdf,sizeof(kdf));f.clear();p.clear();
  }
 } s(fw,pw);
 if(!rng || !password || !passwordBytes || passwordBytes>64 || !station || !ap ||
    !out || capacity<64 || (station[0]&1) || (ap[0]&1) || equal(station,ap,6))return false;
 static constexpr uint8_t prime[32]={0xff,0xff,0xff,0xff,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
 static constexpr uint8_t b[32]={0x5a,0xc6,0x35,0xd8,0xaa,0x3a,0x93,0xe7,0xb3,0xeb,0xbd,0x55,0x76,0x98,0x86,0xbc,0x65,0x1d,6,0xb0,0xcc,0x53,0xb0,0xf6,0x3b,0xce,0x3c,0x3e,0x27,0xd2,0x60,0x4b};
 static constexpr uint8_t zero[32]{};
 auto nonzero=[](const uint8_t *v){uint32_t n=0;for(unsigned i=0;i<32;++i)n|=v[i];return n!=0;};
 auto belowPrime=[&](const uint8_t *v){uint32_t borrow=0;for(size_t i=32;i-->0;){const uint32_t d=uint32_t(v[i])-prime[i]-borrow;borrow=d>>31;}return borrow!=0;};
 auto mul=[&](const uint8_t *a,const uint8_t *b,uint8_t *o){return field.multiply(a,32,b,32,o,32,fw);};
 auto add=[&](const uint8_t *a,const uint8_t *b,uint8_t *o){return field.add(a,b,32,o,32,fw);};
 auto sub=[&](const uint8_t *a,const uint8_t *b,uint8_t *o){return field.subtract(a,b,32,o,32,fw);};
 auto randomField=[&](){
  for(unsigned attempt=0;attempt<128;++attempt){if(!rng(s.r,32))return false;if(belowPrime(s.r) && nonzero(s.r))return true;}return false;
 };
 auto polynomial=[&](const uint8_t *x,uint8_t *o){
  // x^3 - 3*x + b, using separate scratch from the blinding buffers.
  return mul(x,x,s.temporary) && mul(s.temporary,x,o) && sub(o,x,o) && sub(o,x,o) && sub(o,x,o) && add(o,b,o);
 };
 bool greater=false;for(unsigned i=0;i<6;++i){if(station[i]==ap[i])continue;greater=station[i]>ap[i];break;}
 copy(s.addresses,greater?station:ap,6);copy(s.addresses+6,greater?ap:station,6);
 if(!rng(s.dummy,passwordBytes) || !randomField() || !mul(s.r,s.r,s.qr) || !sub(zero,s.qr,s.qnr))return false;
 // For p=3 mod 4, -QR is a QNR. Fresh per-iteration r masks the tested value;
 // parity selects the randomized QR/QNR coset, whose expected result is known.
 static constexpr char label[]="SAE Hunting and Pecking";
 static_assert(sizeof(s.kdf)==2+sizeof(label)-1+32+2,"SHA256 PRF bits envelope");
 s.kdf[0]=1;copy(s.kdf+2,reinterpret_cast<const uint8_t *>(label),sizeof(label)-1);
 copy(s.kdf+2+sizeof(label)-1,prime,32);s.kdf[sizeof(s.kdf)-1]=1; // 256 bits, LE16.
 uint8_t found=0,savedOdd=0;
 for(unsigned counter=1;counter<=200 && (counter<=40 || !found);++counter){
  for(size_t i=0;i<passwordBytes;++i)s.material[i]=uint8_t((s.dummy[i]&found)|(password[i]&uint8_t(~found)));
  s.material[passwordBytes]=uint8_t(counter);
  if(!Crypto::hmac256(s.addresses,12,s.material,passwordBytes+1,s.seed) ||
     !Crypto::hmac256(s.seed,32,s.kdf,sizeof(s.kdf),s.candidate))return false;
  const uint8_t inRange=uint8_t(0u-uint32_t(belowPrime(s.candidate)));
  // Invalid candidates still take the field path, with a canonical substitute.
  for(unsigned i=0;i<32;++i)s.point[i]=uint8_t(s.candidate[i]&inRange);
  if(!polynomial(s.point,s.square) || !randomField() || !mul(s.square,s.r,s.blind) || !mul(s.blind,s.r,s.blind))return false;
  const uint8_t odd=uint8_t(0u-uint32_t(s.r[31]&1));
  for(unsigned i=0;i<32;++i)s.factor[i]=uint8_t((s.qr[i]&odd)|(s.qnr[i]&uint8_t(~odd)));
  if(!mul(s.blind,s.factor,s.blind))return false;
  const auto result=field.squareRootStatus(s.blind,32,s.root,32,fw);
  if(result==P256FieldResult::Error)return false;
  const bool residue=nonzero(s.blind) && ((result==P256FieldResult::Success)==bool(s.r[31]&1));
  const uint8_t take=uint8_t(uint8_t(~found)&inRange&uint8_t(0u-uint32_t(residue)));
  for(unsigned i=0;i<32;++i)s.x[i]=uint8_t((s.candidate[i]&take)|(s.x[i]&uint8_t(~take)));
  savedOdd=uint8_t(((s.seed[31]&1)&take)|(savedOdd&uint8_t(~take)));found|=take;
 }
 if(!found || !polynomial(s.x,s.square) || field.squareRootStatus(s.square,32,s.y,32,fw)!=P256FieldResult::Success || !sub(zero,s.y,s.negative))return false;
 const uint8_t negate=uint8_t(0u-uint32_t((s.y[31]^savedOdd)&1));
 copy(s.point,s.x,32);for(unsigned i=0;i<32;++i)s.point[32+i]=uint8_t((s.negative[i]&negate)|(s.y[i]&uint8_t(~negate)));
 if(!points.validate(s.point,64,pw))return false;
 copy(out,s.point,64);return true;
}
}

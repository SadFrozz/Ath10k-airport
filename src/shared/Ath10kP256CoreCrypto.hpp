#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "Ath10kSHA256.hpp"

namespace AthSecurity {
// Experimental x86_64 context adapter. NOT wired into the Wi-Fi driver.
// Userland tests do not establish kernel ABI or SAE support. Call only outside
// IRQ/WCL/radio gates; CoreCrypto wrappers may allocate and fail.
struct P256CoreCryptoAPI {
    const void *(*curve)();
    int (*importPoint)(const void *,size_t,const uint8_t *,void *);
    bool (*validatePoint)(void *);
    int (*exportPoint)(int,void *,const void *);
    int (*project)(const void *,void *,const void *,void *);
    int (*affine)(const void *,void *,const void *);
    int (*multiply)(const void *,void *,const uint64_t *,const void *,void *);
    int (*add)(const void *,void *,const void *,const void *);
    int (*subtract)(const void *,void *,const void *,const void *);
    int (*readScalar)(size_t,uint64_t *,size_t,const void *);
    void *(*rng)(int *);
    bool complete() const {
        return curve && importPoint && validatePoint && exportPoint && project &&
            affine && multiply && add && subtract && readScalar && rng;
    }
};
// Worker-owned and single-call use. Inputs/output must be separate from this
// workspace. Every exit wipes the entire workspace, including structure padding.
struct alignas(16) P256CoreCryptoWorkspace {
    alignas(16) uint8_t publicA[112],publicB[112];
    alignas(16) uint8_t projectA[96],projectB[96],projectResult[96];
    alignas(16) uint64_t scalar[4];
    uint8_t encoded[65],exported[65];
    void clear(){wipe(this,sizeof(*this));}
};
static_assert(sizeof(P256CoreCryptoWorkspace)<=1024,"Bounded P-256 worker workspace");
class P256CoreCryptoCandidate {
    const P256CoreCryptoAPI api;
    enum class Operation { Validate, Multiply, Add, Subtract };
    struct Cleanup {
        P256CoreCryptoWorkspace &workspace;
        explicit Cleanup(P256CoreCryptoWorkspace &w):workspace(w){workspace.clear();}
        ~Cleanup(){workspace.clear();}
    };
    static bool scalarInRange(const uint8_t *scalar){
        // Standards for Efficient Cryptography 2 (SEC 2), secp256r1 order.
        static constexpr uint8_t order[32]={
            0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
            0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51};
        uint32_t borrow=0,nonzero=0;
        for(size_t i=32;i-->0;){
            nonzero|=scalar[i];
            const uint32_t difference=uint32_t(scalar[i])-uint32_t(order[i])-borrow;
            borrow=difference>>31;
        }
        return nonzero && borrow;
    }
    bool import(const void *curve,const uint8_t *point,uint8_t *context,P256CoreCryptoWorkspace &w) const {
        w.encoded[0]=4;memcpy(w.encoded+1,point,64);
        if(api.importPoint(curve,65,w.encoded,context)!=0)return false;
        const void *actual=nullptr;memcpy(&actual,context,sizeof(actual));
        return actual==curve && api.validatePoint(context);
    }
    bool run(Operation operation,const uint8_t *a,size_t aLength,const uint8_t *b,size_t bLength,
             const uint8_t *scalar,size_t scalarLength,uint8_t *out,size_t capacity,
             P256CoreCryptoWorkspace &w) const {
        Cleanup cleanup(w);
#if !defined(__x86_64__)
        (void)operation;(void)a;(void)aLength;(void)b;(void)bLength;
        (void)scalar;(void)scalarLength;(void)out;(void)capacity;
        return false;
#else
        if(!api.complete() || sizeof(void *)!=8 || !a || aLength!=64)return false;
        if(operation!=Operation::Validate && (!out || capacity<64))return false;
        const bool combine=operation==Operation::Add || operation==Operation::Subtract;
        if(combine && (!b || bLength!=64))return false;
        if(operation==Operation::Multiply && (!scalar || scalarLength!=32 || !scalarInRange(scalar)))return false;
        const void *curve=api.curve();if(!curve)return false;
        size_t units=0;memcpy(&units,curve,sizeof(units));if(units!=4)return false;
        if(!import(curve,a,w.publicA,w))return false;
        if(operation==Operation::Validate)return true;
        int error=0;void *rng=api.rng(&error);if(error || !rng)return false;
        if(api.project(curve,w.projectA,w.publicA+16,rng)!=0)return false;
        int result=0;
        if(operation==Operation::Multiply){
            if(api.readScalar(4,w.scalar,32,scalar)!=0)return false;
            result=api.multiply(curve,w.projectResult,w.scalar,w.projectA,rng);
        }else{
            if(!import(curve,b,w.publicB,w) || api.project(curve,w.projectB,w.publicB+16,rng)!=0)return false;
            result=operation==Operation::Add?api.add(curve,w.projectResult,w.projectA,w.projectB):
                api.subtract(curve,w.projectResult,w.projectA,w.projectB);
        }
        if(result!=0 || api.affine(curve,w.publicA+16,w.projectResult)!=0 || !api.validatePoint(w.publicA))return false;
        if(api.exportPoint(0,w.exported,w.publicA)!=0 || w.exported[0]!=4)return false;
        memcpy(out,w.exported+1,64);return true;
#endif
    }
public:
    explicit P256CoreCryptoCandidate(const P256CoreCryptoAPI &functions):api(functions){}
    bool validate(const uint8_t *point,size_t length,P256CoreCryptoWorkspace &w) const {
        return run(Operation::Validate,point,length,nullptr,0,nullptr,0,nullptr,0,w);
    }
    bool multiply(const uint8_t *scalar,size_t scalarLength,const uint8_t *point,size_t pointLength,
                  uint8_t *out,size_t capacity,P256CoreCryptoWorkspace &w) const {
        return run(Operation::Multiply,point,pointLength,nullptr,0,scalar,scalarLength,out,capacity,w);
    }
    bool add(const uint8_t *a,size_t aLength,const uint8_t *b,size_t bLength,
             uint8_t *out,size_t capacity,P256CoreCryptoWorkspace &w) const {
        return run(Operation::Add,a,aLength,b,bLength,nullptr,0,out,capacity,w);
    }
    bool subtract(const uint8_t *a,size_t aLength,const uint8_t *b,size_t bLength,
                  uint8_t *out,size_t capacity,P256CoreCryptoWorkspace &w) const {
        return run(Operation::Subtract,a,aLength,b,bLength,nullptr,0,out,capacity,w);
    }
};
// SAE group-19 common-secret algebra only: rand * (peerScalar * PWE + peerElement).
// Caller binds validated commits/PWE to the session and enforces reflection rules.
inline bool saeGroup19SharedSecret(const P256CoreCryptoCandidate &engine,
 const uint8_t *randomScalar,size_t randomBytes,const uint8_t *peerScalar,size_t scalarBytes,
 const uint8_t *pwe,size_t pweBytes,const uint8_t *peerElement,size_t elementBytes,
 uint8_t *out,size_t capacity,P256CoreCryptoWorkspace &workspace){
 if(!randomScalar || randomBytes!=32 || !peerScalar || scalarBytes!=32 ||
    !pwe || pweBytes!=64 || !peerElement || elementBytes!=64 || !out || capacity<32){workspace.clear();return false;}
 uint8_t high=0;for(unsigned i=0;i<31;++i)high|=peerScalar[i];
 if(!high && peerScalar[31]<=1){workspace.clear();return false;}
 uint8_t points[3][64]{};
 const bool ok=engine.multiply(peerScalar,32,pwe,64,points[0],64,workspace) &&
     engine.add(points[0],64,peerElement,64,points[1],64,workspace) &&
     engine.multiply(randomScalar,32,points[1],64,points[2],64,workspace);
 if(ok)memcpy(out,points[2],32); // Fixed-width affine x coordinate.
 wipe(points,sizeof(points));workspace.clear();return ok;
}

// Fixed-width arithmetic for an SAE commit scalar; no modulo bias reduction
// of random inputs. RNG sampling/retry is a separate caller responsibility.
inline bool saeGroup19CommitScalar(const uint8_t *randomScalar,const uint8_t *mask,
 size_t bytes,uint8_t *out,size_t capacity){
 if(!randomScalar || !mask || bytes!=32 || !out || capacity<32)return false;
 static constexpr uint8_t order[32]={
  0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
  0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51};
 auto valid=[&](const uint8_t *value){
  uint32_t borrow=0,high=0;
  for(size_t i=32;i-->0;){const uint32_t d=uint32_t(value[i])-order[i]-borrow;borrow=d>>31;if(i<31)high|=value[i];}
  return borrow && (high || value[31]>1);
 };
 if(!valid(randomScalar) || !valid(mask))return false;
 uint8_t sum[33]{},reduced[33]{};uint32_t carry=0,borrow=0;
 for(size_t i=32;i-->0;){const uint32_t v=uint32_t(randomScalar[i])+mask[i]+carry;sum[i+1]=uint8_t(v);carry=v>>8;}
 sum[0]=uint8_t(carry);
 for(size_t i=33;i-->0;){const uint32_t v=uint32_t(sum[i])-(i?order[i-1]:0)-borrow;reduced[i]=uint8_t(v);borrow=v>>31;}
 const uint8_t choose=uint8_t(0u-(1u-borrow));uint32_t high=0;
 for(unsigned i=1;i<33;++i){sum[i]=uint8_t((reduced[i]&choose)|(sum[i]&uint8_t(~choose)));if(i<32)high|=sum[i];}
 const bool ok=high || sum[32]>1;
 if(ok)memcpy(out,sum+1,32);
 wipe(sum,sizeof(sum));wipe(reduced,sizeof(reduced));return ok;
}

// Produce a group-19 scalar || affine element from a pre-derived PWE.
// RNG, retries, PWE derivation and authentication-frame serialization are external.
inline bool saeGroup19Commit(const P256CoreCryptoCandidate &engine,const uint8_t *randomScalar,
 const uint8_t *mask,size_t scalarBytes,const uint8_t *pwe,size_t pweBytes,
 uint8_t *out,size_t capacity,P256CoreCryptoWorkspace &workspace){
 if(!pwe || pweBytes!=64 || !out || capacity<96){workspace.clear();return false;}
 static constexpr uint8_t minusOne[32]={
  0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
  0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x50};
 uint8_t prepared[96]{},masked[64]{};
 const bool ok=saeGroup19CommitScalar(randomScalar,mask,scalarBytes,prepared,32) &&
     engine.multiply(mask,32,pwe,64,masked,64,workspace) &&
     engine.multiply(minusOne,32,masked,64,prepared+32,64,workspace);
 if(ok)memcpy(out,prepared,96);
 wipe(prepared,sizeof(prepared));wipe(masked,sizeof(masked));workspace.clear();return ok;
}

// Reduce the fixed 48-byte H2E expansion modulo the P-256 field prime.
// Bitwise long division keeps fixed loop bounds and a 33-byte remainder.
inline bool saeGroup19ReduceH2EValue(const uint8_t *input,size_t bytes,uint8_t *out,size_t capacity){
 if(!input || bytes!=48 || !out || capacity<32)return false;
 static constexpr uint8_t prime[32]={
  0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
 uint8_t remainder[33]{},reduced[33]{};
 for(unsigned octet=0;octet<48;++octet)for(unsigned bit=0;bit<8;++bit){
  uint32_t carry=(input[octet]>>(7-bit))&1u;
  for(size_t i=33;i-->0;){const uint32_t v=(uint32_t(remainder[i])<<1)|carry;remainder[i]=uint8_t(v);carry=v>>8;}
  uint32_t borrow=0;
  for(size_t i=33;i-->0;){const uint32_t v=uint32_t(remainder[i])-(i?prime[i-1]:0)-borrow;reduced[i]=uint8_t(v);borrow=v>>31;}
  const uint8_t choose=uint8_t(0u-(1u-borrow));
  for(unsigned i=0;i<33;++i)remainder[i]=uint8_t((reduced[i]&choose)|(remainder[i]&uint8_t(~choose)));
 }
 memcpy(out,remainder+1,32);wipe(remainder,sizeof(remainder));wipe(reduced,sizeof(reduced));return true;
}

// Experimental x86_64 field API; not wired into native association.
struct P256FieldAPI {
 const void *(*curve)();size_t (*units)(const void *);
 const uint64_t *(*prime)(const void *);
 int (*multiply)(const void *,uint64_t *,const uint64_t *,const uint64_t *);
 int (*inverse)(const void *,uint64_t *,const uint64_t *);
 int (*add)(const void *,uint64_t *,const uint64_t *,const uint64_t *)=nullptr;
 int (*subtract)(const void *,uint64_t *,const uint64_t *,const uint64_t *)=nullptr;
};
struct alignas(16) P256FieldWorkspace {
 uint64_t a[4]{},b[4]{},ar[4]{},br[4]{},result[4]{},plain[4]{};
 void clear(){wipe(this,sizeof(*this));}
};
enum class P256FieldResult {Success,NotSquare,Error};
class P256FieldCandidate {
 enum class Operation {Multiply,Inverse,SquareRoot,Add,Subtract};
 const P256FieldAPI api;
 static constexpr uint64_t modulus[4]={0xffffffffffffffffull,0x00000000ffffffffull,0,0xffffffff00000001ull};
 static bool read(const uint8_t *in,uint64_t *out){
  for(unsigned i=0;i<4;++i){out[i]=0;for(unsigned j=0;j<8;++j)out[i]|=uint64_t(in[31-8*i-j])<<(8*j);}
  uint64_t borrow=0;
  // Compare as bytes to avoid overflow-dependent machine-word subtraction.
  for(unsigned i=0;i<32;++i){const unsigned limb=i/8,shift=8*(i%8);
   const uint32_t v=uint32_t(in[31-i])-uint8_t(modulus[limb]>>shift)-uint32_t(borrow);borrow=v>>31;}
  return borrow!=0;
 }
 P256FieldResult run(Operation op,const uint8_t *a,size_t aBytes,const uint8_t *b,size_t bBytes,
          uint8_t *out,size_t capacity,P256FieldWorkspace &w) const {
  struct Cleanup {P256FieldWorkspace &w;~Cleanup(){w.clear();}} cleanup{w};w.clear();
  const bool binary=op==Operation::Multiply || op==Operation::Add || op==Operation::Subtract;
  if(!api.curve || !api.units || !api.prime || !api.multiply || !api.inverse ||
     !a || aBytes!=32 || (binary && (!b || bBytes!=32)) || !out || capacity<32)return P256FieldResult::Error;
  const void *curve=api.curve();if(!curve || api.units(curve)!=4)return P256FieldResult::Error;
  const uint64_t *p=api.prime(curve);if(!p)return P256FieldResult::Error;
  for(unsigned i=0;i<4;++i)if(p[i]!=modulus[i])return P256FieldResult::Error;
  if(!read(a,w.a) || (binary && !read(b,w.b)))return P256FieldResult::Error;
  if(op==Operation::Add || op==Operation::Subtract){
   auto operation=op==Operation::Add?api.add:api.subtract;
   if(!operation || operation(curve,w.plain,w.a,w.b)!=0)return P256FieldResult::Error;
   for(unsigned i=0;i<4;++i)for(unsigned j=0;j<8;++j)out[31-8*i-j]=uint8_t(w.plain[i]>>(8*j));
   return P256FieldResult::Success;
  }
  static constexpr uint64_t r2[4]={3,0xfffffffbffffffffull,0xfffffffffffffffeull,0x00000004fffffffdull};
  static constexpr uint64_t one[4]={1,0,0,0};
  P256FieldResult result=P256FieldResult::Success;
  if(api.multiply(curve,w.ar,w.a,r2)!=0)return P256FieldResult::Error;
  if(op==Operation::Inverse){if(api.inverse(curve,w.result,w.ar)!=0)return P256FieldResult::Error;}
  else if(op==Operation::Multiply){
   if(api.multiply(curve,w.br,w.b,r2)!=0 || api.multiply(curve,w.result,w.ar,w.br)!=0)return P256FieldResult::Error;
  }else{
   static constexpr uint8_t exponent[32]={0x3f,0xff,0xff,0xff,0xc0,0x0,0x0,0x0,0x40,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x40,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
   if(api.multiply(curve,w.result,one,r2)!=0)return P256FieldResult::Error;
   for(unsigned bit=0;bit<256;++bit){
    if(api.multiply(curve,w.br,w.result,w.result)!=0)return P256FieldResult::Error;
    memcpy(w.result,w.br,32);
    if((exponent[bit/8]>>(7-bit%8))&1u){
     if(api.multiply(curve,w.br,w.result,w.ar)!=0)return P256FieldResult::Error;
     memcpy(w.result,w.br,32);
    }
   }
   if(api.multiply(curve,w.br,w.result,w.result)!=0)return P256FieldResult::Error;
   if(!equal(reinterpret_cast<const uint8_t *>(w.br),reinterpret_cast<const uint8_t *>(w.ar),32))result=P256FieldResult::NotSquare;
  }
  // Always convert after exponentiation, including the nonsquare case.
  if(api.multiply(curve,w.plain,w.result,one)!=0)return P256FieldResult::Error;
  if(result==P256FieldResult::NotSquare)return result;
  for(unsigned i=0;i<4;++i)for(unsigned j=0;j<8;++j)out[31-8*i-j]=uint8_t(w.plain[i]>>(8*j));
  return P256FieldResult::Success;
 }
public:
 explicit P256FieldCandidate(const P256FieldAPI &functions):api(functions){}
 bool multiply(const uint8_t *a,size_t aBytes,const uint8_t *b,size_t bBytes,uint8_t *out,size_t capacity,P256FieldWorkspace &w) const {
  return run(Operation::Multiply,a,aBytes,b,bBytes,out,capacity,w)==P256FieldResult::Success;
 }
 bool inverse(const uint8_t *a,size_t bytes,uint8_t *out,size_t capacity,P256FieldWorkspace &w) const {
  return run(Operation::Inverse,a,bytes,nullptr,0,out,capacity,w)==P256FieldResult::Success;
 }
 bool squareRoot(const uint8_t *a,size_t bytes,uint8_t *out,size_t capacity,P256FieldWorkspace &w) const {
  return run(Operation::SquareRoot,a,bytes,nullptr,0,out,capacity,w)==P256FieldResult::Success;
 }
 P256FieldResult squareRootStatus(const uint8_t *a,size_t bytes,uint8_t *out,size_t capacity,P256FieldWorkspace &w) const {
  return run(Operation::SquareRoot,a,bytes,nullptr,0,out,capacity,w);
 }

 bool add(const uint8_t *a,const uint8_t *b,size_t bytes,uint8_t *out,size_t capacity,P256FieldWorkspace &w) const {
  return run(Operation::Add,a,bytes,b,bytes,out,capacity,w)==P256FieldResult::Success;
 }
 bool subtract(const uint8_t *a,const uint8_t *b,size_t bytes,uint8_t *out,size_t capacity,P256FieldWorkspace &w) const {
  return run(Operation::Subtract,a,bytes,b,bytes,out,capacity,w)==P256FieldResult::Success;
 }

};

// Experimental SAE group-19 SSWU, Z=-10. Exclusive worker only; workspace
// and buffers must be disjoint. No native authentication path calls this yet.
inline bool saeGroup19SSWU(const P256FieldCandidate &field,const uint8_t *u,size_t bytes,
 uint8_t *out,size_t capacity,P256FieldWorkspace &workspace){
 if(!u || bytes!=32 || !out || capacity<64){workspace.clear();return false;}
 struct Scratch {uint8_t v[16][32]{};P256FieldWorkspace &w;
  explicit Scratch(P256FieldWorkspace &workspace):w(workspace){}
  ~Scratch(){wipe(v,sizeof(v));w.clear();}} scratch(workspace);
 auto &t=scratch.v;
 static constexpr uint8_t a[32]={0xff,0xff,0xff,0xff,0x0,0x0,0x0,0x1,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfc};
 static constexpr uint8_t b[32]={0x5a,0xc6,0x35,0xd8,0xaa,0x3a,0x93,0xe7,0xb3,0xeb,0xbd,0x55,0x76,0x98,0x86,0xbc,0x65,0x1d,0x6,0xb0,0xcc,0x53,0xb0,0xf6,0x3b,0xce,0x3c,0x3e,0x27,0xd2,0x60,0x4b};
 static constexpr uint8_t z[32]={0xff,0xff,0xff,0xff,0x0,0x0,0x0,0x1,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xf5};
 static constexpr uint8_t factor[32]={0x73,0x97,0x67,0x47,0xe3,0x68,0xdb,0xf8,0x3b,0xf9,0x3f,0x1c,0x7c,0xdd,0x82,0x3e,0xcc,0x5f,0x2,0x3b,0x44,0x1b,0xe5,0xa7,0x69,0x44,0xbe,0xbf,0x62,0x9b,0x75,0x6e};
 static constexpr uint8_t exception[32]={0xa5,0x28,0xbd,0x86,0x96,0xbd,0xaf,0x99,0x6c,0x65,0xb9,0x82,0xd9,0x49,0x59,0xd3,0x14,0x6f,0xe6,0xa0,0x20,0x69,0x30,0x90,0xbd,0xba,0x13,0x13,0x23,0x75,0xf2,0x24};
 static constexpr uint8_t one[32]={0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x1};
 static constexpr uint8_t zero[32]={0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
 auto mul=[&](const uint8_t *x,const uint8_t *y,uint8_t *r){return field.multiply(x,32,y,32,r,32,workspace);};
 auto add=[&](const uint8_t *x,const uint8_t *y,uint8_t *r){return field.add(x,y,32,r,32,workspace);};
 if(!mul(u,u,t[0]) || !mul(z,t[0],t[1]) || !mul(t[1],t[1],t[2]) || !add(t[2],t[1],t[2]))return false;
 uint32_t nonzero=0;for(unsigned i=0;i<32;++i)nonzero|=t[2][i];
 const uint8_t exceptional=uint8_t(0u-uint32_t(nonzero==0));
 for(unsigned i=0;i<32;++i)t[3][i]=uint8_t((one[i]&exceptional)|(t[2][i]&uint8_t(~exceptional)));
 if(!field.inverse(t[3],32,t[4],32,workspace))return false;
 for(unsigned i=0;i<32;++i)t[4][i]&=uint8_t(~exceptional);
 if(!add(one,t[4],t[5]) || !mul(factor,t[5],t[6]))return false;
 for(unsigned i=0;i<32;++i)t[6][i]=uint8_t((exception[i]&exceptional)|(t[6][i]&uint8_t(~exceptional)));
 if(!mul(t[1],t[6],t[7]))return false;
 auto polynomial=[&](const uint8_t *x,uint8_t *r){
  return mul(x,x,t[10]) && mul(t[10],x,t[10]) && mul(a,x,t[11]) && add(t[10],t[11],r) && add(r,b,r);
 };
 if(!polynomial(t[6],t[8]) || !polynomial(t[7],t[9]))return false;
 const auto first=field.squareRootStatus(t[8],32,t[12],32,workspace);
 const auto second=field.squareRootStatus(t[9],32,t[13],32,workspace);
 if(first==P256FieldResult::Error || second==P256FieldResult::Error ||
    (first==P256FieldResult::NotSquare && second==P256FieldResult::NotSquare))return false;
 const uint8_t choose=uint8_t(0u-uint32_t(first==P256FieldResult::Success));
 for(unsigned i=0;i<32;++i)t[14][i]=uint8_t((t[12][i]&choose)|(t[13][i]&uint8_t(~choose)));
 if(!field.subtract(zero,t[14],32,t[15],32,workspace))return false;
 const uint8_t negate=uint8_t(0u-uint32_t((u[31]^t[14][31])&1));
 for(unsigned i=0;i<32;++i){
  out[i]=uint8_t((t[6][i]&choose)|(t[7][i]&uint8_t(~choose)));
  out[32+i]=uint8_t((t[15][i]&negate)|(t[14][i]&uint8_t(~negate)));
 }
 return true;
}

// Experimental H2E group-19 password-to-PT pipeline; exclusive worker only.
// Timing behavior and kernel ABI are not approved for native password use.
template<class Crypto> inline bool saeGroup19H2EPT(const P256FieldCandidate &field,
 const P256CoreCryptoCandidate &points,const uint8_t *ssid,size_t ssidBytes,
 const uint8_t *password,size_t passwordBytes,const uint8_t *identifier,size_t identifierBytes,
 uint8_t *out,size_t capacity,P256FieldWorkspace &fieldWorkspace,P256CoreCryptoWorkspace &pointWorkspace){
 struct Scratch {uint8_t values[96]{},u[32]{},p[2][64]{},sum[64]{};
  P256FieldWorkspace &f;P256CoreCryptoWorkspace &e;
  Scratch(P256FieldWorkspace &fw,P256CoreCryptoWorkspace &ew):f(fw),e(ew){}
  ~Scratch(){wipe(values,sizeof(values));wipe(u,sizeof(u));wipe(p,sizeof(p));wipe(sum,sizeof(sum));f.clear();e.clear();}
 } scratch(fieldWorkspace,pointWorkspace);
 if(!out || capacity<64 || !saeGroup19H2EValues<Crypto>(ssid,ssidBytes,password,passwordBytes,
       identifier,identifierBytes,scratch.values,96))return false;
 for(unsigned i=0;i<2;++i){
  if(!saeGroup19ReduceH2EValue(scratch.values+48*i,48,scratch.u,32) ||
     !saeGroup19SSWU(field,scratch.u,32,scratch.p[i],64,fieldWorkspace))return false;
 }
 if(!points.add(scratch.p[0],64,scratch.p[1],64,scratch.sum,64,pointWorkspace))return false;
 memcpy(out,scratch.sum,64);return true;
}

// H2E MAC hash reduced modulo (group order - 1), then incremented.
inline bool saeGroup19H2EScalar(const uint8_t *hash,size_t bytes,uint8_t *out,size_t capacity){
 if(!hash || bytes!=32 || !out || capacity<32)return false;
 static constexpr uint8_t divisor[32]={
  0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
  0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x50};
 uint8_t value[32]{},reduced[32]{};uint32_t borrow=0;
 for(size_t i=32;i-->0;){const uint32_t v=uint32_t(hash[i])-divisor[i]-borrow;reduced[i]=uint8_t(v);borrow=v>>31;}
 const uint8_t choose=uint8_t(0u-(1u-borrow));uint32_t carry=1;
 for(size_t i=32;i-->0;){const uint32_t v=uint32_t((reduced[i]&choose)|(hash[i]&uint8_t(~choose)))+carry;value[i]=uint8_t(v);carry=v>>8;}
 memcpy(out,value,32);wipe(value,sizeof(value));wipe(reduced,sizeof(reduced));return true;
}
// Bind a pre-derived PT to max(MACs)||min(MACs), then multiply by the scalar.
// MAC identity/session validation is a separate caller responsibility.
template<class Crypto> inline bool saeGroup19H2EPWE(const P256CoreCryptoCandidate &points,
 const uint8_t *pt,size_t ptBytes,const uint8_t *a,const uint8_t *b,size_t macBytes,
 uint8_t *out,size_t capacity,P256CoreCryptoWorkspace &workspace){
 if(!pt || ptBytes!=64 || !a || !b || macBytes!=6 || !out || capacity<64){workspace.clear();return false;}
 uint8_t addresses[12]{},salt[32]{},hash[32]{},scalar[32]{},point[64]{};
 bool aGreater=false;for(unsigned i=0;i<6;++i){if(a[i]==b[i])continue;aGreater=a[i]>b[i];break;}
 memcpy(addresses,aGreater?a:b,6);memcpy(addresses+6,aGreater?b:a,6);
 const bool ok=Crypto::hmac256(salt,32,addresses,12,hash) && saeGroup19H2EScalar(hash,32,scalar,32) &&
     points.multiply(scalar,32,pt,64,point,64,workspace);
 if(ok)memcpy(out,point,64);
 wipe(addresses,sizeof(addresses));wipe(salt,sizeof(salt));wipe(hash,sizeof(hash));
 wipe(scalar,sizeof(scalar));wipe(point,sizeof(point));workspace.clear();return ok;
}

}

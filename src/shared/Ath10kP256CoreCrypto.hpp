#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "Ath10kSecurity.hpp"

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
}

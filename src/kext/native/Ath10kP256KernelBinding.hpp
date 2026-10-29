#pragma once
// Explicit diagnostic/native translation units only: private, version-sensitive ABI.
// Constructing these tables calls no crypto. Export linkage is not ABI approval.
#if !defined(ATH10K_P256_DIAGNOSTIC_BINDING) && !defined(ATH10K_P256_NATIVE_BINDING)
#error "P-256 kernel binding requires explicit compilation"
#endif
#include "../../shared/Ath10kP256CoreCrypto.hpp"
#include "../../shared/Ath10kP256DiagnosticPolicy.hpp"
namespace Ath10kP256KernelSymbols {
#ifdef ATH10K_P256_SYMBOLS_TEST
#define ATH10K_P256_SYMBOL(result,name,args) static result (*name) args=nullptr
#else
#define ATH10K_P256_SYMBOL(result,name,args) extern "C" result name args
#endif
ATH10K_P256_SYMBOL(const void *,ccec_cp_256,());
ATH10K_P256_SYMBOL(int,ccec_x963_import_pub,(const void *,size_t,const uint8_t *,void *));
ATH10K_P256_SYMBOL(bool,ccec_validate_pub,(void *));
ATH10K_P256_SYMBOL(int,ccec_x963_export,(int,void *,const void *));
ATH10K_P256_SYMBOL(int,ccec_projectify,(const void *,void *,const void *,void *));
ATH10K_P256_SYMBOL(int,ccec_affinify,(const void *,void *,const void *));
ATH10K_P256_SYMBOL(int,ccec_mult_blinded,(const void *,void *,const uint64_t *,const void *,void *));
ATH10K_P256_SYMBOL(int,ccec_full_add,(const void *,void *,const void *,const void *));
ATH10K_P256_SYMBOL(int,ccec_full_sub,(const void *,void *,const void *,const void *));
ATH10K_P256_SYMBOL(int,ccn_read_uint,(size_t,uint64_t *,size_t,const void *));
ATH10K_P256_SYMBOL(void *,ccrng,(int *));
ATH10K_P256_SYMBOL(size_t,cczp_n,(const void *));
ATH10K_P256_SYMBOL(const uint64_t *,cczp_prime,(const void *));
ATH10K_P256_SYMBOL(int,cczp_mul,(const void *,uint64_t *,const uint64_t *,const uint64_t *));
ATH10K_P256_SYMBOL(int,cczp_inv,(const void *,uint64_t *,const uint64_t *));
ATH10K_P256_SYMBOL(int,cczp_add,(const void *,uint64_t *,const uint64_t *,const uint64_t *));
ATH10K_P256_SYMBOL(int,cczp_sub,(const void *,uint64_t *,const uint64_t *,const uint64_t *));
#undef ATH10K_P256_SYMBOL
}
struct Ath10kP256KernelBinding {
    // Constructing a provider calls no crypto. A different OS never receives
    // these function pointers, even when the caller reuses a previous output.
    static bool providersForIdentity(int major,int minor,int revision,const char *build,const char *kernel,
        AthSecurity::P256CoreCryptoAPI &pointAPI,AthSecurity::P256FieldAPI &fieldAPI){
        pointAPI={};fieldAPI={};
        if(!AthSecurity::p256DiagnosticKernel(major,minor,revision,build,kernel))return false;
        pointAPI=points();fieldAPI=field();return true;
    }
    static AthSecurity::P256CoreCryptoAPI points(){
        using namespace Ath10kP256KernelSymbols;
        return {ccec_cp_256,ccec_x963_import_pub,ccec_validate_pub,ccec_x963_export,
            ccec_projectify,ccec_affinify,ccec_mult_blinded,ccec_full_add,ccec_full_sub,ccn_read_uint,ccrng};
    }
    static AthSecurity::P256FieldAPI field(){
        using namespace Ath10kP256KernelSymbols;
        return {ccec_cp_256,cczp_n,cczp_prime,cczp_mul,cczp_inv,cczp_add,cczp_sub};
    }
};

// Compile-only: no kmod entrypoint, no direct crypto imports, no runtime execution.
#include "../../src/shared/Ath10kP256CoreCrypto.hpp"
extern "C" __attribute__((used)) bool ath10k_p256_candidate_compile_check(
    const AthSecurity::P256CoreCryptoAPI *api,AthSecurity::P256CoreCryptoWorkspace *workspace,
    const uint8_t *scalar,const uint8_t *a,const uint8_t *b,uint8_t *out)
{
    if(!api || !workspace)return false;
    AthSecurity::P256CoreCryptoCandidate engine(*api);
    return engine.validate(a,64,*workspace) && engine.multiply(scalar,32,a,64,out,64,*workspace) &&
        engine.add(a,64,b,64,out,64,*workspace) && engine.subtract(a,64,b,64,out,64,*workspace);
}

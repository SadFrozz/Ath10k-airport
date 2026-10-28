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
extern "C" __attribute__((used)) bool ath10k_sae_shared_secret_compile_check(
    const AthSecurity::P256CoreCryptoAPI *api,AthSecurity::P256CoreCryptoWorkspace *workspace,
    const uint8_t *randomScalar,const uint8_t *peerScalar,const uint8_t *pwe,
    const uint8_t *peerElement,uint8_t *out)
{
    if(!api || !workspace)return false;
    AthSecurity::P256CoreCryptoCandidate engine(*api);
    return AthSecurity::saeGroup19SharedSecret(engine,randomScalar,32,peerScalar,32,
        pwe,64,peerElement,64,out,32,*workspace);
}
extern "C" __attribute__((used)) bool ath10k_sae_scalar_compile_check(
    const uint8_t *randomScalar,const uint8_t *mask,uint8_t *out)
{
    return AthSecurity::saeGroup19CommitScalar(randomScalar,mask,32,out,32);
}
extern "C" __attribute__((used)) bool ath10k_sae_commit_compile_check(
    const AthSecurity::P256CoreCryptoAPI *api,AthSecurity::P256CoreCryptoWorkspace *workspace,
    const uint8_t *randomScalar,const uint8_t *mask,const uint8_t *pwe,uint8_t *out)
{
    if(!api || !workspace)return false;
    AthSecurity::P256CoreCryptoCandidate engine(*api);
    return AthSecurity::saeGroup19Commit(engine,randomScalar,mask,32,pwe,64,out,96,*workspace);
}
extern "C" __attribute__((used)) bool ath10k_sae_h2e_reduce_compile_check(
    const uint8_t *value,uint8_t *out)
{
    return AthSecurity::saeGroup19ReduceH2EValue(value,48,out,32);
}
extern "C" __attribute__((used)) bool ath10k_p256_field_compile_check(
    const AthSecurity::P256FieldAPI *api,AthSecurity::P256FieldWorkspace *workspace,
    const uint8_t *a,const uint8_t *b,uint8_t *out)
{
    if(!api || !workspace)return false;
    AthSecurity::P256FieldCandidate field(*api);
    return field.add(a,b,32,out,32,*workspace) && field.subtract(a,b,32,out,32,*workspace) &&
        field.multiply(a,32,b,32,out,32,*workspace) && field.inverse(a,32,out,32,*workspace) && field.squareRoot(a,32,out,32,*workspace);
}
extern "C" __attribute__((used)) bool ath10k_sae_sswu_compile_check(
    const AthSecurity::P256FieldAPI *api,AthSecurity::P256FieldWorkspace *workspace,
    const uint8_t *u,uint8_t *out)
{
    if(!api || !workspace)return false;
    AthSecurity::P256FieldCandidate field(*api);
    return AthSecurity::saeGroup19SSWU(field,u,32,out,64,*workspace);
}
extern "C" __attribute__((used)) bool ath10k_sae_h2e_scalar_compile_check(
    const uint8_t *hash,uint8_t *out)
{
    return AthSecurity::saeGroup19H2EScalar(hash,32,out,32);
}

// Compile-only: no kmod entrypoint, no direct crypto imports, no runtime execution.
#include "../../src/shared/Ath10kP256CoreCrypto.hpp"
#include "../../src/shared/Ath10kSAE.hpp"
#include "../../src/shared/Ath10kSAEWire.hpp"
#include "../../src/shared/Ath10kSAEExchange.hpp"
#include "../../src/shared/Ath10kSupplicant.hpp"
extern "C" __attribute__((used)) bool ath10k_sae_wire_compile_check(
    const AthSecurity::SAEGroup19AuthMessage *message,AthSecurity::SAEGroup19AuthMessage *decoded,
    const uint8_t *frame,size_t frameBytes,const uint8_t *local,const uint8_t *ap,
    uint8_t *out,size_t capacity,size_t *bytes)
{
    if(!message || !decoded || !bytes)return false;
    return AthSecurity::encodeSAEGroup19ToAP(*message,local,ap,0,out,capacity,*bytes) &&
        AthSecurity::decodeSAEGroup19FromAP(frame,frameBytes,local,ap,message->h2e,*decoded)==AthSecurity::SAEWireResult::Valid;
}
// Compile-only indirection instantiates the complete H2E templates without
// importing a crypto implementation. This object is never linked or executed.
struct CompileOnlyHMAC {
    using Function=bool (*)(const uint8_t *,size_t,const uint8_t *,size_t,uint8_t *);
    inline static Function function=nullptr;
    static bool hmac256(const uint8_t *key,size_t keyBytes,const uint8_t *input,size_t bytes,uint8_t *out){
        return function && function(key,keyBytes,input,bytes,out);
    }
};
struct CompileOnlyPersonal : CompileOnlyHMAC {
    using Block=bool (*)(const uint8_t *,const uint8_t *,uint8_t *);
    using Random=bool (*)(uint8_t *,size_t);
    inline static Function sha1=nullptr;
    inline static Block encryptBlock=nullptr,decryptBlock=nullptr;
    inline static Random randomBytes=nullptr;
    static bool hmac(const uint8_t *k,size_t kl,const uint8_t *d,size_t n,uint8_t *o){return sha1 && sha1(k,kl,d,n,o);}
    static bool encrypt(const uint8_t *k,const uint8_t *d,uint8_t *o){return encryptBlock && encryptBlock(k,d,o);}
    static bool decrypt(const uint8_t *k,const uint8_t *d,uint8_t *o){return decryptBlock && decryptBlock(k,d,o);}
    static bool random(uint8_t *o,size_t n){return randomBytes && randomBytes(o,n);}
};
// Preserve arbitrary established/rekey state: a begin()+receive() entry alone
// permits the optimizer to erase every M3/group path as unreachable from M1.
extern "C" __attribute__((used,noinline)) unsigned ath10k_sae_eapol_receive_compile_check(
    AthSecurity::Supplicant<CompileOnlyPersonal,true,true> *supplicant,
    CompileOnlyHMAC::Function sha256,CompileOnlyHMAC::Function sha1,
    CompileOnlyPersonal::Block encrypt,CompileOnlyPersonal::Block decrypt,CompileOnlyPersonal::Random random,
    const uint8_t *frame,size_t bytes)
{
    if(!supplicant)return 0;
    CompileOnlyPersonal::function=sha256;CompileOnlyPersonal::sha1=sha1;
    CompileOnlyPersonal::encryptBlock=encrypt;CompileOnlyPersonal::decryptBlock=decrypt;CompileOnlyPersonal::randomBytes=random;
    const unsigned result=unsigned(supplicant->receive(frame,bytes));
    CompileOnlyPersonal::function=CompileOnlyPersonal::sha1=nullptr;
    CompileOnlyPersonal::encryptBlock=CompileOnlyPersonal::decryptBlock=nullptr;CompileOnlyPersonal::randomBytes=nullptr;
    return result;
}
extern "C" __attribute__((used)) bool ath10k_sae_eapol_compile_check(
    AthSecurity::Supplicant<CompileOnlyPersonal,true,true> *supplicant,
    CompileOnlyHMAC::Function sha256,CompileOnlyHMAC::Function sha1,
    CompileOnlyPersonal::Block encrypt,CompileOnlyPersonal::Block decrypt,CompileOnlyPersonal::Random random,
    const uint8_t *pmk,const uint8_t *nonce,const uint8_t *local,const uint8_t *ap,
    const uint8_t *rsn,size_t rsnBytes,const uint8_t *pmkid,const uint8_t *frame,size_t bytes)
{
    if(!supplicant)return false;
    CompileOnlyPersonal::function=sha256;CompileOnlyPersonal::sha1=sha1;
    CompileOnlyPersonal::encryptBlock=encrypt;CompileOnlyPersonal::decryptBlock=decrypt;CompileOnlyPersonal::randomBytes=random;
    bool ok=supplicant->begin(pmk,nonce,local,ap,rsn,rsnBytes,8,pmkid,16);
    if(ok)ok=supplicant->receive(frame,bytes)!=decltype(supplicant->receive(frame,bytes))::Fatal;
    CompileOnlyPersonal::function=CompileOnlyPersonal::sha1=nullptr;
    CompileOnlyPersonal::encryptBlock=CompileOnlyPersonal::decryptBlock=nullptr;CompileOnlyPersonal::randomBytes=nullptr;
    return ok;
}
extern "C" __attribute__((used)) bool ath10k_sae_client_compile_check(
    AthSecurity::SAEGroup19ClientExchange *owner,AthSecurity::SAEGroup19CommitTx *tx,
    AthSecurity::SAEGroup19KeyWork *keys,AthSecurity::SAEGroup19ConfirmWork *localJob,
    AthSecurity::SAEGroup19ConfirmWork *peerJob,const AthSecurity::P256CoreCryptoAPI *api,
    AthSecurity::P256CoreCryptoWorkspace *workspace,CompileOnlyHMAC::Function hmac,
    const AthSecurity::SAEGroup19AuthMessage *request,const uint8_t *local,const uint8_t *ap,
    const uint8_t *peerCommit,size_t commitBytes,const uint8_t *peerConfirm,size_t confirmBytes,
    const uint8_t *random,const uint8_t *pwe,uint8_t *frame,size_t capacity,size_t *frameBytes,
    uint8_t *pmk,uint8_t *pmkid)
{
    if(!owner || !tx || !keys || !localJob || !peerJob || !api || !workspace || !request || !frameBytes)return false;
    uint64_t token=0;uint8_t body[34]{};CompileOnlyHMAC::function=hmac;
    AthSecurity::P256CoreCryptoCandidate engine(*api);
    bool ok=owner->begin(*request,local,ap,0,token) && owner->snapshotCommit(*tx,0,0) && owner->completeCommit(*tx,true,0);
    if(ok){
        owner->receiveFromAP(peerCommit,commitBytes,0);
        ok=owner->snapshotKeys(*keys,0) && keys->compute<CompileOnlyHMAC>(engine,random,32,pwe,64,*workspace);
    }
    if(ok){
        owner->completeKeys(*keys,0);
        ok=owner->snapshotLocalConfirm(*localJob,0) && localJob->makeLocal<CompileOnlyHMAC>(body,sizeof(body)) &&
            owner->encodeLocalConfirm(*localJob,1,frame,capacity,*frameBytes,0);
    }
    if(ok){
        owner->completeLocalConfirm(*localJob,true,0);owner->receiveFromAP(peerConfirm,confirmBytes,0);
        ok=owner->snapshotPeerConfirm(*peerJob,body,sizeof(body),0) && peerJob->verifyPeer<CompileOnlyHMAC>(body,sizeof(body));
    }
    if(ok){owner->completePeerConfirm(*peerJob,0);ok=owner->copyPMK(token,pmk,32,pmkid,16,0);}
    owner->cancel();CompileOnlyHMAC::function=nullptr;AthSecurity::wipe(body,sizeof(body));return ok;
}
extern "C" __attribute__((used)) bool ath10k_sae_confirmation_compile_check(
    AthSecurity::SAEGroup19Confirmation *owner,AthSecurity::SAEGroup19ConfirmWork *job,
    AthSecurity::SAEGroup19Keys *keys,CompileOnlyHMAC::Function hmac,
    const uint8_t *localCommit,const uint8_t *peerCommit,const uint8_t *peerBody,
    uint8_t *pmk,uint8_t *pmkid)
{
    if(!owner || !job || !keys)return false;
    uint64_t token=0;uint8_t body[34]{};CompileOnlyHMAC::function=hmac;
    const bool ok=owner->begin(localCommit,96,peerCommit,96,token) && owner->completeKeys(token,true,*keys) &&
        owner->snapshotLocal(token,*job) && job->makeLocal<CompileOnlyHMAC>(body,sizeof(body)) &&
        owner->localReadyToTransmit(*job) && owner->completeLocal(*job,true) && owner->snapshotPeer(token,*job) &&
        job->verifyPeer<CompileOnlyHMAC>(peerBody,34) && owner->completePeer(*job) &&
        owner->copyPMK(token,pmk,32,pmkid,16);
    owner->cancel();CompileOnlyHMAC::function=nullptr;AthSecurity::wipe(body,sizeof(body));return ok;
}
extern "C" __attribute__((used)) bool ath10k_sae_h2e_pipeline_compile_check(
    const AthSecurity::P256CoreCryptoAPI *pointAPI,const AthSecurity::P256FieldAPI *fieldAPI,
    AthSecurity::P256CoreCryptoWorkspace *pointWorkspace,AthSecurity::P256FieldWorkspace *fieldWorkspace,
    CompileOnlyHMAC::Function hmac,const uint8_t *ssid,size_t ssidBytes,
    const uint8_t *password,size_t passwordBytes,const uint8_t *identifier,size_t identifierBytes,
    const uint8_t *a,const uint8_t *b,uint8_t *out)
{
    if(!pointAPI || !fieldAPI || !pointWorkspace || !fieldWorkspace)return false;
    AthSecurity::P256CoreCryptoCandidate points(*pointAPI);
    AthSecurity::P256FieldCandidate field(*fieldAPI);
    uint8_t pt[64]{};CompileOnlyHMAC::function=hmac;
    const bool ok=AthSecurity::saeGroup19H2EPT<CompileOnlyHMAC>(field,points,ssid,ssidBytes,
        password,passwordBytes,identifier,identifierBytes,pt,sizeof(pt),*fieldWorkspace,*pointWorkspace) &&
        AthSecurity::saeGroup19H2EPWE<CompileOnlyHMAC>(points,pt,sizeof(pt),a,b,6,out,64,*pointWorkspace);
    CompileOnlyHMAC::function=nullptr;AthSecurity::wipe(pt,sizeof(pt));return ok;
}
extern "C" __attribute__((used)) bool ath10k_p256_candidate_compile_check(
    const AthSecurity::P256CoreCryptoAPI *api,AthSecurity::P256CoreCryptoWorkspace *workspace,
    const uint8_t *scalar,const uint8_t *a,const uint8_t *b,uint8_t *out)
{
    if(!api || !workspace)return false;
    AthSecurity::P256CoreCryptoCandidate engine(*api);
    return engine.validate(a,64,*workspace) && engine.multiply(scalar,32,a,64,out,64,*workspace) &&
        engine.add(a,64,b,64,out,64,*workspace) && engine.subtract(a,64,b,64,out,64,*workspace);
}
extern "C" __attribute__((used)) bool ath10k_sae_exchange_compile_check(
    const AthSecurity::P256CoreCryptoAPI *api,AthSecurity::P256CoreCryptoWorkspace *workspace,
    CompileOnlyHMAC::Function hmac,const uint8_t *randomScalar,const uint8_t *localCommit,
    const uint8_t *peerCommit,const uint8_t *pwe,const uint8_t *localMAC,const uint8_t *peerMAC,
    const uint8_t *localRejected,size_t localBytes,const uint8_t *peerRejected,size_t peerBytes,
    AthSecurity::SAEGroup19Keys *out)
{
    if(!api || !workspace || !out)return false;
    AthSecurity::P256CoreCryptoCandidate engine(*api);CompileOnlyHMAC::function=hmac;
    const bool ok=AthSecurity::saeGroup19ExchangeCandidate<CompileOnlyHMAC>(engine,randomScalar,32,
        localCommit,96,peerCommit,96,pwe,64,true,localMAC,peerMAC,
        localRejected,localBytes,peerRejected,peerBytes,*out,*workspace);
    CompileOnlyHMAC::function=nullptr;return ok;
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

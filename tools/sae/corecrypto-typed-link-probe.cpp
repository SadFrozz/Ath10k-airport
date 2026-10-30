// Diagnostic symbol/context candidate only. Never install or load this probe.
#define ATH10K_P256_DIAGNOSTIC_BINDING 1
#include "../../src/kext/native/Ath10kP256KernelBinding.hpp"
#include "../../src/shared/Ath10kP256BackendCheck.hpp"
#include <mach/mach_types.h>
#include <mach/kmod.h>
// Caller must supply exclusive worker-owned storage. This entry is preserved
// for offline compilation/link verification; the probe's start never calls it.
extern "C" __attribute__((used,noinline)) bool ath10k_p256_backend_diagnostic(
    AthSecurity::P256BackendCheckWorkspace *workspace,AthSecurity::P256BackendCheckReport *report){
    if(!workspace || !report)return false;
    const auto points=Ath10kP256KernelBinding::points();const auto field=Ath10kP256KernelBinding::field();
    return AthSecurity::checkP256Backend(points,field,*workspace,*report);
}
extern "C" {
extern kern_return_t _start(kmod_info_t *,void *);
extern kern_return_t _stop(kmod_info_t *,void *);
KMOD_EXPLICIT_DECL(br.com.jonasw8.driver.ath10kcryptotypedprobe,"1.0.0",_start,_stop)
static kern_return_t probe_start(kmod_info_t *,void *){return KERN_FAILURE;}
static kern_return_t probe_stop(kmod_info_t *,void *){return KERN_FAILURE;}
kmod_start_func_t *_realmain=probe_start;
kmod_stop_func_t *_antimain=probe_stop;
}

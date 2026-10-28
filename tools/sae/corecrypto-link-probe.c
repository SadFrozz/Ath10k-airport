// Offline link availability only: these declarations must never be called.
// They intentionally assert no parameter/context ABI for the backend.
#include <mach/mach_types.h>
#include <mach/kmod.h>
extern void ccec_cp_256(void);
extern void ccec_x963_import_pub(void);
extern void ccec_validate_pub(void);
extern void ccec_x963_export(void);
extern void ccec_projectify(void);
extern void ccec_affinify(void);
extern void ccec_full_add(void);
extern void ccec_full_sub(void);
extern void ccec_mult_blinded(void);
extern void ccn_read_uint(void);
extern void ccn_write_uint_padded(void);
extern void ccrng(void);
extern void cczp_n(void);
extern void cczp_prime(void);
extern void cczp_mul(void);
extern void cczp_inv(void);
extern void cczp_add(void);
extern void cczp_sub(void);

static void (*volatile ath10k_crypto_link_imports[])(void) __attribute__((used)) = {
    ccec_cp_256,
    ccec_x963_import_pub,
    ccec_validate_pub,
    ccec_x963_export,
    ccec_projectify,
    ccec_affinify,
    ccec_full_add,
    ccec_full_sub,
    ccec_mult_blinded,
    ccn_read_uint,
    ccn_write_uint_padded,
    ccrng,
    cczp_n,
    cczp_prime,
    cczp_mul,
    cczp_inv,
    cczp_add,
    cczp_sub,
};
extern kern_return_t _start(kmod_info_t *,void *);
extern kern_return_t _stop(kmod_info_t *,void *);
KMOD_EXPLICIT_DECL(br.com.jonasw8.driver.ath10kcryptolinkprobe,"1.0.0",_start,_stop)
static kern_return_t probe_start(kmod_info_t *k,void *p){(void)k;(void)p;(void)ath10k_crypto_link_imports;return KERN_FAILURE;}
static kern_return_t probe_stop(kmod_info_t *k,void *p){(void)k;(void)p;return KERN_FAILURE;}
kmod_start_func_t *_realmain=probe_start;
kmod_stop_func_t *_antimain=probe_stop;

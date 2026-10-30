# SAE crypto backend: symbol binding investigation

Status: candidate backend investigation, not implemented SAE. No crypto function
was called by this probe, no module was installed/loaded and the Wi-Fi driver
binary/imports were not changed. Presence/binding does not establish context ABI,
cryptographic correctness, supported timing behavior or cross-version support.

## Authoritative local evidence

The installed Sequoia system reports 15.6.1 (24G90), Darwin 24.6.0.
Read-only BootKernelExtensions.kc inspection identifies:

| Image | UUID |
| --- | --- |
| Kernel | E999BA1A-CC26-3685-A2DB-AB7085F6F12A |
| com.apple.kec.corecrypto | 73605282-B982-31D4-9F9C-3027B1F9F833 |

CoreCrypto has external P-256/EC arithmetic entries. A previous kernel-image-only
symbol search did not inspect this separate module and cannot establish their
absence. The inspected CoreCrypto external-symbol list did not contain a ccsae
entry; that observation alone is not a proof that no other SAE facility exists.

The independently built probe has these 12 strong undefined references:

* ccec_cp_256
* ccec_x963_import_pub / ccec_x963_export
* ccec_validate_pub
* ccec_projectify / ccec_affinify
* ccec_full_add / ccec_full_sub
* ccec_mult_blinded
* ccn_read_uint / ccn_write_uint_padded
* ccrng

A local auxiliary collection successfully binds the exact probe binary,
UUID E093A013-F80F-3ECF-8BF4-50E8B9C6228C, under bundle ID
br.com.jonasw8.driver.ath10kcryptolinkprobe. The collection is separately checked
for its fileset entry and matching embedded UUID; a zero kmutil exit alone is
not the evidence. Adding a deliberately nonexistent strong import in an isolated
negative-control bundle fails binding (exit 31) and names that missing symbol.
The positive probe is separate from the actual Wi-Fi driver, which has no new
ccec imports. Its target is also absent from the normal kext build plan.

## Reproduction scope

`make sae-crypto-link-probe` builds and symbol-checks only
`build/sae-crypto-link-probe/Ath10kCryptoLinkProbe.kext`. This target does not
prepare firmware, change the normal Wi-Fi bundle or install anything. CI builds
this target but does not claim a system-kernel link test on arbitrary CI hosts.

The C file intentionally takes symbol addresses using non-callable placeholder
declarations. It is not a production API header or a callable ECC shim. Its
start/stop functions return failure and it has no IOKit personality. The probe uses the existing kernel SDK/toolchain; no extracted CoreCrypto
binary, header or assembly file is added by this change.

For a local binding investigation, copy the resulting bundle into an isolated
input directory, ad-hoc sign that copy, and use the existing local auxiliary
collection validation workflow with the probe's bundle ID. Preserve an unmodified
stock Boot collection as input; never overwrite system collections. Run
`scripts/validation/verify-kernel-collection.py` against the resulting auxiliary collection
and original probe executable with `--bundle-id` set to the probe ID. This
workflow is offline validation, not a request to load a diagnostic module.

## Execution and lifetime constraints still to resolve

Manual disassembly of this exact CoreCrypto image identifies
ccec_x963_import_pub at 0xffffff80032171d3. It calls cc_malloc_clear at
0xffffff8003217209 and frees its workspace through the callback at
0xffffff8003217262; allocation failure returns -13. ccec_validate_pub at
0xffffff800320d23b also calls cc_malloc_clear (0xffffff800320d2a0).
These observations rule out treating these wrappers as allocation-free interrupt
operations. They reinforce the existing requirement that SAE work run outside
IRQ/WCL/radio critical sections, with explicit allocation failure and cancellation
handling. They do not establish every backend function's runtime behavior.

Before selecting CoreCrypto as a production backend:

1. Recover and verify exact entrypoint parameters, context/point/scalar layout,
   alignment, return values, ownership and workspace cleanup for the selected ABI.
   Current SDK header presence or a newer upstream header is insufficient.
2. Exercise independent P-256/SEC1 positive and negative vectors, invalid points,
   infinity/scalars/range handling and blinded multiplication. Test actual backend
   results; mocked success cannot establish cryptographic behavior.
3. Integrate a retained crypto worker with join-generation checks, cancellation,
   power/stop drain and complete secret retirement. No gate may wait for itself.
4. Complete SAE, H2E, AKM-8 four-way and PMF/BIP work in docs/contracts/WPA3-CONTRACT.md before
   advertising any WPA3 capability or accepting an SAE request.
5. Check each requested OS adapter/kernel independently. A min-version compiler
   flag and this Sequoia link do not establish macOS 11–26 compatibility.

CoreCrypto remains a candidate. An audited portable backend is still an option
if its interface/portability/lifetime properties better satisfy the full goal.

## Unwired P-256 operation candidate (2026-10-28)

`src/security/Ath10kP256CoreCrypto.hpp` contains an independent function-table
adapter for public-point validation, blinded scalar multiplication, addition and
subtraction. It is not included by the Wi-Fi driver. Its caller-owned, aligned
688-byte workspace is cleared at entry and on every return. Invalid scalars,
invalid points, infinity and backend failures cannot publish a partial output.

`make sae-p256-userland-check` tests the actual userland CoreCrypto library,
using 12 multiplication vectors, 14 add/subtract vectors and a separate doubling
case against independent OpenSSL/cryptography fixtures. It exercises 37 injected
backend failure positions, malformed inputs, output canaries and workspace
clearing under AddressSanitizer and UndefinedBehaviorSanitizer. Fixture regeneration
uses the pinned dependencies in tests/fixtures/requirements-fixtures.txt and
`tests/fixtures/generate-p256-fixtures.py`.

The tested userland image UUID is 522269EC-E612-39DA-AFAB-ADF591065C57.
It differs from the kernel CoreCrypto image; these results do not establish
kernel runtime ABI compatibility. `make sae-p256-kernel-compile` checks compilation
and unavailable runtime imports only, using indirect calls. It never loads code.
The earlier isolated symbol-binding probe remains separate.

Caller-workspace clearing does not prove cleanup of the library's internal
allocations, constant-time behavior, cancellation safety or complete SAE.
Kernel execution, per-version ABI checks, scalar/field operations, SAE/H2E,
a retained cancellable worker, four-way AKM-8 and PMF/BIP remain outstanding.
No WPA3 capability is enabled by this candidate.

## WPA3 priority baseline, 2026-10-28 after user-test reboot

Re-ran `make sae-p256-userland-check sae-p256-kernel-compile` on the current
boot. ASan/UBSan user-process validation passed 12 multiplication vectors,
14 add/subtract vectors and 37 injected failures, with a 688-byte workspace
cleared on exits. Userland CoreCrypto UUID: 522269EC-E612-39DA-AFAB-ADF591065C57.
The kernel-target object compiled and passed the import checker. This provides
no kernel execution evidence: kernel runtime ABI/lifetime remains unverified
and the adapter remains disconnected from the installed Wi-Fi path. The next
security gate is matching callable kernel ABI plus execution/cancellation
coverage, before implementing SAE operations on top of this adapter.

## SSWU field backend investigation

The matching local kernel CoreCrypto symbol inventory exports cczp_add/sub,
mul, inv, sqrt, to and workspace variants. It has cczp_from_ws/default_ws
but no standalone cczp_from entry in the searched inventory. Do not substitute
a workspace function for a non-workspace signature.
Local disassembly confirms cczp_mul at 0xffffff800323ef1c preserves four
argument registers and calls cc_malloc_clear at 0xffffff800323ef53; cczp_to
at 0xffffff800321af36 calls it at 0xffffff800321af68; cczp_sqrt at
0xffffff800321c9aa calls it at 0xffffff800321c9d9; cczp_inv at
0xffffff80031f9939 calls it at 0xffffff80031f996c. These wrappers cannot be
assumed allocation-free IRQ/gated operations. Return semantics, selected
curve representation, conversions and failure cleanup require exact-image
validation before a callable adapter is integrated.

Apple's current published cczp headers show opaque field context and arithmetic
entrypoints, but they are a different-version reference, not proof for Sequoia.
In particular, plain integers versus curve-specific field representation must
be tested with independent arithmetic vectors and conversion round trips.
Sources consulted (not copied into this repository):
https://github.com/apple/corecrypto
https://raw.githubusercontent.com/apple/corecrypto/main/cczp/corecrypto/cczp.h
https://raw.githubusercontent.com/apple/corecrypto/main/cczp/corecrypto/cczp_priv.h
The local raw disassembly remains outside repository/SD/public artifacts.

## Field representation experiment (current userland CoreCrypto)

A separate ctypes process resolved curve/n/prime/mul/inv and checked the
context's 4-limb prime against P-256 before arithmetic. Userland lacked
cczp_to/from/sqrt/from_ws symbols in that lookup; this differs from the local
kernel inventory and is not evidence that kernel symbols cannot be called.
Raw cczp_mul(cp,2,3) returned 6*R^-1 mod p, R=2^256, confirming Montgomery
representation for this curve. Using mul(x,R^2 mod p) to enter and mul(x,1)
to leave matched 25 independent Python-integer round trips and 625 modular
products. Inversion on Montgomery inputs for 2,3,p-1 returned Montgomery
inverses, not plain ones. These are user-process observations only, not kernel
ABI, constant-time or per-version proof. Raw outputs are stored locally.

Exact kernel-image disassembly separately shows mul/to return 0 after
successful dispatch and -13 on workspace allocation failure; inv/sqrt preserve
the dispatched arithmetic status and also return -13 on allocation failure.
cczp_from_ws receives workspace first and field context second, dispatching
through the context function table. A callable adapter must keep these
signatures and representations separate rather than borrowing a userland-only
symbol set. No new imports or field calls were added to the installed driver.

An experimental function-table P256FieldCandidate now implements multiplication
and inversion with explicit Montgomery conversion using independently computed
R^2 mod p. It validates 4 limbs and the exact P-256 prime, rejects noncanonical
32-byte inputs, and publishes ordinary BE bytes only after success. Its
192-byte workspace is cleared on every path; input/output must be disjoint
from workspace and calls must run in an exclusive worker outside radio/WCL
gates because provider wrappers allocate. No locking is provided.
Actual userland CoreCrypto ASan/UBSan checks pass 2*3=6 and inverse(2) against
independent Python-integer results, with failures injected at every curve/
multiply/inverse provider stage preserving output and clearing workspace.
A used kernel compile-only entry instantiates the adapter and passes the
import/stack checks. The production kext has no new direct field imports;
kernel runtime ABI, SSWU and complete PWE derivation remain unverified.

P256FieldCandidate now derives a square root with public exponent (p+1)/4,
keeping intermediate powers in Montgomery representation and verifying the
result by squaring before ordinary-byte publication. No direct sqrt import
is required. Actual userland CoreCrypto ASan/UBSan tests pass independent
Python pow fixtures for 0,1,4,9 and reject p-1 (a nonsquare). Injected failures
at initial, middle and final provider calls preserve output and clear the
workspace. A used kernel compile entry instantiates this path and passes
import/stack checks. The operation currently returns bool, so missing square
root and provider failure are not distinguished; this must be resolved for
SSWU candidate selection rather than treating all failures as nonsquares.
Public fixed exponent branches are independent of secret input; machine-level
constant-time behavior and kernel runtime execution are still unverified.

Square-root status is now explicit: Success, NotSquare or Error. Only a
successfully computed candidate whose square differs from the input returns
NotSquare; bad arguments/context/provider failures return Error. Existing bool
wrappers remain compatible. Userland ASan/UBSan tests distinguish p-1 as
NotSquare, p as invalid Error, and an injected arithmetic failure while
processing a nonsquare as Error, preserving output. Kernel compile/import
checks pass. The original point adapter run body was separately compared
byte-for-byte with HEAD and remains unchanged. No SSWU fallback is wired yet.

Field adapter now adds canonical ordinary-value addition/subtraction through
optional function-table entries, with exact P-256 context/range validation and
transactional output publication. Existing multiply/inverse/sqrt require no
new entries. Actual userland CoreCrypto ASan/UBSan tests pass independent
Python modular sums/differences for (2,3), (p-1,p-1), (0,1) and (1,1), with
output guard bytes retained. Kernel compile/import checks instantiate these
operations. This completes the experimental operation set needed by SSWU,
not a verified mapping or a working H2E/WPA3 path. Add/sub provider fault
injection and mapping-level validation are still needed.

A call-count regression identified a residue-dependent provider path: the
original square-root helper returned NotSquare before its final Montgomery
conversion, while Success made one additional multiply/allocation wrapper
call. The test comparing tracked provider-call totals failed before the fix.
Both outcomes now perform the final conversion before status publication;
updated ASan/UBSan userland tests and kernel compile/import checks pass.
This removes the demonstrated missing-provider-call difference only. Status
branches, provider arithmetic/allocator timing and complete H2E behavior still
require side-channel analysis before any native password path is enabled.

The shared-secret helper now rejects local random scalar 1 as well as 0,
matching commit generation's [2,r-1] requirement. Boundary tests cover local
0/1/order/above-order, unchanged output and wiped workspace; 0/1 cause no
provider calls. ASan/UBSan userland checks pass. A compile-only entry now
instantiates the complete password-to-PT-to-PWE H2E chain with a supplied
HMAC callback, rather than just individual field operations. Kernel stack and
import checks pass; this is not kernel execution or timing validation. The
userland checker now explicitly depends on its SHA256/RSN headers so changes
to those helpers cannot silently reuse an older test executable.

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
`scripts/verify-kernel-collection.py` against the resulting auxiliary collection
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
4. Complete SAE, H2E, AKM-8 four-way and PMF/BIP work in WPA3-CONTRACT.md before
   advertising any WPA3 capability or accepting an SAE request.
5. Check each requested OS adapter/kernel independently. A min-version compiler
   flag and this Sequoia link do not establish macOS 11–26 compatibility.

CoreCrypto remains a candidate. An audited portable backend is still an option
if its interface/portability/lifetime properties better satisfy the full goal.

## Unwired P-256 operation candidate (2026-10-28)

`src/shared/Ath10kP256CoreCrypto.hpp` contains an independent function-table
adapter for public-point validation, blinded scalar multiplication, addition and
subtraction. It is not included by the Wi-Fi driver. Its caller-owned, aligned
688-byte workspace is cleared at entry and on every return. Invalid scalars,
invalid points, infinity and backend failures cannot publish a partial output.

`make sae-p256-userland-check` tests the actual userland CoreCrypto library,
using 12 multiplication vectors, 14 add/subtract vectors and a separate doubling
case against independent OpenSSL/cryptography fixtures. It exercises 37 injected
backend failure positions, malformed inputs, output canaries and workspace
clearing under AddressSanitizer and UndefinedBehaviorSanitizer. Fixture regeneration
uses the pinned dependencies in tests/requirements-fixtures.txt and
`tests/generate-p256-fixtures.py`.

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

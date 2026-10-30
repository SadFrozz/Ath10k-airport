# Kernel collection validation correction

## Offline validation correction (2026-10-28)

Several prior `kmutil create -n boot ... -p candidate` runs returned success
but generated a collection containing only `com.apple.kernel`. Their metadata
`offline_kernel_link=true` does **not** prove candidate inclusion or successful
symbol binding. Preserve the historical packages and attach a correction;
do not silently replace their verified manifests. An older local
`native-validation.kc` does include Ath10k, but that alone does not identify it
as the current candidate.

Every future link check must additionally run
`scripts/verify-kernel-collection.py COLLECTION KEXT_EXECUTABLE` and match both
bundle identifier and executable UUID. This is necessary, not sufficient, for
hardware correctness. The verifier rejects missing/duplicate entries, stale
UUIDs and malformed command bounds.

A separate explicit auxiliary-collection experiment reached actual symbol
binding and rejected `_thread_call_cancel_wait` as an unavailable kext export.
That experiment used a separate validation copy with `OSBundleRequired` removed;
it does not prove the original OpenCore-injected bundle cannot boot and is not
proof that this import caused the hardware hang. Replace this private API with
public cancellation plus independently tracked queued/running callback lifetime.
The unchanged candidate auxiliary control run was rejected before linking
("No binaries or codeless kexts were provided"); it is not a passing control.
No OS collection, EFI driver or active network was changed by these checks.


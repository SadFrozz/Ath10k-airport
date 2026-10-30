#if !ATH10K_NATIVE || ATH10K_P256_DIAGNOSTIC
#error "Native SAE backend requires the normal native build"
#endif
#define ATH10K_P256_NATIVE_BINDING 1
#include "Ath10kP256KernelBinding.hpp"
#include "Ath10kNativeSAEKernelBackend.hpp"
#include <IOKit/IORegistryEntry.h>
#include <libkern/c++/OSString.h>
#include <libkern/version.h>

bool Ath10kNativeSAEKernelBackend::providers(AthSecurity::P256CoreCryptoAPI &points,AthSecurity::P256FieldAPI &field){
    points={};field={};
    // Queried on demand: an absent early-boot property is not cached forever.
    // No waiting or cryptographic operation occurs under the caller's gate.
    auto root=IORegistryEntry::getRegistryRoot();
    auto property=root?root->copyProperty("OS Build Version"):nullptr;
    auto build=OSDynamicCast(OSString,property);
    const bool ready=build && Ath10kP256KernelBinding::providersForIdentity(
        version_major,version_minor,version_revision,build->getCStringNoCopy(),version,points,field);
    if(property)property->release();return ready;
}

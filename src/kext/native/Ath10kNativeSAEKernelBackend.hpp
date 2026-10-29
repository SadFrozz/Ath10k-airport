#pragma once
#include "../../shared/Ath10kP256CoreCrypto.hpp"
// This supplies the backend tested in the isolated kernel diagnostic. It does
// not enable SAE admission, validate native credentials, or prove firmware PMF.
struct Ath10kNativeSAEKernelBackend {
    static bool providers(AthSecurity::P256CoreCryptoAPI &,AthSecurity::P256FieldAPI &);
};

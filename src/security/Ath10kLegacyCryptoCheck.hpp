#pragma once
#include "Ath10kSecurity.hpp"
namespace AthSecurity {
// RFC 2202 HMAC-MD5 test case 1. Public synthetic input only. Run before
// admitting an explicitly enabled legacy handshake; no cached readiness can
// survive a different provider binding or disguise a failed invocation.
template<class Crypto> bool legacyHMACReady(){
    uint8_t key[16],digest[16]{};for(auto &v:key)v=0x0b;
    const uint8_t message[]={'H','i',' ','T','h','e','r','e'};
    const uint8_t expected[]={0x92,0x94,0x72,0x7a,0x36,0x38,0xbb,0x1c,0x13,0xf4,0x8e,0xf8,0x15,0x8b,0xfc,0x9d};
    const bool ok=Crypto::hmacMD5(key,sizeof(key),message,sizeof(message),digest) && equal(digest,expected,sizeof(expected));
    wipe(key,sizeof(key));wipe(digest,sizeof(digest));return ok;
}
}

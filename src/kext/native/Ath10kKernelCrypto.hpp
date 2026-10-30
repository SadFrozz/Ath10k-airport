#pragma once
#include <IOKit/IOLib.h>
#include <sys/random.h>
#include "../../shared/Ath10kSecurity.hpp"
extern "C" {
#include <corecrypto/cchmac.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode.h>
}
// Existing bounded provider shared by EAPOL and off-gate PMF jobs.
struct Ath10kKernelCrypto {
    static bool hmac256(const UInt8 *key,size_t keyLength,const UInt8 *data,size_t length,UInt8 *out) {
        const auto di=ccsha256_di();if(!di)return false;
        cchmac(di,keyLength,key,length,data,out);return true;
    }
    static bool encrypt(const UInt8 *key,const UInt8 *data,UInt8 *out) {
        auto mode=ccaes_ecb_encrypt_mode();if(!mode || mode->size>1024)return false;
        alignas(16) UInt8 context[1024]{};auto ctx=reinterpret_cast<ccecb_ctx *>(context);
        bool ok=mode->init(mode,ctx,16,key)==0 && mode->ecb(ctx,1,data,out)==0;
        AthSecurity::wipe(context,sizeof(context));return ok;
    }
    static bool hmac(const UInt8 *key,size_t keyLength,const UInt8 *data,size_t length,UInt8 *out) {
        const auto di=ccsha1_di();if(!di)return false;
        cchmac(di,keyLength,key,length,data,out);return true;
    }
    static bool decrypt(const UInt8 *key,const UInt8 *data,UInt8 *out) {
        auto mode=ccaes_ecb_decrypt_mode();if(!mode || mode->size>1024)return false;
        // Fixed upper bound: no variable-sized kernel stack allocation.
        alignas(16) UInt8 context[1024]{};
        auto ctx=reinterpret_cast<ccecb_ctx *>(context);
        bool ok=mode->init(mode,ctx,16,key)==0 && mode->ecb(ctx,1,data,out)==0;
        AthSecurity::wipe(context,sizeof(context));return ok;
    }
    static bool random(UInt8 *out,size_t length) {read_random(out,length);return true;}
};

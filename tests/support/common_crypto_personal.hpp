#pragma once
#include <stdint.h>
#include <stddef.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonCryptor.h>
struct PersonalTestCrypto {
 static bool random(uint8_t *out,size_t n){for(size_t i=0;i<n;++i)out[i]=uint8_t(i);return true;}
 static bool hmac(const uint8_t *k,size_t kl,const uint8_t *d,size_t n,uint8_t *o){CCHmac(kCCHmacAlgSHA1,k,kl,d,n,o);return true;}
 static bool hmac256(const uint8_t *k,size_t kl,const uint8_t *d,size_t n,uint8_t *o){CCHmac(kCCHmacAlgSHA256,k,kl,d,n,o);return true;}
 static bool encrypt(const uint8_t *k,const uint8_t *d,uint8_t *o){size_t done=0;return CCCrypt(kCCEncrypt,kCCAlgorithmAES,kCCOptionECBMode,k,16,nullptr,d,16,o,16,&done)==kCCSuccess && done==16;}
 static bool decrypt(const uint8_t *k,const uint8_t *d,uint8_t *o){size_t done=0;return CCCrypt(kCCDecrypt,kCCAlgorithmAES,kCCOptionECBMode,k,16,nullptr,d,16,o,16,&done)==kCCSuccess && done==16;}
};

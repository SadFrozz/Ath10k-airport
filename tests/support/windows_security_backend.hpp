#pragma once
// Host-test adapter only. Production code does not depend on Windows APIs.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <cstdint>
#include <cstddef>
struct OpenSSLCrypto {
    static bool random(uint8_t *p, size_t n) {
        // Deterministic nonces used by the existing independent test vectors.
        for (size_t i=0;i<n;++i) p[i]=uint8_t(i+51);
        return true;
    }
    static bool hmac(const uint8_t *key,size_t keyLength,const uint8_t *data,size_t size,uint8_t *out) {
        BCRYPT_ALG_HANDLE alg=nullptr;
        BCRYPT_HASH_HANDLE hash=nullptr;
        bool ok=false;
        if (BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA1_ALGORITHM,nullptr,BCRYPT_ALG_HANDLE_HMAC_FLAG)<0) return false;
        DWORD length=0,received=0;
        if (BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&length),sizeof(length),&received,0)>=0) {
            std::vector<uint8_t> object(length);
            if (BCryptCreateHash(alg,&hash,object.data(),length,const_cast<PUCHAR>(key),ULONG(keyLength),0)>=0) {
                ok=BCryptHashData(hash,const_cast<PUCHAR>(data),ULONG(size),0)>=0 && BCryptFinishHash(hash,out,20,0)>=0;
                BCryptDestroyHash(hash);
            }
        }
        BCryptCloseAlgorithmProvider(alg,0);
        return ok;
    }
    static bool aes(bool decrypt,const uint8_t *key,const uint8_t *in,uint8_t *out) {
        BCRYPT_ALG_HANDLE alg=nullptr;
        BCRYPT_KEY_HANDLE handle=nullptr;
        if (BCryptOpenAlgorithmProvider(&alg,BCRYPT_AES_ALGORITHM,nullptr,0)<0) return false;
        bool ok=false;
        DWORD length=0,received=0,written=0;
        if (BCryptSetProperty(alg,BCRYPT_CHAINING_MODE,reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_ECB)),sizeof(BCRYPT_CHAIN_MODE_ECB),0)>=0 &&
            BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&length),sizeof(length),&received,0)>=0) {
            std::vector<uint8_t> object(length);
            if (BCryptGenerateSymmetricKey(alg,&handle,object.data(),length,const_cast<PUCHAR>(key),16,0)>=0) {
                const NTSTATUS result=decrypt ?
                    BCryptDecrypt(handle,const_cast<PUCHAR>(in),16,nullptr,nullptr,0,out,16,&written,0) :
                    BCryptEncrypt(handle,const_cast<PUCHAR>(in),16,nullptr,nullptr,0,out,16,&written,0);
                ok=result>=0 && written==16;
                BCryptDestroyKey(handle);
            }
        }
        BCryptCloseAlgorithmProvider(alg,0);
        return ok;
    }
    static bool decrypt(const uint8_t *k,const uint8_t *p,uint8_t *o) {return aes(true,k,p,o);}
    static bool encrypt(const uint8_t *k,const uint8_t *p,uint8_t *o) {return aes(false,k,p,o);}
};

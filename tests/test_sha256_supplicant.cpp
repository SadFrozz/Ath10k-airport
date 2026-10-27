#include <cassert>
#include <cstring>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonCryptor.h>
#include "../src/shared/Ath10kSupplicant.hpp"
#include "sha256_vectors.inc"
struct Crypto {
 static bool random(uint8_t *out,size_t n){for(size_t i=0;i<n;++i)out[i]=uint8_t(i);return true;}
 static bool hmac(const uint8_t *k,size_t kl,const uint8_t *p,size_t n,uint8_t *o){CCHmac(kCCHmacAlgSHA1,k,kl,p,n,o);return true;}
 static bool hmac256(const uint8_t *k,size_t kl,const uint8_t *p,size_t n,uint8_t *o){CCHmac(kCCHmacAlgSHA256,k,kl,p,n,o);return true;}
 static bool encrypt(const uint8_t *k,const uint8_t *p,uint8_t *o){size_t done=0;return CCCrypt(kCCEncrypt,kCCAlgorithmAES,kCCOptionECBMode,k,16,nullptr,p,16,o,16,&done)==kCCSuccess && done==16;}
 static bool decrypt(const uint8_t *k,const uint8_t *p,uint8_t *o){size_t done=0;return CCCrypt(kCCDecrypt,kCCAlgorithmAES,kCCOptionECBMode,k,16,nullptr,p,16,o,16,&done)==kCCSuccess && done==16;}
};
int main(){
 using S=AthSecurity::Supplicant<Crypto,true>;S s;
 assert(!s.begin(nullptr,s_snonce,s_sta,s_ap,s_rsn,sizeof(s_rsn),6));
 assert(s.begin(s_pmk,s_snonce,s_sta,s_ap,s_rsn,sizeof(s_rsn),6));
 uint8_t wrong[sizeof(s_m1)];memcpy(wrong,s_m1,sizeof(wrong));wrong[20]^=1;
 assert(s.receive(wrong,sizeof(wrong))==S::Ignore);
 assert(s.receive(s_m1,sizeof(s_m1))==S::Reply);
 assert(s.outputLength==sizeof(s_m2) && !memcmp(s.output,s_m2,sizeof(s_m2)));
 assert(s.receive(s_m3,sizeof(s_m3))==S::Keys);
 assert(s.outputLength==sizeof(s_m4) && !memcmp(s.output,s_m4,sizeof(s_m4)));
 assert(!memcmp(s.keys,s_ptk+32,16) && !memcmp(s.keys+16,s_gtk,16));
 assert(s.receive(s_m3,sizeof(s_m3))==S::Reply); // no reinstallation
 assert(s.receive(s_group,sizeof(s_group))==S::GroupKeys);
 assert(!memcmp(s.keys+16,s_newgtk,16));
 assert(s.outputLength==sizeof(s_groupAck) && !memcmp(s.output,s_groupAck,sizeof(s_groupAck)));
 assert(s.receive(s_group,sizeof(s_group))==S::Reply);
 assert(s.receive(s_rekey1,sizeof(s_rekey1))==S::Reply);
 assert(s.pairwisePending());
 assert(s.outputLength==sizeof(s_rekey2) && !memcmp(s.output,s_rekey2,sizeof(s_rekey2)));
 assert(s.receive(s_rekey3,sizeof(s_rekey3))==S::PairKeys);
 assert(!memcmp(s.keys,s_nextPTK+32,16));
 assert(s.outputLength==sizeof(s_rekey4) && !memcmp(s.output,s_rekey4,sizeof(s_rekey4)));
 assert(s.receive(s_rekey3,sizeof(s_rekey3))==S::Reply);
 assert(s.receive(s_m3,sizeof(s_m3))==S::Ignore);
 S bad;assert(bad.begin(s_pmk,s_snonce,s_sta,s_ap,s_rsn,sizeof(s_rsn),6));
 assert(bad.receive(s_m1,sizeof(s_m1))==S::Reply);
 uint8_t corrupt[sizeof(s_m3)];memcpy(corrupt,s_m3,sizeof(corrupt));corrupt[14+81]^=1;
 assert(bad.receive(corrupt,sizeof(corrupt))==S::Fatal);
 uint8_t mandatory[sizeof(s_rsn)];memcpy(mandatory,s_rsn,sizeof(mandatory));mandatory[20]|=0x40;
 assert(!bad.begin(s_pmk,s_snonce,s_sta,s_ap,mandatory,sizeof(mandatory),6));
 assert(!bad.begin(s_pmk,s_snonce,s_sta,s_ap,s_rsn,sizeof(s_rsn),2));
 AthSecurity::Supplicant<Crypto> legacy;assert(!legacy.begin(s_pmk,s_snonce,s_sta,s_ap,s_rsn,sizeof(s_rsn),6));
 // RFC 4493 AES-CMAC example 1 (empty message).
 const uint8_t key[]={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
 const uint8_t expected[]={0xbb,0x1d,0x69,0x29,0xe9,0x59,0x37,0x28,0x7f,0xa3,0x7d,0x12,0x9b,0x75,0x67,0x46};
 uint8_t tag[16];
 assert(!AthSecurity::SHA256Personal<Crypto>::derive(nullptr,s_snonce,tag));
 assert(!AthSecurity::SHA256Personal<Crypto>::mic(key,key,513,tag));
 assert(AthSecurity::SHA256Personal<Crypto>::mic(key,nullptr,0,tag));assert(!memcmp(tag,expected,16));
 const uint8_t block[]={0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
 const uint8_t fullTag[]={0x07,0x0a,0x16,0xb4,0x6b,0x4d,0x41,0x44,0xf7,0x9b,0xdd,0x9d,0xd0,0x4a,0x28,0x7c};
 assert(AthSecurity::SHA256Personal<Crypto>::mic(key,block,sizeof(block),tag));assert(!memcmp(tag,fullTag,16));

}

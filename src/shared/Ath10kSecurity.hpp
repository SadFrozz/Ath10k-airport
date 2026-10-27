#pragma once
#include <stdint.h>
#include <stddef.h>
#include "Ath10kRSN.hpp"
namespace AthSecurity {
inline void wipe(void *p,size_t n){volatile uint8_t *b=(volatile uint8_t *)p;while(n--)*b++=0;}
inline bool equal(const uint8_t *a,const uint8_t *b,size_t n){uint8_t d=0;for(size_t i=0;i<n;++i)d|=a[i]^b[i];return d==0;}
inline uint16_t le16(const uint8_t *p){return static_cast<uint16_t>(p[0]|(uint16_t(p[1])<<8));}
inline uint16_t be16(const uint8_t *p){return static_cast<uint16_t>((uint16_t(p[0])<<8)|p[1]);}
inline void put16(uint8_t *p,uint16_t n){p[0]=static_cast<uint8_t>(n>>8);p[1]=static_cast<uint8_t>(n);}
inline uint64_t be64(const uint8_t *p){uint64_t n=0;for(unsigned i=0;i<8;++i)n=(n<<8)|p[i];return n;}
inline void copy(uint8_t *a,const uint8_t *b,size_t n){for(size_t i=0;i<n;++i)a[i]=b[i];}
// RSN IEs selected by this STA: CCMP pairwise and either CCMP or TKIP group,
// always with PSK AKM and without PMF.
static constexpr uint8_t stationRSN[]={48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,2,0,0};
static constexpr uint8_t stationRSNTKIP[]={48,20,1,0,0,15,172,2,1,0,0,15,172,4,1,0,0,15,172,2,0,0};
static constexpr uint8_t cipherTKIP=2,cipherCCMP=4;
inline bool suite(const uint8_t *p,uint8_t type){return !p[0]&&p[1]==15&&p[2]==172&&p[3]==type;}
inline uint8_t wpa2GroupCipher(const uint8_t *ie,size_t n){
 if(!ie||n<8||n>257||ie[0]!=48||size_t(ie[1])+2!=n||le16(ie+2)!=1)return 0;
 if(suite(ie+4,cipherTKIP))return cipherTKIP;
 if(suite(ie+4,cipherCCMP))return cipherCCMP;
 return 0;
}
static constexpr uint8_t stationRSNSHA256[]={48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,6,0,0};
inline const uint8_t *stationRSNForGroup(uint8_t group,size_t &n,uint8_t akm=2){
 if(akm==6){if(group==cipherCCMP){n=sizeof(stationRSNSHA256);return stationRSNSHA256;}n=0;return nullptr;}
 if(akm!=2){n=0;return nullptr;}
 if(group==cipherCCMP){n=sizeof(stationRSN);return stationRSN;}
 if(group==cipherTKIP){n=sizeof(stationRSNTKIP);return stationRSNTKIP;}
 n=0;return nullptr;
}
// Strict bounds on optional fields; require AES/CCMP pairwise and PSK.
// TKIP is allowed only for the group cipher; TKIP pairwise remains unsupported.
inline bool supportsWPA2(const uint8_t *ie,size_t n){
 RSNInfo ap{};
 if(!parseRSN(ie,n,ap))return false;
 // The existing user-client/supplicant path has no PMF support yet.
 return !ap.mfpr() && bool(selectPersonal(ie,n,PersonalMode::WPA2));
}
}

namespace AthSecurity {
inline bool supportsPSKAKM(const uint8_t *ie,size_t n,uint8_t akm){
 if(akm==2)return supportsWPA2(ie,n);
 RSNInfo ap{};
 return akm==6 && parseRSN(ie,n,ap) && !ap.mfpr() && ap.akmHas(6) &&
  ap.pairwiseHas(4) && ap.group==4 && !(ap.capabilities&((1u<<9)|(1u<<13)));
}
}

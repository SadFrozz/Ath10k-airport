#pragma once
#include <stdint.h>
#include <stddef.h>
#include "Ath10kRSN.hpp"
namespace AthSecurity {
inline void wipe(void *p,size_t n){volatile uint8_t *b=(volatile uint8_t *)p;while(n--)*b++=0;}
inline bool equal(const uint8_t *a,const uint8_t *b,size_t n){uint8_t d=0;for(size_t i=0;i<n;++i)d|=a[i]^b[i];return d==0;}
// Worker/gate-owned software IGTK state. Call activate only after authenticated
// key delivery and required installation acknowledgement. Never access concurrently.
class PMFKeyEpochs {
 struct Slot {IGTKCMAC128 key{};uint64_t epoch=0;bool valid=false;} slots[2]{};
 uint64_t nextEpoch=0;
public:
 PMFKeyEpochs()=default;
 PMFKeyEpochs(const PMFKeyEpochs &)=delete;
 PMFKeyEpochs &operator=(const PMFKeyEpochs &)=delete;
 ~PMFKeyEpochs(){wipe(this,sizeof(*this));}
 void clear(){wipe(slots,sizeof(slots));} // Preserve monotonic epoch across reuse.
 bool activate(const IGTKCMAC128 &key){
  if((key.keyID!=4 && key.keyID!=5) || key.ipn>0xffffffffffffull)return false;
  for(unsigned i=0;i<2;++i)if(slots[i].valid && equal(slots[i].key.key,key.key,16))
   return slots[i].key.keyID==key.keyID; // Retransmission cannot reset replay state.
  if(nextEpoch==~uint64_t(0))return false;
  auto &slot=slots[key.keyID-4];wipe(&slot,sizeof(slot));
  slot.key=key;slot.epoch=++nextEpoch;slot.valid=true;return true;
 }
 bool snapshot(uint16_t id,IGTKCMAC128 &key,uint64_t &epoch) const {
  if(id<4 || id>5 || !slots[id-4].valid)return false;
  key=slots[id-4].key;epoch=slots[id-4].epoch;return true;
 }
 // Commit a verified packet only if its snapshot still belongs to this key.
 bool commitIPN(uint16_t id,uint64_t epoch,uint64_t ipn){
  if(id<4 || id>5 || !slots[id-4].valid || ipn>0xffffffffffffull)return false;
  auto &slot=slots[id-4];
  if(slot.epoch!=epoch || ipn<=slot.key.ipn)return false;
  slot.key.ipn=ipn;return true;
 }
};
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

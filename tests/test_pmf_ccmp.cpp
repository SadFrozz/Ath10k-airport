#include <cassert>
#include <cstring>
#include <array>
#include <vector>
#include <initializer_list>
#include "../src/shared/Ath10kPMFCCMP.hpp"
#include "../src/shared/Ath10kSHA256.hpp"
#include "common_crypto_personal.hpp"
#include "pmf_ccmp_vectors.inc"
using C=AthSecurity::PMFCCMP128<PersonalTestCrypto>;using Result=AthSecurity::PMFCCMPResult;
using Workspace=AthSecurity::PMFCCMPWorkspace;using Epoch=AthSecurity::PMFPairwiseEpoch;
struct FailedEncrypt : PersonalTestCrypto {
 static inline unsigned calls=0,failAt=0;
 static bool encrypt(const uint8_t *k,const uint8_t *d,uint8_t *o){++calls;if(calls==failAt){memset(o,0x77,16);return false;}return PersonalTestCrypto::encrypt(k,d,o);}
};
static bool zero(const Workspace &w){const auto *p=reinterpret_cast<const uint8_t *>(&w);for(size_t i=0;i<sizeof(w);++i)if(p[i])return false;return true;}
static void unchanged(const Result &out,const Result &saved){assert(out.bytes==saved.bytes && out.pn==saved.pn && !memcmp(out.frame,saved.frame,512));}
struct Vector {const uint8_t *wire,*plain,*decrypted;size_t wireBytes,plainBytes;uint64_t pn;};
#define VECTOR(name) Vector{name##_wire,name##_plain,name##_decrypted,sizeof(name##_wire),sizeof(name##_plain),name##_pn}
static const Vector vectors[]={VECTOR(c_query),VECTOR(c_deauth),VECTOR(c_disassoc),VECTOR(c_body15),VECTOR(c_body16),VECTOR(c_body17),VECTOR(c_body472),VECTOR(c_vendor)};
static void known(){
 Workspace w;Result out;
 for(const auto &v:vectors){
  assert(C::receive(v.wire,v.wireBytes,c_key,c_sta,c_ap,v.pn-1,C::RXLayout::Ciphertext,out,w));
  assert(out.bytes==v.plainBytes && out.pn==v.pn && !memcmp(out.frame,v.plain,v.plainBytes) && zero(w));
  assert(C::receive(v.decrypted,v.wireBytes,c_key,c_sta,c_ap,0,C::RXLayout::PlaintextWithEncryptedTag,out,w));
  assert(out.bytes==v.plainBytes && out.pn==v.pn && !memcmp(out.frame,v.plain,v.plainBytes) && zero(w));
  Result saved=out;
  assert(!C::receive(v.wire,v.wireBytes,c_key,c_sta,c_ap,v.pn,C::RXLayout::Ciphertext,out,w));unchanged(out,saved);assert(zero(w));
  assert(!C::receive(v.decrypted,v.wireBytes,c_key,c_sta,c_ap,0,C::RXLayout::Ciphertext,out,w));unchanged(out,saved);
  assert(!C::receive(v.wire,v.wireBytes,c_key,c_sta,c_ap,0,C::RXLayout::PlaintextWithEncryptedTag,out,w));unchanged(out,saved);
 }
 assert(C::protect(c_tx_plain,sizeof(c_tx_plain),c_key,c_sta,c_ap,c_tx_pn,out,w));
 assert(out.bytes==sizeof(c_tx_wire) && !memcmp(out.frame,c_tx_wire,out.bytes) && out.pn==c_tx_pn && zero(w));
 // Admission is direction-specific, not just an AES round trip to the same code.
 assert(!C::receive(c_tx_wire,sizeof(c_tx_wire),c_key,c_sta,c_ap,0,C::RXLayout::Ciphertext,out,w));
 assert(!C::protect(c_query_plain,sizeof(c_query_plain),c_key,c_sta,c_ap,c_query_pn,out,w));
}
static void authenticatedLayouts(){
 Workspace w;Result out;
 for(const auto &v:vectors)for(bool plaintext:{false,true}){
  auto selected=C::RXLayout::Authenticated;const auto data=plaintext?v.decrypted:v.wire;
  assert(C::receiveAuthenticated(data,v.wireBytes,c_key,c_sta,c_ap,0,selected,out,w));
  assert(selected==(plaintext?C::RXLayout::PlaintextWithEncryptedTag:C::RXLayout::Ciphertext));
  assert(out.bytes==v.plainBytes && out.pn==v.pn && !memcmp(out.frame,v.plain,v.plainBytes) && zero(w));
  auto saved=out;selected=C::RXLayout::Authenticated;
  assert(!C::receiveAuthenticated(data,v.wireBytes,c_key,c_sta,c_ap,v.pn,selected,out,w));
  unchanged(out,saved);assert(selected==C::RXLayout::Authenticated && zero(w));
  std::vector<uint8_t> bad(data,data+v.wireBytes);bad.back()^=1;
  assert(!C::receiveAuthenticated(bad.data(),bad.size(),c_key,c_sta,c_ap,0,selected,out,w));unchanged(out,saved);
  // Missing CCMP tag is never accepted as a firmware-decrypted shortcut.
  assert(!C::receiveAuthenticated(data,v.wireBytes-8,c_key,c_sta,c_ap,0,selected,out,w));unchanged(out,saved);
 }
 using F=AthSecurity::PMFCCMP128<FailedEncrypt>;
 for(bool plaintext:{false,true}){
  const auto &v=vectors[6];const auto data=plaintext?v.decrypted:v.wire;
  auto selected=C::RXLayout::Authenticated;FailedEncrypt::calls=FailedEncrypt::failAt=0;
  assert(F::receiveAuthenticated(data,v.wireBytes,c_key,c_sta,c_ap,0,selected,out,w));
  const auto calls=FailedEncrypt::calls;const auto saved=out;
  for(unsigned fail=1;fail<=calls;++fail){
   FailedEncrypt::calls=0;FailedEncrypt::failAt=fail;selected=C::RXLayout::Authenticated;
   assert(!F::receiveAuthenticated(data,v.wireBytes,c_key,c_sta,c_ap,0,selected,out,w));
   unchanged(out,saved);assert(selected==C::RXLayout::Authenticated && zero(w));
  }
 }
 FailedEncrypt::calls=FailedEncrypt::failAt=0;
}
static void corruption(){
 Workspace w;Result out;out.bytes=77;out.pn=88;memset(out.frame,0xa5,512);const Result saved=out;
 for(size_t i=0;i<sizeof(c_query_wire);++i){
  // Duration and sequence number are intentionally absent from authenticated AAD.
  if(i==2 || i==3 || i==22 || i==23)continue;
  std::array<uint8_t,sizeof(c_query_wire)> bad{};memcpy(bad.data(),c_query_wire,bad.size());bad[i]^=1;
  assert(!C::receive(bad.data(),bad.size(),c_key,c_sta,c_ap,0,C::RXLayout::Ciphertext,out,w));unchanged(out,saved);assert(zero(w));
 }
 for(uint8_t bit:{uint8_t(8),uint8_t(16),uint8_t(32)}){
  auto f=std::vector<uint8_t>(c_query_wire,c_query_wire+sizeof(c_query_wire));f[1]^=bit;f[2]^=0xff;f[22]=0xf0;f[23]=0xff;
  assert(C::receive(f.data(),f.size(),c_key,c_sta,c_ap,0,C::RXLayout::Ciphertext,out,w));
 }
 // Fragment number is authenticated but this profile does not reassemble it.
 auto f=std::vector<uint8_t>(c_query_wire,c_query_wire+sizeof(c_query_wire));f[22]|=1;
 assert(!C::receive(f.data(),f.size(),c_key,c_sta,c_ap,0,C::RXLayout::Ciphertext,out,w));
 for(uint8_t flags:{uint8_t(0),uint8_t(0x21),uint8_t(0x60),uint8_t(0xa0),uint8_t(0xe0)}){
  f.assign(c_query_wire,c_query_wire+sizeof(c_query_wire));f[27]=flags;
  assert(!C::receive(f.data(),f.size(),c_key,c_sta,c_ap,0,C::RXLayout::Ciphertext,out,w));
 }
 assert(!C::receive(c_public_wire,sizeof(c_public_wire),c_key,c_sta,c_ap,0,C::RXLayout::Ciphertext,out,w));
 uint8_t wrong[16];memcpy(wrong,c_key,16);wrong[15]^=1;
 assert(!C::receive(c_query_wire,sizeof(c_query_wire),wrong,c_sta,c_ap,0,C::RXLayout::Ciphertext,out,w));
}
static void bounds(){
 Workspace w;Result out;out.bytes=77;out.pn=88;memset(out.frame,0xa5,512);const Result saved=out;
 std::array<uint8_t,513> frame{};memcpy(frame.data(),c_query_wire,sizeof(c_query_wire));
 for(size_t n=0;n<42;++n){assert(!C::receive(frame.data(),n,c_key,c_sta,c_ap,0,C::RXLayout::Ciphertext,out,w));unchanged(out,saved);}
 assert(!C::receive(frame.data(),513,c_key,c_sta,c_ap,0,C::RXLayout::Ciphertext,out,w));unchanged(out,saved);
 assert(!C::receive(nullptr,44,c_key,c_sta,c_ap,0,C::RXLayout::Ciphertext,out,w));
 assert(!C::receive(c_query_wire,44,nullptr,c_sta,c_ap,0,C::RXLayout::Ciphertext,out,w));
 assert(!C::receive(c_query_wire,44,c_key,nullptr,c_ap,0,C::RXLayout::Ciphertext,out,w));
 assert(!C::receive(c_query_wire,44,c_key,c_sta,nullptr,0,C::RXLayout::Ciphertext,out,w));
 assert(!C::receive(c_query_wire,44,c_key,c_sta,c_ap,C::MaxPN+1,C::RXLayout::Ciphertext,out,w));
 assert(!C::receive(c_query_wire,44,c_key,c_sta,c_ap,0,static_cast<C::RXLayout>(9),out,w));
 for(uint64_t pn:{uint64_t(0),C::MaxPN+1}){assert(!C::protect(c_tx_plain,sizeof(c_tx_plain),c_key,c_sta,c_ap,pn,out,w));unchanged(out,saved);}
 assert(!C::protect(frame.data(),497,c_key,c_sta,c_ap,1,out,w));unchanged(out,saved);
 assert(!C::receive(out.frame,44,c_key,c_sta,c_ap,0,C::RXLayout::Ciphertext,out,w));unchanged(out,saved);
 assert(!C::receive(w.candidate,44,c_key,c_sta,c_ap,0,C::RXLayout::Ciphertext,out,w));unchanged(out,saved);
}
static void failures(){
 using F=AthSecurity::PMFCCMP128<FailedEncrypt>;
 for(bool protect:{false,true}){
  Workspace w;Result out;FailedEncrypt::calls=0;FailedEncrypt::failAt=0;
  if(protect)assert(F::protect(c_tx_plain,sizeof(c_tx_plain),c_key,c_sta,c_ap,c_tx_pn,out,w));
  else assert(F::receive(c_query_wire,sizeof(c_query_wire),c_key,c_sta,c_ap,0,F::RXLayout::Ciphertext,out,w));
  const unsigned count=FailedEncrypt::calls;assert(count>4);
  out.bytes=77;out.pn=88;memset(out.frame,0xa5,512);const Result saved=out;
  for(unsigned i=1;i<=count;++i){FailedEncrypt::calls=0;FailedEncrypt::failAt=i;
   if(protect)assert(!F::protect(c_tx_plain,sizeof(c_tx_plain),c_key,c_sta,c_ap,c_tx_pn,out,w));
   else assert(!F::receive(c_query_wire,sizeof(c_query_wire),c_key,c_sta,c_ap,0,F::RXLayout::Ciphertext,out,w));
   unchanged(out,saved);assert(zero(w));
  }
 }
}
static void epochsAndQuery(){
 Epoch owner;Epoch::Snapshot old,now;AthSecurity::PMFVerifiedRX stamp{};
 assert(!owner.snapshot(old));assert(owner.activate(c_key,c_sta,c_ap,9) && owner.snapshot(old));
 AthSecurity::SAQueryExchange q;assert(q.bind(c_sta,c_ap,9,old.epoch,0) && q.start(0));
 const uint8_t id[]={0x12,0x34};AthSecurity::SAQueryExchange::TX tx;assert(q.reserve(id,0,tx) && q.submitted(tx,true,0));
 Workspace w;Result out;assert(C::receive(c_query_wire,sizeof(c_query_wire),old.key,old.local,old.ap,old.rxPN,C::RXLayout::Ciphertext,out,w));
 assert(owner.commit(old,out.pn,stamp));assert(q.response(out.frame,out.bytes,stamp,1));
 assert(!owner.commit(old,out.pn,stamp));assert(owner.activate(c_key,c_sta,c_ap,9) && owner.snapshot(now));
 assert(now.epoch==old.epoch && now.rxPN==out.pn); // Same-key redelivery cannot reset replay.
 assert(!owner.activate(c_key,c_sta,c_ap,10));
 // Verification may complete after key rotation; only current epoch commits.
 uint8_t replacement[16];memcpy(replacement,c_key,16);replacement[0]^=1;
 assert(owner.activate(replacement,c_sta,c_ap,9) && owner.snapshot(now));assert(now.epoch>old.epoch && now.rxPN==0);
 stamp={77,88,false,false};assert(!owner.commit(old,out.pn+1,stamp) && stamp.connection==77 && !stamp.integrity);
 assert(owner.commit(now,2,stamp) && !owner.commit(now,1,stamp));
 const uint64_t epoch=now.epoch;owner.clear();assert(!owner.commit(now,3,stamp));
 assert(owner.activate(replacement,c_sta,c_ap,10) && owner.snapshot(now) && now.epoch>epoch);
 assert(!owner.commit(old,4,stamp));assert(!owner.commit(now,0,stamp));assert(!owner.commit(now,C::MaxPN+1,stamp));
 assert(!owner.activate(nullptr,c_sta,c_ap,10));assert(!owner.activate(replacement,c_sta,c_ap,0));
 assert(!owner.activate(replacement,c_sta,c_sta,10));
}
static void groupFrames(){
 AthSecurity::IGTKCMAC128 key{};key.keyID=4;memcpy(key.key,c_key,16);uint64_t accepted=0;
 struct BIP {const uint8_t *wire;size_t wireBytes;uint64_t pn;};
#define GROUP_GOOD(name) BIP{name##_wire,sizeof(name##_wire),name##_pn}
 for(const auto &v:{GROUP_GOOD(c_group_action),GROUP_GOOD(c_group_disassoc),GROUP_GOOD(c_group_max)}){
  assert(AthSecurity::verifyBIPManagement<PersonalTestCrypto>(v.wire,v.wireBytes,c_ap,key,6,accepted) && accepted==v.pn);
  assert(!AthSecurity::verifyBIPManagement<PersonalTestCrypto>(v.wire,v.wireBytes,c_ap,key,v.pn,accepted));
 }
 assert(!AthSecurity::verifyBIPDisconnect<PersonalTestCrypto>(c_group_action_wire,sizeof(c_group_action_wire),c_ap,key,6,accepted));
 struct Packet {const uint8_t *p;size_t n;};
#define GROUP_BAD(name) Packet{name##_wire,sizeof(name##_wire)}
 for(auto p:{GROUP_BAD(c_group_zero),GROUP_BAD(c_group_protected),GROUP_BAD(c_group_nonrobust_4),GROUP_BAD(c_group_nonrobust_7),
   GROUP_BAD(c_group_nonrobust_11),GROUP_BAD(c_group_nonrobust_15),GROUP_BAD(c_group_nonrobust_20),GROUP_BAD(c_group_nonrobust_21),
   GROUP_BAD(c_group_nonrobust_22),GROUP_BAD(c_group_nonrobust_127)}){
  accepted=123;assert(!AthSecurity::verifyBIPManagement<PersonalTestCrypto>(p.p,p.n,c_ap,key,0,accepted) && accepted==123);
 }
 for(size_t i=0;i<sizeof(c_group_action_wire);++i){
  if(i==2 || i==3 || i==22 || i==23)continue;
  auto bad=std::vector<uint8_t>(c_group_action_wire,c_group_action_wire+sizeof(c_group_action_wire));bad[i]^=1;
  accepted=123;assert(!AthSecurity::verifyBIPManagement<PersonalTestCrypto>(bad.data(),bad.size(),c_ap,key,0,accepted) && accepted==123);
 }
}
static void txPacketNumbers(){
 uint64_t pn=123;assert(AthSecurity::nextCCMPPacketNumber(C::MaxPN-1,pn) && pn==C::MaxPN);
 assert(!AthSecurity::nextCCMPPacketNumber(C::MaxPN,pn) && pn==C::MaxPN);
 assert(!AthSecurity::nextCCMPPacketNumber(~uint64_t(0),pn));
 Epoch owner;Epoch::Snapshot lease,old;pn=123;assert(!owner.reserveTX(lease,pn) && pn==123);
 assert(owner.activate(c_key,c_sta,c_ap,9));assert(owner.reserveTX(lease,pn) && pn==1);old=lease;
 assert(owner.reserveTX(lease,pn) && pn==2 && owner.current(old));
 assert(owner.activate(c_key,c_sta,c_ap,9));assert(owner.reserveTX(lease,pn) && pn==3);
 uint8_t replacement[16];memcpy(replacement,c_key,16);replacement[0]^=1;
 assert(owner.activate(replacement,c_sta,c_ap,9) && !owner.current(old));
 assert(owner.reserveTX(lease,pn) && pn==1);owner.clear();assert(!owner.current(lease) && !owner.reserveTX(lease,pn));
}
int main(){known();authenticatedLayouts();corruption();bounds();failures();epochsAndQuery();groupFrames();txPacketNumbers();}

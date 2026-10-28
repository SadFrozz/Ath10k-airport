#include <cassert>
#include <cstring>
#include <initializer_list>
#include "../src/shared/Ath10kSupplicant.hpp"
#include "common_crypto_personal.hpp"
#include "sae_eapol_vectors.inc"
#include "rsnxe_eapol_vectors.inc"
using S=AthSecurity::Supplicant<PersonalTestCrypto,true,true>;
struct FailedEncrypt : PersonalTestCrypto {
 static inline unsigned calls=0,failAt=0;
 static bool encrypt(const uint8_t *k,const uint8_t *d,uint8_t *o){if(++calls==failAt){memset(o,0x77,16);return false;}return PersonalTestCrypto::encrypt(k,d,o);}
};
template<class T> static void begin(T &s){assert(s.begin(w_pmk,w_snonce,w_sta,w_ap,w_rsn,sizeof(w_rsn),8,w_pmkid,16));}
static void connected(S &s){begin(s);assert(s.receive(w_m1,sizeof(w_m1))==S::Reply);assert(s.receive(w_m3,sizeof(w_m3))==S::Keys);}
static void rotated(S &s){connected(s);assert(s.receive(w_mgmt_only,sizeof(w_mgmt_only))==S::ManagementKeys);assert(s.receive(w_group_both,sizeof(w_group_both))==S::GroupKeys);assert(s.receive(w_group_gtk_only,sizeof(w_group_gtk_only))==S::GroupKeys);}
int main(){
 { S bound;begin(bound);uint8_t snapshot[3];memcpy(snapshot,x_rsnxe,3);
   assert(bound.bindRSNXE(snapshot,3,true));snapshot[2]=0;
   uint8_t own[3]{};size_t bytes=99;assert(bound.copyAssociationRSNXE(own,sizeof(own),bytes) && bytes==3 && !memcmp(own,x_rsnxe,3));
   assert(!bound.bindRSNXE(x_rsnxe,3,true));
   assert(bound.receive(w_m1,sizeof(w_m1))==S::Reply && bound.outputLength==160 && !memcmp(bound.output,x_m2,sizeof(x_m2)));
   for(auto key:bound.keys)assert(!key);assert(!bound.keyChanges);
   assert(!bound.bindRSNXE(nullptr,0,false));
   assert(bound.receive(x_m3,sizeof(x_m3))==S::Keys && bound.keyChanges==7);
   assert(bound.receive(x_retry_m3,sizeof(x_retry_m3))==S::Reply);
   assert(bound.receive(w_rekey1,sizeof(w_rekey1))==S::Reply && !memcmp(bound.output,x_rekey2,sizeof(x_rekey2)));
   assert(bound.receive(x_rekey3,sizeof(x_rekey3))==S::PairKeys);
 }
 for(unsigned kind=0;kind<3;++kind){S bad;begin(bad);assert(bad.bindRSNXE(x_rsnxe,3,true));assert(bad.receive(w_m1,sizeof(w_m1))==S::Reply);
   const auto packet=kind==0?w_m3:(kind==1?x_changed_m3:x_duplicate_m3);
   const auto bytes=kind==0?sizeof(w_m3):(kind==1?sizeof(x_changed_m3):sizeof(x_duplicate_m3));
   assert(bad.receive(packet,bytes)==S::Fatal && !bad.keyChanges && !bad.managementKey.keyID);
 }
 for(bool changed : {false,true}){S bound;begin(bound);assert(bound.bindRSNXE(x_rsnxe,3,true));assert(bound.receive(w_m1,sizeof(w_m1))==S::Reply);
   assert(bound.receive(x_m3,sizeof(x_m3))==S::Keys);
   assert(bound.receive(changed?x_changed_group:x_group,changed?sizeof(x_changed_group):sizeof(x_group))==(changed?S::Fatal:S::GroupKeys));
 }
 {S bad;begin(bad);assert(!bad.bindRSNXE(nullptr,0,true));uint8_t wrong[]={244,1,0};assert(!bad.bindRSNXE(wrong,3,true));
   wrong[2]=0x21;assert(!bad.bindRSNXE(wrong,3,false));assert(bad.bindRSNXE(nullptr,0,false));
   uint8_t out[3]={1,2,3};size_t bytes=99;assert(bad.copyAssociationRSNXE(out,3,bytes) && !bytes && out[0]==1);
   assert(bad.receive(w_m1,sizeof(w_m1))==S::Reply && bad.outputLength==sizeof(w_m2));
   assert(bad.receive(x_m3,sizeof(x_m3))==S::Fatal); // Unexpected authenticated AP extension.
 }

 AthSecurity::Supplicant<PersonalTestCrypto,true> disabled;
 assert(!disabled.begin(w_pmk,w_snonce,w_sta,w_ap,w_rsn,sizeof(w_rsn),8));
 S s;begin(s);
 assert(s.receive(nullptr,113)==S::Ignore);
 { S optional;assert(optional.begin(w_pmk,w_snonce,w_sta,w_ap,w_rsn,sizeof(w_rsn),8));
   assert(optional.receive(w_m1,sizeof(w_m1))==S::Reply && optional.outputLength==sizeof(w_m2_withoutid));
   assert(!memcmp(optional.output,w_m2_withoutid,sizeof(w_m2_withoutid)));
 }
 for(auto profile:{0,1}){
   S varied;const auto *rsn=profile?w_transition_rsn:w_default_management_rsn;
   const size_t n=profile?sizeof(w_transition_rsn):sizeof(w_default_management_rsn);
   const auto *m3=profile?w_transition_m3:w_default_management_m3;
   const size_t m3Bytes=profile?sizeof(w_transition_m3):sizeof(w_default_management_m3);
   assert(varied.begin(w_pmk,w_snonce,w_sta,w_ap,rsn,n,8,w_pmkid,16));
   assert(varied.receive(w_m1,sizeof(w_m1))==S::Reply && !memcmp(varied.output,w_m2,sizeof(w_m2)));
   assert(varied.receive(m3,m3Bytes)==S::Keys && varied.keyChanges==7);
 }
 assert(!s.keyChanges);
 for(uint8_t version:{uint8_t(2),uint8_t(3)}){uint8_t f[sizeof(w_m1)];memcpy(f,w_m1,sizeof(f));f[20]|=version;assert(s.receive(f,sizeof(f))==S::Ignore);}
 assert(s.receive(w_m1,sizeof(w_m1))==S::Reply);
 assert(s.outputLength==sizeof(w_m2) && !memcmp(s.output,w_m2,sizeof(w_m2)));
 assert(s.receive(w_m3,sizeof(w_m3))==S::Keys);
 assert(s.keyChanges==(S::PTKChanged|S::GTKChanged|S::IGTKChanged));
 assert(!memcmp(s.keys,w_ptk+32,16) && !memcmp(s.keys+16,w_gtk,16));
 assert(s.managementKey.keyID==4 && s.managementKey.ipn==1 && !memcmp(s.managementKey.key,w_igtk,16));
 assert(s.outputLength==sizeof(w_m4) && !memcmp(s.output,w_m4,sizeof(w_m4)));
 const auto firstManagement=s.managementKey;uint8_t oldKeys[56];memcpy(oldKeys,s.keys,56);
 assert(s.receive(w_m3,sizeof(w_m3))==S::Reply && !memcmp(s.keys,oldKeys,56));
 assert(s.receive(w_m3_retry,sizeof(w_m3_retry))==S::Reply);
 assert(s.outputLength==sizeof(w_m4_retry) && !memcmp(s.output,w_m4_retry,sizeof(w_m4_retry)));
 assert(!memcmp(&s.managementKey,&firstManagement,sizeof(firstManagement)));
 assert(s.receive(w_mgmt_only,sizeof(w_mgmt_only))==S::ManagementKeys && s.keyChanges==S::IGTKChanged);
 assert(!memcmp(s.keys,oldKeys,56));assert(s.managementKey.keyID==5 && !memcmp(s.managementKey.key,w_next_igtk,16));
 assert(s.outputLength==sizeof(w_mgmt_ack) && !memcmp(s.output,w_mgmt_ack,sizeof(w_mgmt_ack)));
 assert(s.receive(w_mgmt_only,sizeof(w_mgmt_only))==S::Reply);
 assert(s.receive(w_group_both,sizeof(w_group_both))==S::GroupKeys && s.keyChanges==(S::GTKChanged|S::IGTKChanged));
 assert(!memcmp(s.keys+16,w_next_gtk,16) && s.managementKey.keyID==4 && s.managementKey.ipn==2);
 assert(!memcmp(s.managementKey.key,w_third_igtk,16));
 assert(s.outputLength==sizeof(w_group_ack) && !memcmp(s.output,w_group_ack,sizeof(w_group_ack)));
 const auto installed=s.managementKey;
 assert(s.receive(w_group_same,sizeof(w_group_same))==S::Reply); // Same key/lower IPN never requests reinstall.
 assert(!memcmp(&s.managementKey,&installed,sizeof(installed)));
 assert(s.receive(w_group_gtk_only,sizeof(w_group_gtk_only))==S::GroupKeys && s.keyChanges==S::GTKChanged);
 assert(!memcmp(s.keys+16,w_third_gtk,16) && !memcmp(&s.managementKey,&installed,sizeof(installed)));
 assert(s.receive(w_rekey1,sizeof(w_rekey1))==S::Reply && s.pairwisePending());
 assert(s.outputLength==sizeof(w_rekey2) && !memcmp(s.output,w_rekey2,sizeof(w_rekey2)));
 assert(s.receive(w_rekey3,sizeof(w_rekey3))==S::PairKeys && s.keyChanges==S::PTKChanged);
 assert(!memcmp(s.keys,w_next_ptk+32,16) && !memcmp(s.keys+16,w_third_gtk,16));
 assert(!memcmp(&s.managementKey,&installed,sizeof(installed)));
 assert(s.outputLength==sizeof(w_rekey4) && !memcmp(s.output,w_rekey4,sizeof(w_rekey4)));
 assert(s.receive(w_rekey3,sizeof(w_rekey3))==S::Reply);
 { S same;rotated(same);assert(same.receive(w_rekey1,sizeof(w_rekey1))==S::Reply);
   assert(same.receive(w_rekey3_withkeys,sizeof(w_rekey3_withkeys))==S::PairKeys && same.keyChanges==S::PTKChanged);
 }
 { S moved;rotated(moved);const auto previous=moved.managementKey;
   assert(moved.receive(w_group_moved_igtk,sizeof(w_group_moved_igtk))==S::Fatal);
   assert(!memcmp(&moved.managementKey,&previous,sizeof(previous)));
 }
 struct Packet {const uint8_t *p;size_t n;};
 for(auto packet:{Packet{w_missing_igtk,sizeof(w_missing_igtk)},Packet{w_duplicate_igtk,sizeof(w_duplicate_igtk)},
     Packet{w_bad_igtk_id,sizeof(w_bad_igtk_id)},Packet{w_bad_padding,sizeof(w_bad_padding)},
     Packet{w_changed_rsn,sizeof(w_changed_rsn)},Packet{w_bad_wrap,sizeof(w_bad_wrap)}}){
   S bad;begin(bad);assert(bad.receive(w_m1,sizeof(w_m1))==S::Reply);memset(bad.keys,0xa5,56);
   assert(bad.receive(packet.p,packet.n)==S::Fatal);
   for(auto v:bad.keys)assert(v==0xa5);assert(!bad.keyChanges && !bad.managementKey.keyID);
 }
 { S bad;begin(bad);assert(bad.receive(w_m1,sizeof(w_m1))==S::Reply);
   uint8_t frame[sizeof(w_m3)];memcpy(frame,w_m3,sizeof(frame));frame[14+81]^=1;
   assert(bad.receive(frame,sizeof(frame))==S::Fatal && !bad.keyChanges && !bad.managementKey.keyID);
 }
 { S bad;connected(bad);const auto previous=bad.managementKey;uint8_t before[56];memcpy(before,bad.keys,56);
   uint8_t frame[sizeof(w_mgmt_only)];memcpy(frame,w_mgmt_only,sizeof(frame));frame[14+81]^=1;
   assert(bad.receive(frame,sizeof(frame))==S::Ignore);
   assert(!memcmp(before,bad.keys,56) && !memcmp(&bad.managementKey,&previous,sizeof(previous)));
 }
 { using F=AthSecurity::Supplicant<FailedEncrypt,true,true>;F bad;begin(bad);
   FailedEncrypt::calls=FailedEncrypt::failAt=0;assert(bad.receive(w_m1,sizeof(w_m1))==F::Reply);
   FailedEncrypt::calls=0;FailedEncrypt::failAt=2+(sizeof(w_m3)-14+15)/16;
   memset(bad.keys,0xa5,56);assert(bad.receive(w_m3,sizeof(w_m3))==F::Fatal);
   for(auto v:bad.keys)assert(v==0xa5);assert(!bad.keyChanges && !bad.managementKey.keyID);
   FailedEncrypt::failAt=0;
 }
 uint8_t wrongRSN[sizeof(w_rsn)];
 for(unsigned kind=0;kind<4;++kind){memcpy(wrongRSN,w_rsn,sizeof(w_rsn));
   if(kind==0)wrongRSN[20]=0;if(kind==1)wrongRSN[27]=11;if(kind==2)wrongRSN[19]=6;if(kind==3)wrongRSN[7]=2;
   assert(!s.begin(w_pmk,w_snonce,w_sta,w_ap,wrongRSN,sizeof(wrongRSN),8));
 }
 assert(!s.begin(w_pmk,w_snonce,w_sta,w_ap,w_rsn,sizeof(w_rsn),8,w_pmkid,15));
 uint8_t rsn[48];memset(rsn,0xa5,sizeof(rsn));size_t bytes=999;
 assert(!AthSecurity::buildSAEStationRSN(w_pmkid,16,rsn,43,bytes) && bytes==999);
 for(auto v:rsn)assert(v==0xa5);
 assert(AthSecurity::buildSAEStationRSN(w_pmkid,16,rsn,sizeof(rsn),bytes) && bytes==44 && !memcmp(rsn,w_station_rsn,44));
 assert(AthSecurity::buildSAEStationRSN(nullptr,0,rsn,sizeof(rsn),bytes) && bytes==28 && !memcmp(rsn,w_rsn,28));
}

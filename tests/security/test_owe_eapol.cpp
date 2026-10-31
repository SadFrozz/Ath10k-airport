#include <cassert>
#include <cstring>
#include <vector>
#include "../../src/security/Ath10kSupplicant.hpp"
#include "../support/common_crypto_personal.hpp"
#include "../fixtures/owe_eapol_vectors.inc"
using S=AthSecurity::Supplicant<PersonalTestCrypto,false,false,false,false,false,true>;
template<class T> void begin(T &s){assert(s.begin(w_pmk,w_snonce,w_sta,w_ap,w_rsn,sizeof(w_rsn),18));}
void connected(S &s){begin(s);assert(s.receive(w_m1,sizeof(w_m1))==S::Reply);assert(s.outputLength==sizeof(w_m2) && !memcmp(s.output,w_m2,sizeof(w_m2)));assert(s.receive(w_m3,sizeof(w_m3))==S::Keys);assert(s.outputLength==sizeof(w_m4) && !memcmp(s.output,w_m4,sizeof(w_m4)));assert(s.keyChanges==7);}
int main(){
 {S s;begin(s);assert(s.receive(w_m1,sizeof(w_m1))==S::Reply);
  AthSecurity::TransitionDisableUpdate update{};
  assert(!s.takeTransitionDisable(w_sta,w_ap,update));
  assert(s.receive(w_policy_m3,sizeof(w_policy_m3))==S::Keys);
  assert(s.takeTransitionDisable(w_sta,w_ap,update) && update.length==1);
  assert(update.bitmap[0]==8);
  assert(!s.takeTransitionDisable(w_sta,w_ap,update));
 }
 {S s;begin(s);assert(s.receive(w_m1,sizeof(w_m1))==S::Reply);
  assert(s.receive(w_policy_duplicate,sizeof(w_policy_duplicate))==S::Fatal);
  AthSecurity::TransitionDisableUpdate update{};assert(!s.takeTransitionDisable(w_sta,w_ap,update));
 }

 {AthSecurity::Supplicant<PersonalTestCrypto,true,true,true,true,true> disabled;assert(!disabled.begin(w_pmk,w_snonce,w_sta,w_ap,w_rsn,sizeof(w_rsn),18));}
 {S s;assert(!s.begin(w_pmk,w_snonce,w_sta,w_ap,w_rsn,sizeof(w_rsn),18,w_pmkid,16));}
 {S s;connected(s);assert(!memcmp(s.keys,w_ptk+32,16));assert(s.receive(w_m3,sizeof(w_m3))==S::Reply);assert(s.keyChanges==7);
  assert(s.receive(w_mgmt_only,sizeof(w_mgmt_only))==S::ManagementKeys);assert(s.keyChanges==4);
  assert(s.receive(w_group_both,sizeof(w_group_both))==S::GroupKeys);assert(s.keyChanges==6);
  assert(s.receive(w_group_same,sizeof(w_group_same))==S::Reply && s.keyChanges==6);
  assert(s.receive(w_group_gtk_only,sizeof(w_group_gtk_only))==S::GroupKeys && s.keyChanges==2);
  assert(s.receive(w_rekey1,sizeof(w_rekey1))==S::Reply);
  assert(s.outputLength==sizeof(w_rekey2) && !memcmp(s.output,w_rekey2,sizeof(w_rekey2)));
  assert(s.receive(w_rekey3,sizeof(w_rekey3))==S::PairKeys && s.keyChanges==1);
  assert(s.outputLength==sizeof(w_rekey4) && !memcmp(s.output,w_rekey4,sizeof(w_rekey4)));
  s.reset();assert(s.receive(w_rekey3,sizeof(w_rekey3))==S::Ignore);
 }
 struct Packet {const uint8_t *p;size_t n;};
 const Packet failures[]={{w_missing_igtk,sizeof(w_missing_igtk)},{w_duplicate_igtk,sizeof(w_duplicate_igtk)},{w_bad_igtk_id,sizeof(w_bad_igtk_id)},{w_bad_padding,sizeof(w_bad_padding)},{w_changed_rsn,sizeof(w_changed_rsn)},{w_bad_wrap,sizeof(w_bad_wrap)}};
 for(const auto &f:failures){S s;begin(s);assert(s.receive(w_m1,sizeof(w_m1))==S::Reply);assert(s.receive(f.p,f.n)==S::Fatal && !s.keyChanges);}
 {S s;begin(s);assert(s.receive(w_m1,sizeof(w_m1))==S::Reply);std::vector<uint8_t> bad(w_m3,w_m3+sizeof(w_m3));bad[95]^=1;assert(s.receive(bad.data(),bad.size())==S::Fatal && !s.keyChanges);}
 {S s;begin(s);std::vector<uint8_t> bad(w_m1,w_m1+sizeof(w_m1));bad[20]|=3;assert(s.receive(bad.data(),bad.size())==S::Ignore);}
}

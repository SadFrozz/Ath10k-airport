#define ATH10K_NATIVE_KEY_STAGE_TEST
#include "test_native_pmf_receive.cpp"
#include "native_rsnxe_query.inc"
#include "sae_eapol_vectors.inc"
#include "sha256_vectors.inc"
#include <array>
static void begin(Ath10kPCIDevice *d,bool h2e){
 auto sec=d->_nativeSecurity;sec->supplicant.reset();
 assert(sec->supplicant.begin(w_pmk,w_snonce,w_sta,w_ap,w_rsn,sizeof(w_rsn),8,w_pmkid,16));
 // The AP advertises extra capabilities that must not leak into the STA IE.
 const uint8_t apRSNXE[]={244,2,0x61,0x80};
 assert(sec->supplicant.bindRSNXE(apRSNXE,sizeof(apRSNXE),h2e));sec->ready=true;
 d->_connection.secure=true;d->_connection.securityAKM=8;
}
int main(){
 std::array<uint8_t,266> storage{};auto output=storage.data()+1;
 // Golden ABI bytes recovered independently from the stock 264-byte wrapper.
 for(bool h2e:{false,true}){
  auto d=create();begin(d,h2e);storage.fill(0xa5);
  assert(d->nativeAssociationRSNXE(output));assert(storage.front()==0xa5 && storage.back()==0xa5);
  assert(output[0]==1 && output[1]==0 && output[2]==0 && output[3]==0);
  assert(output[4]==(h2e?3:0) && output[5]==0);
  if(h2e)assert(output[6]==244 && output[7]==1 && output[8]==0x20);
  for(size_t i=h2e?9:6;i<264;++i)assert(output[i]==0);
  // Exactly the production association/M2 encoder, never the beacon RSNXE.
  uint8_t expected[3]{};size_t n=0;assert(d->_nativeSecurity->supplicant.copyAssociationRSNXE(expected,sizeof(expected),n));
  assert(!memcmp(output+6,expected,n));stop(d);
 }
 for(unsigned barrier=0;barrier<11;++barrier){
  auto d=create();begin(d,true);auto sec=d->_nativeSecurity;auto &s=d->_connection;
  if(barrier==0)d->_nativeStopping=true;
  if(barrier==1)d->blocked=true;
  if(barrier==2)sec->ready=false;
  if(barrier==3)s.cancelRequested=true;
  if(barrier==4)s.disconnect=Ath10k::DisconnectStage::Drain;
  if(barrier==5)s.stage=Ath10k::LinkStage::Disabled;
  if(barrier==6)s.stage=Ath10k::LinkStage::Scan;
  if(barrier==7)s.stage=Ath10k::LinkStage::Failed;
  if(barrier==8)s.secure=false;
  if(barrier==9)sec->supplicant.reset();
  if(barrier==10){sec->supplicant.reset();assert(sec->supplicant.begin(w_pmk,w_snonce,w_sta,w_ap,w_rsn,sizeof(w_rsn),8,w_pmkid,16));}
  storage.fill(0xa5);assert(!d->nativeAssociationRSNXE(output));
  for(auto byte:storage)assert(byte==0xa5);stop(d);
 }
 // Pending association is readable only after binding; no last-AP fallback.
 {auto d=create();begin(d,true);auto &s=d->_connection;s.stage=Ath10k::LinkStage::Assoc;
  assert(!d->nativeAssociationRSNXE(output));d->_nativeJoinPending=true;assert(d->nativeAssociationRSNXE(output));
  assert(!d->nativeAssociationRSNXE(nullptr));d->_nativeSecurity->reset();assert(!d->nativeAssociationRSNXE(output));stop(d);}
 // Existing PSK-SHA256 has no station RSNXE even if the AP advertises H2E.
 {auto d=create();auto sec=d->_nativeSecurity;
  assert(sec->supplicant.begin(s_pmk,s_snonce,s_sta,s_ap,s_rsn,sizeof(s_rsn),6));
  const uint8_t advertised[]={244,1,0x20};assert(sec->supplicant.bindRSNXE(advertised,sizeof(advertised),false));
  sec->ready=true;d->_connection.securityAKM=6;
  assert(d->nativeAssociationRSNXE(output) && output[4]==0 && output[5]==0);
  d->_nativeSecurity=nullptr;storage.fill(0xa5);assert(!d->nativeAssociationRSNXE(output));
  for(auto byte:storage)assert(byte==0xa5);d->_nativeSecurity=sec;stop(d);}
 // Rekey temporarily closes the data port while the association IE stays valid.
 {auto d=create();begin(d,true);d->_connection.portAuthorized=false;d->_connection.rekeyKind=2;
  assert(d->nativeAssociationRSNXE(output));stop(d);}
}

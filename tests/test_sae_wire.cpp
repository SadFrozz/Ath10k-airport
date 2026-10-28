#include <cassert>
#include <cstring>
#include <vector>
#include <array>
#include "../src/shared/Ath10kSAEWire.hpp"
using namespace AthSecurity;
using Message=SAEGroup19AuthMessage;
using Result=SAEWireResult;
static const uint8_t local[6]={2,1,2,3,4,5},ap[6]={2,6,7,8,9,10};
static std::vector<uint8_t> commitFixture(bool h2e){
 // Public structural fixture: alg/transaction/status/group LE, scalar/X/Y BE.
 std::vector<uint8_t> v={3,0,1,0,uint8_t(h2e?126:0),0,19,0};
 for(unsigned i=0;i<96;++i)v.push_back(uint8_t(i));
 return v;
}
static std::vector<uint8_t> fromAP(const std::vector<uint8_t> &body){
 std::vector<uint8_t> v(24);v[0]=0xb0;
 memcpy(v.data()+4,local,6);memcpy(v.data()+10,ap,6);memcpy(v.data()+16,ap,6);
 v.insert(v.end(),body.begin(),body.end());return v;
}
static void unchanged(const Message &a,const Message &b){assert(!memcmp(&a,&b,sizeof(a)));}
int main(){
 Message m{},out{};std::array<uint8_t,1544> encoded{};size_t bytes=987;
 m.kind=SAEAuthKind::Commit;m.h2e=true;
 for(unsigned i=0;i<96;++i)m.commit[i]=uint8_t(i);
 m.identifierPresent=true;m.identifierBytes=3;m.identifier[0]='a';m.identifier[1]=0;m.identifier[2]=255;
 m.rejectedBytes=4;m.rejected[0]=20;m.rejected[2]=21;
 m.tokenBytes=3;m.token[0]=1;m.token[1]=2;m.token[2]=3;
 auto expected=commitFixture(true);expected.insert(expected.end(),{255,4,33,'a',0,255,255,5,92,20,0,21,0,255,4,93,1,2,3});
 encoded.fill(0xa5);assert(encodeSAEGroup19AuthBody(m,encoded.data(),encoded.size(),bytes));
 assert(bytes==expected.size() && !memcmp(encoded.data(),expected.data(),bytes));
 for(size_t i=bytes;i<encoded.size();++i)assert(encoded[i]==0xa5);
 assert(decodeSAEGroup19AuthBody(expected.data(),expected.size(),true,0,out)==Result::Valid);
 assert(out.kind==SAEAuthKind::Commit && out.h2e && out.status==126 && out.group==19);
 assert(!memcmp(out.commit,m.commit,96) && out.identifierPresent && out.identifierBytes==3 && out.identifier[1]==0);
 assert(out.rejectedBytes==4 && !memcmp(out.rejected,m.rejected,4));
 assert(out.tokenBytes==3 && !memcmp(out.token,m.token,3));
 const auto saved=out;
 // Every truncation within required fixed fields and each incomplete IE fails atomically.
 for(size_t n=0;n<104;++n){assert(decodeSAEGroup19AuthBody(expected.data(),n,true,0,out)!=Result::Valid);unchanged(out,saved);}
 for(size_t n:{105u,106u,107u,108u,109u,111u,112u,113u,114u,115u,116u,118u,119u,120u,121u,122u}){
  assert(decodeSAEGroup19AuthBody(expected.data(),n,true,0,out)!=Result::Valid);unchanged(out,saved);
 }
 for(auto tail:std::vector<std::vector<uint8_t>>{{255},{255,0},{255,1},{255,255,33},
       {255,1,114},{255,2,92,20},{255,3,92,19,0},{255,3,92,0,0},{255,1,93},{1,1,0}}){
  auto bad=commitFixture(true);bad.insert(bad.end(),tail.begin(),tail.end());
  assert(decodeSAEGroup19AuthBody(bad.data(),bad.size(),true,0,out)!=Result::Valid);unchanged(out,saved);
 }
 auto duplicate=expected;duplicate.insert(duplicate.end(),{255,4,93,1,2,3});
 assert(decodeSAEGroup19AuthBody(duplicate.data(),duplicate.size(),true,0,out)==Result::Malformed);unchanged(out,saved);
 auto reordered=commitFixture(true);reordered.insert(reordered.end(),{255,2,93,9,255,1,33});
 assert(decodeSAEGroup19AuthBody(reordered.data(),reordered.size(),true,0,out)==Result::Malformed);unchanged(out,saved);
 assert(decodeSAEGroup19AuthBody(expected.data(),expected.size(),false,0,out)==Result::ModeMismatch);unchanged(out,saved);
 auto legacy=commitFixture(false);
 assert(decodeSAEGroup19AuthBody(legacy.data(),legacy.size(),true,0,out)==Result::ModeMismatch);unchanged(out,saved);
 legacy.insert(legacy.begin()+8,{9,8,7});legacy.insert(legacy.end(),{255,2,33,'x'});
 assert(decodeSAEGroup19AuthBody(legacy.data(),legacy.size(),false,3,out)==Result::Valid);
 assert(out.tokenBytes==3 && out.token[0]==9 && !memcmp(out.commit,m.commit,96) && out.identifierBytes==1);
 // No heuristic token-length detection; absent context does not shift the scalar.
 assert(decodeSAEGroup19AuthBody(legacy.data(),legacy.size(),false,0,out)!=Result::Valid);
 Message old=out;
 for(auto challenge:std::vector<std::vector<uint8_t>>{{3,0,1,0,76,0,19,0,255,4,93,1,2,3},
                                                    {3,0,1,0,76,0,19,0,255,2,93,7}}){
  assert(decodeSAEGroup19AuthBody(challenge.data(),challenge.size(),true,0,out)==Result::Valid);
  assert(out.kind==SAEAuthKind::TokenRequest && out.tokenBytes==challenge.size()-11);
  assert(encodeSAEGroup19AuthBody(out,encoded.data(),encoded.size(),bytes));
  assert(bytes==challenge.size() && !memcmp(encoded.data(),challenge.data(),bytes));
 }
 old=out;
 for(auto bad:std::vector<std::vector<uint8_t>>{{3,0,1,0,76,0,19,0},{3,0,1,0,76,0,19,0,255,1,93},
     {3,0,1,0,76,0,19,0,255,2,93},{3,0,1,0,76,0,19,0,255,2,92,7},
     {3,0,1,0,76,0,19,0,255,2,93,7,0}}){
  assert(decodeSAEGroup19AuthBody(bad.data(),bad.size(),true,0,out)!=Result::Valid);unchanged(out,old);
 }
 const uint8_t legacyChallenge[]={3,0,1,0,76,0,19,0,9,8,7};
 assert(decodeSAEGroup19AuthBody(legacyChallenge,sizeof(legacyChallenge),false,0,out)==Result::Valid);
 assert(out.kind==SAEAuthKind::TokenRequest && out.tokenBytes==3 && out.token[0]==9);
 const uint8_t groupReject[]={3,0,1,0,77,0,19,0},unsupportedGroup[]={3,0,1,0,77,0,20,0};
 assert(decodeSAEGroup19AuthBody(groupReject,8,true,0,out)==Result::Valid && out.kind==SAEAuthKind::GroupRejected);
 assert(decodeSAEGroup19AuthBody(unsupportedGroup,8,true,0,out)==Result::Unsupported);
 const uint8_t rejected[]={3,0,1,0,123,0};
 assert(decodeSAEGroup19AuthBody(rejected,6,true,0,out)==Result::Valid && out.kind==SAEAuthKind::Rejected && out.status==123);
 Message confirm{};confirm.kind=SAEAuthKind::Confirm;
 for(unsigned i=0;i<34;++i)confirm.confirm[i]=uint8_t(90+i);
 assert(encodeSAEGroup19AuthBody(confirm,encoded.data(),encoded.size(),bytes) && bytes==40);
 assert(encoded[0]==3 && encoded[2]==2 && encoded[4]==0 && !memcmp(encoded.data()+6,confirm.confirm,34));
 assert(decodeSAEGroup19AuthBody(encoded.data(),bytes,true,0,out)==Result::Valid && out.kind==SAEAuthKind::Confirm);
 old=out;
 for(size_t n=6;n<40;++n){assert(decodeSAEGroup19AuthBody(encoded.data(),n,true,0,out)!=Result::Valid);unchanged(out,old);}
 auto frame=fromAP(expected);
 assert(decodeSAEGroup19FromAP(frame.data(),frame.size(),local,ap,true,out)==Result::Valid);
 old=out;
 for(unsigned offset:{4u,10u,16u}){auto bad=frame;bad[offset]^=2;assert(decodeSAEGroup19FromAP(bad.data(),bad.size(),local,ap,true,out)==Result::WrongPeer);unchanged(out,old);}
 for(unsigned bit:{0u,1u,2u,3u,4u,6u,7u}){auto bad=frame;bad[1]|=uint8_t(1u<<bit);
  const auto result=decodeSAEGroup19FromAP(bad.data(),bad.size(),local,ap,true,out);
  if(bit==3 || bit==4)assert(result==Result::Valid);else assert(result==Result::Malformed);
 }
 frame[1]=0x38;assert(decodeSAEGroup19FromAP(frame.data(),frame.size(),local,ap,true,out)==Result::Valid);
 frame[22]=1;assert(decodeSAEGroup19FromAP(frame.data(),frame.size(),local,ap,true,out)==Result::Malformed);
 encoded.fill(0xa5);bytes=987;
 assert(encodeSAEGroup19ToAP(m,local,ap,4095,encoded.data(),encoded.size(),bytes));
 assert(bytes==24+expected.size() && encoded[0]==0xb0 && encoded[22]==0xf0 && encoded[23]==0xff);
 assert(!memcmp(encoded.data()+4,ap,6) && !memcmp(encoded.data()+10,local,6) && !memcmp(encoded.data()+16,ap,6));
 assert(!memcmp(encoded.data()+24,expected.data(),expected.size()));
 for(unsigned variant=0;variant<7;++variant){auto bad=m;
  if(variant==0)bad.identifierBytes=255;if(variant==1)bad.tokenBytes=255;if(variant==2)bad.rejectedBytes=255;
  if(variant==3)bad.identifierPresent=false;if(variant==4)bad.group=20;if(variant==5)bad.rejected[0]=19;if(variant==6)bad.kind=SAEAuthKind::Empty;
  encoded.fill(0xa5);bytes=987;
  assert(!encodeSAEGroup19ToAP(bad,local,ap,0,encoded.data(),encoded.size(),bytes) && bytes==987);
  for(auto v:encoded)assert(v==0xa5);
 }
 encoded.fill(0xa5);bytes=987;
 assert(!encodeSAEGroup19ToAP(m,local,ap,4096,encoded.data(),encoded.size(),bytes));
 assert(!encodeSAEGroup19ToAP(m,local,local,0,encoded.data(),encoded.size(),bytes));
 assert(!encodeSAEGroup19ToAP(m,local,ap,0,encoded.data(),24+expected.size()-1,bytes));
 assert(bytes==987);for(auto v:encoded)assert(v==0xa5);
 // Boundary lengths: all three H2E extension payloads fit, legacy token has its own bound.
 m.identifierBytes=254;m.rejectedBytes=254;m.tokenBytes=254;
 for(unsigned i=0;i<127;++i){m.rejected[2*i]=20;m.rejected[2*i+1]=0;}
 assert(encodeSAEGroup19AuthBody(m,encoded.data(),encoded.size(),bytes) && bytes==875);
 assert(decodeSAEGroup19AuthBody(encoded.data(),bytes,true,0,out)==Result::Valid);
 m.h2e=false;m.rejectedBytes=0;m.tokenBytes=1024;
 assert(encodeSAEGroup19AuthBody(m,encoded.data(),encoded.size(),bytes) && bytes==1385);
 assert(decodeSAEGroup19AuthBody(encoded.data(),bytes,false,1024,out)==Result::Valid);
 m.tokenBytes=1025;bytes=987;encoded.fill(0xa5);
 assert(!encodeSAEGroup19AuthBody(m,encoded.data(),encoded.size(),bytes) && bytes==987);
 for(auto v:encoded)assert(v==0xa5);
 // An explicitly present empty identifier is distinct from an absent element.
 m.h2e=true;m.tokenBytes=0;m.identifierBytes=0;
 assert(encodeSAEGroup19AuthBody(m,encoded.data(),encoded.size(),bytes) && bytes==107);
 assert(decodeSAEGroup19AuthBody(encoded.data(),bytes,true,0,out)==Result::Valid && out.identifierPresent && !out.identifierBytes);
 old=out;
 assert(decodeSAEGroup19AuthBody(encoded.data(),1513,true,0,out)==Result::Malformed);unchanged(out,old);
 assert(decodeSAEGroup19AuthBody(encoded.data(),bytes,true,1,out)==Result::Malformed);unchanged(out,old);
 assert(decodeSAEGroup19AuthBody(encoded.data(),bytes,false,1025,out)==Result::Malformed);unchanged(out,old);
 // Deterministic malformed-input exercise with guarded publication.
 uint32_t seed=0x53414519;
 for(unsigned i=0;i<3000;++i){auto bad=expected;
  seed=seed*1664525u+1013904223u;const size_t at=seed%bad.size();bad[at]^=uint8_t((seed>>24)|1);
  old=out;const auto result=decodeSAEGroup19AuthBody(bad.data(),bad.size(),true,0,out);
  if(result!=Result::Valid)unchanged(out,old);
 }
 assert(decodeSAEGroup19AuthBody(nullptr,104,true,0,out)==Result::Malformed);
 assert(decodeSAEGroup19FromAP(nullptr,128,local,ap,true,out)==Result::Malformed);
 assert(decodeSAEGroup19FromAP(encoded.data(),1537,local,ap,true,out)==Result::Malformed);
}

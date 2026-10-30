#pragma once
#include "Ath10kNativeSAEJoin.hpp"
// Owner-gated transaction: reserve a fresh connection identity, then create the
// PMF owner and retained password job. No crypto or worker drain happens here.
// Security supplies PMFSessionType plus the actual retained owner fields.
template<class Security> const char *startNativeSAEJoin(Security &sec,
    const AirportWCL::JoinRequest &join,const Ath10k::WMIBSS &ap,
    const AthSecurity::P256CoreCryptoAPI &points,const AthSecurity::P256FieldAPI &field,
    bool (*random)(uint8_t *,size_t),const uint8_t *station,uint64_t now){
    if(nativeJoinAuth(join,true)!=NativeJoinAuth::SAE ||
       nativeSAEPasswordMode(join,ap)==NativeSAEPasswordMode::Unsupported)return "native-sae-password-profile";
    if(!sec.saeWorker || sec.ready || sec.pmfSession || sec.saeSession || sec.saeRadio ||
       sec.saePreparation.active())return "native-sae-owner-not-empty";
    if(sec.nextSAEGeneration==0xffffffffu)return "native-sae-generation-exhausted";
    const uint32_t generation=++sec.nextSAEGeneration; // Never recycled on failure/reset.
    auto pmf=new typename Security::PMFSessionType;
    if(!pmf)return "native-sae-pmf-allocation";
    if(!pmf->initConnection(station,join.bssid,generation)){
        pmf->release();return "native-sae-pmf-initialization";
    }
    if(!sec.saePreparation.begin(sec.saeWorker,join,ap,points,field,random,station,generation,now)){
        pmf->cancel();pmf->release();return "native-sae-preparation-initialization";
    }
    sec.pmfSession=pmf;return nullptr;
}

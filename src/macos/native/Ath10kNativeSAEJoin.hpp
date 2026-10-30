#pragma once
#include "Ath10kNativeWire.hpp"
#include "../../security/Ath10kP256CoreCrypto.hpp"
// Preparation policy only. Native SAE admission is an explicit experimental
// opt-in and still requires kernel providers, PMF readiness and empty owners.
enum class NativeSAEPasswordMode {Unsupported,Legacy,H2E};
inline NativeSAEPasswordMode nativeSAEPasswordMode(const AirportWCL::JoinRequest &join,const Ath10k::WMIBSS &ap){
    if(!nativeSAEPasswordEnvelope(join) || !ap.privacy || !ap.rsnPresent ||
       ap.ssidLength>sizeof(ap.ssid) || (!ap.ssidLength && !ap.hidden) ||
       (ap.ssidLength && (join.ssidLength!=ap.ssidLength || memcmp(join.ssid,ap.ssid,join.ssidLength))) ||
       memcmp(join.bssid,ap.bssid,6) ||
       ap.rsnLength>sizeof(ap.rsn) || !AthSecurity::validSAEPersonalRSN(ap.rsn,ap.rsnLength) ||
       ap.rsnxeLength>sizeof(ap.rsnxe) || (ap.rsnxeLength && !AthSecurity::validRSNXE(ap.rsnxe,ap.rsnxeLength)) ||
       (join.rsnLength && !AthSecurity::validSAEPersonalRSN(join.rsn,join.rsnLength)))return NativeSAEPasswordMode::Unsupported;
    return AthSecurity::rsnxeHasH2E(ap.rsnxe,ap.rsnxeLength)?NativeSAEPasswordMode::H2E:NativeSAEPasswordMode::Legacy;
}
// Caller freezes the selected BSS/security snapshot in the same connection
// generation and has already checked channel/regulatory/backend/PMF readiness.
// The supplied retained job copies password/SSID/identities without running
// crypto here. Selection is explicit; derivation failure never changes mode.
// Native password flags/identifier transport are not validated by this helper.
template<class Job> inline NativeSAEPasswordMode initNativeSAEPasswordCandidate(Job &job,
    const AirportWCL::JoinRequest &join,const Ath10k::WMIBSS &ap,
    const AthSecurity::P256CoreCryptoAPI &points,const AthSecurity::P256FieldAPI &field,
    bool (*random)(uint8_t *,size_t),const uint8_t *station,uint32_t generation,uint64_t now){
    const auto mode=nativeSAEPasswordMode(join,ap);bool initialized=false;
    if(mode==NativeSAEPasswordMode::H2E)
        initialized=job.initH2E(points,field,random,join.ssid,join.ssidLength,join.key,join.keyLength,nullptr,0,station,join.bssid,generation,now);
    else if(mode==NativeSAEPasswordMode::Legacy)
        initialized=job.initLegacyPassword(points,field,random,join.ssid,join.ssidLength,join.key,join.keyLength,station,join.bssid,generation,now);
    return initialized?mode:NativeSAEPasswordMode::Unsupported;
}

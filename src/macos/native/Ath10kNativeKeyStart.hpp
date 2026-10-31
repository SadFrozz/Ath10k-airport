#pragma once
#include "../../security/Ath10kSecurity.hpp"

namespace AthNative {
// Initial Personal/Enterprise master-key handoff only. SAE has its own owner.
// Caller owns nonce generation, association admission and reset on failure.
// The supplicant's compile-time gates still decide whether legacy is enabled.
template<class Supplicant,class State>
bool beginMasterKey(Supplicant &supplicant,const State &s,const uint8_t *pmk,const uint8_t *nonce){
    if(s.securityAKM==5){
        if(!pmk || !nonce || !s.secure || !s.pmfRequired || s.wpa1Selected || s.pairCipher!=4 || s.groupCipher!=4 ||
           !AthSecurity::validEAPSHA256RSN(s.ap.rsn,s.ap.rsnLength))return false;
        return supplicant.begin(pmk,nonce,s.local,s.bssid,s.ap.rsn,s.ap.rsnLength,5,nullptr,0,4) &&
            supplicant.bindRSNXE(s.ap.rsnxe,s.ap.rsnxeLength,false);
    }
    if(!pmk || !nonce || !s.secure || s.pmfRequired ||
       (s.securityAKM!=1 && s.securityAKM!=2 && s.securityAKM!=6))return false;
    if(s.wpa1Selected){
        AthSecurity::WPAInfo ap{};
        if(s.securityAKM==6 || !AthSecurity::parseWPA(s.ap.wpa,s.ap.wpaLength,ap) || ap.group!=s.groupCipher)return false;
        return supplicant.beginWPA1(pmk,nonce,s.local,s.bssid,s.ap.wpa,s.ap.wpaLength,s.securityAKM,s.pairCipher);
    }
    AthSecurity::RSNInfo ap{};
    if(!AthSecurity::parseRSN(s.ap.rsn,s.ap.rsnLength,ap) || ap.group!=s.groupCipher)return false;
    return supplicant.begin(pmk,nonce,s.local,s.bssid,s.ap.rsn,s.ap.rsnLength,s.securityAKM,nullptr,0,s.pairCipher) &&
        supplicant.bindRSNXE(s.ap.rsnxe,s.ap.rsnxeLength,false);
}
}

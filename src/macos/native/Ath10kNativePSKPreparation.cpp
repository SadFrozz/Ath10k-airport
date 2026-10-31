#include "Ath10kNativePSKPreparation.hpp"
#include "Ath10kKernelCrypto.hpp"
OSDefineMetaClassAndStructors(Ath10kNativePSKJob,Ath10kSAEWorkItem)
bool Ath10kNativePSKJob::initPassword(const uint8_t *secret,size_t bytes,const uint8_t *name,size_t nameBytes){
 if(initialized || !name || !nameBytes || nameBytes>32 || !AthSecurity::validPSKPassword(secret,bytes) || !OSObject::init())return false;
 AthSecurity::copy(password,secret,bytes);passwordBytes=bytes;AthSecurity::copy(ssid,name,nameBytes);ssidBytes=nameBytes;initialized=true;return true;
}
void Ath10kNativePSKJob::execute(){
 if(!initialized || executed || consumed)return;
 valid=AthSecurity::pskFromPassword<Ath10kKernelCrypto>(password,passwordBytes,ssid,ssidBytes,pmk) && Ath10kKernelCrypto::random(nonce,sizeof(nonce));
 AthSecurity::wipe(password,sizeof(password));passwordBytes=0;AthSecurity::wipe(ssid,sizeof(ssid));ssidBytes=0;
 if(!valid){AthSecurity::wipe(pmk,sizeof(pmk));AthSecurity::wipe(nonce,sizeof(nonce));}executed=true;
}
bool Ath10kNativePSKJob::take(uint8_t *key,uint8_t *snonce){
 if(!key || !snonce || !executed || !valid || consumed)return false;
 AthSecurity::copy(key,pmk,32);AthSecurity::copy(snonce,nonce,32);discard();return true;
}
void Ath10kNativePSKJob::discard(){
 AthSecurity::wipe(password,sizeof(password));AthSecurity::wipe(ssid,sizeof(ssid));AthSecurity::wipe(pmk,sizeof(pmk));AthSecurity::wipe(nonce,sizeof(nonce));passwordBytes=ssidBytes=0;valid=false;consumed=true;
}
void Ath10kNativePSKPreparation::cancel(){
 if(job){if(submitted && worker)worker->cancelFor(job);job->release();job=nullptr;}
 if(worker){worker->release();worker=nullptr;}submitted=false;AthSecurity::wipe(&profile,sizeof(profile));
}
bool Ath10kNativePSKPreparation::begin(Ath10kSAEWorker *queue,const AirportWCL::JoinRequest &join,const Ath10k::WMIBSS &ap,const uint8_t *station,uint32_t generation,uint64_t now,bool allowLegacy){
 if(active() || !queue || !station || !generation || now>~uint64_t(0)-5000 || !nativePSKPasswordEnvelope(join,allowLegacy) ||
    !AthSecurity::saQueryIdentities(station,join.bssid) || memcmp(join.bssid,ap.bssid,6) || !ap.privacy ||
    (ap.ssidLength?(ap.ssidLength!=join.ssidLength || memcmp(ap.ssid,join.ssid,join.ssidLength)):!ap.hidden) ||
    ap.rsnLength>sizeof(profile.rsn) || ap.wpaLength>sizeof(profile.rsn) || ap.rsnxeLength>sizeof(profile.rsnxe))return false;
 const auto auth=nativeJoinAuth(join,false,false,allowLegacy);NativeSelectedRSN selected{};
 if(!nativeSelectedRSN(join,auth,selected,allowLegacy,allowLegacy))return false;
 const uint8_t akm=auth==NativeJoinAuth::PSKSHA256?6:2;
 uint8_t group=0;
 if(selected.wpa1){AthSecurity::WPAInfo info{};uint8_t ie[24]{};size_t n=0;
    if(!ap.wpaPresent || !AthSecurity::parseWPA(ap.wpa,ap.wpaLength,info) ||
       !AthSecurity::buildWPA1StationIE(ap.wpa,ap.wpaLength,selected.pairwise,akm,ie,sizeof(ie),n))return false;
    group=info.group;
 }else {
    if(!ap.rsnPresent || !AthSecurity::supportsSelectedRSN(ap.rsn,ap.rsnLength,akm,selected.pairwise,allowLegacy))return false;
    group=AthSecurity::wpa2GroupCipher(ap.rsn,ap.rsnLength);
 }
 if(selected.specified && selected.group!=group)return false;
 auto candidate=new Ath10kNativePSKJob;if(!candidate)return false;
 if(!candidate->initPassword(join.key,join.keyLength,join.ssid,join.ssidLength)){candidate->release();return false;}
 AthSecurity::copy(profile.ssid,join.ssid,join.ssidLength);profile.ssidBytes=join.ssidLength;
 AthSecurity::copy(profile.station,station,6);AthSecurity::copy(profile.bssid,ap.bssid,6);
 profile.wpa1=selected.wpa1;profile.pairwise=selected.pairwise;profile.group=group;
 profile.rsnBytes=selected.wpa1?ap.wpaLength:ap.rsnLength;
 AthSecurity::copy(profile.rsn,selected.wpa1?ap.wpa:ap.rsn,profile.rsnBytes);
 AthSecurity::copy(profile.rsnxe,ap.rsnxe,ap.rsnxeLength);profile.rsnxeBytes=ap.rsnxeLength;
 profile.akm=akm;profile.generation=generation;profile.lastNow=now;profile.deadline=now+5000;
 worker=queue;worker->retain();job=candidate;submitted=worker->submit(job);return true;
}
Ath10kNativePSKPreparation::Result Ath10kNativePSKPreparation::collect(const Ath10k::ConnectionState &s,uint32_t generation,uint64_t now){
 if(!active())return {State::Idle};State failure=State::Pending;
 if(s.stage!=Ath10k::LinkStage::Auth || s.cancelRequested || s.disconnect!=Ath10k::DisconnectStage::None || !s.ap.privacy || (profile.wpa1?!s.ap.wpaPresent:!s.ap.rsnPresent) ||
    s.ssidLength!=profile.ssidBytes || memcmp(s.ssid,profile.ssid,profile.ssidBytes) ||
    memcmp(s.local,profile.station,6) || memcmp(s.bssid,profile.bssid,6) || memcmp(s.ap.bssid,profile.bssid,6) ||
    s.wpa1Selected!=profile.wpa1 || s.pairCipher!=profile.pairwise || s.groupCipher!=profile.group ||
    s.securityAKM!=profile.akm || !s.secure || s.pmfRequired || generation!=profile.generation ||
    (profile.wpa1?s.ap.wpaLength:s.ap.rsnLength)!=profile.rsnBytes || memcmp(profile.wpa1?s.ap.wpa:s.ap.rsn,profile.rsn,profile.rsnBytes) ||
    s.ap.rsnxeLength!=profile.rsnxeBytes || memcmp(s.ap.rsnxe,profile.rsnxe,profile.rsnxeBytes) ||
    (s.ap.ssidLength?(s.ap.ssidLength!=profile.ssidBytes || memcmp(s.ap.ssid,profile.ssid,profile.ssidBytes)):!s.ap.hidden))failure=State::Changed;
 else if(now<profile.lastNow)failure=State::ClockError;
 else if(now>=profile.deadline)failure=State::Expired;
 if(failure!=State::Pending){cancel();return {failure};}profile.lastNow=now;
 if(!submitted){submitted=worker->submit(job);return {State::Pending};}
 auto completed=worker->takeCompletedFor(job);
 if(!completed){if(worker->available()){cancel();return {State::Failed};}return {State::Pending};}
 Result result{State::Failed};if(completed==job && job->take(result.pmk,result.nonce))result.state=State::Ready;
 completed->release();submitted=false;cancel();return result;
}

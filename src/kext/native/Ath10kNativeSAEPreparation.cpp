#include "Ath10kNativeSAEPreparation.hpp"

void Ath10kNativeSAEPreparation::cancel(){
    if(job){
        if(submitted && worker)worker->cancelFor(job);
        // A running callback owns its own reference. Never discard its buffers
        // here; final release will wipe them after execution has returned.
        job->release();job=nullptr;
    }
    if(worker){worker->release();worker=nullptr;}
    submitted=false;AthSecurity::wipe(&profile,sizeof(profile));
}
bool Ath10kNativeSAEPreparation::begin(Ath10kSAEWorker *queue,const AirportWCL::JoinRequest &join,
    const Ath10k::WMIBSS &ap,const AthSecurity::P256CoreCryptoAPI &points,
    const AthSecurity::P256FieldAPI &field,bool (*random)(uint8_t *,size_t),
    const uint8_t *station,uint32_t generation,uint64_t now){
    if(active() || !queue || nativeSAEPasswordMode(join,ap)==NativeSAEPasswordMode::Unsupported)return false;
    auto candidate=new Ath10kSAEPrepareJob;if(!candidate)return false;
    const auto mode=initNativeSAEPasswordCandidate(*candidate,join,ap,points,field,random,station,generation,now);
    if(mode==NativeSAEPasswordMode::Unsupported){candidate->release();return false;}
    memcpy(profile.station,station,6);memcpy(profile.bssid,ap.bssid,6);
    memcpy(profile.ssid,join.ssid,join.ssidLength);profile.ssidBytes=join.ssidLength;
    memcpy(profile.rsn,ap.rsn,ap.rsnLength);profile.rsnBytes=ap.rsnLength;
    memcpy(profile.rsnxe,ap.rsnxe,ap.rsnxeLength);profile.rsnxeBytes=ap.rsnxeLength;
    profile.mode=mode;profile.generation=generation;profile.lastNow=now;
    profile.deadline=now+AthSecurity::SAEGroup19ClientExchange::DeadlineMs;
    job=candidate;worker=queue;worker->retain();submitted=worker->submit(job);
    // A retiring/cancelled earlier job may still own the shared queue. Keep our
    // immutable request and original deadline while waiting; never steal it.
    return true;
}
Ath10kNativeSAEPreparation::Result Ath10kNativeSAEPreparation::collect(
    const uint8_t *ssid,size_t bytes,const Ath10k::WMIBSS &ap,const uint8_t *station,
    uint32_t generation,uint64_t now){
    if(!active())return {State::Idle};
    State failure=State::Pending;
    if(!ssid || !station || bytes!=profile.ssidBytes || memcmp(ssid,profile.ssid,bytes) ||
       memcmp(station,profile.station,6) || memcmp(ap.bssid,profile.bssid,6) || generation!=profile.generation ||
       !ap.privacy || !ap.rsnPresent || ap.rsnLength!=profile.rsnBytes || ap.rsnxeLength!=profile.rsnxeBytes ||
       memcmp(ap.rsn,profile.rsn,profile.rsnBytes) || memcmp(ap.rsnxe,profile.rsnxe,profile.rsnxeBytes) ||
       (ap.ssidLength?(ap.ssidLength!=bytes || memcmp(ap.ssid,ssid,bytes)):!ap.hidden))failure=State::Changed;
    else if(now<profile.lastNow)failure=State::ClockError;
    else if(now>=profile.deadline)failure=State::Expired;
    if(failure!=State::Pending){cancel();return {failure};}
    profile.lastNow=now;
    if(!submitted){submitted=worker->submit(job);return {State::Pending};}
    auto completed=worker->takeCompletedFor(job);
    if(!completed){
        if(worker->available()){cancel();return {State::Failed};}
        return {State::Pending};
    }
    auto session=completed==job?job->takePreparedPassword(profile.ssid,profile.ssidBytes,
        profile.station,profile.bssid,profile.generation,now):nullptr;
    if(session && session->usingH2E()!=(profile.mode==NativeSAEPasswordMode::H2E)){
        session->cancel();session->release();session=nullptr;
    }
    completed->release();submitted=false;cancel();
    return {session?State::Ready:State::Failed,session};
}

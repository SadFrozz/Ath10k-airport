#include "Ath10kP256RegistryJob.hpp"
OSDefineMetaClassAndStructors(Ath10kP256RegistryJob,Ath10kSAEWorkItem)
bool Ath10kP256RegistryJob::initReport(const AthSecurity::P256CoreCryptoAPI &points,
    const AthSecurity::P256FieldAPI &field,IOService *entry,uint64_t (*clock)(),uint32_t generation){
    if(check || target || executed || consumed || !publication.pending() || !entry || !clock || !generation || !OSObject::init())return false;
    submitted=clock();auto inner=new Ath10kP256CheckJob;
    if(!inner)return false;
    if(!inner->initCheck(points,field,generation,submitted/1000000u)){inner->release();return false;}
    check=inner;target=entry;target->retain();clockNS=clock;epoch=generation;return true;
}
void Ath10kP256RegistryJob::execute(){
    if(!check || !target || executed || consumed || publication.cancelled())return;executed=true;
    const auto began=clockNS();check->execute();const auto ended=clockNS();
    AthSecurity::P256BackendCheckReport report{};
    const bool collected=check->takeReport(epoch,ended/1000000u,report);
    if(!publication.beginReport())return;
    const bool monotonic=began>=submitted && ended>=began;
    const bool passed=collected && report.complete && monotonic;
    target->setProperty("Ath10kP256CheckPassed",passed);
    target->setProperty("Ath10kP256CheckStep",uint64_t(report.step),32);
    target->setProperty("Ath10kP256CheckMask",uint64_t(report.passed),32);
    target->setProperty("Ath10kP256CheckEpoch",uint64_t(epoch),32);
    target->setProperty("Ath10kP256CheckSubmittedNS",submitted,64);
    target->setProperty("Ath10kP256CheckElapsedNS",ended>=began?ended-began:0,64);
    target->setProperty("Ath10kP256CheckQueueNS",began>=submitted?began-submitted:0,64);
    target->setProperty("Ath10kP256CheckState",!monotonic?"clock-error":(!collected?"expired":(passed?"passed":"failed")));
    publication.finishReport();
}
void Ath10kP256RegistryJob::discard(){
    publication.cancel();
    if(check){check->release();check=nullptr;}
    if(target){target->release();target=nullptr;}
    clockNS=nullptr;epoch=0;submitted=0;consumed=true;
}

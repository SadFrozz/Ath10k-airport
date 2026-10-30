#include "Ath10kP256CheckJob.hpp"
OSDefineMetaClassAndStructors(Ath10kP256CheckJob,Ath10kSAEWorkItem)
bool Ath10kP256CheckJob::initCheck(const AthSecurity::P256CoreCryptoAPI &p,
    const AthSecurity::P256FieldAPI &f,uint32_t generation,uint64_t now){
    if(initialized || consumed || !OSObject::init() || !generation || now>~uint64_t(0)-DeadlineMs ||
       !p.complete() || !f.curve || !f.units || !f.prime || !f.multiply || !f.inverse || !f.add || !f.subtract)return false;
    points=p;field=f;epoch=generation;started=now;deadline=now+DeadlineMs;initialized=true;return true;
}
void Ath10kP256CheckJob::execute(){
    if(!initialized || executed || consumed)return;executed=true;
    AthSecurity::checkP256Backend(points,field,workspace,report);
}
bool Ath10kP256CheckJob::takeReport(uint32_t generation,uint64_t now,AthSecurity::P256BackendCheckReport &out){
    out={};if(!executed || consumed)return false;
    const bool valid=initialized && generation==epoch && now>=started && now<deadline;
    if(valid)out=report;discard();return valid;
}
void Ath10kP256CheckJob::discard(){
    AthSecurity::wipe(&points,sizeof(points));AthSecurity::wipe(&field,sizeof(field));
    workspace.clear();AthSecurity::wipe(&report,sizeof(report));epoch=0;started=deadline=0;
    initialized=executed=false;consumed=true;
}

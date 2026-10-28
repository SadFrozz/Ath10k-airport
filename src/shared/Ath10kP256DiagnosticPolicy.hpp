#pragma once
#include <stdint.h>
#include <string.h>
namespace AthSecurity {
inline bool p256DiagnosticDevice(uint16_t vendor,uint16_t device,uint16_t subvendor,uint16_t subsystem){
 return vendor==0x168c && device==0x42 && subvendor==0x1a3b && subsystem==0x2b51;
}
// Deliberately one known OS build for the first private-ABI diagnostic. This
// is a test admission guard, not proof that CoreCrypto's runtime ABI is valid.
inline bool p256DiagnosticKernel(int major,int minor,int revision,const char *build,const char *kernel){
 if(major!=24 || minor!=6 || revision!=0 || !build || !kernel || strcmp(build,"24G90"))return false;
 static constexpr char tag[]="root:xnu-11417.140.69~1/RELEASE_X86_64";
 size_t length=strlen(kernel);if(length && kernel[length-1]=='\n')--length;
 return length>=sizeof(tag)-1 && memcmp(kernel+length-(sizeof(tag)-1),tag,sizeof(tag)-1)==0;
}
// Publication and cancellation linearize without taking any driver/registry
// lock. A writer that wins may finish; a winning cancellation forbids writes.
class P256DiagnosticPublication {
 enum : uint32_t {Pending,Writing,Reported,Cancelled};
 alignas(4) uint32_t state=Pending;
 bool change(uint32_t from,uint32_t to){return __atomic_compare_exchange_n(&state,&from,to,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);}
public:
 P256DiagnosticPublication()=default;
 P256DiagnosticPublication(const P256DiagnosticPublication &)=delete;
 P256DiagnosticPublication &operator=(const P256DiagnosticPublication &)=delete;
 static_assert(__atomic_always_lock_free(sizeof(uint32_t),nullptr),"Diagnostic publication must not add a runtime atomic lock");
 bool pending() const {return __atomic_load_n(&state,__ATOMIC_ACQUIRE)==Pending;}
 bool cancelled() const {return __atomic_load_n(&state,__ATOMIC_ACQUIRE)==Cancelled;}
 bool beginReport(){return change(Pending,Writing);}
 bool finishReport(){return change(Writing,Reported);}
 bool cancel(){return change(Pending,Cancelled);}
};
}

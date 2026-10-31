#include <cassert>
#include <cstdint>
#include <cstring>
#include <strings.h>
#include <vector>
#include "../../src/security/Ath10kTKIPMICOwner.hpp"
using UInt64=uint64_t;
struct OSObject {virtual ~OSObject()=default;void release(){delete this;}};
struct OSData:OSObject {std::vector<uint8_t> bytes;size_t getLength(){return bytes.size();}const void *getBytesNoCopy(){return bytes.data();}};
#define OSDynamicCast(T,p) dynamic_cast<T *>(p)
struct IOService {bool fail=false,wrongType=false,present=false;std::vector<uint8_t> data;
 bool setProperty(const char *,void *p,size_t n){if(fail)return false;data.assign((uint8_t*)p,(uint8_t*)p+n);present=true;return true;}
 OSObject *copyProperty(const char *){if(!present)return nullptr;if(wrongType)return new OSObject;auto p=new OSData;p->bytes=data;return p;}
};
namespace Ath10k {static UInt64 now=30;UInt64 uptimeNS(){return now*1000000;}}
class Ath10kPCIDevice {public:
 struct Security {AthSecurity::TKIPMICOwner tkipMICOwner;}security;
 Security *_nativeSecurity=&security;IOService *_pci=nullptr;
 bool saveNativeMICWindow(IOService *);bool restoreNativeMICWindow();
};
#include "native_mic_persistence.inc"
int main(){using O=AthSecurity::TKIPMICOwner;IOService provider;Ath10kPCIDevice old;
 auto &owner=old.security.tkipMICOwner;assert(owner.begin(1,0));
 assert(owner.detect({1,1,1,0,16},1)==O::Detection::Report);
 assert(owner.detect({1,1,2,0,16},2)==O::Detection::Countermeasures);
 assert(old.saveNativeMICWindow(&provider));assert(provider.data.size()==32);
 Ath10kPCIDevice fresh;fresh._pci=&provider;assert(fresh.restoreNativeMICWindow());
 assert(fresh.security.tkipMICOwner.blocked(60001) && !fresh.security.tkipMICOwner.pending());
 assert(!fresh.security.tkipMICOwner.generation());
 provider.fail=true;assert(!old.saveNativeMICWindow(&provider));provider.fail=false;
 for(unsigned bad=0;bad<4;++bad){IOService p;p.present=true;p.data=provider.data;
  if(bad==0)p.wrongType=true;if(bad==1)p.data.pop_back();
  if(bad==2)p.data[0]=2;if(bad==3)p.data[24]=2;
  Ath10kPCIDevice d;d._pci=&p;assert(!d.restoreNativeMICWindow());}
 IOService absent;Ath10kPCIDevice empty;empty._pci=&absent;assert(empty.restoreNativeMICWindow());
 assert(!empty.saveNativeMICWindow(nullptr));
}

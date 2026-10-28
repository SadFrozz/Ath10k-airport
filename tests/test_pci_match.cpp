#include <cassert>
#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include "IOKit/IOTypes.h"
using SInt32=int32_t;
#define ATH10K_NATIVE 1
#define ATH10K_TRACE(...) do{}while(0)
#define OSDynamicCast(type,object) dynamic_cast<type *>(object)
static unsigned version_major=24,version_minor=6;
struct OSObject {
 unsigned references=1;virtual ~OSObject()=default;
 void retain(){++references;}void release(){assert(references>1);--references;}
};
struct OSData:OSObject {
 std::vector<UInt8> bytes;bool nullBytes=false;
 unsigned getLength(){return bytes.size();}const void *getBytesNoCopy(){return nullBytes?nullptr:bytes.data();}
};
struct OSNumber:OSObject {UInt64 value=0;UInt64 unsigned64BitValue(){return value;}};
struct OSBoolean:OSObject {bool value=false;bool isTrue(){return value;}};
struct IOService:OSObject {
 std::map<std::string,OSObject *> properties;
 OSObject *getProperty(const char *key){auto i=properties.find(key);return i==properties.end()?nullptr:i->second;}
 OSObject *copyProperty(const char *key){auto p=getProperty(key);if(p)p->retain();return p;}
 void setProperty(const char *,const char *){}
};
struct IOPCIDevice:IOService {}; // Deliberately has no configRead, MMIO or open API.
namespace Ath10k {static bool isSupportedDevice(UInt16 vendor,UInt16 device){return vendor==0x168c && (device==0x42 || device==0x3e);}}
struct Ath10kPCIDevice:IOService {IOService *probe(IOService *,SInt32 *);};
#include "pci_match_method.inc"
static void put(OSData &data,UInt32 value){data.bytes={UInt8(value),UInt8(value>>8),UInt8(value>>16),UInt8(value>>24)};}
int main(){
 IOPCIDevice pci;OSData vendor,device,subvendor,subsystem;
 put(vendor,0x168c);put(device,0x42);put(subvendor,0x1a3b);put(subsystem,0x2b51);
 pci.properties={{"vendor-id",&vendor},{"device-id",&device},{"subsystem-vendor-id",&subvendor},{"subsystem-id",&subsystem}};
 Ath10kPCIDevice driver;SInt32 score=7;
 assert(driver.probe(&pci,&score)==&driver && score==1007);
 assert(vendor.references==1 && device.references==1 && subvendor.references==1 && subsystem.references==1);
 OSNumber number;number.value=0x168c;pci.properties["vendor-id"]=&number;
 assert(driver.probe(&pci,nullptr)==&driver && number.references==1);
 for(UInt64 invalid:{0x10000ull,0xffffffffffffffffull}){number.value=invalid;score=9;assert(!driver.probe(&pci,&score) && score==9 && number.references==1);}
 pci.properties["vendor-id"]=&vendor;
 UInt16 unchanged=123;OSData malformed;
 for(unsigned size:{0u,1u,2u,3u,5u,8u}){malformed.bytes.assign(size,0);pci.properties["vendor-id"]=&malformed;assert(!ath10kRegistryPCIID(&pci,"vendor-id",unchanged) && unchanged==123 && malformed.references==1);}
 put(malformed,0x10000);assert(!ath10kRegistryPCIID(&pci,"vendor-id",unchanged));
 put(malformed,0x168c);malformed.nullBytes=true;assert(!ath10kRegistryPCIID(&pci,"vendor-id",unchanged));
 pci.properties["vendor-id"]=&vendor;
 for(const char *key:{"vendor-id","device-id","subsystem-vendor-id","subsystem-id"}){
  auto saved=pci.properties[key];pci.properties.erase(key);score=10;assert(!driver.probe(&pci,&score) && score==10);pci.properties[key]=saved;
 }
 put(subsystem,0x2b52);assert(!driver.probe(&pci,nullptr));put(subsystem,0x2b51);
 put(subvendor,0x1a3c);assert(!driver.probe(&pci,nullptr));put(subvendor,0x1a3b);
 put(vendor,0x8086);assert(!driver.probe(&pci,nullptr));put(vendor,0x168c);
 version_major=26;assert(!driver.probe(&pci,nullptr));version_major=24;
 version_minor=1;assert(!driver.probe(&pci,nullptr));version_minor=6;
 OSBoolean diagnostic;diagnostic.value=true;driver.properties["Ath10kProbeOnly"]=&diagnostic;
 score=4;assert(!driver.probe(&pci,&score) && score==4);
 diagnostic.value=false;assert(driver.probe(&pci,nullptr)==&driver);
 put(device,0x3e);assert(!driver.probe(&pci,nullptr));put(device,0x42);
 assert(ath10kNativePCIIdentity(0x168c,0x42,0x1a3b,0x2b51));
 assert(!ath10kNativePCIIdentity(0x168c,0x3e,0x1a3b,0x2b51));
 IOService nonPCI;assert(!driver.probe(&nonPCI,nullptr));
 OSBoolean wrongType;pci.properties["vendor-id"]=&wrongType;
 assert(!driver.probe(&pci,nullptr) && wrongType.references==1);
}

#include <cassert>
#include <cstdint>
using UInt8=uint8_t;using UInt16=uint16_t;
static void ATH10K_TRACE(const char *,...){}
static void IOLog(const char *,...){}
constexpr unsigned kIOPCIConfigCommand=4;
constexpr UInt8 kPCIeLinkControlOffset=0x10;constexpr UInt16 kPCIeLinkControlASPMMask=3;
struct PCI {
 bool powered=true,unavailable=false,failAfterWrite=false;unsigned reads=0,writes=0;UInt16 value=0x10;
 UInt16 configRead16(unsigned){assert(powered);++reads;return unavailable || (failAfterWrite && writes)?0xffff:value;}
 void setBusMasterEnable(bool enable){assert(powered);++writes;if(enable)value|=4;else value&=~4;}
 void configWrite16(unsigned,UInt16 next){assert(powered && !unavailable);++writes;value=next;}
};
struct Ath10kPCIDevice {
 PCI pci;PCI *_pci=&pci;bool _aspmRestoreSucceeded=false,_aspmDisableAttempted=true,_aspmDisabled=false,_hasPCIe=true;
 UInt8 _pcieCapOffset=0x40;UInt16 _pcieLinkControlBefore=3,_pcieLinkControlDuring=0xffff,_pcieLinkControlAfterRestore=0xffff;
 bool _pciConfigured=true,_reprobeRequested=false,_dmaQuarantine=false;UInt16 _originalCommand=0x406;
 struct {bool needsRestart=false;} _power;
 bool disableASPMForBringup();void restoreASPM();void restoreOwnedPCICommand();
};
#include "restore_aspm_methods.inc"
int main(){
 {Ath10kPCIDevice d;d.restoreASPM();assert(d._aspmRestoreSucceeded && d.pci.value==0x13 && d.pci.reads==2 && d.pci.writes==1);
  d.pci.powered=false;d.restoreASPM();assert(d.pci.reads==2 && d.pci.writes==1);}
 {Ath10kPCIDevice d;d.pci.unavailable=true;d.restoreASPM();assert(!d._aspmRestoreSucceeded && !d.pci.writes && d.pci.reads==1);}
 {Ath10kPCIDevice d;d.pci.failAfterWrite=true;d.restoreASPM();assert(!d._aspmRestoreSucceeded && d._pcieLinkControlAfterRestore==0xffff);}
 {Ath10kPCIDevice d;d.pci.unavailable=true;assert(!d.disableASPMForBringup() && !d.pci.writes);
  auto reads=d.pci.reads;d.restoreASPM();assert(d.pci.reads==reads && !d._aspmRestoreSucceeded);}
 {Ath10kPCIDevice d;d.pci.value=0x13;assert(d.disableASPMForBringup() && d.pci.value==0x10);
  d.restoreASPM();assert(d._aspmRestoreSucceeded && d.pci.value==0x13);
  assert(d.disableASPMForBringup() && !d._aspmRestoreSucceeded);d.restoreASPM();assert(d._aspmRestoreSucceeded);}
 {Ath10kPCIDevice d;d._reprobeRequested=true;d.pci.powered=false;d.restoreOwnedPCICommand();assert(!d._pciConfigured && !d.pci.reads && !d.pci.writes);}
 {Ath10kPCIDevice d;d._power.needsRestart=true;d.pci.powered=false;d.restoreOwnedPCICommand();assert(!d._pciConfigured && !d.pci.writes);}
 {Ath10kPCIDevice d;d.restoreOwnedPCICommand();assert(!d._pciConfigured && d.pci.value==d._originalCommand && d.pci.writes==1);
  d.pci.powered=false;d.restoreOwnedPCICommand();assert(d.pci.writes==1);}
 {Ath10kPCIDevice d;d._dmaQuarantine=true;d.restoreOwnedPCICommand();assert(!d._pciConfigured && !(d.pci.value&4) && d.pci.writes==1);}

}

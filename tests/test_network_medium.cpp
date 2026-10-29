// Execute the production selector for both personalities. This models the
// BSD media-type consumer, not a live IONetworkController or ioctl call.
#include <cassert>
using IOMediumType=unsigned;
using IOReturn=int;
constexpr unsigned kIOMediumEthernetAuto=0x20,kIOMediumIEEE80211Auto=0x80;
constexpr int kIOReturnSuccess=0,kIOReturnUnsupported=1,kIOReturnError=2;
struct IONetworkMedium {
    unsigned type;
    unsigned getType() const {return type;}
};
struct Selector {
    bool accept=true;unsigned calls=0;const IONetworkMedium *selected=nullptr;
    bool setSelectedMedium(const IONetworkMedium *medium) {
        ++calls;if(!accept)return false;selected=medium;return true;
    }
};
namespace Native {
struct Ath10kPCIDevice:Selector {IOReturn selectMedium(const IONetworkMedium *);};
#define ATH10K_NATIVE 1
#include "network_medium.inc"
#undef ATH10K_NATIVE
}
namespace Diagnostic {
struct Ath10kPCIDevice:Selector {IOReturn selectMedium(const IONetworkMedium *);};
#include "network_medium.inc"
}
template<class Driver> void verify(unsigned wanted,unsigned wrong) {
    Driver driver;IONetworkMedium valid{wanted},invalid{wrong};
    assert(driver.selectMedium(nullptr)==kIOReturnUnsupported);
    assert(driver.selectMedium(&invalid)==kIOReturnUnsupported);
    assert(driver.calls==0 && !driver.selected);
    driver.accept=false;
    assert(driver.selectMedium(&valid)==kIOReturnError);
    assert(!driver.selected);
    driver.accept=true;
    assert(driver.selectMedium(&valid)==kIOReturnSuccess);
    assert(driver.selected==&valid && driver.calls==2);
}
int main() {
    assert((Native::kAth10kAutoMedium&0xe0)==0x80);
    assert((Diagnostic::kAth10kAutoMedium&0xe0)==0x20);
    verify<Native::Ath10kPCIDevice>(0x80,0x20);
    verify<Diagnostic::Ath10kPCIDevice>(0x20,0x80);
}

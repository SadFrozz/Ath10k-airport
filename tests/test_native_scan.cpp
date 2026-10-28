#include <cassert>
#include <cstring>
#include <cstdint>
#define __MAC_15_2 150200
#define __IO80211_TARGET __MAC_15_2
#include "../src/kext/native/Ath10kNativeWire.hpp"
#include "../src/kext/Ath10kWMI.hpp"

int main(){
    using namespace Ath10k;
    // A mixed 2.4 GHz/DFS request, including a duplicate. The native decode
    // and actual firmware builder must agree, not merely filter final results.
    UInt8 request[0x58+4*12]{};
    htcWriteLE32(request+0x40,1);htcWriteLE32(request+0x54,4);
    const UInt32 channels[]={6,52,52,5},bands[]={8,16,16,0x2000};
    for(unsigned i=0;i<4;++i){
        htcWriteLE32(request+0x58+12*i+4,channels[i]);
        htcWriteLE32(request+0x58+12*i+8,bands[i]);
    }
    AirportWCL::ScanRequest scan{};
    assert(AirportWCL::decodeScan(request,sizeof(request),scan));
    const UInt64 mask=wmiRequestedScanMask(scan.channels,sizeof(scan.channels));
    assert(regulatoryScanCount(nullptr,mask)==2);
    UInt8 frame[293];memset(frame,0xa5,sizeof(frame));
    assert(buildWMIScan(frame,148,2,0xa123,false,nullptr,110,mask));
    assert(htcReadLE16(frame+2)==140 && wmiReadLE32(frame+16)==0xa123);
    assert(wmiReadLE32(frame+80)==2 && htcReadLE16(frame+116)==8);
    assert(wmiReadLE32(frame+120)==2437 && wmiReadLE32(frame+124)==5260);
    assert(wmiReadLE32(frame+40)==110 && wmiReadLE32(frame+72)==0x31);
    assert(htcReadLE16(frame+130)==19 && htcReadLE16(frame+132)==8);
    assert(frame[148]==0xa5); // Exact variable-length frame, no overflow.
    assert(!buildWMIScan(frame,147,2,0xa123,false,nullptr,110,mask));
    assert(wmiRequestedScanMask(scan.channels,31)==0);
    assert(wmiRequestedScanMask(nullptr,0)==~UInt64(0));
    // No overlap must be rejected, not turned into an all-band scan.
    memset(frame,0xa5,sizeof(frame));
    assert(!buildWMIScan(frame,sizeof(frame),2,1,false,nullptr,110,0));
    assert(frame[0]==0xa5);
    assert(!buildWMIScan(frame,sizeof(frame),2,1,false,nullptr,110,UInt64(1)<<63));
    // A caller cannot use a selected bitmap to bypass country restrictions.
    RegulatoryPolicy us{};us.country=regulatoryCountry("US");
    assert(!configureRegulatory(us,0x64,2412,2472,5180,5825));
    UInt8 forbidden[32]{};forbidden[13/8]|=1u<<(13%8);
    UInt64 forbiddenMask=wmiRequestedScanMask(forbidden,sizeof(forbidden));
    assert(regulatoryScanCount(&us,forbiddenMask)==0);
    assert(!buildWMIScan(frame,sizeof(frame),2,1,false,&us,110,forbiddenMask));
    // Connected background scans retain the home-channel rest and dwell cap.
    UInt8 one[32]{};one[52/8]|=1u<<(52%8);
    const UInt64 oneMask=wmiRequestedScanMask(one,sizeof(one));
    assert(buildWMIScan(frame,144,2,1,true,nullptr,120,oneMask));
    assert(wmiReadLE32(frame+80)==1 && wmiReadLE32(frame+120)==5260);
    assert(wmiReadLE32(frame+40)==100 && wmiReadLE32(frame+44)==150);
    assert(buildWMIScan(frame,292,2));
    assert(wmiReadLE32(frame+80)==38 && htcReadLE16(frame+2)==284);
}

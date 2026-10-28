#include <cassert>
#include <cstring>
#include <cstdint>
#include <initializer_list>
#define __MAC_15_2 150200
#define __IO80211_TARGET __MAC_15_2
#include "../src/kext/native/Ath10kNativeWire.hpp"
#include "../src/kext/Ath10kWMI.hpp"

// Execute the production pre-submission cancellation path. The seam records
// reaching the hardware submission section without touching hardware.
class Ath10kPCIDevice {
public:
    Ath10k::WMIScanState _wmiScan{};
    Ath10k::ConnectionState _connection{};
    unsigned submissions=0;
    const char *serviceWMIScan(UInt64 nowMs);
};
#include "native_scan_start.inc"

int main(){
    using namespace Ath10k;
    for(unsigned phase=1;phase<=unsigned(ChannelSwitchPhase::Confirm);++phase){
        Ath10kPCIDevice driver;
        driver._connection.csa.phase=static_cast<ChannelSwitchPhase>(phase);
        assert(!driver.serviceWMIScan(100));
        assert(!driver.submissions && driver._wmiScan.cancelRequested);
        assert(driver._wmiScan.completed && driver._wmiScan.terminal);
        // Once submitted, ownership must survive until the STOP/event/credit
        // path handles it. The admission guard must not fabricate completion.
        Ath10kPCIDevice inFlight;
        inFlight._connection.csa.phase=static_cast<ChannelSwitchPhase>(phase);
        inFlight._wmiScan.attempted=inFlight._wmiScan.submitted=true;
        inFlight._wmiScan.txOwned=true;
        assert(!inFlight.serviceWMIScan(100));
        assert(inFlight.submissions==1 && inFlight._wmiScan.cancelRequested);
        assert(inFlight._wmiScan.txOwned && !inFlight._wmiScan.completed && !inFlight._wmiScan.terminal);
        // A finished scan awaiting native notification is immutable here.
        Ath10kPCIDevice finished;
        finished._connection.csa.phase=static_cast<ChannelSwitchPhase>(phase);
        finished._wmiScan.completed=finished._wmiScan.terminal=true;
        const auto saved=finished._wmiScan;
        assert(!finished.serviceWMIScan(100) && !finished.submissions);
        assert(!memcmp(&saved,&finished._wmiScan,sizeof(saved)));

    }
    { Ath10kPCIDevice pending;pending._connection.pmfTXPending=true;
      assert(!pending.serviceWMIScan(100) && pending._wmiScan.completed && pending._wmiScan.cancelRequested && !pending.submissions);
      Ath10kPCIDevice owned;owned._connection.pmfTXPending=true;
      owned._wmiScan.attempted=owned._wmiScan.submitted=owned._wmiScan.txOwned=true;
      assert(!owned.serviceWMIScan(100) && owned._wmiScan.cancelRequested && !owned._wmiScan.completed && owned._wmiScan.txOwned); }
    { Ath10kPCIDevice driver;assert(!driver.serviceWMIScan(100));
      assert(driver.submissions==1 && !driver._wmiScan.cancelRequested); }

    { // A prior generation's terminal event must not invalidate the current
      // completed scan while its ScanDone notification is being retried.
        UInt8 packet[40]{};packet[0]=2;packet[2]=32;
        htcWriteLE32(packet+8,0x3001);packet[12]=24;packet[14]=36;
        htcWriteLE32(packet+16,2);htcWriteLE32(packet+28,kWMIScanRequestId);
        htcWriteLE32(packet+32,0xa036);
        WMIScanState scan{};scan.id=0xa037;scan.generation=1;
        scan.submitted=scan.started=scan.terminal=scan.completed=true;
        HTCCreditState credits{};credits.initialize(2,256,2);WMIInitState init{};
        const char *error=parseWMIInitResponse(packet,sizeof(packet),2,credits,init,nullptr,&scan);
        assert(!error && scan.terminal && scan.completed && scan.eventCount==0);
        // Stale IDs do not bypass format checks or mutate command credits.
        assert(credits.reserve(20));
        const auto savedScan=scan;const auto savedCredits=credits;
        auto reject=[&](const UInt8 *bytes,size_t length){
            WMIInitState state{};state.lastEventId=0x12345678;
            assert(parseWMIInitResponse(bytes,length,2,credits,state,nullptr,&scan));
            assert(!memcmp(&scan,&savedScan,sizeof(scan)));
            assert(credits.available==savedCredits.available && credits.outstanding==savedCredits.outstanding);
            assert(state.lastEventId==0x12345678);
        };
        for(size_t length=0;length<sizeof(packet);++length)reject(packet,length);
        for(unsigned offset:{12u,16u,28u,36u}){
            UInt8 bad[40];memcpy(bad,packet,sizeof(bad));
            htcWriteLE32(bad+offset,3); // bad TLV, multi-bit type, requestor or vdev
            reject(bad,sizeof(bad));
        }
        // A stale event still carries real transport credits. Reject an
        // over-return transactionally, then accept the valid credit once.
        UInt8 credited[48]{};memcpy(credited,packet,sizeof(packet));
        credited[1]=2;credited[4]=8;htcWriteLE16(credited+2,40);
        credited[40]=1;credited[41]=4;credited[44]=2;credited[45]=2;
        reject(credited,sizeof(credited));
        credited[45]=1;
        error=parseWMIInitResponse(credited,sizeof(credited),2,credits,init,nullptr,&scan);
        assert(!error && credits.outstanding==0 && init.creditReturned);
        assert(!memcmp(&scan,&savedScan,sizeof(scan)));
        htcWriteLE32(packet+32,scan.id);
        error=parseWMIInitResponse(packet,sizeof(packet),2,credits,init,nullptr,&scan);
        assert(error && !strcmp(error,"scan-event-after-terminal"));
    }
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

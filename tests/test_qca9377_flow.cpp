#define ATH10K_PROFILE_FLOW_TEST
#include "test_firmware_flow.cpp"
int main(){
    const auto &lunnen=Ath10kPayload::selectProfile(0x168c,0x0042,0x1a3b,0x2b51,1);
    assert(lunnen.available && lunnen.kBoardSize==8124);
    assert(!strcmp(lunnen.kBoardSelection,"board-api2-exact"));
    assert(!strcmp(lunnen.kBoardSHA256,"ba14e9b4d189bf213e144ad1936f16cbb2b5286f152d394c9d3f1750a723d991"));
    const auto &dell=Ath10kPayload::selectProfile(0x168c,0x0042,0x1028,0x1810,1);
    assert(lunnen.kFirmware==dell.kFirmware && lunnen.kOTP==dell.kOTP);
    assert(memcmp(lunnen.kBoard,dell.kBoard,8124));
    assert(!Ath10kPayload::selectProfile(0x168c,0x0042,0x1a3b,0x2b52,1).available);
    assert(!Ath10kPayload::selectProfile(0x168c,0x0042,0x1a3b,0x2b51,0).available);
    const auto &p=Ath10kPayload::selectProfile(0x168c,0x0042,0x1028,0x1810,1);
    assert(p.available && p.targetVersion==0x05020001 && p.kBoardSize==8124);
    assert(!strcmp(p.kBoardSelection,"board-api2-exact"));
    assert(strcmp(p.kFirmwareVersion,Ath10kPayload::kFirmwareVersion));
    assert(memcmp(p.kBoard,Ath10kPayload::kBoard,8124));
    assert(p.matchesTarget(0x05020001,8,12));
    for(auto version:{0x05030000u,0x05020000u,0u})assert(!p.matchesTarget(version,8,12));
    assert(!p.matchesTarget(0x05020001,7,12) && !p.matchesTarget(0x05020001,8,8));
    assert(!Ath10kPayload::selectProfile(0x168c,0x0042,0x1028,0x1811,1).available);
    assert(!Ath10kPayload::selectProfile(0x168c,0x0042,0x1028,0x1810,0).available);
    assert(!Ath10kPayload::selectProfile(0x1234,0x0042,0x1028,0x1810,1).available);
    for(auto addr:{0u,0x400800u,0x400ffcu,0x401001u,0x404000u,0xfffffffcu})assert(!p.boardAddressValid(addr));
    {FirmwareDriver d(true); assert(d.runBMIFirmwareDownloadTest());
        assert(d._bmiBoardBytesVerified==8124 && d.executions==1);
        assert(d._otpWireBytesSent==24196 && d._fwWireBytesSent==727128);
        assert(d._fwVerifiedSegments==6 && d._fwReadbackBytes==727053);
        assert(!d.runBMIFirmwareDownloadTest());}
    {FirmwareDriver d(true); d.postVersion=0x05030000;
        assert(!d.runBMIFirmwareDownloadTest() && !d._fwPostBMIProbeSucceeded && d.reads==0);}
    {FirmwareDriver d(true); d.corruptAddress=0xa0400+26272;
        assert(!d.runBMIFirmwareDownloadTest() && d._fwFailedSegment==5 && !d._fwReadbackSucceeded);}
    {FirmwareDriver d(true); d._subsystemVendorId=0x17aa;
        assert(!d.runBMIFirmwareDownloadTest() && d._regs.posts==0);}
    {Ath10kPCIDevice d; d._deviceId=0x0042; d._subsystemVendorId=0x1028; d._subsystemId=0x1810;
        d._selectedHw=Ath10k::findCandidate(0x0042,1); // wrong ROM, no board write
        assert(!d.runBMIBoardUploadTest() && d._regs.posts==0);}
}

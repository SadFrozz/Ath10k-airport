#include <cassert>
#include <cstring>
#include "Ath10kPayload.hpp"
int main() {
    const auto &p=Ath10kPayload::selectProfile(0x168c,0x0042,0x1a3b,0x2b51,1);
    const auto &dell=Ath10kPayload::selectProfile(0x168c,0x0042,0x1028,0x1810,1);
    assert(p.available && p.kBoardSize==8124);
    assert(!strcmp(p.kBoardSelection,"board-api2-exact"));
    assert(!strcmp(p.kBoardSHA256,"ba14e9b4d189bf213e144ad1936f16cbb2b5286f152d394c9d3f1750a723d991"));
    assert(std::memcmp(p.kBoard,dell.kBoard,8124));
    assert(p.kFirmware==dell.kFirmware && p.kOTP==dell.kOTP);
    assert(p.matchesTarget(0x05020001,8,12));
    assert(!p.matchesTarget(0x05030000,8,12));
    assert(!Ath10kPayload::selectProfile(0x168c,0x0042,0x1a3b,0x2b52,1).available);
    assert(!Ath10kPayload::selectProfile(0x168c,0x0042,0x1a3b,0x2b51,0).available);
    assert(!Ath10kPayload::selectProfile(0x1234,0x0042,0x1a3b,0x2b51,1).available);
}

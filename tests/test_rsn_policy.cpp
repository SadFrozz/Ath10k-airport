#include <cassert>
#include <cstdint>
#include <vector>
#include "../src/shared/Ath10kSecurity.hpp"
using namespace AthSecurity;

static std::vector<uint8_t> rsn(bool psk, bool sae, uint16_t caps = 0x80) {
    std::vector<uint8_t> v = {48,0,1,0,0,15,172,4,1,0,0,15,172,4,
                             uint8_t(psk + sae),0};
    if (psk) v.insert(v.end(), {0,15,172,2});
    if (sae) v.insert(v.end(), {0,15,172,8});
    v.insert(v.end(), {uint8_t(caps),uint8_t(caps >> 8)});
    v[1] = uint8_t(v.size() - 2);
    return v;
}
int main() {
    auto wpa2 = rsn(true, false, 0);
    auto wpa3 = rsn(false, true, 0xc0);
    auto mixed = rsn(true, true);
    RSNInfo parsed{};
    assert(parseRSN(mixed.data(), mixed.size(), parsed));
    assert(parsed.akmHas(2) && parsed.akmHas(8) && parsed.mfpc() && !parsed.mfpr());
    assert(parsed.pairwiseHas(4) && parsed.groupManagement == 6);
    assert(supportsWPA2(wpa2.data(), wpa2.size()));
    assert(supportsWPA2(mixed.data(), mixed.size()));
    assert(!supportsWPA2(wpa3.data(), wpa3.size()));
    assert(!supportsWPA2(nullptr, 22));
    assert(selectPersonal(wpa2.data(), wpa2.size(), PersonalMode::WPA2));
    assert(selectPersonal(mixed.data(), mixed.size(), PersonalMode::WPA3).error == SecurityError::SAEUnavailable);
    assert(selectPersonal(wpa2.data(), wpa2.size(), PersonalMode::WPA3).error == SecurityError::UnsupportedAKM);
    assert(selectPersonal(wpa3.data(), wpa3.size(), PersonalMode::WPA2).error == SecurityError::UnsupportedAKM);
    // These flags model a future backend, not capabilities advertised by today's driver.
    SecurityBackend full{true,true,true};
    auto selection = selectPersonal(mixed.data(), mixed.size(), PersonalMode::WPA3, full);
    assert(selection && selection.akm == 8 && selection.pmf && selection.pairwise == 4);
    assert(selectPersonal(wpa3.data(), wpa3.size(), PersonalMode::WPA3, {true,false,false}).error == SecurityError::PMFUnavailable);
    assert(selectPersonal(wpa3.data(), wpa3.size(), PersonalMode::WPA3, {true,true,false}).error == SecurityError::UnsupportedGroupManagement);
    auto noPMF = rsn(false,true,0);
    assert(selectPersonal(noPMF.data(), noPMF.size(), PersonalMode::WPA3, full).error == SecurityError::PMFRequired);
    auto inconsistent = rsn(false,true,0x40);
    assert(!parseRSN(inconsistent.data(), inconsistent.size(), parsed));
    auto tkip = wpa3; tkip[7] = 2;
    assert(selectPersonal(tkip.data(), tkip.size(), PersonalMode::WPA3, full).error == SecurityError::UnsupportedCipher);
    auto oldGroup = wpa2; oldGroup[7] = 2;
    assert(supportsWPA2(oldGroup.data(), oldGroup.size()));
    auto foreign = wpa2; foreign[16] = 1;
    assert(!supportsWPA2(foreign.data(), foreign.size()));
    // Optional PMKIDs and explicit group management cipher are bounds checked.
    auto ids = wpa3; ids.insert(ids.end(), {1,0}); ids.insert(ids.end(),16,0xab);
    ids.insert(ids.end(), {0,15,172,6}); ids[1] = uint8_t(ids.size()-2);
    assert(parseRSN(ids.data(), ids.size(), parsed) && parsed.pmkidCount == 1);
    assert(selectPersonal(ids.data(), ids.size(), PersonalMode::WPA3, full));
    auto wrongBIP = ids; wrongBIP.back() = 11;
    assert(selectPersonal(wrongBIP.data(), wrongBIP.size(), PersonalMode::WPA3, full).error == SecurityError::UnsupportedGroupManagement);
    ids[22] = 2; // Declares two PMKIDs with room for only one.
    assert(!parseRSN(ids.data(), ids.size(), parsed));
    auto extra = wpa2; extra.push_back(0); extra[1]++;
    assert(!parseRSN(extra.data(), extra.size(), parsed));
    auto peerKey = rsn(true,false,0x200);
    auto extKey = rsn(true,false,0x2000);
    assert(!supportsWPA2(peerKey.data(),peerKey.size()));
    assert(!supportsWPA2(extKey.data(),extKey.size()));
    // Truncation and oversized-list inputs cannot read outside their supplied span.
    for (const auto &v : {wpa2,wpa3,mixed}) {
        for (size_t n = 0; n < v.size(); ++n)
            assert(!parseRSN(v.data(), n, parsed));
        for (unsigned value = 0; value < 256; ++value) {
            auto bad = v; bad[8] = uint8_t(value); bad[9] = 0xff;
            assert(!parseRSN(bad.data(), bad.size(), parsed));
        }
    }
    // Deterministic parser stress over arbitrary on-air bytes, including null input.
    uint32_t seed = 0x9377;
    for (unsigned n = 0; n <= 300; ++n) {
        std::vector<uint8_t> bytes(n);
        for (unsigned trial = 0; trial < 64; ++trial) {
            for (auto &b : bytes) { seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5; b = uint8_t(seed); }
            if (n >= 2 && n <= 257) { bytes[0] = 48; bytes[1] = uint8_t(n-2); }
            parseRSN(bytes.data(), bytes.size(), parsed);
        }
    }
}

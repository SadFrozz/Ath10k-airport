#include <cassert>
#include <cstdint>
#include <vector>
#include <cstring>
#include "../../src/security/Ath10kSecurity.hpp"
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
static void wpa1SelectionTests(){
    // AP offers both ciphers and both AKMs. Output must contain exactly the
    // requested profile, preserving AP group cipher rather than choosing PSK.
    uint8_t ap[]={221,30,0,0x50,0xf2,1,1,0,0,0x50,0xf2,2,
        2,0,0,0x50,0xf2,2,0,0x50,0xf2,4,
        2,0,0,0x50,0xf2,1,0,0x50,0xf2,2};
    uint8_t out[25];size_t bytes=999;
    for(uint8_t group:{2,4})for(uint8_t pair:{2,4})for(uint8_t akm:{1,2}){
        ap[11]=group;memset(out,0xa5,sizeof(out));
        assert(buildWPA1StationIE(ap,sizeof(ap),pair,akm,out,24,bytes));
        assert(bytes==24 && out[24]==0xa5);WPAInfo selected{};
        assert(parseWPA(out,bytes,selected));
        assert(selected.group==group && selected.pairwise==(1u<<pair) && selected.akms==(1u<<akm));
    }
    memset(out,0xa5,sizeof(out));
    for(size_t n=0;n<sizeof(ap);++n){
        assert(!buildWPA1StationIE(ap,n,2,1,out,sizeof(out),bytes));assert(!bytes);
    }
    for(unsigned bad=0;bad<256;++bad){
        if(bad!=2 && bad!=4)assert(!buildWPA1StationIE(ap,sizeof(ap),uint8_t(bad),1,out,sizeof(out),bytes));
        if(bad!=1 && bad!=2)assert(!buildWPA1StationIE(ap,sizeof(ap),2,uint8_t(bad),out,sizeof(out),bytes));
    }
    assert(!buildWPA1StationIE(ap,sizeof(ap),2,1,out,23,bytes));
    assert(!buildWPA1StationIE(ap,sizeof(ap),2,1,nullptr,24,bytes));
    for(auto b:out)assert(b==0xa5);
    // Single-suite Personal AP must not be silently used for Enterprise.
    const uint8_t personal[]={221,22,0,0x50,0xf2,1,1,0,0,0x50,0xf2,2,
        1,0,0,0x50,0xf2,2,1,0,0,0x50,0xf2,2};
    assert(!buildWPA1StationIE(personal,sizeof(personal),2,1,out,24,bytes));
    assert(!buildWPA1StationIE(personal,sizeof(personal),4,2,out,24,bytes));
    assert(!buildWPA1StationIE(stationRSN,sizeof(stationRSN),2,2,out,24,bytes));
    for(auto b:out)assert(b==0xa5);
}
static void selectedRSN(){
    for(uint8_t group:{2,4})for(uint8_t pair:{2,4})for(uint8_t akm:{1,2,6}){
        uint8_t out[23];memset(out,0xa5,sizeof(out));size_t bytes=99;
        const bool allowed=akm!=6 || (group==4 && pair==4);
        assert(buildSelectedStationRSN(group,pair,akm,out,22,bytes)==allowed);
        if(allowed){RSNInfo parsed{};assert(bytes==22 && parseRSN(out,bytes,parsed));
            assert(parsed.group==group && parsed.pairwise==(1u<<pair) && parsed.akms==(1u<<akm));assert(out[22]==0xa5);
            assert(supportsSelectedRSN(out,bytes,akm,pair,true));
            assert(!supportsSelectedRSN(out,bytes,akm,pair==2?4:2,true));
            assert(!supportsSelectedRSN(out,bytes,akm==1?2:1,pair,true));
            const bool defaultAllowed=pair==4 && (akm!=1 || group==4);
            assert(supportsSelectedRSN(out,bytes,akm,pair)==defaultAllowed);
            out[20]=0xc0;assert(!supportsSelectedRSN(out,bytes,akm,pair,true));out[20]=0;
            out[21]=2;assert(!supportsSelectedRSN(out,bytes,akm,pair,true));out[21]=0;

        }else {assert(!bytes);for(auto b:out)assert(b==0xa5);}
    }
    uint8_t out[22];memset(out,0xa5,sizeof(out));size_t bytes=99;
    for(unsigned v=0;v<256;++v){
        if(v!=2 && v!=4){assert(!buildSelectedStationRSN(v,4,2,out,22,bytes));assert(!buildSelectedStationRSN(4,v,2,out,22,bytes));}
        if(v!=1 && v!=2 && v!=6)assert(!buildSelectedStationRSN(4,4,v,out,22,bytes));
    }
    for(size_t n=0;n<22;++n)assert(!buildSelectedStationRSN(4,4,2,out,n,bytes));
    assert(!buildSelectedStationRSN(4,4,2,nullptr,22,bytes));
    for(auto b:out)assert(b==0xa5);
}
int main() {
    selectedRSN();
    wpa1SelectionTests();
    {const uint8_t raw[]={221,22,0,0x50,0xf2,1,1,0,0,0x50,0xf2,2,1,0,0,0x50,0xf2,2,1,0,0,0x50,0xf2,2};
     WPAInfo info{};assert(parseWPA(raw,sizeof(raw),info));
     assert(info.group==2 && info.pairwise==4 && info.akms==4);
     for(size_t n=0;n<sizeof(raw);++n)assert(!parseWPA(raw,n,info));
     for(size_t n: {8u,12u,18u,24u}){std::vector<uint8_t> v(raw,raw+n);v[1]=uint8_t(n-2);
       assert(parseWPA(v.data(),v.size(),info));assert(info.akms==(n==24?4u:2u));}
     for(unsigned at: {0u,1u,2u,3u,4u,5u,6u,7u,12u,13u,18u,19u}){
       std::vector<uint8_t> v(raw,raw+sizeof(raw));v[at]=255;
       assert(!parseWPA(v.data(),v.size(),info));assert(!info.group && !info.akms && !info.pairwise);}
     std::vector<uint8_t> v(raw,raw+sizeof(raw));v.insert(v.end(),{0x34,0x12});v[1]=24;
     assert(parseWPA(v.data(),v.size(),info) && info.capabilities==0x1234);
     v.push_back(0);v[1]++;assert(!parseWPA(v.data(),v.size(),info));
     v.assign(raw,raw+sizeof(raw));v[15]=15;v[16]=172;
     assert(parseWPA(v.data(),v.size(),info) && info.pairwise==0); // RSN OUI is not WPA.
     RSNInfo rsnInfo{};assert(!parseRSN(raw,sizeof(raw),rsnInfo));
     assert(!parseWPA(nullptr,24,info));
    }

    {uint8_t ie[18]={244,1,0x20};assert(validRSNXE(ie,3) && rsnxeHasH2E(ie,3));
     for(size_t n=0;n<19;++n)if(n!=3)assert(!validRSNXE(ie,n));
     assert(!validRSNXE(nullptr,3));ie[0]=48;assert(!validRSNXE(ie,3));ie[0]=244;
     ie[2]=0;assert(validRSNXE(ie,3) && !rsnxeHasH2E(ie,3));
     for(unsigned body=1;body<=16;++body){ie[1]=uint8_t(body);ie[2]=uint8_t(0x20|(body-1));
       for(unsigned j=3;j<body+2;++j)ie[j]=uint8_t(0x80+j);
       assert(validRSNXE(ie,body+2) && rsnxeHasH2E(ie,body+2));
       ie[2]^=1;assert(!validRSNXE(ie,body+2));ie[2]^=1;
     }}

    {uint8_t ie[44]{},id[16]{};size_t bytes=0;
     for(bool withID : {false,true}){
       assert(buildSAEStationRSN(withID?id:nullptr,withID?16:0,ie,sizeof(ie),bytes));
       assert(validSAEStationRSN(ie,bytes));
       for(size_t n=0;n<bytes;++n)assert(!validSAEStationRSN(ie,n));
       for(unsigned at : {0u,1u,7u,13u,19u,20u,22u,23u}){auto saved=ie[at];ie[at]^=1;assert(!validSAEStationRSN(ie,bytes));ie[at]=saved;}
     }
     assert(!validSAEStationRSN(nullptr,44));}

    { uint8_t ie[30]={221,28,0,15,172,9,4,0,1,2,3,4,5,6};
      for(unsigned i=0;i<16;++i)ie[14+i]=uint8_t(i+1);
      IGTKCMAC128 result{};assert(parseIGTKCMAC128(ie,sizeof(ie),result));
      assert(result.keyID==4 && result.ipn==0x060504030201ull && result.key[15]==16);
      const auto saved=result;
      for(unsigned n=0;n<30;++n){assert(!parseIGTKCMAC128(ie,n,result));assert(!memcmp(&result,&saved,sizeof(result)));}
      assert(!parseIGTKCMAC128(nullptr,30,result));
      for(unsigned offset: {0u,1u,2u,3u,4u,5u,6u,7u}){
        uint8_t bad[30];memcpy(bad,ie,30);bad[offset]=255;
        assert(!parseIGTKCMAC128(bad,30,result));assert(!memcmp(&result,&saved,sizeof(result)));
      }
      ie[6]=5;assert(parseIGTKCMAC128(ie,30,result) && result.keyID==5);
      assert(findIGTKCMAC128(ie,30,result));const auto previous=result;
      std::vector<uint8_t> block(ie,ie+30);block.push_back(1); // Truncated following IE.
      assert(!findIGTKCMAC128(block.data(),block.size(),result));
      assert(!memcmp(&result,&previous,sizeof(result)));
      block.assign(ie,ie+30);block.insert(block.end(),ie,ie+30);
      assert(!findIGTKCMAC128(block.data(),block.size(),result)); // Duplicate, even identical.
      assert(!memcmp(&result,&previous,sizeof(result)));
      block.assign(ie,ie+30);block.insert(block.end(),{221,0,0,0});
      assert(findIGTKCMAC128(block.data(),block.size(),result));
      block.back()=1;assert(!findIGTKCMAC128(block.data(),block.size(),result));
      assert(!memcmp(&result,&previous,sizeof(result)));
      uint8_t other[]={1,1,7};assert(!findIGTKCMAC128(other,sizeof(other),result));
      assert(!findIGTKCMAC128(nullptr,30,result));

    }

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

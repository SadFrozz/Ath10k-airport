#include <cassert>
#include <cstring>
#include <array>
#include <cstdint>
#define __MAC_15_2 150200
#define __IO80211_TARGET __MAC_15_2
#include "../../src/macos/native/Ath10kNativeWire.hpp"
#include "../../src/security/Ath10kSecurity.hpp"
#include "native_capability_abi.inc"
using IOReturn=int;
constexpr int kIOReturnSuccess=0,kIOReturnBadArgument=1;
class IO80211SkywalkInterface;
class Ath10kPCIDevice {
public:
 bool wep=false;bool nativeWEPEnabled() const {return wep;}
 bool legacy=false;bool nativeLegacyEnabled() const {return legacy;}
 bool enabled=false;bool nativeSAEEnabled() const {return enabled;}
 bool owe=false;bool nativeOWEEnabled() const {return owe && enabled;}
 IOReturn getCARD_CAPABILITIES(IO80211SkywalkInterface *,apple80211_capability_data *);
};
#include "native_card_capabilities.inc"
static void capabilities(){
 Ath10kPCIDevice d;assert(d.getCARD_CAPABILITIES(nullptr,nullptr)==kIOReturnBadArgument);
 struct Guard {apple80211_capability_data caps;uint64_t end=0x123456789abcdef0ull;} out;
 for(bool wep:{false,true})for(bool legacy:{false,true})for(bool enabled:{false,true})for(bool owe:{false,true}){d.owe=owe;d.wep=wep;d.legacy=legacy;d.enabled=enabled;memset(&out.caps,0xa5,sizeof(out.caps));
  assert(d.getCARD_CAPABILITIES(nullptr,&out.caps)==kIOReturnSuccess && out.caps.version==1 && out.end==0x123456789abcdef0ull);
  for(size_t i=0;i<sizeof(out.caps.capabilities);++i){
   const unsigned expected=i==0?(wep?0x0b:0x0a):i==1?(legacy?0x70:0x50):i==2?2:i==5?0x40:i==6 && enabled?1:i==9?(enabled?10:2):i==12 && owe && enabled?1:0;
   assert(out.caps.capabilities[i]==expected);
  }
 }
}
static std::array<UInt8,0x2cc> request(){
    std::array<UInt8,0x2cc> p{};
    Ath10k::htcWriteLE32(p.data()+0x10,1);Ath10k::htcWriteLE32(p.data()+0x14,8);
    Ath10k::htcWriteLE32(p.data()+0x1c,4);memcpy(p.data()+0x20,"test",4);
    Ath10k::htcWriteLE16(p.data()+0x4c,0x1234);Ath10k::htcWriteLE16(p.data()+0x4e,2);
    Ath10k::htcWriteLE32(p.data()+0x44,32);Ath10k::htcWriteLE32(p.data()+0x48,6);
    for(unsigned i=0;i<64;++i)p[0x50+i]=UInt8(i^0xa5);
    p[0x50+17]=0; // Credential bytes are not a NUL-terminated string.
    Ath10k::htcWriteLE32(p.data()+0x214,1);p[0x21c]=2;p[0x221]=0x55;
    Ath10k::htcWriteLE16(p.data()+0x228,0xd034);return p;
}
int main(){
    capabilities();
    {AirportWCL::JoinRequest e{};e.lowerAuth=1;e.upperAuth=4;
     assert(nativeJoinAuth(e)==NativeJoinAuth::Unsupported);
     assert(nativeJoinAuth(e,false,true)==NativeJoinAuth::EAP);
     auto sha=e;sha.upperAuth=1u<<11;assert(nativeJoinAuth(sha)==NativeJoinAuth::Unsupported);
     assert(nativeJoinAuth(sha,false,true)==NativeJoinAuth::EAPSHA256);
     for(unsigned bad=0;bad<7;++bad){auto q=e;
      switch(bad){case 0:q.keyLength=32;break;case 1:q.keyCipher=9;break;
       case 2:q.keyFlags=1;break;case 3:q.keyIndex=1;break;
       case 4:q.upperAuth|=8;break;case 5:q.upperAuth=1u<<15;break;
       case 6:q.transitionDisable=NativeTransitionDisable::Enterprise;break;}
      assert(nativeJoinAuth(q,false,true)==NativeJoinAuth::Unsupported);
     }
    }
    struct Output {AirportWCL::JoinRequest join;UInt64 tail=0x1234567812345678ull;} out;
    static_assert(sizeof(out.join.key)==64,"Sequoia join decoder must retain full credential slot");
    auto p=request();assert(AirportWCL::decodeJoin(p.data(),p.size(),out.join));
    assert(nativeJoinAuth(out.join)==NativeJoinAuth::PSK);
    assert(out.join.keyLength==32 && !memcmp(out.join.key,p.data()+0x50,32));
    assert(out.join.keyFlags==0x1234 && out.join.keyIndex==2);
    for(unsigned n:{0u,1u,31u,32u,33u,63u,64u}){
        Ath10k::htcWriteLE32(p.data()+0x44,n);
        memset(&out.join,0xcc,sizeof(out.join));
        assert(AirportWCL::decodeJoin(p.data(),p.size(),out.join));
        assert(out.join.keyLength==n && !memcmp(out.join.key,p.data()+0x50,n));
        for(unsigned i=n;i<64;++i)assert(out.join.key[i]==0);
        assert(out.tail==0x1234567812345678ull);
        assert(nativeJoinAuth(out.join)==(n==32?NativeJoinAuth::PSK:NativeJoinAuth::Unsupported));
    }
    for(UInt32 upper:{8u,1024u,4096u,8192u,4104u,4u}){
        for(UInt32 cipher:{6u,7u,9u,10u}){
            for(UInt32 n:{32u,64u}){
                Ath10k::htcWriteLE32(p.data()+0x14,upper);Ath10k::htcWriteLE32(p.data()+0x48,cipher);
                Ath10k::htcWriteLE32(p.data()+0x44,n);assert(AirportWCL::decodeJoin(p.data(),p.size(),out.join));
                const bool supported=n==32 && (cipher==6 || cipher==7) && (upper==8 || upper==1024);
                assert(nativeJoinAuth(out.join)==(supported?(upper==8?NativeJoinAuth::PSK:NativeJoinAuth::PSKSHA256):NativeJoinAuth::Unsupported));
            }
        }
    }
    p=request();Ath10k::htcWriteLE32(p.data()+0x14,4096);Ath10k::htcWriteLE32(p.data()+0x48,10);
    Ath10k::htcWriteLE32(p.data()+0x44,64);assert(AirportWCL::decodeJoin(p.data(),p.size(),out.join));
    assert(!memcmp(out.join.key,p.data()+0x50,64) && nativeJoinAuth(out.join)==NativeJoinAuth::Unsupported);
    AthSecurity::wipe(out.join.key,sizeof(out.join.key));for(auto b:out.join.key)assert(!b);
    // Maximum candidate count requires the entire envelope, before any decode writes.
    p=request();Ath10k::htcWriteLE32(p.data()+0x214,10);
    for(size_t n=0;n<p.size();++n){
        memset(&out.join,0xcc,sizeof(out.join));
        assert(!AirportWCL::decodeJoin(p.data(),n,out.join));
        for(auto b:reinterpret_cast<const UInt8 (&)[sizeof(out.join)]>(out.join))assert(b==0xcc);
    }
    assert(AirportWCL::decodeJoin(p.data(),p.size(),out.join));
    for(UInt32 n:{65u,0xffffffffu}){
        Ath10k::htcWriteLE32(p.data()+0x44,n);assert(!AirportWCL::decodeJoin(p.data(),p.size(),out.join));
    }
    // Match stock WCL's 8/16/16 limits before any output/key copy.
    for(const auto &field:std::array<std::pair<size_t,UInt32>,3>{{{0x90,8},{0xa4,16},{0xb8,16}}}){
        for(UInt32 count:{0u,field.second,field.second+1,0xffffffffu}){
            p=request();Ath10k::htcWriteLE32(p.data()+field.first,count);memset(&out.join,0xcc,sizeof(out.join));
            assert(AirportWCL::decodeJoin(p.data(),p.size(),out.join)==(count<=field.second));
            if(count>field.second)for(auto b:reinterpret_cast<const UInt8 (&)[sizeof(out.join)]>(out.join))assert(b==0xcc);
        }
    }
    p=request();Ath10k::htcWriteLE32(p.data()+0x14,1u<<12);Ath10k::htcWriteLE32(p.data()+0x48,10);
    for(UInt32 length:{0u,1u,32u,64u}){
        Ath10k::htcWriteLE32(p.data()+0x44,length);assert(AirportWCL::decodeJoin(p.data(),p.size(),out.join));
        assert(nativeSAEPasswordEnvelope(out.join)==(length!=0));assert(nativeJoinAuth(out.join)==NativeJoinAuth::Unsupported);
    }
    assert(nativeJoinAuth(out.join,true)==NativeJoinAuth::Unsupported); // Unknown password flags/index.
    out.join.keyFlags=out.join.keyIndex=0;
    assert(nativeJoinAuth(out.join,true)==NativeJoinAuth::SAE);
    out.join.upperAuthExt=1;assert(nativeJoinAuth(out.join,true)==NativeJoinAuth::Unsupported);out.join.upperAuthExt=0;
    out.join.keyCipher=6;assert(!nativeSAEPasswordEnvelope(out.join));out.join.keyCipher=10;
    out.join.upperAuth|=8;assert(!nativeSAEPasswordEnvelope(out.join));out.join.upperAuth=1u<<13;assert(!nativeSAEPasswordEnvelope(out.join));
    auto reject=[](std::array<UInt8,0x2cc> bad){AirportWCL::JoinRequest j{};assert(!AirportWCL::decodeJoin(bad.data(),bad.size(),j));};
    p=request();p[0x21c]=1;reject(p);p=request();memset(p.data()+0x21c,0,6);reject(p);
    p=request();Ath10k::htcWriteLE32(p.data()+0x214,0);reject(p);Ath10k::htcWriteLE32(p.data()+0x214,11);reject(p);
    p=request();Ath10k::htcWriteLE32(p.data()+0x1c,33);reject(p);
    p=request();Ath10k::htcWriteLE16(p.data()+0xd4,258);reject(p);
    p=request();Ath10k::htcWriteLE32(p.data()+0x14,0);Ath10k::htcWriteLE32(p.data()+0x44,0);
    assert(AirportWCL::decodeJoin(p.data(),p.size(),out.join) && nativeJoinAuth(out.join)==NativeJoinAuth::Open);
    // Stock WCL's extended auth 1 names OWE even when upperAuth is zero.
    // Decode and preserve all policy fields; classification must never erase them.
    for(UInt32 extension:{0u,1u,2u,0x80000000u,0xffffffffu}){
        Ath10k::htcWriteLE32(p.data()+0x18,extension);
        Ath10k::htcWriteLE32(p.data()+0x210,0xfedcba98u);
        assert(AirportWCL::decodeJoin(p.data(),p.size(),out.join));
        assert(out.join.upperAuthExt==extension && out.join.allowAuths==0xfedcba98u);
        assert(nativeJoinAuth(out.join)==(extension?NativeJoinAuth::Unsupported:NativeJoinAuth::Open));
    }
    Ath10k::htcWriteLE32(p.data()+0x18,0);
    p[0x1e9]=0xff;p[0x1ea]=0xa5;p[0x1eb]=0x7e; // Byte policy, not adjacent padding.
    struct PolicyCase {UInt8 bitmap;bool open,psk,sae;};
    const PolicyCase policies[]={
        {0,true,true,true},       // Existing unrestricted profiles.
        {1,true,false,true},      // WPA3-Personal-only: never use PSK.
        {2,true,false,false},     // SAE-PK-only: ordinary SAE is insufficient.
        {4,true,true,true},       // Enterprise restriction does not change these personal modes.
        {8,false,true,true},      // Enhanced Open-only: never plaintext Open.
        {3,true,false,false},
        {15,false,false,false},
        {16,false,false,false},   // Unidentified stock bit 4.
        {0x80,false,false,false}, // Unknown policy is preserved, never silently discarded.
        {0xff,false,false,false}
    };
    for(const auto &policy:policies){
        p[0x1e8]=policy.bitmap;
        for(UInt32 upper:{0u,8u,1024u,4096u}){
            const bool open=!upper,sae=upper==4096;
            Ath10k::htcWriteLE32(p.data()+0x14,upper);
            Ath10k::htcWriteLE32(p.data()+0x44,open?0:32);Ath10k::htcWriteLE32(p.data()+0x48,sae?10:6);
            assert(AirportWCL::decodeJoin(p.data(),p.size(),out.join));assert(out.join.transitionDisable==policy.bitmap);
            const auto expected=open?(policy.open?NativeJoinAuth::Open:NativeJoinAuth::Unsupported):
                (!sae && policy.psk?(upper==8?NativeJoinAuth::PSK:NativeJoinAuth::PSKSHA256):NativeJoinAuth::Unsupported);
            assert(nativeJoinAuth(out.join)==expected);
            assert(nativeSAEPasswordEnvelope(out.join)==(sae && policy.sae));
        }
    }
    // Live Sequoia request after capability 75: WPA2-SHA256 plus CIPHER_PWD.
    // Password representation must not select SAE or change the requested AKM.
    for(UInt32 upper:{8u,1024u}){
        p=request();Ath10k::htcWriteLE32(p.data()+0x14,upper);Ath10k::htcWriteLE32(p.data()+0x48,10);
        Ath10k::htcWriteLE32(p.data()+0x44,9);memcpy(p.data()+0x50,"test-pass",9);
        Ath10k::htcWriteLE16(p.data()+0x4c,0);Ath10k::htcWriteLE16(p.data()+0x4e,0);Ath10k::htcWriteLE32(p.data()+0x210,0x40000004);
        assert(AirportWCL::decodeJoin(p.data(),p.size(),out.join));
        for(bool experimental:{false,true})assert(nativeJoinAuth(out.join,experimental)==(upper==8?NativeJoinAuth::PSK:NativeJoinAuth::PSKSHA256));
        assert(nativePSKPasswordEnvelope(out.join) && !nativeSAEPasswordEnvelope(out.join));
        for(unsigned bad=0;bad<7;++bad){auto j=out.join;
            if(bad==0)j.keyLength=7;if(bad==1)j.keyFlags=1;if(bad==2)j.keyIndex=1;
            if(bad==3)j.upperAuth|=4096;if(bad==4)j.upperAuthExt=1;if(bad==5)j.transitionDisable=1;if(bad==6)j.bssid[0]|=1;
            assert(nativeJoinAuth(j,true)==NativeJoinAuth::Unsupported && !nativePSKPasswordEnvelope(j));
        }
        out.join.keyLength=64;memset(out.join.key,'A',64);assert(nativePSKPasswordEnvelope(out.join));
        out.join.key[63]='g';assert(!nativePSKPasswordEnvelope(out.join));
    }
    // An extension cannot be ignored for an otherwise supported PMK request or
    // a candidate-only SAE password, either.
    p=request();Ath10k::htcWriteLE32(p.data()+0x18,1);
    assert(AirportWCL::decodeJoin(p.data(),p.size(),out.join) && nativeJoinAuth(out.join)==NativeJoinAuth::Unsupported);
    Ath10k::htcWriteLE32(p.data()+0x14,4096);Ath10k::htcWriteLE32(p.data()+0x48,10);
    assert(AirportWCL::decodeJoin(p.data(),p.size(),out.join) && !nativeSAEPasswordEnvelope(out.join));
    p=request();Ath10k::htcWriteLE32(p.data()+0x14,0);Ath10k::htcWriteLE32(p.data()+0x44,0);
    assert(AirportWCL::decodeJoin(p.data(),p.size(),out.join) && nativeJoinAuth(out.join)==NativeJoinAuth::Open);
    out.join.lowerAuth=2;assert(nativeJoinAuth(out.join)==NativeJoinAuth::Unsupported);
    assert(!AirportWCL::decodeJoin(nullptr,p.size(),out.join));
}

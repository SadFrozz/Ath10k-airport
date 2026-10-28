#include <cassert>
#include <cstring>
#include <array>
#include <cstdint>
#define __MAC_15_2 150200
#define __IO80211_TARGET __MAC_15_2
#include "../src/kext/native/Ath10kNativeWire.hpp"
#include "../src/shared/Ath10kSecurity.hpp"
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
    auto reject=[](std::array<UInt8,0x2cc> bad){AirportWCL::JoinRequest j{};assert(!AirportWCL::decodeJoin(bad.data(),bad.size(),j));};
    p=request();p[0x21c]=1;reject(p);p=request();memset(p.data()+0x21c,0,6);reject(p);
    p=request();Ath10k::htcWriteLE32(p.data()+0x214,0);reject(p);Ath10k::htcWriteLE32(p.data()+0x214,11);reject(p);
    p=request();Ath10k::htcWriteLE32(p.data()+0x1c,33);reject(p);
    p=request();Ath10k::htcWriteLE16(p.data()+0xd4,258);reject(p);
    p=request();Ath10k::htcWriteLE32(p.data()+0x14,0);Ath10k::htcWriteLE32(p.data()+0x44,0);
    assert(AirportWCL::decodeJoin(p.data(),p.size(),out.join) && nativeJoinAuth(out.join)==NativeJoinAuth::Open);
    out.join.lowerAuth=2;assert(nativeJoinAuth(out.join)==NativeJoinAuth::Unsupported);
    assert(!AirportWCL::decodeJoin(nullptr,p.size(),out.join));
}

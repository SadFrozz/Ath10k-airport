#include <cassert>
#include <cstring>
#include <initializer_list>
#include "../../src/security/Ath10kWPA1KeyData.hpp"
int main(){
    using namespace AthSecurity;
    uint8_t key[32],input[513]{},output[514];for(unsigned i=0;i<32;++i)key[i]=uint8_t(i+1);
    // RFC 6229, key 01..20, stream offset256 (independent known-answer vector).
    // https://www.rfc-editor.org/rfc/rfc6229#section-2
    const uint8_t expected[]={0x02,0xe1,0xe7,0x05,0x6b,0x0f,0x62,0x39,0x00,0x49,0x64,0x22,0x94,0x3e,0x97,0xb6};
    memset(output,0x5a,sizeof(output));
    assert(decryptWPA1KeyData(key,key+16,input,16,output,16));
    assert(!memcmp(output,expected,16) && output[16]==0x5a);
    assert(decryptWPA1KeyData(key,key+16,output,16,output,16));
    for(unsigned i=0;i<16;++i)assert(!output[i]);
    for(size_t n:{size_t(1),size_t(31),size_t(512)}){
        for(size_t i=0;i<n;++i)input[i]=uint8_t(i^0xa5);
        assert(decryptWPA1KeyData(key,key+16,input,n,output,n));
        assert(decryptWPA1KeyData(key,key+16,output,n,output,n));
        assert(!memcmp(input,output,n));
    }
    memset(output,0x5a,sizeof(output));
    assert(!decryptWPA1KeyData(key,key+16,input,16,output,15));
    assert(!decryptWPA1KeyData(key,key+16,input,513,output,sizeof(output)));
    assert(!decryptWPA1KeyData(nullptr,key+16,input,16,output,sizeof(output)));
    assert(!decryptWPA1KeyData(key,nullptr,input,16,output,sizeof(output)));
    assert(!decryptWPA1KeyData(key,key+16,input,0,output,sizeof(output)));
    assert(!decryptWPA1KeyData(key,key+16,output,16,output+1,16));
    assert(!decryptWPA1KeyData(key,key+16,output+1,16,output,16));
    for(auto byte:output)assert(byte==0x5a);
}

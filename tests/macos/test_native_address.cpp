#include <cassert>
#include <cstdint>
#include <cstddef>
#include <cstring>
using UInt8=uint8_t;using UInt32=uint32_t;
#include "../../src/macos/native/Ath10kNativeAddress.hpp"
#include "../../src/macos/native/Ath10kNativeOps.hpp"
using IOReturn=int;
constexpr int kIOReturnNotReady=1,kIOReturnBadArgument=2;
struct Interface { unsigned writes=0; int result=0; UInt8 v4[16]{},v6[164]{}; };
int ath10kStoreIPv4Params(Interface *p,const void *r){++p->writes;if(!p->result)memcpy(p->v4,r,16);return p->result;}
int ath10kStoreIPv6Params(Interface *p,const void *r){++p->writes;if(!p->result)memcpy(p->v6,r,164);return p->result;}
const void *ath10kReadIPv4Params(Interface *p){return p->v4;}
int dispatch(Interface *_nativeInterface,AthNativeOp op,void *data){using N=AthNativeOp;switch(op){
#include "native_address_dispatch.inc"
default:return 99;}}
int main(){
    Interface iface;UInt8 v4[16];memset(v4,0xcd,sizeof(v4));v4[0]=192;v4[1]=168;v4[2]=1;v4[3]=2;
    assert(dispatch(&iface,AthNativeOp::setIPV4_PARAMS,v4)==0);
    assert(!memcmp(iface.v4,v4,14) && !iface.v4[14] && !iface.v4[15]);
    UInt8 v6[164];memset(v6,0xab,sizeof(v6));v6[0]=10;v6[1]=v6[2]=v6[3]=0;
    assert(dispatch(&iface,AthNativeOp::setIPV6_PARAMS,v6)==0);
    assert(!memcmp(iface.v6,v6,sizeof(v6)));
    v6[0]=1;assert(dispatch(&iface,AthNativeOp::setIPV6_PARAMS,v6)==0);
    for(size_t i=20;i<164;++i)assert(!iface.v6[i]);
    assert(!memcmp(iface.v4,v4,14)); // replacing IPv6 cannot erase IPv4
    v6[0]=0;assert(dispatch(&iface,AthNativeOp::setIPV6_PARAMS,v6)==0);
    for(auto b:iface.v6)assert(!b); // removing the final address reaches OS cache
    unsigned writes=iface.writes;
    v6[0]=11;assert(dispatch(&iface,AthNativeOp::setIPV6_PARAMS,v6)==kIOReturnBadArgument);
    v6[0]=0;v6[3]=0x80;assert(dispatch(&iface,AthNativeOp::setIPV6_PARAMS,v6)==kIOReturnBadArgument);
    assert(dispatch(&iface,AthNativeOp::setIPV4_PARAMS,nullptr)==kIOReturnBadArgument);
    assert(dispatch(nullptr,AthNativeOp::setIPV6_PARAMS,v6)==kIOReturnNotReady);
    assert(iface.writes==writes);
    iface.result=37;assert(dispatch(&iface,AthNativeOp::setIPV4_PARAMS,v4)==37);
    AthNative::IPv6Params out;memset(&out,0x5a,sizeof(out));
    for(size_t n=0;n<164;++n)assert(!AthNative::copyIPv6Params(v6,n,out));
    for(auto b:out.bytes)assert(b==0x5a);
    // Borrowed input can be unaligned; no packed/typed dereference.
    UInt8 storage[165]{};storage[1]=1;storage[5]=0xfe;storage[6]=0x80;
    assert(AthNative::copyIPv6Params(storage+1,164,out));assert(out.bytes[4]==0xfe);
    iface.result=0;
    UInt8 arp[24]{};arp[0]=1;arp[12]=10;arp[15]=1;arp[16]=2;arp[21]=7;
    assert(dispatch(&iface,AthNativeOp::setOFFLOAD_ARP,arp)==0);
    assert(!memcmp(iface.v4,v4,4)); // zero control preserves local IPv4
    assert(iface.v4[4]==10 && iface.v4[7]==1 && iface.v4[8]==2 && iface.v4[13]==7);
    arp[4]=1;arp[8]=172;arp[9]=16;arp[11]=3;
    assert(dispatch(&iface,AthNativeOp::setOFFLOAD_ARP,arp)==0);
    assert(iface.v4[0]==172 && iface.v4[3]==3);
    memset(arp+8,0,4);assert(dispatch(&iface,AthNativeOp::setOFFLOAD_ARP,arp)==0);
    for(size_t i=0;i<8;++i)assert(!iface.v4[i]);
    UInt8 ndp[72];memset(ndp,0xac,sizeof(ndp));ndp[4]=4;ndp[5]=ndp[6]=ndp[7]=0;
    assert(dispatch(&iface,AthNativeOp::setOFFLOAD_NDP,ndp)==0);
    assert(iface.v6[0]==4 && !memcmp(iface.v6+4,ndp+8,64));
    for(size_t i=68;i<164;++i)assert(!iface.v6[i]);
    ndp[4]=0;assert(dispatch(&iface,AthNativeOp::setOFFLOAD_NDP,ndp)==0);
    for(auto b:iface.v6)assert(!b);
    writes=iface.writes;ndp[4]=5;
    assert(dispatch(&iface,AthNativeOp::setOFFLOAD_NDP,ndp)==kIOReturnBadArgument);
    assert(dispatch(&iface,AthNativeOp::setOFFLOAD_NDP,nullptr)==kIOReturnBadArgument);
    assert(dispatch(nullptr,AthNativeOp::setOFFLOAD_ARP,arp)==kIOReturnNotReady);
    assert(iface.writes==writes);
    iface.result=41;assert(dispatch(&iface,AthNativeOp::setOFFLOAD_ARP,arp)==41);
    AthNative::IPv4Params oldOut;memset(&oldOut,0x5a,sizeof(oldOut));
    for(size_t n=0;n<24;++n)assert(!AthNative::translateARPParams(arp,n,v4,oldOut));
    for(auto b:oldOut.bytes)assert(b==0x5a);
    for(size_t n=0;n<72;++n)assert(!AthNative::translateNDPParams(ndp,n,out));
}

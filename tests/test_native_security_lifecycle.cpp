#include <cassert>
#include <cstring>
#include "../src/kext/native/Ath10kNativeCandidates.hpp"
#include "../src/kext/native/Ath10kNativeWire.hpp"
#include "../src/shared/Ath10kSupplicant.hpp"
#include "sha256_vectors.inc"
// No crypto operation is invoked: begin stores the fixture and reset must
// wipe it. Definitions are deliberately absent to catch accidental operations.
struct Ath10kKernelCrypto {};
class Ath10kPCIDevice {
public:
    class NativeSecurity;
    NativeSecurity *_nativeSecurity=nullptr;
    AirportWCL::JoinRequest _nativeJoin{};
    void discardNativeSecurity();
};
#include "native_security_class.inc"
#include "native_security_discard.inc"
int main(){
    Ath10kPCIDevice d;Ath10kPCIDevice::NativeSecurity security;
    d._nativeSecurity=&security;
    assert(security.supplicant.begin(s_pmk,s_snonce,s_sta,s_ap,s_rsn,sizeof(s_rsn),6));
    memset(security.reply,0xa5,sizeof(security.reply));memset(security.keys,0x5a,sizeof(security.keys));
    memset(security.supplicant.output,0x3c,sizeof(security.supplicant.output));
    memset(security.supplicant.keys,0x4b,sizeof(security.supplicant.keys));
    security.supplicant.outputLength=123;
    security.ready=security.replyPending=security.keysPending=security.authorizePending=true;
    security.replyLength=120;security.keyOperation=3;security.pairDeadline=5000;
    security.cachedGeneration=12;
    memset(d._nativeJoin.key,0x7d,sizeof(d._nativeJoin.key));
    memcpy(d._nativeJoin.bssid,s_ap,6);
    d.discardNativeSecurity();
    AthSecurity::Supplicant<Ath10kKernelCrypto,true> pristine;pristine.reset();
    assert(!memcmp(&security.supplicant,&pristine,sizeof(pristine)));
    for(auto v:security.reply)assert(!v);
    for(auto v:security.keys)assert(!v);
    for(auto v:d._nativeJoin.key)assert(!v);
    assert(!security.ready && !security.replyPending && !security.keysPending && !security.authorizePending);
    assert(!security.replyLength && !security.keyOperation && !security.pairDeadline);
    // Nonsecret association metadata survives until terminal event acceptance.
    assert(!memcmp(d._nativeJoin.bssid,s_ap,6) && security.cachedGeneration==12);
    d.discardNativeSecurity();
    assert(!memcmp(&security.supplicant,&pristine,sizeof(pristine)));
    d._nativeSecurity=nullptr;d.discardNativeSecurity();
}

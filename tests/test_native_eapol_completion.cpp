#include <cassert>
#include <initializer_list>
#include <cstring>
#include "../src/kext/Ath10kWMI.hpp"
struct Driver {
    Ath10k::ConnectionState state{};
    struct {bool authorizePending=false,pairUpdateReply=false,ptkUpdatePending=false;UInt32 ptkUpdateGeneration=0;} security;
    unsigned discarded=0;
    void discardNativeSecurity(){++discarded;security={};}
    void service();
};
#include "native_eapol_completion.inc"
#include "native_eapol_retirement.inc"
static void start(Driver &d,unsigned phase){
    d.state={};d.security={};d.security.authorizePending=true;d.discarded=0;
    d.state.securityPhase=phase;d.state.txId=17;d.state.txOwned=true;
    d.state.lastTxEAPOL=true;d.state.eapolCompletion.begin(17);
}
int main(){
    Driver d;
    for(unsigned phase: {0u,3u,5u}){
        start(d,phase);d.service();assert(d.security.authorizePending);
        // Wrong/late ID cannot finish the outstanding reply.
        d.state.eapolCompletion.retire(16,0);d.service();assert(d.security.authorizePending);
        d.state.txStatus=0;retire(d.state);
        // Subsequent serial management TX must not replace EAPOL's result.
        d.state.txId=18;d.state.txStatus=7;d.state.txOwned=true;d.state.txComplete=false;
        d.service();assert(!d.security.authorizePending && !d.state.cancelRequested);
        assert(d.state.authorizeRequested==(phase==3));
        assert(!d.state.eapolCompletion.pending);
        d.service();assert(!d.discarded);
        start(d,phase);d.state.txStatus=1;retire(d.state);
        d.state.txId=18;d.state.txStatus=0;d.state.txComplete=true;
        d.service();assert(d.discarded==1 && d.state.cancelRequested && !d.state.authorizeRequested);
        assert(!strcmp(d.state.error,"native-eapol-tx-failed"));
    }
    for(unsigned failure=0;failure<4;++failure){
        start(d,5);d.security.pairUpdateReply=true;d.security.ptkUpdateGeneration=7;
        d.state.securityGeneration=failure==1?7:8;d.state.portAuthorized=failure!=2;
        d.state.txStatus=failure==3?1:0;retire(d.state);d.service();
        assert(d.security.ptkUpdatePending==(failure==0));
        assert(d.state.cancelRequested==(failure!=0));
        if(!failure)assert(d.security.ptkUpdateGeneration==8);
    }
    start(d,5);d.state.txStatus=0;retire(d.state);
    d.security.authorizePending=false;d.service();assert(!d.state.authorizeRequested);
    // Connection retirement clears any old completion before association reuse.
    d.state={};assert(!d.state.eapolCompletion.pending && !d.state.eapolCompletion.complete);
    start(d,3);d.state.txStatus=0;retire(d.state);
    d.state.eapolCompletion.retire(17,9);d.service();assert(d.state.authorizeRequested);
}

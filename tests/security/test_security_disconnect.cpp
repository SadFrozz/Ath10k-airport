#define ATH10K_CHANNEL_SWITCH_TEST
#include "../core/test_connection.cpp"
#include <cstdio>
using D=Ath10k::DisconnectStage;
// All 36 bytes captured on QCA6174 0.0.88, not a fabricated SEC_IND payload.
static std::vector<UInt8> capturedClear(){
    return {1,0,28,0,0,59,0,0,11,128,71,0,0,0,0,0,0,0,0,0,136,54,67,0,4,0,0,1,0,0,192,0,1,0,4,0};
}
static std::vector<UInt8> sec(UInt16 peer,UInt8 flags){
    auto p=capturedClear();p[9]=flags;Ath10k::htcWriteLE16(p.data()+10,peer);return p;
}
static std::vector<UInt8> unmap(UInt16 peer){
    std::vector<UInt8> p={1,0,4,0,0,0,0,0,4,0,0,0};Ath10k::htcWriteLE16(p.data()+10,peer);return p;
}
static std::vector<UInt8> map(const Ath10k::ConnectionState &s,UInt16 peer,bool own=true){
    std::vector<UInt8> p(20);p[0]=1;p[2]=12;p[8]=3;Ath10k::htcWriteLE16(p.data()+10,peer);
    memcpy(p.data()+12,s.bssid,6);if(!own)p[12]^=2;return p;
}
static const char *parse(Ath10k::ConnectionState &s,const std::vector<UInt8> &p){
    Ath10k::HTCCreditState c{};c.initialize(2,256,2);Ath10k::RxSetupState htt{};
    htt.ringOwned=true;
    return Ath10k::parseHTTSetup(p.data(),p.size(),1,c,htt,&s);
}
static void parserCases(){
    {
        Ath10k::ConnectionState s{};s.secure=true;s.pairCipher=AthSecurity::cipherTKIP;s.securityPhase=1;
        for(unsigned i=0;i<32;++i)s.temporalKey[i]=UInt8(i+1);
        UInt8 command[256]{};assert(Ath10k::buildSecurityWMI(command,sizeof(command),2,s)==144);
        assert(Ath10k::connLE32(command+36)==2 && Ath10k::connLE32(command+96)==32);
        assert(!memcmp(command+112,s.temporalKey,16));
        assert(!memcmp(command+128,s.temporalKey+24,8) && !memcmp(command+136,s.temporalKey+16,8));
        for(unsigned i=0;i<32;++i)assert(s.temporalKey[i]==i+1);
        assert(Ath10k::expectedSecurityIndication(s)==0x84);
        s.disconnect=D::ClearPair;assert(Ath10k::buildDisconnectWMI(command,sizeof(command),2,s)==144);
        assert(!Ath10k::connLE32(command+36) && Ath10k::connLE32(command+100)==8 && Ath10k::connLE32(command+104)==8);
        for(unsigned i=112;i<144;++i)assert(!command[i]);
        s.pmfRequired=true;assert(!Ath10k::buildSecurityWMI(command,sizeof(command),2,s));
        memset(s.installedPair,0xa5,sizeof(s.installedPair));Ath10k::wipeConnectionSecrets(s);
        for(auto v:s.temporalKey)assert(!v);for(auto v:s.installedPair)assert(!v);
    }

    for(UInt8 cipher:{UInt8(2),UInt8(4)})for(D stage:{D::ClearPair,D::ClearGroup}){
        Ath10k::ConnectionState s{};s.secure=true;s.groupCipher=cipher;s.groupIndex=2;s.disconnect=stage;
        UInt8 command[256];memset(command,0x5a,sizeof(command));
        const UInt32 length=stage==D::ClearGroup && cipher==2?32:16;
        assert(Ath10k::buildDisconnectWMI(command,256,2,s)==112+length);
        assert(Ath10k::connLE32(command+36)==0 && Ath10k::connLE32(command+96)==length);
        assert(Ath10k::connLE32(command+28)==(stage==D::ClearGroup?2u:0u));
        assert(Ath10k::connLE32(command+32)==(stage==D::ClearGroup?1u:0u));
        assert(Ath10k::connLE32(command+100)==(length==32?8u:0u));
        assert(Ath10k::connLE32(command+104)==(length==32?8u:0u));
        for(UInt32 at=112;at<256;++at)assert(!command[at]);
    }

    for(D stage:{D::ClearPair,D::ClearGroup}){
        Ath10k::ConnectionState s{};s.stage=LinkStage::Connected;s.secure=true;s.securityPhase=5;
        s.disconnect=stage;s.submitted=true;s.peerCount=2;s.peerIDs[2]=(1u<<7)|(1u<<8);
        assert(!parse(s,unmap(71)) && s.peerCount==1 && Ath10k::retiredPeer(s,71));
        const UInt8 expected=stage==D::ClearPair?0x80:0;
        assert(!parse(s,sec(71,expected^0x80)) && !s.securityAck);
        assert(!parse(s,sec(999,expected)) && !s.securityAck);
        assert(!parse(s,sec(71,expected)) && s.securityAck && s.securityInd.lateClears==1);
        assert(s.stage==LinkStage::Connected && !s.portAuthorized && s.securityPhase==5);
        s.securityAck=false;assert(!parse(s,unmap(72)) && !s.peerCount);
        assert(!parse(s,capturedClear()));
        assert(s.stage==LinkStage::Connected); // teardown unmaps do not fail a new association
        Ath10k::resetDisconnected(s);
        assert(!Ath10k::retiredPeer(s,71) && !s.securityAck && s.securityInd.received==4);
    }
    // Reused ID cannot acknowledge a clear for our old AP mapping.
    Ath10k::ConnectionState reused{};reused.stage=LinkStage::Connected;reused.secure=true;
    reused.disconnect=D::ClearPair;reused.submitted=true;reused.peerIDs[2]=1u<<7;reused.peerCount=1;
    assert(!parse(reused,unmap(71)));assert(!parse(reused,map(reused,71,false)));
    assert(!Ath10k::retiredPeer(reused,71));assert(!parse(reused,capturedClear()) && !reused.securityAck);
    // NONE may not acknowledge install/rekey, open the port, or reset PN/key material.
    for(UInt32 phase:{0u,1u,2u,3u,4u,5u}){
        Ath10k::ConnectionState s{};s.stage=LinkStage::Connected;s.secure=true;s.securityPhase=phase;
        s.submitted=true;s.peerIDs[2]=1u<<7;s.peerCount=1;s.pairPN[0]=42;s.temporalKey[0]=0x55;
        assert(!parse(s,capturedClear()));
        assert(!s.securityAck && !s.portAuthorized && s.securityPhase==phase && s.pairPN[0]==42 && s.temporalKey[0]==0x55);
    }
    Ath10k::ConnectionState idle{};assert(!parse(idle,capturedClear()) && !idle.securityAck);
    // A cipher loss of an authorized mapped peer closes the port before next TX/RX.
    Ath10k::ConnectionState live{};live.stage=LinkStage::Connected;live.secure=true;live.portAuthorized=true;
    live.peerCount=1;live.peerIDs[2]=1u<<7;live.securityPhase=5;live.pairPN[0]=42;
    assert(!parse(live,capturedClear()));
    assert(!live.portAuthorized && live.cancelRequested && live.pairPN[0]==42 && !live.securityAck);
    assert(!strcmp(live.error,"firmware-key-cleared"));
    // Malformed layout/fields/credits are still rejected transactionally.
    for(unsigned n=0;n<36;++n){
        Ath10k::ConnectionState s{};auto p=capturedClear();p.resize(n);
        assert(parse(s,p) && !s.securityInd.received && !s.securityAck);
    }
    auto p=capturedClear();p.push_back(0);p[2]=29;Ath10k::ConnectionState s{};assert(parse(s,p));
    assert(parse(s,sec(2048,0x80)));assert(parse(s,sec(71,0x88)));
    p=capturedClear();addPkgCredit(p);p[p.size()-3]=255;
    Ath10k::HTCCreditState c{};c.initialize(2,256,2);assert(c.reserve(20));const auto saved=c;
    Ath10k::RxSetupState htt{};htt.ringOwned=true;s.secure=true;s.disconnect=D::ClearPair;s.submitted=true;s.peerIDs[2]=1u<<7;
    assert(Ath10k::parseHTTSetup(p.data(),p.size(),1,c,htt,&s));
    assert(!s.securityInd.received && !s.securityAck && c.available==saved.available && c.outstanding==saved.outstanding);
}
static void receive(ConnectionDriver &d,const std::vector<UInt8> &p){
    d.deliver(1,p);assert(!d.drainWMIRuntime());
}
static std::vector<UInt8> stopped(bool credit){
    std::vector<UInt8> p={2,0,12,0,0,0,0,0,2,0x50,0,0,4,0,41,0,0,0,0,0};
    if(credit)addPkgCredit(p);
    return p;
}
static void runtimeCases(){
    // Only SEC_IND is captured verbatim. MAP/UNMAP, credits and WMI replies
    // below model Linux wire layouts; logs did not capture their payloads.
    for(D target:{D::ClearPair,D::ClearGroup})for(unsigned hold=0;hold<4;++hold){
        ConnectionDriver d;d.connect();assert(d.networkUp && d._wmiLive.active);
        auto association=d._regs.tx3Consume;auto &s=d._connection;
        s.secure=true;s.securityPhase=5;s.pairInstalled=true;s.groupIndex=2;s.groupInstalled[2]=true;
        s.temporalKey[0]=0x55;s.groupKey[0]=0x66;s.pairPN[0]=42;
        s.securityGeneration=41;s.groupKeySerial=100;s.pairKeySerial=51;s.pairKeyEpoch=51;
        for(unsigned slot=0;slot<4;++slot){s.groupInstalled[slot]=true;s.groupKeyEpoch[slot]=97+slot;
            memset(s.installedGroups[slot],int(0x80+slot),32);
            for(unsigned tid=0;tid<17;++tid)s.groupPN[slot][tid]=100+slot*17+tid;}

        receive(d,map(s,55));receive(d,map(s,71));assert(s.peerCount==3);
        assert(Ath10k::requestDisconnect(s,2000));d.networkLink(false);
        bool injected=false;unsigned clearCommands=0,deleteCommands=0;D pending=D::None;
        auto credit=[&](){d.deliver(2,{0,2,8,0,8,0,0,0,1,4,0,0,2,1,0,0});};
        d._regs.tx3Consume=[&](){
            ++d.commands;
            if(s.disconnect==D::ClearPair || s.disconnect==D::ClearGroup){
                ++clearCommands;
                if(s.disconnect==target){
                    injected=true;receive(d,unmap(7));receive(d,unmap(55));receive(d,unmap(71));
                    receive(d,capturedClear());assert(!s.peerCount && d._wmiLive.active);
                    if(hold==1){pending=s.disconnect;return;}
                }else receive(d,sec(71,0x80));
            }else if(s.disconnect==D::DeletePeer){
                ++deleteCommands;assert(!s.peerCount && s.peerCreateIssued);
                // A late abort arrives after software key retirement, while
                // submitted now belongs to DELETE_PEER, not INSTALL_KEY.
                s.cancelRequested=true;s.securityPhase=0;s.securityAck=false;
            }
            else if(s.disconnect==D::Stop){
                if(hold==2){pending=D::Stop;credit();}else d.deliver(2,stopped(true));return;
            }else if(s.disconnect==D::Barrier){
                if(hold==3){pending=D::Barrier;credit();}
                else d.deliver(2,echoPacket(0xa7590001));
                return;
            }else assert(s.disconnect==D::Down);
            credit();
        };
        for(unsigned i=0;i<60 && s.disconnect!=D::None && pending==D::None;++i)d.tick(2010+i*10);
        assert(injected && d._wmiLive.active && !d._dmaQuarantine && !d.networkUp);
        if(hold){
            for(unsigned i=0;i<10;++i)d.tick(2700+i*10);
            assert(s.disconnect==pending && s.stage!=LinkStage::Disabled && d._wmiLive.active);
            assert(s.temporalKey[0]==0x55 && s.pairPN[0]==42); // no premature cleanup
            assert(s.securityGeneration==41);
            for(unsigned slot=0;slot<4;++slot){assert(s.groupInstalled[slot]);
                for(auto keyByte:s.installedGroups[slot])assert(keyByte==0x80+slot);
                for(unsigned tid=0;tid<17;++tid)assert(s.groupPN[slot][tid]==100+slot*17+tid);}

            if(hold==1){assert(s.wmiOwned && d._wmi.credits.outstanding);credit();}
            else if(hold==2){assert(!s.stopReply);d.deliver(2,stopped(false));}
            else {assert(!d._connectionEcho.replyReceived);d.deliver(2,echoPacket(0xa7590001,false));}
            for(unsigned i=0;i<60 && s.disconnect!=D::None;++i)d.tick(2900+i*10);
        }
        assert(s.stage==LinkStage::Disabled && s.disconnect==D::None && s.disconnectCount==1);
        assert(d._wmiLive.active && d._rxSetup.ringOwned && !s.temporalKey[0] && !s.groupKey[0] && !s.pairPN[0]);
        assert(!s.wmiOwned && !s.txOwned && !s.peerCount && deleteCommands==1);
        assert(s.securityGeneration==42 && s.groupKeySerial==100);
        assert(s.pairKeySerial==51 && !s.pairKeyEpoch);
        for(unsigned slot=0;slot<4;++slot){assert(!s.groupInstalled[slot] && !s.groupKeyEpoch[slot]);
            for(auto keyByte:s.installedGroups[slot])assert(!keyByte);
            for(auto pn:s.groupPN[slot])assert(!pn);}

        assert(clearCommands==(target==D::ClearPair?1u:2u));
        assert(!Ath10k::retiredPeer(s,71) && s.securityInd.received);
        // The same live driver re-associates after cleanup, without rematching.
        s.secure=false;const auto &b=d._wmiBSS.entries[0];memcpy(s.bssid,b.bssid,6);
        memcpy(s.ssid,b.ssid,b.ssidLength);s.ssidLength=b.ssidLength;s.stage=LinkStage::Scan;
        d._regs.tx3Consume=association;
        for(unsigned i=0;i<60 && !d.networkUp;++i)d.tick(4000+i*10);
        assert(d.networkUp && d._wmiLive.active && s.stage==LinkStage::Connected);d.releaseWMIRuntime();
    }
}
static void retirementOwners(){
    // Invoke the production retirement routine with each independent owner
    // held after ECHO. It must retain keys/state until that owner retires.
    for(unsigned owner=0;owner<9;++owner){
        ConnectionDriver d;auto &s=d._connection;
        s.stage=LinkStage::Connected;s.disconnect=D::Barrier;s.submitted=true;
        s.sinceMs=100;s.temporalKey[0]=0x5a;
        d._wmiScan.completed=true;d._connectionEcho.replyReceived=true;
        d._connectionEcho.cookie=0xa7590001;
        if(owner==0)d._connectionEcho.cookie^=1;
        if(owner==1)d._rxSetup.pendingMPDUs=1;
        if(owner==2)d._wmiScan.completed=false;
        if(owner==3)d._wmiScan.txOwned=true;
        if(owner==4)s.txOwned=true;
        if(owner==5)s.dataPending=1;
        if(owner==6)d._wmi.credits.outstanding=1;
        if(owner==7)s.peerCount=1;
        if(owner==8)s.pmfTXPending=true;
        assert(!d.serviceDisconnect(110));
        assert(s.disconnect==D::Barrier && s.temporalKey[0]==0x5a && !s.disconnectCount);
        d._connectionEcho.cookie=0xa7590001;d._rxSetup.pendingMPDUs=0;
        d._wmiScan.completed=true;d._wmiScan.txOwned=false;s.txOwned=false;
        s.dataPending=0;d._wmi.credits.outstanding=0;s.peerCount=0;s.pmfTXPending=false;
        assert(!d.serviceDisconnect(120));
        assert(s.stage==LinkStage::Disabled && s.disconnect==D::None && s.disconnectCount==1 && !s.temporalKey[0]);
    }
    ConnectionDriver d;auto &s=d._connection;
    s.stage=LinkStage::Connected;s.disconnect=D::Drain;s.sinceMs=100;
    d._wmiScan.completed=true;d._wmiScan.txOwned=true;
    assert(!d.serviceDisconnect(110) && s.disconnect==D::Drain && !s.submitted);
}
static void rejectedReceiptRecovery(){
    ConnectionDriver d;d.connect();auto &s=d._connection;
    auto association=d._regs.tx3Consume;
    s.secure=true;s.securityPhase=1;s.submitted=true;s.pairInstalled=true;
    s.temporalKey[0]=0x55;s.sinceMs=2000;
    receive(d,sec(7,4)); // group TKIP is not this outstanding pair CCMP install
    assert(s.securityReceiptRejected && s.cancelRequested && !s.portAuthorized && d._wmiLive.active);
    d._regs.tx3Consume=[&](){
        ++d.commands;
        if(s.disconnect==D::ClearPair)receive(d,sec(7,0x80));
        else if(s.disconnect==D::ClearGroup)receive(d,sec(7,0));
        else if(s.disconnect==D::DeletePeer)receive(d,unmap(7));
        else if(s.disconnect==D::Stop){d.deliver(2,stopped(true));return;}
        else if(s.disconnect==D::Barrier){d.deliver(2,echoPacket(0xa7590001));return;}
        else assert(s.disconnect==D::Down);
        d.deliver(2,{0,2,8,0,8,0,0,0,1,4,0,0,2,1,0,0});
    };
    for(unsigned i=0;i<80 && s.stage!=LinkStage::Disabled;++i)d.tick(2010+i*10);
    assert(s.stage==LinkStage::Disabled && s.disconnectCount==1 && !s.temporalKey[0]);
    assert(d._wmiLive.active && d._rxSetup.ringOwned && !d._dmaQuarantine);
    assert(s.securityInd.rejected==1 && !s.securityReceiptRejected);
    s.secure=false;const auto &b=d._wmiBSS.entries[0];memcpy(s.bssid,b.bssid,6);
    memcpy(s.ssid,b.ssid,b.ssidLength);s.ssidLength=b.ssidLength;s.stage=LinkStage::Scan;
    d._regs.tx3Consume=association;
    for(unsigned i=0;i<60 && !d.networkUp;++i)d.tick(4000+i*10);
    assert(d.networkUp && d._wmiLive.active);d.releaseWMIRuntime();
}
static void rejectedReceiptTransport(){
    for(D stage:{D::ClearPair,D::ClearGroup}){
        Ath10k::ConnectionState s{};s.secure=true;s.disconnect=stage;s.submitted=true;
        s.peerId=7;s.peerIDs[0]=1u<<7;s.securityPhase=5;
        assert(!parse(s,sec(7,stage==D::ClearPair?0x80:0)) && s.securityAck);
        assert(!parse(s,sec(7,0x86))); // late install, never a clear completion
        assert(s.securityAck && !s.cancelRequested && s.disconnect==stage);
        assert(s.securityInd.rejected==1 && !s.securityInd.ack);
    }

    for(bool wep:{false,true}){
        Ath10k::ConnectionState s{};s.stage=LinkStage::Connected;s.secure=true;
        s.peerId=7;s.peerCount=1;s.peerIDs[0]=1u<<7;s.portAuthorized=true;
        s.wmiOwned=true;s.temporalKey[0]=0x55;
        if(wep){s.securityAKM=1;s.pairCipher=1;assert(Ath10k::armWEPKeyReceipt(s,1,2,7,3));}
        else {s.securityPhase=1;s.submitted=true;}
        auto f=sec(8,wep?3:0x86);addPkgCredit(f);
        Ath10k::HTCCreditState credits;assert(credits.initialize(2,256,2) && credits.reserve(36));
        Ath10k::RxSetupState rx;rx.ringOwned=true;
        // Invalid trailer must commit neither association failure nor credits.
        auto malformed=f;malformed[malformed.size()-3]=2;
        assert(Ath10k::parseHTTSetup(malformed.data(),malformed.size(),1,credits,rx,&s));
        assert(!s.securityReceiptRejected && s.portAuthorized && credits.outstanding==1);
        assert(!Ath10k::parseHTTSetup(f.data(),f.size(),1,credits,rx,&s));
        assert(!credits.outstanding && credits.available==2);
        assert(s.cancelRequested && s.securityReceiptRejected && !s.portAuthorized && !s.securityAck);
        assert(s.wmiOwned && s.temporalKey[0]==0x55); // no speculative DMA/key retirement
        assert(s.securityInd.firstRejectPeer==8 && s.securityInd.firstRejectExpectedPeer==7);
        const auto flags=s.securityInd.firstRejectFlags;
        assert(!parse(s,sec(7,0))); // subsequent NONE must not overwrite first failure
        assert(s.securityInd.firstRejectPeer==8 && s.securityInd.firstRejectFlags==flags);
        if(wep)assert(s.wepKeyReceipt.active && !s.wepKeyReceipt.received);
        Ath10k::resetDisconnected(s);assert(!s.securityReceiptRejected && s.securityInd.rejected==1);
    }
}
int main(){
    parserCases();runtimeCases();retirementOwners();rejectedReceiptTransport();rejectedReceiptRecovery();
    puts("SECURITY_IND teardown regression passed: captured 36 bytes, early unmaps, partial/reused peers, NONE/install isolation, credit/STOP/ECHO gates and reconnect without runtime restart.");
}

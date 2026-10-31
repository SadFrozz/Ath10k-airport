#define ATH10K_RX_REFILL_TEST
#include "test_rx_setup.cpp"
using Ath10k::LinkStage;
static std::vector<UInt8> managementResponse(const Ath10k::ConnectionState &s,bool assoc,UInt16 status=0){
    std::vector<UInt8> p(92);p[0]=2;p[2]=84;
    Ath10k::htcWriteLE32(p.data()+8,0x7001);p[12]=40;p[14]=44;
    Ath10k::htcWriteLE32(p.data()+16,s.ap.rxChannel);Ath10k::htcWriteLE32(p.data()+32,30);
    p[56]=32;p[58]=17;UInt8 *f=p.data()+60;f[0]=assoc?0x10:0xb0;
    for(unsigned i=0;i<6;++i){f[4+i]=s.local[i];f[10+i]=f[16+i]=s.bssid[i];}
    if(assoc){Ath10k::htcWriteLE16(f+26,status);Ath10k::htcWriteLE16(f+28,0xc007);}
    else {Ath10k::htcWriteLE16(f+26,2);Ath10k::htcWriteLE16(f+28,status);}
    if(assoc && s.htEnabled){
        std::vector<UInt8> ies={45,26};ies.insert(ies.end(),s.ap.ht,s.ap.ht+26);
        if(s.vhtEnabled){ies.insert(ies.end(),{191,12});ies.insert(ies.end(),s.ap.vht,s.ap.vht+12);}
        ies.insert(ies.end(),{221,24,0,0x50,0xf2,2,1,1,0,0});ies.insert(ies.end(),s.ap.wmm,s.ap.wmm+16);
        const unsigned len=30+ies.size(),aligned=(len+3)&~3u;p.resize(60+aligned);
        std::copy(ies.begin(),ies.end(),p.begin()+90);
        Ath10k::htcWriteLE16(p.data()+2,p.size()-8);Ath10k::htcWriteLE32(p.data()+32,len);
        Ath10k::htcWriteLE16(p.data()+56,aligned);
    }
    return p;
}
static std::vector<UInt8> comebackResponse(const Ath10k::ConnectionState &state,UInt32 tu){
    auto p=managementResponse(state,true,30);const UInt32 old=Ath10k::wmiReadLE32(p.data()+32),bytes=old+7,aligned=(bytes+3)&~3u;
    p.resize(60+aligned);UInt8 *ie=p.data()+60+old;ie[0]=56;ie[1]=5;ie[2]=3;Ath10k::htcWriteLE32(ie+3,tu);
    Ath10k::htcWriteLE16(p.data()+2,p.size()-8);Ath10k::htcWriteLE32(p.data()+32,bytes);Ath10k::htcWriteLE16(p.data()+56,aligned);return p;
}
static std::vector<UInt8> completion(UInt16 id=0){
    std::vector<UInt8> p(16);p[0]=1;p[2]=8;p[8]=7;p[10]=1;Ath10k::htcWriteLE16(p.data()+12,id);return p;
}
static std::vector<UInt8> mgmtCompletion(UInt32 id=1,UInt32 status=0){
    // Exact firmware capture: 01000c00000800000e0000000100000000000000.
    std::vector<UInt8> p={1,0,12,0,0,8,0,0,14,0,0,0,1,0,0,0,0,0,0,0};
    Ath10k::htcWriteLE32(p.data()+12,id);Ath10k::htcWriteLE32(p.data()+16,status);return p;
}
static void mgmtCompletionTests(){
    auto check=[](std::vector<UInt8> p,bool valid,bool owned=true,bool management=true,bool done=false){
        Ath10k::ConnectionState s{};s.txId=1;s.txOwned=owned;s.txManagement=management;s.txComplete=done;
        Ath10k::RxSetupState rx{};rx.ringOwned=true;
        Ath10k::HTCCreditState credits{};credits.initialize(2,256,2);assert(credits.reserve(120));
        const char *error=Ath10k::parseHTTSetup(p.data(),p.size(),1,credits,rx,&s);
        assert((error==nullptr)==valid);
        if(valid){assert(s.txComplete && s.txOwned && s.txStatus==Ath10k::connectionReadLE32(p.data()+16));}
        else {assert(s.txComplete==done && s.txOwned==owned);}
        assert(credits.outstanding==1);
    };
    auto p=mgmtCompletion();check(p,true);
    for(unsigned n=0;n<p.size();++n)check(std::vector<UInt8>(p.begin(),p.begin()+n),false);
    for(unsigned status=1;status<=2;++status)check(mgmtCompletion(1,status),true);
    check(mgmtCompletion(1,3),false);check(mgmtCompletion(0x10001),false);
    check(p,false,false);check(p,false,true,false);check(p,false,true,true,true);
    p.resize(28);p[2]=20;check(p,true);
    p=mgmtCompletion();p[1]=2;p[4]=8;p[2]=20;
    p.insert(p.end(),{1,4,0,0,2,3,0,0});check(p,false); // invalid credit: no commit
}
class ConnectionDriver:public SetupDriver {
public:
    unsigned commands=0,packets=0,temporaryAssociationRejects=0;UInt32 comebackTU=1000;
    bool suppressCompletion=false,wrongID=false,rejectAssociation=false;
    ConnectionDriver(){
        run();deliver(2,scanPacket(1));tick(1250);deliver(2,scanPacket(2));tick(1260);
        _wmi.htCapability=1;
        assert(_wmiScan.completed);
        _networkEnabled=true;auto &s=_connection;s.stage=LinkStage::Scan;s.ssidLength=4;
        memcpy(s.ssid,"TEST",4);const UInt8 mac[6]={2,1,2,3,4,5};const UInt8 ap[6]={2,6,7,8,9,10};
        memcpy(s.local,mac,6);memcpy(s.bssid,ap,6);
        _wmiBSS.count=1;auto &b=_wmiBSS.entries[0];memcpy(b.ssid,s.ssid,4);b.ssidLength=4;
        memcpy(b.bssid,ap,6);b.capabilities=0x421;b.beaconInterval=100;b.rxChannel=b.advertisedChannel=6;
        b.rateCount=4;const UInt8 rates[]={0x82,0x84,0x8b,0x96};memcpy(b.rates,rates,4);
        _packetBuffer.isAllocated=_packetCommand.isAllocated=_packetFragments.isAllocated=false;
        _packetBuffer.iovm=0x1100000;_packetCommand.iovm=0x1200000;_packetFragments.iovm=0x1300000;
        _connectionCommand.isAllocated=false;_connectionCommand.iovm=0x1400000;
        _regs.tx3Consume=[this](){
            auto &s=_connection;const UInt8 *f=static_cast<const UInt8 *>(_connectionCommand.virtualAddress());
            if(s.stats.step){
                assert(s.stats.submitted && s.wmiOwned);assert(f[5]==s.wmiSequence);++commands;
                if(s.stats.step==2)deliver(2,echoPacket(Ath10k::statsCookie(s)));
                else deliver(2,{0,2,8,0,8,0,0,0,1,4,0,0,2,1,0,0});
                return;
            }
            if(s.maintenance.step){
                assert(s.maintenance.submitted && s.wmiOwned);assert(f[5]==s.wmiSequence);++commands;
                if(s.maintenance.step==8)deliver(2,echoPacket(Ath10k::apMaintenanceCookie(s)));
                else deliver(2,{0,2,8,0,8,0,0,0,1,4,0,0,2,1,0,0});
                return;
            }
            assert(s.submitted && s.wmiOwned);assert(f[5]==s.wmiSequence);++commands;
            if(s.disconnect!=Ath10k::DisconnectStage::None){
                using D=Ath10k::DisconnectStage;
                if(s.disconnect==D::DeletePeer)deliver(1,{1,0,4,0,0,0,0,0,4,0,7,0});
                else if(s.disconnect==D::Stop){
                    auto event=std::vector<UInt8>{2,0,12,0,0,0,0,0,2,0x50,0,0,4,0,41,0,0,0,0,0};
                    addPkgCredit(event);deliver(2,event);return;
                }else if(s.disconnect==D::Barrier){deliver(2,echoPacket(0xa7590000u|((s.disconnectCount+1)&0xffff)));return;}
                else assert(s.disconnect==D::Down && (s.vdevUp || s.csa.blocked));
                deliver(2,{0,2,8,0,8,0,0,0,1,4,0,0,2,1,0,0});return;
            }

            if(s.stage==LinkStage::Start){
                assert(Ath10k::wmiReadLE32(f+8)==0x5003 && f[14]==88);
                assert(Ath10k::wmiReadLE32(f+92)==(s.operatingChannel>14?5000+5*s.operatingChannel:2407+5*s.operatingChannel) && (Ath10k::wmiReadLE32(f+104)&63)==Ath10k::connectionPhyMode(s));
                std::vector<UInt8> p(56);p[0]=2;p[2]=48;p[8]=1;p[9]=0x50;p[12]=40;p[14]=40;
                p[32]=3;p[36]=3;
                addPkgCredit(p);deliver(2,p);
            }else if(s.stage==LinkStage::Peer){
                assert(f[14]==97 && Ath10k::sameMAC(f+20,s.bssid));
                std::vector<UInt8> p(20);p[0]=1;p[2]=12;p[8]=3;p[10]=7;memcpy(p.data()+12,s.bssid,6);deliver(1,p);
                deliver(2,{0,2,8,0,8,0,0,0,1,4,0,0,2,1,0,0});
            }else if(s.stage==LinkStage::Barrier){deliver(2,echoPacket(0xa7100047));}
            else {
                assert(s.assocReply && s.aid==7 && !networkUp);
                if(s.stage==LinkStage::PeerAssoc){
                    if(s.ap.wmmPresent && !s.wmmConfigured)assert(f[14]==83 && Ath10k::wmiReadLE32(f+8)==0x4006);
                    else assert(f[14]==101 && Ath10k::wmiReadLE32(f+32)==7);
                }
                if(s.stage==LinkStage::Authorize){
                    assert(f[14]==100 && Ath10k::wmiReadLE32(f+28)==3);
                    std::vector<UInt8> p={2,0,24,0,0,54,0,0,5,96,0,0,16,0,44,1,0,0,0,0,150,100,30,220,77,144,0,0,2,0,0,0};
                    memcpy(p.data()+20,s.bssid,6);deliver(2,p);
                    assert(!networkUp);
                }
                if(s.stage==LinkStage::Up){assert(f[14]==92 && Ath10k::wmiReadLE32(f+20)==7);}
                deliver(2,{0,2,8,0,8,0,0,0,1,4,0,0,2,1,0,0});
            }
        };
        _regs.tx4Consume=[this](){
            const UInt8 *f=static_cast<const UInt8 *>(_packetCommand.virtualAddress());++packets;
            assert(_connection.txOwned && f[8]==1 && f[5]==2+packets);
            if(_connection.txManagement){
                assert(f[9]==0x65 && Ath10k::htcReadLE16(f+10)==0xc40);
                assert(Ath10k::wmiReadLE32(f+16)==_packetBuffer.dmaAddress());
                if(_connection.stage==LinkStage::Assoc && temporaryAssociationRejects){
                    --temporaryAssociationRejects;deliver(2,comebackResponse(_connection,comebackTU));
                }else deliver(2,managementResponse(_connection,_connection.stage==LinkStage::Assoc,
                    rejectAssociation && _connection.stage==LinkStage::Assoc?17:0));
            }else{
                const UInt8 expected=_connection.tkipDataBlocked?0x42:0x46;
                assert(networkUp && f[9]==expected && Ath10k::htcReadLE16(f+10)==0xc00);
                assert(Ath10k::wmiReadLE32(f+16)==_packetFragments.dmaAddress());
                auto *frags=static_cast<const UInt8 *>(_packetFragments.virtualAddress());
                assert(Ath10k::wmiReadLE32(frags)==_packetBuffer.dmaAddress());
                assert(Ath10k::wmiReadLE32(frags+8)==0);
            }
            if(!suppressCompletion)deliver(1,_connection.txManagement?mgmtCompletion(wrongID?_connection.txId+1:_connection.txId):completion(wrongID?static_cast<UInt16>(_connection.txId+1):_connection.txId));
        };
    }
    void connect(){for(unsigned now=1270;now<1800 && _wmiLive.active && (!networkUp || !_connection.maintenance.valid);now+=10)tick(now);}
};
static void rxTests(const Ath10k::ConnectionState &s){
    UInt8 d[2048]{},out[1514]{};Ath10k::htcWriteLE32(d+4,0x80000000);Ath10k::htcWriteLE32(d+32,1<<8);
    UInt8 *f=d+300;f[0]=8;f[1]=2;memcpy(f+4,s.local,6);memcpy(f+10,s.bssid,6);
    const UInt8 source[6]={2,4,4,4,4,4};memcpy(f+16,source,6);
    f[24]=f[25]=0xaa;f[26]=3;f[30]=8;f[31]=6;f[32]=0x42;
    Ath10k::htcWriteLE32(d+24,33);
    assert(Ath10k::decodeEthernetRX(s,d,sizeof(d),1,s.peerId,out,sizeof(out))==15);
    assert(Ath10k::sameMAC(out,s.local) && Ath10k::sameMAC(out+6,source) && out[12]==8 && out[13]==6 && out[14]==0x42);
    for(unsigned status=0;status<16;++status)if(status!=1)assert(!Ath10k::decodeEthernetRX(s,d,sizeof(d),status,s.peerId,out,sizeof(out)));
    assert(!Ath10k::decodeEthernetRX(s,d,sizeof(d),1,s.peerId+1,out,sizeof(out)));
    for(unsigned bytes=0;bytes<333;++bytes)assert(!Ath10k::decodeEthernetRX(s,d,bytes,1,s.peerId,out,sizeof(out)));
    f[0]=0x88;assert(Ath10k::decodeEthernetRX(s,d,sizeof(d),1,s.peerId,out,sizeof(out))==15);f[0]=8;
    f[10]^=2;assert(!Ath10k::decodeEthernetRX(s,d,sizeof(d),1,s.peerId,out,sizeof(out)));f[10]^=2;
    f[1]|=0x40;assert(!Ath10k::decodeEthernetRX(s,d,sizeof(d),1,s.peerId,out,sizeof(out)));f[1]=2;
    Ath10k::htcWriteLE32(d+4,0xc0000000);assert(!Ath10k::decodeEthernetRX(s,d,sizeof(d),1,s.peerId,out,sizeof(out)));
    Ath10k::htcWriteLE32(d+4,0x80000000);Ath10k::htcWriteLE32(d+32,2<<8);Ath10k::htcWriteLE32(d+24,14);
    memcpy(f,s.local,6);assert(Ath10k::decodeEthernetRX(s,d,sizeof(d),1,s.peerId,out,sizeof(out))==14);
}
static void amsduTests(const Ath10k::ConnectionState &source){
    Ath10k::ConnectionState s=source;s.stage=LinkStage::Connected;s.peerCount=0;
    UInt8 d[2048]{},out[1514]{};Ath10k::htcWriteLE32(d+4,0x80000000);Ath10k::htcWriteLE32(d+32,1<<8);
    UInt8 *p=d+300;p[0]=0x88;p[1]=2;memcpy(p+4,s.local,6);memcpy(p+10,s.bssid,6);
    const UInt8 src1[]={2,3,4,5,6,7},src2[]={2,3,4,5,6,8};
    memcpy(p+16,src1,6);Ath10k::htcWriteLE16(p+22,0x10);p[24]=0x80;p[25]=0;
    auto sub=[&](UInt32 at,const UInt8 *src,UInt8 value){
        memcpy(p+at,s.local,6);memcpy(p+at+6,src,6);p[at+12]=0;p[at+13]=12;
        const UInt8 snap[]={0xaa,0xaa,3,0,0,0,8,0,value,UInt8(value+1),UInt8(value+2),UInt8(value+3)};
        memcpy(p+at+14,snap,sizeof(snap));
    };
    sub(26,src1,1);sub(54,src2,9);Ath10k::htcWriteLE32(d+24,80);
    UInt32 next=0;assert(Ath10k::decodeEthernetRX(s,d,sizeof(d),1,s.peerId,out,sizeof(out),0,0,&next)==18 && next==28);
    UInt32 finalOffset=0;assert(Ath10k::decodeEthernetRX(s,d,sizeof(d),1,s.peerId,out,sizeof(out),0,next,&finalOffset)==18 && !finalOffset);
    assert(Ath10k::sameMAC(out,s.local) && Ath10k::sameMAC(out+6,src2) && out[12]==8 && out[13]==0);
    // Ethernet2 decap can carry the same 14-byte A-MSDU subframe format.
    UInt8 e[2048]{},eout[1514]{};Ath10k::htcWriteLE32(e+4,0x80000000);Ath10k::htcWriteLE32(e+32,2<<8);
    UInt8 *ep=e+300;auto subEther=[&](UInt32 at,const UInt8 *src,UInt8 value){
        memcpy(ep+at,s.local,6);memcpy(ep+at+6,src,6);ep[at+12]=0;ep[at+13]=12;
        const UInt8 snap[]={0xaa,0xaa,3,0,0,0,8,0,value,UInt8(value+1),UInt8(value+2),UInt8(value+3)};
        memcpy(ep+at+14,snap,sizeof(snap));
    };
    subEther(0,src1,1);subEther(28,src2,9);Ath10k::htcWriteLE32(e+24,54);
    next=0;assert(Ath10k::decodeEthernetRX(s,e,sizeof(e),1,s.peerId,eout,sizeof(eout),0,0,&next)==18 && next==28);
    assert(Ath10k::decodeEthernetRX(s,e,sizeof(e),1,s.peerId,eout,sizeof(eout),0,next,&finalOffset)==18 && !finalOffset);
    // CCMP PN replay is allowed only for the same QoS sequence carrying the
    // remaining A-MSDU subframes.
    Ath10k::ConnectionState secure=s;secure.secure=true;secure.securityPhase=5;secure.portAuthorized=true;
    UInt8 desc[2048]{},ether[64]{};Ath10k::htcWriteLE32(desc+4,0x80000000);Ath10k::htcWriteLE32(desc+12,(6u<<28)|(1u<<13));Ath10k::htcWriteLE32(desc+16,5);
    UInt8 *h=desc+236;h[0]=0x88;h[1]=0x42;memcpy(h+10,secure.bssid,6);Ath10k::htcWriteLE16(h+22,0x10);h[24]=0x80;h[28+3]=0x20;ether[12]=8;
    assert(Ath10k::acceptSecureRX(secure,desc,ether,64));
    assert(!Ath10k::acceptSecureRX(secure,desc,ether,64));
    assert(!Ath10k::acceptSecureRX(secure,desc,ether,64));
    assert(!Ath10k::acceptSecureRX(secure,desc,ether,64));
    Ath10k::htcWriteLE16(h+22,0x20);assert(!Ath10k::acceptSecureRX(secure,desc,ether,64));
}
static void chainedRxTests(){
    ConnectionDriver d;d.connect();assert(d.networkUp);
    const UInt16 first=17,second=18;const UInt32 firstAddress=d._rxSetup.addresses[first],secondAddress=d._rxSetup.addresses[second];
    assert(firstAddress && secondAddress && !d._rxSetup.addressPending[first] && !d._rxSetup.addressPending[second]);
    auto dataFor=[&](UInt16 id)->UInt8 *{
        return d._httRecycled[id].allocated()?static_cast<UInt8 *>(d._httRecycled[id].virtualAddress()):
            static_cast<UInt8 *>(d._httRxPool.virtualAddress())+UInt32(id)*Ath10k::kHTTRxBufferBytes;
    };
    UInt8 *data=dataFor(first);memset(data,0,Ath10k::kHTTRxBufferBytes);Ath10k::htcWriteLE32(data+4,0x80000000);
    data[10]=1;Ath10k::htcWriteLE32(data+32,2<<8);Ath10k::htcWriteLE32(data+24,60);
    memset(data+300,0xff,6);memcpy(data+306,d._connection.local,6);data[312]=8;data[313]=0;
    UInt8 *fragment=dataFor(second);memset(fragment,0x5a,Ath10k::kHTTRxBufferBytes);
    std::vector<UInt8> event(32);event[0]=1;event[2]=24;event[5]=6;event[8]=0x12;event[9]=0x40;
    Ath10k::htcWriteLE16(event.data()+10,d._connection.peerId);Ath10k::htcWriteLE16(event.data()+14,2);
    Ath10k::htcWriteLE32(event.data()+16,firstAddress);Ath10k::htcWriteLE16(event.data()+20,60);
    Ath10k::htcWriteLE32(event.data()+24,secondAddress);Ath10k::htcWriteLE16(event.data()+28,100);
    d.deliver(1,event);d.tick(1800);
    assert(d._wmiLive.active && d.networkUp && d.receivedFrames==1);
    assert(d._connection.rxChainedBuffers==1 && !d._connection.rxChainDrops && d._rxSetup.recycled>=2);
    assert(!d._rxSetup.pendingMPDUs && !d._rxSetup.addressPending[first] && !d._rxSetup.addressPending[second]);
    // Real payload crosses the 1748-byte head limit. The payload-only tail
    // arrives in a second indication: ownership must remain untouched until then.
    data=dataFor(first);fragment=dataFor(second);memset(data,0,2048);memset(fragment,0,2048);
    Ath10k::htcWriteLE32(data+4,0x80000000);data[10]=1;
    Ath10k::htcWriteLE32(data+32,2<<8);Ath10k::htcWriteLE32(data+24,2030);Ath10k::htcWriteLE32(data+56,0xc000);
    std::vector<UInt8> payload(2030,0x42);
    for(unsigned at:{0u,1016u}){memcpy(payload.data()+at,d._connection.local,6);memcpy(payload.data()+at+6,d._connection.bssid,6);
        payload[at+12]=3;payload[at+13]=0xe8;const UInt8 snap[]={0xaa,0xaa,3,0,0,0,8,0};memcpy(payload.data()+at+14,snap,8);}
    memcpy(data+300,payload.data(),1748);memcpy(fragment,payload.data()+1748,payload.size()-1748);
    event.resize(24);event[2]=16;event[9]=0;event[14]=1;
    Ath10k::htcWriteLE32(event.data()+16,d._rxSetup.addresses[first]);Ath10k::htcWriteLE16(event.data()+20,2030);
    const UInt32 recycled=d._rxSetup.recycled;
    d.deliver(1,event);d.tick(1801);assert(d._rxSetup.recycled==recycled && d._rxSetup.pendingMPDUs==1);
    assert(d._rxSetup.rxChainWaits==1 && d.receivedFrames==1);
    Ath10k::htcWriteLE32(event.data()+16,d._rxSetup.addresses[second]);Ath10k::htcWriteLE16(event.data()+20,0);
    d.deliver(1,event);d.tick(1802);assert(d._rxSetup.recycled==recycled+2 && !d._rxSetup.pendingMPDUs);
    assert(d.receivedFrames==3 && d._wmiLive.active);
    d.releaseWMIRuntime();
}
static void startResponseTests(){
    // Exact hardware capture from 0.0.49: tag 40, payload 40, common status 0.
    const std::vector<UInt8> captured={0x02,0x00,0x30,0x00,0x00,0x36,0x00,0x00,0x01,0x50,0x00,0x00,0x28,0x00,0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    auto check=[&](std::vector<UInt8> p,bool valid,bool rejected=false){
        Ath10k::ConnectionState s{};s.stage=LinkStage::Start;s.submitted=true;
        Ath10k::HTCCreditState credits{};assert(credits.initialize(2,256,2));
        assert(credits.reserve(120));Ath10k::WMIInitState events{};
        const char *error=Ath10k::parseWMIInitResponse(p.data(),static_cast<UInt32>(p.size()),2,credits,events,nullptr,nullptr,nullptr,false,&s);
        if(!valid){assert(error && !s.startReply && s.stage==LinkStage::Start && credits.outstanding==1);}
        else {assert(!error && s.startReply);assert((s.stage==LinkStage::Failed)==rejected);}
    };
    check(captured,true);
    auto p=captured;p.resize(32);p[2]=24;p[12]=16;check(p,true); // Original ABI retained.
    p=captured;p[28]=3;check(p,true,true); // Firmware rejection remains a failure.
    p=captured;p[12]=44;check(p,false); // Declared extension beyond frame.
    p=captured;p.resize(28);p[2]=20;p[12]=12;check(p,false); // Missing status word.
    p=captured;p[16]=1;check(p,false); // Wrong vdev.
    p=captured;p[20]=1;check(p,false); // Wrong request.
    p=captured;p[24]=1;check(p,false); // Restart response instead of start.
    p=captured;p.insert(p.end(),captured.begin()+12,captured.end());p[2]=92;check(p,false); // Duplicate fixed TLV.
    p=captured;p[1]=2;p[4]=8;p[2]=56;p.insert(p.end(),{1,4,0,0,2,3,0,0});
    check(p,false); // Invalid credit must not commit the start response.
    for(unsigned n=0;n<captured.size();++n){p=captured;p.resize(n);check(p,false);}
}
static void peerStateTests(){
    const std::vector<UInt8> captured={2,0,24,0,0,54,0,0,5,96,0,0,16,0,44,1,0,0,0,0,150,100,30,220,77,144,0,0,2,0,0,0};
    auto check=[&](std::vector<UInt8> p,bool valid){
        Ath10k::ConnectionState s{};memcpy(s.bssid,captured.data()+20,6);s.stage=LinkStage::Authorize;
        Ath10k::HTCCreditState c{};c.initialize(2,256,2);assert(c.reserve(120));
        Ath10k::WMIInitState out{};
        const char *e=Ath10k::parseWMIInitResponse(p.data(),p.size(),2,c,out,nullptr,nullptr,nullptr,false,&s);
        assert((e==nullptr)==valid);assert(s.stage==LinkStage::Authorize && !s.txComplete && !s.startReply);
        assert(c.outstanding==1);
    };
    check(captured,true);
    for(unsigned n=0;n<captured.size();++n)check(std::vector<UInt8>(captured.begin(),captured.begin()+n),false);
    auto p=captured;p[14]=43;check(p,false);
    p=captured;p[16]=1;check(p,false);
    p=captured;p[20]^=1;check(p,false);
    p=captured;p.insert(p.end(),captured.begin()+12,captured.end());p[2]=44;check(p,false);
    p=captured;p[1]=2;p[4]=8;p[2]=32;p.insert(p.end(),{1,4,0,0,2,3,0,0});check(p,false);
}
static std::vector<UInt8> paddrEvent(UInt32 address,UInt16 length=60,UInt16 peer=7){
    std::vector<UInt8> p={1,0,16,0,0,6,0,0,18,16,187,0,0,0,1,0,0,72,76,37,114,1,0,0};
    Ath10k::htcWriteLE32(p.data()+16,address);Ath10k::htcWriteLE16(p.data()+20,length);
    Ath10k::htcWriteLE16(p.data()+10,peer);return p;
}
static void paddrTests(){
    // Exact notification from 0.0.52: one 370-byte MSDU at 0x254c4800, peer 187.
    auto captured=paddrEvent(0x254c4800,370,187);
    auto check=[&](std::vector<UInt8> p,bool valid,bool pending=false){
        Ath10k::RxSetupState rx{};rx.ringOwned=true;rx.addresses[7]=0x254c4800;rx.addressPending[7]=pending;
        Ath10k::HTCCreditState c{};c.initialize(2,256,2);assert(c.reserve(120));
        auto err=Ath10k::parseHTTSetup(p.data(),p.size(),1,c,rx);
        assert((err==nullptr)==valid && c.outstanding==1);
        assert(rx.pendingMPDUs==(valid?1u:0u));assert(rx.addressPending[7]==(valid||pending));
        if(valid)assert(rx.rxMode==2 && rx.completionIds[0]==7 && rx.completionLengths[0]==370 && rx.mpduPeer[0]==187);
    };
    check(captured,true);
    for(UInt8 info:{0x80,0x90,0x92}){auto high=captured;high[9]=info;check(high,true);}
    // Exact rejected frame from 0.0.57, 2026-09-23 23:36:28.917.
    std::vector<UInt8> observed={1,0,16,0,0,52,1,0,18,144,71,0,0,0,1,0,0,200,13,55,174,2,0,0};
    Ath10k::RxSetupState seen{};seen.ringOwned=true;seen.addresses[17]=0x370dc800;
    Ath10k::HTCCreditState credits{};credits.initialize(2,256,2);
    assert(!Ath10k::parseHTTSetup(observed.data(),observed.size(),1,credits,seen));
    assert(seen.pendingMPDUs==1 && seen.completionIds[0]==17 && seen.completionLengths[0]==686 && seen.mpduPeer[0]==71);

    for(unsigned n=0;n<captured.size();++n)check(std::vector<UInt8>(captured.begin(),captured.begin()+n),false);
    auto p=captured;p[16]++;check(p,false); // not a posted address
    check(captured,false,true);
    p=captured;p.insert(p.end(),captured.begin()+16,captured.end());p[2]=24;p[14]=2;check(p,false);
    p=captured;p[21]=255;check(p,false);
    auto fragmented=captured;fragmented[9]=0x40;check(fragmented,true);
    auto fragmentedOpaque=captured;fragmentedOpaque[9]=0xc0;check(fragmentedOpaque,true);
    for(UInt8 flags:{0x20,0x60,0xa0,0xe0}){p=captured;p[9]=flags;check(p,false);}
    p=captured;p[12]=1;check(p,false);
    p=captured;p[1]=2;p[4]=8;p[2]=24;p.insert(p.end(),{1,4,0,0,2,3,0,0});check(p,false);
    // Run real RX service through > one ring wrap, deliberately skipping slots.
    ConnectionDriver d;d.connect();assert(d.networkUp);
    for(unsigned i=0;i<2200;++i){
        unsigned id=(i*17)%1023;
        auto *data=d._httRecycled[id].allocated()?static_cast<UInt8 *>(d._httRecycled[id].virtualAddress()):
            static_cast<UInt8 *>(d._httRxPool.virtualAddress())+2048*id;
        memset(data,0,2048);Ath10k::htcWriteLE32(data+4,0x80000000);
        Ath10k::htcWriteLE32(data+32,2<<8); // Ethernet II; notification owns length.
        memset(data+300,0xff,6);data[312]=8;data[313]=0; // broadcast IPv4 (DHCP uses this path)
        auto event=paddrEvent(d._rxSetup.addresses[id],60,187);event[9]=(i%2)?0x90:0x92;
        d.deliver(1,event);d.tick(1800+i*10);
        assert(d._wmiLive.active && d.networkUp && d.receivedFrames==i+1);
        assert(d._rxSetup.recycled==i+1 && !d._rxSetup.pendingMPDUs && !d._rxSetup.addressPending[id]);
        assert(d._rxSetup.addresses[id]==d._httRecycled[id].dmaAddress());
        assert(Ath10k::wmiReadLE32(static_cast<UInt8 *>(d._httRxIndex.virtualAddress()))==((1024+i)&2047));
    }
    // Firmware discard must reclaim memory without delivering the frame.
    unsigned id=31;auto *drop=static_cast<UInt8 *>(d._httRecycled[id].virtualAddress());
    memset(drop,0,2048);Ath10k::htcWriteLE32(drop+4,0x80000000);Ath10k::htcWriteLE32(drop+32,2<<8);
    memset(drop+300,0xff,6);auto discard=paddrEvent(d._rxSetup.addresses[id],60,187);discard[22]=1;
    d.deliver(1,discard);d.tick(25000);assert(d.receivedFrames==2200 && d._rxSetup.recycled==2201);
    d.releaseWMIRuntime();
    ConnectionDriver premature;premature.connect();
    // An indication may beat the final MSDU_DONE write by one poll.  It is
    // recoverable: ownership stays pending and the next poll consumes it.
    const unsigned prematureID=17;
    auto prematureEvent=paddrEvent(premature._rxSetup.addresses[prematureID]);
    premature.deliver(1,prematureEvent);premature.tick(1800);
    assert(premature._wmiLive.active && !premature._rxSetup.recycled &&
           premature._rxSetup.pendingMPDUs==1 && premature._rxSetup.rxCompletionNotDone==1);
    auto *prematureData=static_cast<UInt8 *>(premature._httRxPool.virtualAddress())+prematureID*2048;
    Ath10k::htcWriteLE32(prematureData+4,0x80000000);Ath10k::htcWriteLE32(prematureData+32,2<<8);
    memset(prematureData+300,0xff,6);prematureData[312]=8;prematureData[313]=0;
    premature.tick(1810);
    assert(premature._wmiLive.active && premature._rxSetup.recycled==1 &&
           !premature._rxSetup.pendingMPDUs);
    premature.releaseWMIRuntime();
    // CPU and device views differ for a recycled IODMACommand bounce mapping.
    // DMA updates deviceData only; omitting syncFromDevice() would see zero
    // DONE and stall. Repeat the same buffer to cover multiple reuse cycles.
    ConnectionDriver bounce;bounce.connect();
    auto *initial=static_cast<UInt8 *>(bounce._httRxPool.virtualAddress())+17*2048;
    Ath10k::htcWriteLE32(initial+4,0x80000000);Ath10k::htcWriteLE32(initial+32,2<<8);
    memset(initial+300,0xff,6);initial[312]=8;
    bounce.deliver(1,paddrEvent(bounce._rxSetup.addresses[17]));bounce.tick(1800);
    auto &mapping=bounce._httRecycled[17];mapping.bounce=true;
    assert(mapping.syncForDevice());
    for(unsigned n=0;n<3;++n){
        auto *dma= reinterpret_cast<UInt8 *>(mapping.deviceData.data());
        Ath10k::htcWriteLE32(dma+4,0x80000000);Ath10k::htcWriteLE32(dma+32,2<<8);
        memset(dma+300,0xff,6);dma[312]=8;
        assert(!Ath10k::wmiReadLE32(static_cast<UInt8 *>(mapping.virtualAddress())+4));
        auto syncs=mapping.syncInCount;
        bounce.deliver(1,paddrEvent(bounce._rxSetup.addresses[17]));bounce.tick(1801+n);
        assert(mapping.syncInCount>syncs && bounce.receivedFrames==n+2 &&
               bounce._rxSetup.recycled==n+2 && bounce._wmiLive.active);
        assert(!Ath10k::wmiReadLE32(reinterpret_cast<UInt8 *>(mapping.deviceData.data())+4));
    }
    // Actual DMA synchronization failure remains fatal, not a DONE retry.
    mapping.syncInOK=false;bounce.resetOK=false;
    bounce.deliver(1,paddrEvent(bounce._rxSetup.addresses[17]));bounce.tick(1810);
    assert(!bounce._wmiLive.active && bounce._dmaQuarantine &&
           !strcmp(bounce._wmiLive.status,"htt-rx-buffer-sync") &&
           bounce._rxSetup.addressPending[17] && bounce._rxSetup.recycled==4);
    bounce.releaseWMIRuntime();
    ConnectionDriver failure;failure.connect();
    auto *data=static_cast<UInt8 *>(failure._httRxPool.virtualAddress())+17*2048;
    Ath10k::htcWriteLE32(data+4,0x80000000);failure._httRxIndex.syncOK=false;failure.resetOK=false;
    failure.deliver(1,paddrEvent(failure._rxSetup.addresses[17]));failure.tick(1800);
    assert(failure._dmaQuarantine && !failure._rxSetup.recycled && failure._rxSetup.addressPending[17]);
    failure.releaseWMIRuntime();
}
static void rxLayoutTests(){
    // Linux rx_desc.h ABI, independent fields: info0, flow_id_crc, info1.
    struct MSDUStart { UInt32 info0; UInt32 flowCRC; UInt32 info1; };
    static_assert(sizeof(MSDUStart)==12,"RX ABI");
    static_assert(offsetof(MSDUStart,info1)==8,"info1 follows flow CRC");
    Ath10k::ConnectionState s{};s.stage=LinkStage::Connected;s.peerId=7;
    UInt8 d[2048]{},out[1514]{};
    Ath10k::htcWriteLE32(d+4,0x80000000);
    // Full Ethernet broadcast frame with IPv4 EtherType.
    memset(d+300,0xff,6);d[312]=8;d[313]=0;
    Ath10k::htcWriteLE32(d+24+offsetof(MSDUStart,info0),60);
    Ath10k::htcWriteLE32(d+24+offsetof(MSDUStart,info1),2<<8);
    for(unsigned hashMode=0;hashMode<4;++hashMode){
        Ath10k::htcWriteLE32(d+24+offsetof(MSDUStart,flowCRC),hashMode<<8);
        assert(Ath10k::decodeEthernetRX(s,d,sizeof(d),1,7,out,sizeof(out))==60);
        assert(!memcmp(out,d+300,60));
    }
    // A misleading CRC must not make an unsupported decap look like Ethernet.
    Ath10k::htcWriteLE32(d+28,2<<8);Ath10k::htcWriteLE32(d+32,0);
    assert(!Ath10k::decodeEthernetRX(s,d,sizeof(d),1,7,out,sizeof(out)));
}
static std::vector<UInt8> pauseEvent(UInt32 action=0,UInt32 reason=1,UInt32 map=1){
    std::vector<UInt8> p={2,0,28,0,0,13,0,0,5,64,0,0,20,0,230,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0};
    Ath10k::htcWriteLE32(p.data()+16,reason);Ath10k::htcWriteLE32(p.data()+20,action);
    Ath10k::htcWriteLE32(p.data()+24,map);return p;
}
static void pauseTests(){
    auto parse=[](std::vector<UInt8> p,Ath10k::ConnectionState &s){
        Ath10k::HTCCreditState c{};c.initialize(2,256,2);assert(c.reserve(120));
        Ath10k::WMIInitState out{};
        auto error=Ath10k::parseWMIInitResponse(p.data(),p.size(),2,c,out,nullptr,nullptr,nullptr,false,&s);
        assert(c.outstanding==1);return error;
    };
    Ath10k::ConnectionState s{};s.stage=LinkStage::Connected;
    assert(!parse(pauseEvent(),s) && s.txPauseMask==2 && !s.txWakePending);
    assert(!parse(pauseEvent(0,4),s) && s.txPauseMask==18);
    assert(!parse(pauseEvent(1),s) && s.txPauseMask==16 && !s.txWakePending);
    assert(!parse(pauseEvent(1,4),s) && !s.txPauseMask && s.txWakePending);
    s.txWakePending=false;
    assert(!parse(pauseEvent(0,1,2),s) && !s.txPauseMask);
    assert(!parse(pauseEvent(0,21),s) && !s.txPauseMask); // ignored by Linux
    auto captured=pauseEvent();
    for(unsigned n=0;n<captured.size();++n){
        auto before=s.txPauseEvents;
        assert(parse(std::vector<UInt8>(captured.begin(),captured.begin()+n),s));
        assert(!s.txPauseMask && s.txPauseEvents==before);
    }
    auto p=captured;p[20]=2;assert(parse(p,s) && !s.txPauseMask);
    p=captured;p[14]=229;assert(parse(p,s) && !s.txPauseMask);
    p=captured;p.insert(p.end(),captured.begin()+12,captured.end());p[2]=52;assert(parse(p,s) && !s.txPauseMask);
    p=captured;p[1]=2;p[4]=8;p[2]=36;p.insert(p.end(),{1,4,0,0,2,3,0,0});assert(parse(p,s) && !s.txPauseMask);
    ConnectionDriver d;d.connect();d.queueEnabled=true;d.deliver(2,captured);d.tick(1800);
    assert(d.networkUp && d._wmiLive.active && d._connection.txPauseMask==2);
    d.deliver(2,pauseEvent(1));d.tick(1810);
    assert(d.networkUp && d._wmiLive.active && !d._connection.txPauseMask && !d._connection.txWakePending && d.queue.wakes==1);
    d.releaseWMIRuntime();
}
static void peerMapTests(){
    Ath10k::ConnectionState s{};s.stage=LinkStage::Connected;
    const UInt8 ap[]={0x96,0x64,0x1e,0xdc,0x4d,0x90};memcpy(s.bssid,ap,6);
    UInt8 p[20]={};p[8]=3;memcpy(p+12,ap,6);
    for(UInt16 id:{187,171}){Ath10k::htcWriteLE16(p+10,id);assert(!Ath10k::validateConnectionHTT(s,p,20));Ath10k::commitConnectionHTT(s,p);}
    assert(s.peerCount==2 && Ath10k::mappedPeer(s,187) && Ath10k::mappedPeer(s,171));
    Ath10k::commitConnectionHTT(s,p);assert(s.peerCount==2);
    UInt8 d[2048]{},out[1514]{};Ath10k::htcWriteLE32(d+4,0x82300043);Ath10k::htcWriteLE32(d+32,1<<8);
    const UInt8 h[]={8,2,58,1,72,95,153,222,109,127,150,100,30,220,77,144,150,100,30,220,77,144,96,216,170,170,3,0,0,0,8,0};
    memcpy(d+300,h,32);memcpy(s.local,h+4,6);
    assert(Ath10k::decodeEthernetRX(s,d,2048,1,187,out,1514,370)==352);
    assert(!Ath10k::decodeEthernetRX(s,d,2048,1,188,out,1514,370));
    p[8]=4;Ath10k::htcWriteLE16(p+10,187);Ath10k::commitConnectionHTT(s,p);
    assert(s.peerCount==1 && s.stage==LinkStage::Connected);
    assert(!Ath10k::decodeEthernetRX(s,d,2048,1,187,out,1514,370));
    Ath10k::htcWriteLE16(p+10,171);Ath10k::commitConnectionHTT(s,p);assert(s.stage==LinkStage::Failed);
    s={};s.stage=LinkStage::Connected;memcpy(s.bssid,ap,6);p[8]=3;
    Ath10k::commitConnectionHTT(s,p);assert(s.peerCount==1);
    p[12]^=2;Ath10k::commitConnectionHTT(s,p);
    assert(!s.peerCount && s.stage==LinkStage::Failed);
}
static void secureConnectionTests(bool separateInitialGroup=false){
    {
        Ath10k::ConnectionState tkip{};tkip.secure=true;tkip.securityPhase=2;tkip.groupCipher=AthSecurity::cipherTKIP;tkip.groupIndex=3;
        for(unsigned i=0;i<32;++i)tkip.groupKey[i]=UInt8(0x40+i);
        UInt8 command[256]{};const UInt32 bytes=Ath10k::buildSecurityWMI(command,sizeof(command),2,tkip);
        assert(bytes==144 && Ath10k::htcReadLE16(command+2)==136);
        assert(Ath10k::wmiReadLE32(command+36)==AthSecurity::cipherTKIP && Ath10k::wmiReadLE32(command+96)==32);
        assert(Ath10k::wmiReadLE32(command+100)==8 && Ath10k::wmiReadLE32(command+104)==8);
        assert(Ath10k::htcReadLE16(command+108)==32 && Ath10k::htcReadLE16(command+110)==17);
        assert(!memcmp(command+112,tkip.groupKey,16));
        assert(!memcmp(command+128,tkip.groupKey+24,8)); // Station TX MIC.
        assert(!memcmp(command+136,tkip.groupKey+16,8)); // Station RX MIC.
        for(unsigned i=0;i<32;++i)assert(tkip.groupKey[i]==UInt8(0x40+i));
        UInt8 retry[256]{};assert(Ath10k::buildSecurityWMI(retry,sizeof(retry),2,tkip)==bytes);
        assert(!memcmp(command,retry,bytes)); // Retries must not swap stored keys again.
        tkip.groupCipher=0;assert(Ath10k::buildSecurityWMI(command,sizeof(command),2,tkip)==0);
    }
    ConnectionDriver d;auto &s=d._connection;s.secure=true;
    auto &b=d._wmiBSS.entries[0];b.privacy=b.rsnPresent=true;b.capabilities|=0x10;
    b.rsnLength=sizeof(AthSecurity::stationRSN);memcpy(b.rsn,AthSecurity::stationRSN,b.rsnLength);
    auto original=d._regs.tx3Consume;unsigned installs=0;
    d._regs.tx3Consume=[&](){
        if(s.stage!=LinkStage::Connected || s.maintenance.step){original();return;}
        const auto *f=static_cast<const UInt8 *>(d._connectionCommand.virtualAddress());
        if(!s.rekeyKind)assert(!d.networkUp);
        if(s.securityPhase<=2){
            ++installs;assert(Ath10k::htcReadLE16(f+2)==120 && Ath10k::wmiReadLE32(f+8)==0x5009);
            assert(Ath10k::htcReadLE16(f+12)==92 && Ath10k::htcReadLE16(f+14)==96);
            assert(Ath10k::wmiReadLE32(f+36)==4 && Ath10k::wmiReadLE32(f+96)==16);
            assert(Ath10k::sameMAC(f+20,s.bssid));
            std::vector<UInt8> event(36);event[0]=1;event[2]=28;event[8]=11;
            event[9]=s.securityPhase==1?0x86:6;event[10]=7;
            d.deliver(1,event);
        }
        if(s.securityPhase==4){d.deliver(2,echoPacket(0xa7100057));return;}
        d.deliver(2,{0,2,8,0,8,0,0,0,1,4,0,0,2,1,0,0});
    };
    d.connect();assert(s.stage==LinkStage::Connected && !d.networkUp && !s.portAuthorized);
    // PTK/GTK acknowledgements alone must not enable DHCP.
    s.securityPhase=1;s.groupIndex=1;s.submitted=false;s.initialGroupPending=separateInitialGroup;
    for(unsigned i=0;i<16;++i){s.temporalKey[i]=UInt8(i);s.groupKey[i]=UInt8(i+16);}
    for(unsigned t=1800;t<1900;t+=10)d.tick(t);
    if(separateInitialGroup){
        assert(installs==1 && s.securityPhase==3 && s.initialGroupPending && s.pairInstalled);
        assert(!s.groupInstalled[1] && !s.portAuthorized && !d.networkUp);
        // A mistaken early authorize request cannot cross the firmware barrier.
        s.authorizeRequested=true;
        assert(!strcmp(d.serviceConnection(1891),"initial-group-not-installed"));
        s.authorizeRequested=false;
        s.securityPhase=2;s.submitted=false;s.initialGroupReply=true;
        for(unsigned i=0;i<16;++i)s.groupKey[i]=UInt8(i+16);
        for(unsigned t=1892;t<1900;++t)d.tick(t);
        assert(!s.initialGroupPending && s.groupInstalled[1] && !s.authorizeRequested);
        UInt8 eapol[64]{},tx[256]{};eapol[12]=0x88;eapol[13]=0x8e;
        assert(Ath10k::buildHTTPacket(tx,sizeof(tx),eapol,sizeof(eapol),0x1000,0x2000,1,s,false));
        assert(tx[9]==0x42); // PTK-protected initial group ACK before authorization.
        eapol[12]=8;eapol[13]=0;
        assert(Ath10k::buildHTTPacket(tx,sizeof(tx),eapol,sizeof(eapol),0x1000,0x2000,1,s,false));
        assert(tx[9]==0x46); // No blanket encryption exception for ordinary data.
    }
    assert(installs==2 && s.securityPhase==3 && !d.networkUp);
    assert(s.pairKeyEpoch==1 && s.pairKeySerial==1);
    for(auto c:s.temporalKey)assert(!c);
    for(auto c:s.groupKey)assert(!c);
    s.authorizeRequested=true;
    for(unsigned t=1900;t<2000;t+=10)d.tick(t);
    assert(s.securityPhase==5 && s.portAuthorized && d.networkUp && !s.initialGroupReply);

    // GTK replacement: keep Ethernet link up; PN changes only after key ACK/ECHO
    // and pending RX delivery has drained. The pairwise replay floor is preserved.
    assert(s.groupKeyEpoch[s.groupIndex]==1 && s.groupKeySerial==1);
    const UInt8 previousGroup=s.groupIndex;
    s.pairPN[0]=42;s.groupPN[s.groupIndex][0]=41;s.portAuthorized=false;s.securityPhase=2;
    s.rekeyKind=1;s.groupIndex=2;s.sinceMs=2000;s.submitted=false;
    for(unsigned i=0;i<16;++i)s.groupKey[i]=UInt8(100+i);
    s.groupRSC[0]=5;
    auto &oldRX=d._rxReorder.sessions[0];
    oldRX.initialized=true;oldRX.peer=7;oldRX.tid=3;oldRX.generation=9;
    oldRX.head=4094;oldRX.pending=2;oldRX.gapSince=1900;d._rxReorder.held=2;
    oldRX.slots[4095&63]=static_cast<Ath10k::RXBatch *>(calloc(1,sizeof(Ath10k::RXBatch)));
    oldRX.slots[1]=static_cast<Ath10k::RXBatch *>(calloc(1,sizeof(Ath10k::RXBatch)));
    assert(oldRX.slots[4095&63] && oldRX.slots[1]);
    d._rxDefrag.entries[0].active=true;d._rxBatch.count=1;
    d._wmiScan.completed=false;
    assert(!d.serviceConnection(2000) && installs==2 && !s.submitted);
    d._wmiScan.completed=true;d._rxSetup.pendingMPDUs=1;
    for(unsigned t=2000;t<2100;t+=10)d.tick(t);
    assert(installs==3 && s.securityPhase==4 && !s.portAuthorized && d.networkUp && s.groupPN[previousGroup][0]==41 && !s.groupPN[2][0]);
    assert(oldRX.pending==2 && d._rxReorder.held==2 && d._rxDefrag.entries[0].active);
    d._rxSetup.pendingMPDUs=0;d.tick(2110);
    assert(s.portAuthorized && s.securityPhase==5 && s.securityGeneration==2 && s.pairPN[0]==42 && s.groupPN[s.groupIndex][0]==5);
    assert(s.groupInstalled[2] && s.installedGroups[2][0]==100 && s.groupPN[previousGroup][0]==41);
    assert(s.groupKeyEpoch[previousGroup]==1 && s.groupKeyEpoch[2]==2 && s.groupKeySerial==2);
    assert(oldRX.initialized && oldRX.head==2 && oldRX.peer==7 && oldRX.tid==3 && oldRX.generation==9);
    assert(!oldRX.pending && !d._rxReorder.held && !oldRX.gapSince && !d._rxReorder.released);
    for(auto *slot:oldRX.slots)assert(!slot);
    assert(!d._rxDefrag.entries[0].active && !d._rxBatch.count);
    // PTK replacement with unchanged GTK must not reinstall GTK or reset its PN.
    s.pairPN[0]=55;s.groupPN[s.groupIndex][0]=30;s.portAuthorized=false;s.securityPhase=1;
    s.rekeyKind=2;s.rekeySkipGroup=true;s.submitted=false;s.sinceMs=2200;
    for(unsigned i=0;i<16;++i){s.temporalKey[i]=UInt8(150+i);s.groupKey[i]=UInt8(100+i);}
    for(unsigned t=2200;t<2300;t+=10)d.tick(t);
    assert(installs==4 && s.securityGeneration==3 && s.portAuthorized && !s.rekeyKind);
    assert(s.pairPN[0]==0 && s.groupPN[s.groupIndex][0]==30 && s.installedPair[0]==150);
    assert(s.groupKeyEpoch[2]==2 && s.groupKeySerial==2);
    assert(s.pairKeyEpoch==2 && s.pairKeySerial==2);
    UInt8 packet[64]{},cmd[256]{};packet[12]=8;
    assert(Ath10k::buildHTTPacket(cmd,256,packet,64,0x1000,0x2000,1,s,false));assert(cmd[9]==0x42);
    s.portAuthorized=false;
    assert(Ath10k::buildHTTPacket(cmd,256,packet,64,0x1000,0x2000,1,s,false));assert(cmd[9]==0x46);
    d.releaseWMIRuntime();
    // Security acknowledgements are tied to the mapped peer, key type and phase.
    Ath10k::ConnectionState state{};state.secure=true;state.securityPhase=1;state.submitted=true;state.peerCount=1;state.peerIDs[0]=1u<<7;
    UInt8 event[36]{};event[8]=11;event[9]=0x86;event[10]=7;
    assert(!Ath10k::validateConnectionHTT(state,event,36));
    for(unsigned n=0;n<36;++n)assert(Ath10k::validateConnectionHTT(state,event,n));
    event[10]=8;assert(Ath10k::securityIndicationMismatch(state,event));event[10]=7;
    event[9]=6;assert(Ath10k::securityIndicationMismatch(state,event));
    state.securityPhase=2;state.groupCipher=AthSecurity::cipherTKIP;event[9]=4;
    assert(!Ath10k::validateConnectionHTT(state,event,36));
    state.securityAck=false;Ath10k::commitConnectionHTT(state,event);
    assert(state.securityAck && state.securityInd.ack && state.securityInd.flags==4 && state.securityInd.received==1);
    event[9]=6;assert(Ath10k::securityIndicationMismatch(state,event));
    state.groupCipher=AthSecurity::cipherCCMP;event[9]=6;
    assert(!Ath10k::validateConnectionHTT(state,event,36));
    // Original header + descriptor PN is independent of the decapped Ethernet data.
    UInt8 desc[2048]{},ether[64]{};state.securityPhase=5;state.portAuthorized=true;state.groupIndex=1;
    Ath10k::htcWriteLE32(desc+12,(6u<<28)|(1u<<13));Ath10k::htcWriteLE32(desc+16,5);
    desc[236]=8;desc[237]=0x42;desc[236+24+3]=0x20;ether[12]=8;
    assert(Ath10k::acceptSecureRX(state,desc,ether,64));
    assert(!Ath10k::acceptSecureRX(state,desc,ether,64)); // repeated PN
    Ath10k::htcWriteLE32(desc+16,6);assert(Ath10k::acceptSecureRX(state,desc,ether,64));
    Ath10k::htcWriteLE32(desc+12,7u<<28);assert(!Ath10k::acceptSecureRX(state,desc,ether,64));
    ether[12]=0x88;ether[13]=0x8e;assert(Ath10k::acceptSecureRX(state,desc,ether,64));
}
// First 64 bytes reproduce the hardware log prefix. The log truncates there;
// the remaining header bytes and ARRAY_BYTE payload below are synthetic.
static std::vector<UInt8> statsPacket(){
    std::vector<UInt8> p(236);p[0]=2;p[2]=0xe4;p[5]=6;
    Ath10k::htcWriteLE32(p.data()+8,0x1d004);p[12]=52;p[14]=70;p[24]=1;
    p[68]=164;p[70]=17;return p;
}
static void statsEventTests(){
    auto check=[](std::vector<UInt8> p,bool good){
        Ath10k::ConnectionState s{};s.stage=LinkStage::Connected;s.disconnect=Ath10k::DisconnectStage::Stop;s.submitted=true;
        Ath10k::WMIEchoState echo{};echo.submitted=true;echo.cookie=123;
        Ath10k::HTCCreditState credits{};credits.initialize(2,256,2);assert(credits.reserve(20));
        Ath10k::WMIInitState out{};
        const char *error=Ath10k::parseWMIInitResponse(p.data(),p.size(),2,credits,out,&echo,nullptr,nullptr,false,&s);
        assert((error==nullptr)==good);assert(out.statsCount==(good && Ath10k::wmiReadLE32(p.data()+8)==0x1d004?1u:0u));
        assert(!s.stopReply && !s.deleteReply && !echo.replyReceived && !s.portAuthorized);
        if(!good)assert(credits.outstanding==1);
    };
    auto p=statsPacket();check(p,true);
    for(unsigned n=0;n<p.size();++n)check(std::vector<UInt8>(p.begin(),p.begin()+n),false);
    p=statsPacket();p[12]=0xff;check(p,false);
    p=statsPacket();p[14]=69;check(p,false);
    p=statsPacket();p[70]=18;check(p,false);
    p=statsPacket();p[68]=168;check(p,false);
    p=statsPacket();p[8]=0xff;check(p,true); // bounded opaque notifications do not acknowledge teardown
    p=statsPacket();p.insert(p.end(),{0,0,17,0});Ath10k::htcWriteLE16(p.data()+2,p.size()-8);check(p,false);
    p=statsPacket();const auto duplicate=p;p.insert(p.end(),duplicate.begin()+12,duplicate.begin()+68);Ath10k::htcWriteLE16(p.data()+2,p.size()-8);check(p,false);
    p=statsPacket();addPkgCredit(p);check(p,true);
    p.back()=0; // credit count byte is within the last four bytes
    p[p.size()-3]=3;check(p,false);
}
// Exercise production teardown with simulated CE, HTT and WMI responses.
static void disconnectTests(){
    using D=Ath10k::DisconnectStage;
    for(bool secure:{false,true})for(unsigned missing=0;missing<(secure?6u:4u);++missing){
        ConnectionDriver d;d.connect();assert(d.networkUp);
        auto association=d._regs.tx3Consume;
        bool statsWaiting=false;UInt32 previousStats=0;
        auto &s=d._connection;s.secure=secure;s.securityPhase=secure?5:0;s.portAuthorized=true;s.groupIndex=2;
        if(secure)d._wmi.serviceBitmap[92/4]|=1u<<(92%4);
        auto teardown=[&](){
            const UInt8 *f=static_cast<const UInt8 *>(d._connectionCommand.virtualAddress());
            assert(s.wmiOwned && s.submitted);assert(f[5]==static_cast<UInt8>(10+d.commands++));
            switch(s.disconnect){
            case D::Down:assert(Ath10k::connLE32(f+8)==0x5007 && f[14]==94);break;
            case D::ClearPair:case D::ClearGroup:{
                const bool group=s.disconnect==D::ClearGroup;
                assert(secure && Ath10k::connLE32(f+8)==0x5009 && f[14]==96);
                assert(Ath10k::connLE32(f+36)==0 && Ath10k::connLE32(f+96)==16);
                assert(Ath10k::connLE32(f+28)==(group?2u:0u));
                for(unsigned i=112;i<128;++i)assert(f[i]==0);
                std::vector<UInt8> p(36);p[0]=1;p[2]=28;p[8]=11;p[9]=group?0:0x80;p[10]=7;
                if(missing!=4)d.deliver(1,p);
                break;
            }
            case D::DeletePeer:
                assert(Ath10k::connLE32(f+8)==0x6002 && f[14]==98 && Ath10k::sameMAC(f+20,s.bssid));
                if(missing!=1)d.deliver(1,{1,0,4,0,0,0,0,0,4,0,7,0});
                if(secure && missing!=5){
                    std::vector<UInt8> p(28);p[0]=2;p[2]=20;p[8]=7;p[9]=0x60;p[12]=12;
                    Ath10k::htcWriteLE16(p.data()+14,451);memcpy(p.data()+20,s.bssid,6);
                    addPkgCredit(p);d.deliver(2,p);return;
                }
                break;
            case D::Stop:
                assert(Ath10k::connLE32(f+8)==0x5006 && f[14]==93);
                {auto p=statsPacket();addPkgCredit(p);previousStats=d._wmiEvents.statsCount;
                 statsWaiting=missing!=2;d.deliver(2,p);return;}
                break;
            case D::Barrier:
                if(missing!=3){d.deliver(2,echoPacket(0xa7590000u|((s.disconnectCount+1)&0xffff)));return;}
                break;
            default:assert(false);
            }
            d.deliver(2,{0,2,8,0,8,0,0,0,1,4,0,0,2,1,0,0});
        };
        for(unsigned cycle=0;cycle<(missing?1u:3u);++cycle){
            const UInt64 now=2000+cycle*1000;
            const UInt16 previousID=s.txId;
            s.temporalKey[0]=99;s.groupKey[0]=88;s.eapolFrames[0][0]=77;s.pairPN[0]=123;
            assert(Ath10k::requestDisconnect(s,now));d.networkLink(false);
            d._regs.tx3Consume=teardown;
            for(unsigned i=0;i<45 && s.disconnect!=D::None;++i){
                if(statsWaiting && d._wmiEvents.statsCount>previousStats){
                    assert(s.disconnect==D::Stop && !s.stopReply);
                    d.deliver(2,{2,0,12,0,0,0,0,0,2,0x50,0,0,4,0,41,0,0,0,0,0});statsWaiting=false;
                }
                d.tick(now+i*10);
            }
            if(missing){
                if(s.disconnect==D::None || !d._wmiLive.active)fprintf(stderr,"missing=%u secure=%d disconnect=%u active=%d error=%s runtime=%s\n",missing,secure,unsigned(s.disconnect),d._wmiLive.active,s.error,d._wmiLive.status);
                assert(s.disconnect!=D::None && d._wmiLive.active && !d.networkUp);
                d.tick(now+6000);assert(!d._wmiLive.active);break;
            }
            if(s.stage!=LinkStage::Disabled)fprintf(stderr,"disconnect secure=%d cycle=%u stage=%u disconnect=%u active=%d error=%s runtime=%s\n",secure,cycle,unsigned(s.stage),unsigned(s.disconnect),d._wmiLive.active,s.error,d._wmiLive.status);
            assert(s.stage==LinkStage::Disabled && s.disconnect==D::None && d._wmiLive.active && !d.networkUp);
            assert(s.disconnectCount==cycle+1 && !s.peerCount && !s.txOwned && !s.wmiOwned);
            assert(!s.temporalKey[0] && !s.groupKey[0] && !s.eapolFrames[0][0] && !s.pairPN[0]);
            assert(s.txId==previousID && d._rxSetup.ringOwned);
            // Re-associate with retained DMA buffers and fresh ECHO state.
            const auto &b=d._wmiBSS.entries[0];memcpy(s.bssid,b.bssid,6);memcpy(s.ssid,b.ssid,b.ssidLength);s.ssidLength=b.ssidLength;
            s.stage=LinkStage::Scan;d._regs.tx3Consume=association;
            for(unsigned i=0;i<45 && !d.networkUp;++i)d.tick(now+500+i*10);
            assert(d.networkUp && s.stage==LinkStage::Connected && d._wmiLive.active);
            s.secure=secure;s.securityPhase=secure?5:0;s.portAuthorized=true;s.groupIndex=2;
        }
        d.releaseWMIRuntime();
    }
    // A live TX buffer must not be reused or torn down before HTT completion.
    {
        ConnectionDriver d;d.connect();d.suppressCompletion=true;
        UInt8 packet[60]{};packet[0]=0xff;memcpy(packet+6,d._connection.local,6);packet[12]=8;
        assert(!d.submitNetworkPacket(packet,sizeof(packet),false,2000));
        unsigned commands=d.commands;
        assert(Ath10k::requestDisconnect(d._connection,2000));d.networkLink(false);
        d.tick(2010);assert(d._connection.txOwned && d._connection.disconnect==D::Drain && d.commands==commands);
        d.deliver(1,completion(d._connection.txId));
        // Stop before submission: direct service with outstanding WMI credits
        // demonstrates the drain cannot proceed on CE consumption alone.
        d._wmi.credits.outstanding=1;
        d.tick(2020);assert(!d._connection.txOwned && d._connection.disconnect==D::Drain && d.commands==commands);
        d.releaseWMIRuntime();
    }
    // Stop event parsing is transactional: malformed replies cannot unblock us.
    Ath10k::ConnectionState s{};s.disconnect=D::Stop;s.submitted=true;
    Ath10k::HTCCreditState credits{};credits.initialize(2,256,2);Ath10k::WMIInitState init{};
    UInt8 p[]={2,0,12,0,0,0,0,0,2,0x50,0,0,4,0,41,0,1,0,0,0};
    assert(Ath10k::parseWMIInitResponse(p,sizeof(p),2,credits,init,nullptr,nullptr,nullptr,false,&s));assert(!s.stopReply);
    p[16]=0;assert(!Ath10k::parseWMIInitResponse(p,sizeof(p),2,credits,init,nullptr,nullptr,nullptr,false,&s));assert(s.stopReply);
}
static void pipelineTests(){
    ConnectionDriver d;d.connect();assert(d.networkUp);
    d._regs.tx4Consume=[](){};
    for(unsigned i=0;i<Ath10k::kDataTxSlots;++i){
        auto &b=d._dataBuffers[i];b.payload.isAllocated=b.command.isAllocated=b.fragments.isAllocated=false;
        b.payload.iovm=0x2000000+i*0x10000;b.command.iovm=b.payload.iovm+0x1000;b.fragments.iovm=b.payload.iovm+0x2000;
    }
    UInt8 frame[64]{};frame[12]=8;
    const unsigned entries=Ath10k::kCEHostConfig[4].srcEntries;
    d._regs.tx4Read=d._regs.tx4Written=entries-4;d._regs.tx4Timeout=true;
    d._connection.txId=1050;
    std::vector<UInt16> ids;
    for(unsigned i=0;i<Ath10k::kDataTxSlots;++i){assert(!d.submitDataPacket(frame,sizeof(frame),1800));ids.push_back(d._connection.txId);}
    assert(d._connection.dataPending==Ath10k::kDataTxSlots && d._connection.dataHigh==Ath10k::kDataTxSlots);
    assert(d.submitDataPacket(frame,sizeof(frame),1801));
    auto batch=[&](std::vector<UInt16> list){
        std::vector<UInt8> p((12+list.size()*2+3)&~3);p[0]=1;p[8]=7;p[10]=list.size();
        Ath10k::htcWriteLE16(p.data()+2,p.size()-8);
        for(unsigned i=0;i<list.size();++i)Ath10k::htcWriteLE16(p.data()+12+i*2,list[i]);
        return p;
    };
    auto bad=batch({ids[0],ids[0]});
    assert(Ath10k::parseHTTSetup(bad.data(),bad.size(),1,d._wmi.credits,d._rxSetup,&d._connection));
    assert(!d._connection.dataTX[0].complete);
    auto p=batch(ids);d.deliver(1,p);d.tick(1810);
    assert(d._connection.dataPending==Ath10k::kDataTxSlots && d._connection.dataTX[0].complete);
    assert(d._connection.dataCECount==0 && d._connection.dataHTTCount==Ath10k::kDataTxSlots);
    assert(d._connection.dataHTTTimeMs==10*Ath10k::kDataTxSlots);
    d.queueEnabled=true;d._dataTXStalled=true;
    d._regs.tx4Read=d._regs.tx4Written;assert(!d.serviceDataTX(1820));
    assert(d._connection.dataCETimeMs==20*Ath10k::kDataTxSlots);
    assert(d.queue.wakes==1 && d._perf.txWakeups==1 && !d._dataTXStalled);
    assert(!d._connection.dataPending && d._connection.dataCompleted==Ath10k::kDataTxSlots && d._connection.txBytes==64*Ath10k::kDataTxSlots);
    d._regs.tx4Timeout=false;
    ids.clear();for(unsigned i=0;i<4;++i){assert(!d.submitDataPacket(frame,sizeof(frame),1830));ids.push_back(d._connection.txId);}
    assert(!d.serviceDataTX(1840));assert(d._connection.dataPending==4);
    d._dataTXStalled=true;d._connection.txPauseMask=1;
    p=batch({ids[3],ids[1]});d.deliver(1,p);d.tick(1850);assert(d._connection.dataPending==2);
    assert(d.queue.wakes==1 && d._dataTXStalled);d._connection.txPauseMask=0;
    p=batch({ids[0],ids[2]});d.deliver(1,p);d.tick(1860);assert(!d._connection.dataPending);
    assert(!d.submitDataPacket(frame,sizeof(frame),1861));
    assert(Ath10k::requestDisconnect(d._connection,1862));d.networkLink(false);
    assert(!d.serviceDisconnect(1863));assert(d._connection.disconnect==Ath10k::DisconnectStage::Drain);
    assert(d.serviceDataTX(7000));assert(d._connection.dataPending==1);
    d._connection.disconnect=Ath10k::DisconnectStage::None;d._connection.portAuthorized=true;
    d._regs.tx4Fail=true;assert(d.submitDataPacket(frame,sizeof(frame),1870));
    assert(d._connection.dataPending==2); // ambiguous doorbell must retain ownership
    d.releaseWMIRuntime();
}
static void htTests(){
    auto caps=[](Ath10k::WMIBSS &a,bool vht){
        a.htPresent=a.htOperation=a.wmmPresent=true;a.ht[3]=255;
        const UInt8 edca[]={3,0xa4,0,0,0x27,0xa4,0,0,0x42,0x43,94,0,0x62,0x32,47,0};
        memcpy(a.wmm,edca,16);
        if(vht){a.vhtPresent=a.vhtOperation=true;
            Ath10k::htcWriteLE16(a.vht+4,0xfffa);Ath10k::htcWriteLE16(a.vht+8,0xfffa);
            Ath10k::htcWriteLE16(a.vhtOp+3,0xfffc);}
    };
    // Entire production association flow now includes WMM, HT IE and PEER_ASSOC.
    ConnectionDriver ht;caps(ht._wmiBSS.entries[0],false);ht.connect();
    assert(ht.networkUp && ht._connection.htEnabled && ht._connection.wmmConfigured);
    assert(!ht._connection.vhtEnabled && ht._connection.htRateCount==8);ht.releaseWMIRuntime();
    ConnectionDriver vht;auto &ap=vht._wmiBSS.entries[0];caps(ap,true);
    ap.rxChannel=ap.advertisedChannel=36;ap.rates[0]=12;ap.rates[1]=24;ap.rates[2]=48;ap.rates[3]=108;
    vht.connect();assert(vht.networkUp && vht._connection.vhtEnabled && vht._connection.wmmConfigured);
    auto rejected=vht._connection;rejected.stage=LinkStage::Assoc;rejected.submitted=true;rejected.assocReply=false;
    auto absent=managementResponse(rejected,true); // Remove all capability IEs from actual 802.11 response.
    Ath10k::receiveStationManagement(rejected,absent.data()+60,30,0);
    assert(rejected.stage==LinkStage::Failed && !rejected.assocReply);
    auto restricted=vht._connection;restricted.stage=LinkStage::Assoc;restricted.submitted=true;restricted.assocReply=false;
    restricted.vhtMap=0xfffc; // Request advertised only MCS0-7; AP response supports MCS0-9.
    auto expanded=managementResponse(restricted,true);
    Ath10k::receiveStationManagement(restricted,expanded.data()+60,Ath10k::connLE32(expanded.data()+32),0);
    assert(restricted.assocReply && restricted.vhtMap==0xfffc);
    auto htOnly=vht._connection;htOnly.stage=LinkStage::Assoc;htOnly.submitted=true;htOnly.assocReply=false;
    htOnly.vhtEnabled=false;htOnly.vhtMap=0xffff;
    Ath10k::receiveStationManagement(htOnly,expanded.data()+60,Ath10k::connLE32(expanded.data()+32),0);
    assert(htOnly.assocReply && !htOnly.vhtEnabled);
    vht.releaseWMIRuntime();
    Ath10k::ConnectionState s{};caps(s.ap,true);s.operatingChannel=36;
    Ath10k::negotiateHighThroughput(s);assert(s.htEnabled && s.vhtEnabled && s.width==20 && s.vhtMap==0xfffe && Ath10k::peerRateSet(s,1,20).rx==0xfffd);
    // A TKIP group cipher does not prevent CCMP unicast HT/VHT. Pairwise
    // WEP/TKIP does, including when an AP continues advertising fast modes.
    for(UInt8 cipher:{UInt8(1),UInt8(2),UInt8(5)}){
        auto legacy=s;legacy.pairCipher=cipher;legacy.groupCipher=4;
        UInt8 rejected[256];memset(rejected,0xa5,sizeof(rejected));legacy.stage=LinkStage::Assoc;
        assert(!Ath10k::buildStationManagement(rejected,sizeof(rejected),legacy));
        assert(!Ath10k::buildConnectionWMI(rejected,sizeof(rejected),2,legacy,LinkStage::PeerAssoc));
        for(auto byte:rejected)assert(byte==0xa5);
        Ath10k::negotiateHighThroughput(legacy);Ath10k::rememberNegotiatedRates(legacy);
        assert(!legacy.htEnabled && !legacy.vhtEnabled && !legacy.htRateCount && legacy.width==20);
        assert(legacy.nss==1 && !legacy.shortGI && !legacy.localHT && !legacy.localVHT);
        assert(!legacy.negotiatedHTMask && legacy.negotiatedWidth==20 && legacy.negotiatedVHTRx==0xffff);
        assert(!strcmp(legacy.phyReason,"legacy-pairwise-no-ht-vht"));
        Ath10k::negotiateHighThroughput(legacy);assert(!legacy.htEnabled && !legacy.vhtEnabled);
        legacy.ap.rateCount=1;legacy.ap.rates[0]=12;legacy.wmmConfigured=true;
        const auto bytes=Ath10k::buildStationManagement(rejected,sizeof(rejected),legacy);assert(bytes>=28);
        for(unsigned pos=28;pos<bytes;pos+=2+rejected[pos+1]){
            assert(pos+2+rejected[pos+1]<=bytes);assert(rejected[pos]!=45 && rejected[pos]!=191 && rejected[pos]!=199);
        }
        // A maintenance override must not resurrect wider PHY flags.
        assert(Ath10k::buildConnectionWMI(rejected,sizeof(rejected),2,legacy,LinkStage::PeerAssoc,2,80));
        assert(!(Ath10k::connLE32(rejected+36)&(0x1000u|0x2000u|0x02000000u|0x04000000u)));
        assert(Ath10k::connLE32(rejected+64)==1 && Ath10k::connLE32(rejected+72)==0);

        Ath10k::CandidateConfiguration candidate{};candidate.ap=s.ap;candidate.operatingChannel=36;
        candidate.firmwareHT=s.firmwareHT;candidate.firmwareVHT=s.firmwareVHT;candidate.pairCipher=cipher;
        Ath10k::negotiateHighThroughput(candidate);assert(!candidate.htEnabled && !candidate.vhtEnabled);
    }
    {auto mixed=s;mixed.groupCipher=AthSecurity::cipherTKIP;
     Ath10k::negotiateHighThroughput(mixed);assert(mixed.htEnabled && mixed.vhtEnabled);}
    for(UInt8 group:{UInt8(2),UInt8(4)})for(UInt8 pair:{UInt8(2),UInt8(4)})for(UInt8 akm:{UInt8(1),UInt8(2)}){
        auto selected=s;selected.secure=true;selected.pairCipher=pair;selected.groupCipher=group;selected.securityAKM=akm;
        selected.stage=LinkStage::Assoc;selected.ap.rateCount=1;selected.ap.rates[0]=12;
        Ath10k::negotiateHighThroughput(selected);UInt8 frame[256]{};
        const auto bytes=Ath10k::buildStationManagement(frame,sizeof(frame),selected);assert(bytes>=28);
        unsigned rsnCount=0;
        for(unsigned pos=28;pos<bytes;pos+=2+frame[pos+1]){
            assert(pos+2+frame[pos+1]<=bytes);
            if(frame[pos]==48){AthSecurity::RSNInfo parsed{};assert(AthSecurity::parseRSN(frame+pos,frame[pos+1]+2,parsed));
                assert(parsed.group==group && parsed.pairwise==(1u<<pair) && parsed.akms==(1u<<akm));++rsnCount;}
        }
        assert(rsnCount==1);
        UInt8 ie[22];size_t ieBytes=0;
        assert(AthSecurity::buildSelectedStationRSN(group,pair,akm,ie,sizeof(ie),ieBytes));
        const bool ordinary=pair==4 && (akm!=1 || group==4);
        assert(Ath10k::connectionRSNAccepted(selected,ie,ieBytes)==ordinary);
        selected.legacyRSNAllowed=true;assert(Ath10k::connectionRSNAccepted(selected,ie,ieBytes));
        ie[13]=pair==2?4:2;assert(!Ath10k::connectionRSNAccepted(selected,ie,ieBytes));ie[13]=pair;
        selected.pmfRequired=true;assert(!Ath10k::connectionRSNAccepted(selected,ie,ieBytes));
    }

    for(UInt8 group:{UInt8(2),UInt8(4)})for(UInt8 pair:{UInt8(2),UInt8(4)})for(UInt8 akm:{UInt8(1),UInt8(2)}){
        auto selected=s;selected.secure=true;selected.wpa1Selected=true;
        selected.pairCipher=pair;selected.groupCipher=group;selected.securityAKM=akm;selected.stage=LinkStage::Assoc;
        UInt8 ie[]={221,22,0,0x50,0xf2,1,1,0,0,0x50,0xf2,group,1,0,0,0x50,0xf2,pair,1,0,0,0x50,0xf2,akm};
        memcpy(selected.ap.wpa,ie,sizeof(ie));selected.ap.wpaLength=sizeof(ie);selected.ap.wpaPresent=true;
        selected.ap.rateCount=1;selected.ap.rates[0]=12;
        Ath10k::negotiateHighThroughput(selected);
        assert(Ath10k::connectionRSNAccepted(selected,ie,sizeof(ie)));
        assert(!Ath10k::connectionRSNAccepted(selected,AthSecurity::stationRSN,sizeof(AthSecurity::stationRSN)));
        UInt8 frame[256]{};const auto bytes=Ath10k::buildStationManagement(frame,sizeof(frame),selected);assert(bytes>=28);
        unsigned count=0;for(unsigned pos=28;pos<bytes;pos+=2+frame[pos+1]){
            assert(frame[pos]!=48);
            if(frame[pos]==221 && frame[pos+1]>=4 && frame[pos+5]==1){
                assert(frame[pos+1]==22 && !memcmp(frame+pos,ie,sizeof(ie)));++count;}
        }assert(count==1);
        selected.groupCipher=group==2?4:2;assert(!Ath10k::buildStationManagement(frame,sizeof(frame),selected));
        selected.groupCipher=group;selected.pmfRequired=true;assert(!Ath10k::buildStationManagement(frame,sizeof(frame),selected));
    }

    s.ap.vhtOp[3]=0;s.ap.vhtOp[4]=0;Ath10k::negotiateHighThroughput(s);
    assert(s.htEnabled && s.vhtEnabled && s.width==20 && s.vhtMap==0xfffe && Ath10k::peerRateSet(s,1,20).rx==0xfffd);
    s.ap.vhtOp[3]=0xfc;s.ap.vhtOp[4]=0xff;
    // Independent standard channel geometry and WMI packed power regression.
    assert(Ath10k::channelDefinitionAllowed(36,38,40));
    assert(Ath10k::channelDefinitionAllowed(44,46,40));
    assert(!Ath10k::channelDefinitionAllowed(40,42,40));
    assert(!Ath10k::channelDefinitionAllowed(161,163,40));
    assert(Ath10k::channelDefinitionAllowed(165,165,20));
    assert(!Ath10k::channelDefinitionAllowed(165,163,40));
    for(unsigned primary:{36u,40u,44u,48u})assert(Ath10k::channelDefinitionAllowed(primary,42,80));
    for(unsigned primary:{149u,153u,157u,161u})assert(Ath10k::channelDefinitionAllowed(primary,155,80));
    assert(!Ath10k::channelDefinitionAllowed(40,46,80));
    assert(!Ath10k::channelDefinitionAllowed(52,58,80));
    assert(!Ath10k::channelDefinitionAllowed(36,50,160));
    assert(Ath10k::channelDefinitionPowerHalfDbm(149,155,80)==20);
    assert(!Ath10k::channelDefinitionPowerHalfDbm(165,155,80));
    auto malformed=s;
    malformed.ap.vhtPresent=false;malformed.ap.ht[0]|=2;malformed.ap.htOp[1]=5;
    malformed.operatingChannel=40;Ath10k::negotiateHighThroughput(malformed);
    assert(malformed.width==20 && malformed.centerChannel==40);
    malformed.operatingChannel=165;malformed.ap.htOp[1]=7;
    Ath10k::negotiateHighThroughput(malformed);
    assert(malformed.width==20 && malformed.centerChannel==165);
    malformed=s;malformed.ap.vhtOp[0]=1;malformed.ap.vhtOp[1]=46;
    Ath10k::negotiateHighThroughput(malformed);assert(malformed.width!=80);
    UInt8 wire[256]{};s.stage=LinkStage::Start;
    assert(Ath10k::buildConnectionWMI(wire,sizeof(wire),2,s)==120);
    assert(Ath10k::connLE32(wire+104)==(8|0x1800));
    assert(wire[108]==0 && wire[109]==20 && wire[110]==20 && wire[111]==0);
    assert(wire[112]==0 && wire[113]==20 && wire[114]==0 && wire[115]==0);
    s.txPowerHalfDbm=21;assert(!Ath10k::buildConnectionWMI(wire,sizeof(wire),2,s));
    s.txPowerHalfDbm=0;assert(!Ath10k::buildConnectionWMI(wire,sizeof(wire),2,s));
    s.txPowerHalfDbm=20;

    s.stage=LinkStage::Assoc;s.ap.rateCount=1;s.ap.rates[0]=12;
    assert(!Ath10k::buildStationManagement(wire,128,s));
    unsigned bytes=Ath10k::buildStationManagement(wire,256,s);bool htIE=false,vhtIE=false,op=false;
    for(unsigned p=28;p<bytes;p+=2+wire[p+1]){assert(p+2+wire[p+1]<=bytes);htIE|=wire[p]==45;vhtIE|=wire[p]==191;op|=wire[p]==199;if(wire[p]==45)assert(wire[p+2+2]==27);}
    assert(htIE && vhtIE && op);
    s.stage=LinkStage::PeerAssoc;s.wmmConfigured=true;
    assert(Ath10k::buildConnectionWMI(wire,256,2,s)==132);
    assert((Ath10k::connLE32(wire+36)&0x02001002)==0x02001002);
    assert(Ath10k::connLE32(wire+48)==Ath10k::htcReadLE16(s.ap.ht));
    assert(Ath10k::connLE32(wire+88)==8 && Ath10k::connLE32(wire+120)==0xfffd && Ath10k::connLE32(wire+128)==0xfffd);
    // Peer VHT caps must reach firmware; preserve HT aggregate limit when
    // an AP supplies VHT exponent zero (Linux Netgear/Linksys workaround).
    s.ap.ht[2]=3;Ath10k::htcWriteLE32(s.ap.vht,0x20);
    Ath10k::negotiateHighThroughput(s);
    assert(Ath10k::buildConnectionWMI(wire,256,2,s));
    assert(Ath10k::connLE32(wire+68)==0x20 && Ath10k::connLE32(wire+52)==65535);
    s.ap.vhtPresent=false;Ath10k::negotiateHighThroughput(s);
    assert(!strcmp(s.phyReason,"ap-missing-vht-capability") && !s.vhtEnabled);
    s.ap.vhtPresent=true;s.ap.vhtOperation=false;Ath10k::negotiateHighThroughput(s);
    assert(!strcmp(s.phyReason,"ap-missing-vht-operation"));s.ap.vhtOperation=true;
    s.ap.vhtOp[3]=0xf8;Ath10k::negotiateHighThroughput(s);assert(s.htEnabled && !s.vhtEnabled); // AP requires two streams
    s.ap.htOp[7]=1;Ath10k::negotiateHighThroughput(s);assert(!s.htEnabled);
    // Production beacon parser: bounded HT/VHT and EDCA data, duplicate rejection.
    Ath10k::WMIBSSCache cache{};std::vector<UInt8> beacon(36);beacon[0]=0x80;beacon[16]=2;beacon[32]=100;beacon[34]=1;
    beacon.insert(beacon.end(),{0,1,'T',1,1,12,45,26});
    s.ap.htOp[7]=0;beacon.insert(beacon.end(),s.ap.ht,s.ap.ht+26);
    beacon.insert(beacon.end(),{61,22});s.ap.htOp[0]=36;beacon.insert(beacon.end(),s.ap.htOp,s.ap.htOp+22);
    beacon.insert(beacon.end(),{191,12});beacon.insert(beacon.end(),s.ap.vht,s.ap.vht+12);
    beacon.insert(beacon.end(),{192,5});beacon.insert(beacon.end(),s.ap.vhtOp,s.ap.vhtOp+5);
    beacon.insert(beacon.end(),{221,24,0,0x50,0xf2,2,1,1,0,0});beacon.insert(beacon.end(),s.ap.wmm,s.ap.wmm+16);
    Ath10k::recordWMIBSS(cache,beacon.data(),beacon.size(),36,30,0);
    assert(cache.count==1 && cache.entries[0].htPresent && cache.entries[0].vhtPresent && cache.entries[0].wmmPresent);
    auto before=cache.accepted;beacon.insert(beacon.end(),{45,0});
    Ath10k::recordWMIBSS(cache,beacon.data(),beacon.size(),36,30,0);assert(cache.accepted==before && cache.malformed==1);
}
static void rsnxeBSSScanTests(){
    Ath10k::WMIBSSCache cache{};std::vector<UInt8> base(36);base[0]=0x80;base[16]=2;base[32]=100;base[34]=0x11;
    base.insert(base.end(),{0,1,'T',1,1,12});uint8_t rsn[44]{};size_t rsnBytes=0;
    assert(AthSecurity::buildSAEStationRSN(nullptr,0,rsn,sizeof(rsn),rsnBytes));base.insert(base.end(),rsn,rsn+rsnBytes);
    for(unsigned body=1;body<=16;++body){
        auto frame=base;frame.push_back(244);frame.push_back(UInt8(body));frame.push_back(UInt8(0xa0|(body-1)));
        for(unsigned i=1;i<body;++i)frame.push_back(UInt8(0x80+i));
        Ath10k::recordWMIBSS(cache,frame.data(),frame.size(),36,30,0);
        assert(cache.count==1 && cache.entries[0].rsnxeLength==body+2);
        assert(!memcmp(cache.entries[0].rsnxe,frame.data()+base.size(),body+2));
        assert(AthSecurity::rsnxeHasH2E(cache.entries[0].rsnxe,cache.entries[0].rsnxeLength));
        const auto saved=cache.entries[0];const auto accepted=cache.accepted;
        frame.insert(frame.end(),{244,1,0x20}); // Duplicate cannot replace a valid observation.
        Ath10k::recordWMIBSS(cache,frame.data(),frame.size(),36,30,0);
        assert(cache.accepted==accepted && !memcmp(&cache.entries[0],&saved,sizeof(saved)));
    }
    const auto saved=cache.entries[0];const auto accepted=cache.accepted;
    for(const std::vector<UInt8> &bad : {std::vector<UInt8>{244,0}, {244,1,0x21}, {244,2,0x20,0}, {244,2,0x21}}){
        auto frame=base;frame.insert(frame.end(),bad.begin(),bad.end());
        Ath10k::recordWMIBSS(cache,frame.data(),frame.size(),36,30,0);
        assert(cache.accepted==accepted && !memcmp(&cache.entries[0],&saved,sizeof(saved)));
    }
    Ath10k::recordWMIBSS(cache,base.data(),base.size(),36,30,0);
    assert(cache.accepted==accepted+1 && !cache.entries[0].rsnxeLength);
    for(auto v:cache.entries[0].rsnxe)assert(!v); // A later omission cannot inherit old H2E support.
}
static void blockAckTests(){
    Ath10k::ConnectionState s{};s.stage=LinkStage::Connected;s.peerIDs[0]=1u<<7;s.peerCount=1;
    UInt8 f[16]{};f[0]=1;f[2]=4;f[8]=5;f[9]=64;Ath10k::htcWriteLE16(f+10,(7<<4)|3);
    assert(!Ath10k::validateConnectionHTT(s,f,12));
    for(unsigned len=0;len<12;++len)assert(Ath10k::validateConnectionHTT(s,f,len));
    f[9]=0;assert(Ath10k::validateConnectionHTT(s,f,12));f[9]=65;assert(Ath10k::validateConnectionHTT(s,f,12));f[9]=64;
    Ath10k::HTCCreditState credits{};Ath10k::RxSetupState rx{};rx.ringOwned=true;
    // Bad trailer must not commit BA state.
    f[1]=Ath10k::kHTCTrailerPresent;f[2]=8;f[4]=4;f[12]=1;f[13]=4;
    assert(Ath10k::parseHTTSetup(f,16,1,credits,rx,&s));assert(!s.baAdded);
    f[1]=0;f[2]=4;f[4]=0;
    assert(!Ath10k::parseHTTSetup(f,12,1,credits,rx,&s));assert(s.baAdded==1 && s.ba[0].window==64 && s.ba[0].tid==3);
    f[9]=32;Ath10k::commitConnectionHTT(s,f);assert(s.baAdded==2 && s.ba[0].window==32 && !s.ba[1].window);
    f[8]=6;assert(!Ath10k::parseHTTSetup(f,12,1,credits,rx,&s));assert(s.baDeleted==1 && !s.ba[0].window);
    f[8]=5;Ath10k::htcWriteLE16(f+10,8<<4);Ath10k::commitConnectionHTT(s,f);assert(s.baIgnored==1 && !s.ba[0].window);
    Ath10k::htcWriteLE16(f+10,7<<4);Ath10k::commitConnectionHTT(s,f);assert(s.ba[0].window);
    UInt8 desc[64]{};Ath10k::htcWriteLE32(desc+12,7u|(10u<<16));Ath10k::htcWriteLE32(desc+20,0);
    Ath10k::recordRxBlockAck(s,desc);Ath10k::htcWriteLE32(desc+12,7u|(12u<<16));Ath10k::recordRxBlockAck(s,desc);
    assert(s.baFrames==2 && s.baGaps==1 && s.ba[0].frames==2 && s.ba[0].gaps==1);
    f[8]=4;Ath10k::htcWriteLE16(f+10,7);Ath10k::commitConnectionHTT(s,f);assert(!s.ba[0].window);
    // Bounded table: full state cannot overwrite another peer/TID.
    s.peerIDs[0]=1u<<7;for(auto &ba:s.ba){ba.peer=9;ba.tid=0;ba.window=64;}
    f[8]=5;Ath10k::htcWriteLE16(f+10,7<<4);Ath10k::commitConnectionHTT(s,f);
    assert(s.baOverflow==1 && s.ba[0].peer==9);
}
static void partialCancelTests(){
    ConnectionDriver untouched;untouched._connection.cancelRequested=true;untouched.tick(1270);
    assert(untouched._wmiLive.active && untouched._connection.stage==LinkStage::Disabled && !untouched.commands);
    untouched.releaseWMIRuntime();
    ConnectionDriver authenticating;
    for(unsigned t=1270;t<1400 && authenticating._connection.stage!=LinkStage::Auth;t+=10)authenticating.tick(t);
    auto &s=authenticating._connection;
    assert(s.stage==LinkStage::Auth && s.vdevStarted && !s.vdevUp && s.peerCount);
    s.cancelRequested=true;
    for(unsigned t=1400;t<1600;t+=10)authenticating.tick(t);
    assert(authenticating._wmiLive.active && s.stage==LinkStage::Disabled && !s.peerCount && !authenticating.networkUp);
    authenticating.releaseWMIRuntime();
    ConnectionDriver scanning;scanning.connect();auto &c=scanning._connection;
    scanning._wmiScan.completed=false;c.cancelRequested=true;scanning.networkLink(false);
    assert(!scanning.serviceConnection(1900));
    assert(scanning._wmiScan.cancelRequested && c.disconnect==Ath10k::DisconnectStage::Drain && !c.wmiOwned);
    scanning._wmiScan.completed=true;
    for(unsigned t=1910;t<2100;t+=10)scanning.tick(t);
    assert(scanning._wmiLive.active && c.stage==LinkStage::Disabled);scanning.releaseWMIRuntime();
}

#if !defined(ATH10K_CHANNEL_SWITCH_TEST) && !defined(ATH10K_AP_MAINTENANCE_TEST)
static void deferredDataWakeTests(){
    ConnectionDriver d;d.connect();auto &s=d._connection;
    d.queueEnabled=true;d._dataTXStalled=true;
    s.eapolPause=true;s.txWakePending=true;
    assert(!d.serviceConnection(1800));
    assert(!d.queue.wakes && s.txWakePending && d._dataTXStalled);
    UInt8 frame[64]{};frame[12]=8;
    assert(d.submitDataPacket(frame,sizeof(frame),1801));
    assert(!s.dataPending); // Direct submission obeys the same EAPOL hold.
    s.eapolPause=false;d.queueEnabled=false;
    assert(!d.serviceConnection(1810));assert(s.txWakePending && d._dataTXStalled);
    d.queueEnabled=true;
    assert(!d.serviceConnection(1820));
    assert(d.queue.wakes==1 && !s.txWakePending && !d._dataTXStalled);
    // A stalled BSD queue must recover even without a new completion/WAKE event.
    d._dataTXStalled=true;s.eapolPause=true;
    assert(!d.serviceConnection(1830));assert(d.queue.wakes==1 && d._dataTXStalled);
    s.eapolPause=false;
    assert(!d.serviceConnection(1840));assert(d.queue.wakes==2 && !d._dataTXStalled);
    d.releaseWMIRuntime();
}
static void sharedWEPSubmission(){
 ConnectionDriver d;d.connect();auto &s=d._connection;
 s.stage=LinkStage::Auth;s.secure=s.sharedKeyAuth=true;s.pairCipher=1;s.portAuthorized=false;s.securityAKM=0;
 AthSecurity::WEPSharedAuthentication owner;UInt8 key[5]{},iv[3]={1,2,3},challenge[9]={1,0,2,0,0,0,16,1,42},frame[64]{};
 assert(owner.begin(1,s.local,s.bssid,key,5,0,iv,1900,3000));assert(owner.requestSubmitted());
 assert(owner.receive(1,s.local,s.bssid,challenge,sizeof(challenge),1950));
 const auto n=owner.buildResponseFrame(1,s.local,s.bssid,2000,1,frame,sizeof(frame));assert(n==41);
 Ath10k::WEPAuthenticationTX proof{&owner,1,2000};bool submitted=false;
 d._regs.tx4Consume=[&](){
  const auto *cmd=static_cast<const UInt8 *>(d._packetCommand.virtualAddress());
  assert(cmd[9]==0x65 && !memcmp(d._packetBuffer.virtualAddress(),frame,n));submitted=true;
  d.deliver(1,mgmtCompletion(s.txId));
 };
 const auto mode=AthSecurity::ManagementTX::SoftwareWEPAuthentication;
 const auto purpose=Ath10k::ConnectionState::EAPOLPurpose::Handshake;
 const auto id=s.txId;
 assert(d.submitNetworkPacket(frame,n,true,2000,mode));assert(!submitted && s.txId==id);
 proof.now=1999;assert(d.submitNetworkPacket(frame,n,true,2000,mode,purpose,&proof));assert(!submitted && s.txId==id);
 proof.now=2000;assert(!d.submitNetworkPacket(frame,n,true,2000,mode,purpose,&proof));
 assert(submitted && s.txOwned && !s.lastTxPMF && !s.lastTxEAPOL);
 owner.cancel(); // DMA retains its own copied ciphertext until retirement.
 s.submitted=true;s.managementRetryMs=3000;d.tick(2010);assert(!s.txOwned);
 d.releaseWMIRuntime();
}
static void protectedManagementTransport(){
    ConnectionDriver d;d.connect();auto &s=d._connection;s.secure=true;s.pairInstalled=true;s.pmfRequired=true;s.portAuthorized=true;s.securityPhase=5;
    UInt8 plain[28]{};plain[0]=0xd0;plain[1]=0x40;memcpy(plain+4,s.bssid,6);memcpy(plain+10,s.local,6);memcpy(plain+16,s.bssid,6);
    plain[24]=8;plain[26]=0x12;plain[27]=0x34;AthSecurity::PMFCCMPResult prepared;
    assert(AthSecurity::PMFHardwareCCMP::prepare(plain,sizeof(plain),s.local,s.bssid,1,prepared));
    bool submitted=false;
    d._regs.tx4Consume=[&](){
        const auto cmd=static_cast<const UInt8 *>(d._packetCommand.virtualAddress());
        assert(s.txOwned && cmd[9]==0x61 && Ath10k::htcReadLE16(cmd+12)==prepared.bytes);
        assert(Ath10k::wmiReadLE32(cmd+16)==d._packetBuffer.dmaAddress());
        assert(!memcmp(d._packetBuffer.virtualAddress(),prepared.frame,prepared.bytes));submitted=true;
        d.deliver(1,mgmtCompletion(s.txId));
    };
    const auto id=s.txId;const bool complete=s.txComplete;
    assert(d.submitNetworkPacket(prepared.frame,prepared.bytes,true,2000)); // Plain mode cannot bypass protected TX.
    assert(s.txId==id && s.txComplete==complete && !s.txOwned && !submitted);
    assert(d.submitNetworkPacket(prepared.frame,prepared.bytes,true,2000,AthSecurity::ManagementTX::SoftwareCCMP));
    assert(!s.txOwned && !submitted);
    s.pairCipher=AthSecurity::cipherTKIP;
    assert(d.submitNetworkPacket(prepared.frame,prepared.bytes,true,2000,AthSecurity::ManagementTX::HardwareCCMP));
    assert(!s.txOwned && !submitted);s.pairCipher=AthSecurity::cipherCCMP;
    assert(!d.submitNetworkPacket(prepared.frame,prepared.bytes,true,2000,AthSecurity::ManagementTX::HardwareCCMP));
    assert(submitted && s.txOwned && s.lastTxPMF);d.tick(2010);assert(!s.txOwned && !s.cancelRequested);
    d._regs.tx4Consume=[&](){d.deliver(1,mgmtCompletion(s.txId,1));};
    assert(AthSecurity::PMFHardwareCCMP::prepare(plain,sizeof(plain),s.local,s.bssid,2,prepared));
    assert(!d.submitNetworkPacket(prepared.frame,prepared.bytes,true,2020,AthSecurity::ManagementTX::HardwareCCMP));
    d.tick(2030);assert(!s.txOwned && !s.cancelRequested && s.txErrors==1); // Query coordinator, not generic MLME failure, decides retry/timeout.
    s.pmfTXPending=true;assert(!Ath10k::dataTXAdmissionOpen(s));s.pmfTXPending=false;assert(Ath10k::dataTXAdmissionOpen(s));
    s.spectrum.pending=true;s.spectrum.length=31;const auto before=s.txId;
    assert(!d.serviceConnection(2040) && s.txId==before && s.spectrum.pending && !s.txOwned); // Required reports are never submitted raw.
    s.spectrum.pending=false;s.spectrum.inFlight=true;
    d._regs.tx4Consume=[&](){d.deliver(1,mgmtCompletion(s.txId));};
    assert(!d.submitNetworkPacket(prepared.frame,prepared.bytes,true,2050,AthSecurity::ManagementTX::HardwareCCMP));
    s.lastTxSpectrum=true; // Native handoff marks the retained report after the copied payload is accepted.
    d.tick(2060);assert(!s.txOwned && !s.spectrum.inFlight && s.spectrum.completed==1);
    d.releaseWMIRuntime();
}
static void pmfFirmwarePolicy(){
    ConnectionDriver d;d.connect();auto &s=d._connection;UInt8 f[256]{};
    s.pmfRequired=true;s.firmwareMFPSupport=true;s.pmfQoSTransported=false;
    assert(!Ath10k::buildConnectionWMI(f,sizeof(f),2,s,LinkStage::PeerAssoc));
    s.pmfQoSTransported=true;s.firmwareMFPSupport=false;
    assert(Ath10k::buildConnectionWMI(f,sizeof(f),2,s,LinkStage::PeerAssoc) && !(Ath10k::wmiReadLE32(f+36)&0x08000000));
    s.firmwareMFPSupport=true;assert(Ath10k::buildConnectionWMI(f,sizeof(f),2,s,LinkStage::PeerAssoc) && (Ath10k::wmiReadLE32(f+36)&0x08000000));
    assert(Ath10k::buildConnectionWMI(f,sizeof(f),2,s,LinkStage::Start) && !Ath10k::wmiReadLE32(f+32)); // Linux STA keeps VDEV_START PMF flag clear.
    s.pmfRequired=false;assert(Ath10k::buildConnectionWMI(f,sizeof(f),2,s,LinkStage::PeerAssoc) && !(Ath10k::wmiReadLE32(f+36)&0x08000000));
    Ath10k::resetDisconnected(s);assert(s.firmwareMFPSupport && s.pmfQoSTransported && !s.pmfRequired);d.releaseWMIRuntime();
}
static void associationComebackTests(){
    const UInt8 ie[]={56,5,3,0xe8,3,0,0};UInt32 tu=999;
    assert(Ath10k::associationComebackInterval(ie,sizeof(ie),tu) && tu==1000);
    for(unsigned mode=0;mode<6;++mode){
        std::vector<UInt8> bad(ie,ie+sizeof(ie));
        if(mode==0)bad.pop_back();if(mode==1)bad[1]=4;if(mode==2)bad[2]=2;
        if(mode==3)bad.insert(bad.end(),ie,ie+sizeof(ie));
        if(mode==4)bad.push_back(1);if(mode==5)bad[0]=1;
        tu=999;assert(!Ath10k::associationComebackInterval(bad.data(),bad.size(),tu) && tu==999);
    }
    Ath10k::ConnectionState state;state.stage=LinkStage::Assoc;state.submitted=state.txComplete=true;
    state.sinceMs=100;state.managementAttempts=1;state.associationComeback.pending=true;state.associationComeback.intervalTU=1000;
    bool waiting=false;assert(!Ath10k::serviceAssociationComeback(state,200,waiting) && waiting);
    const UInt64 until=state.associationComeback.untilMs;assert(until==1224);
    assert(!Ath10k::serviceAssociationComeback(state,1000,waiting) && waiting && state.associationComeback.untilMs==until);
    state.txOwned=true;assert(!Ath10k::serviceAssociationComeback(state,until,waiting) && waiting && state.submitted);
    state.txOwned=false;assert(!Ath10k::serviceAssociationComeback(state,until,waiting) && !waiting && !state.submitted && !state.associationComeback.pending);
    for(unsigned mode=0;mode<4;++mode){
        state={};state.stage=LinkStage::Assoc;state.submitted=state.txComplete=true;state.sinceMs=100;state.managementAttempts=1;
        state.associationComeback.pending=true;state.associationComeback.intervalTU=1000;UInt64 now=200;
        if(mode==0)state.managementAttempts=3;
        if(mode==1)state.associationComeback.intervalTU=0xffffffffu;
        if(mode==2)now=99;
        if(mode==3){state.sinceMs=~UInt64(0)-100;now=~UInt64(0)-50;}
        assert(Ath10k::serviceAssociationComeback(state,now,waiting) && state.submitted && !waiting);
    }
    // Independent protocol boundary values: zero TU is immediate; one TU
    // requires two milliseconds in the host clock, never a truncated 1 ms.
    for(unsigned interval:{0u,1u}){
        state={};state.stage=LinkStage::Assoc;state.sinceMs=100;state.submitted=state.txComplete=true;state.managementAttempts=1;
        state.associationComeback.pending=true;state.associationComeback.intervalTU=interval;
        assert(!Ath10k::serviceAssociationComeback(state,200,waiting));
        if(interval)assert(waiting && state.associationComeback.untilMs==202);
        else assert(!waiting && !state.associationComeback.pending && !state.submitted);
    }
    for(unsigned cancel=0;cancel<3;++cancel){
        state={};state.stage=LinkStage::Assoc;state.submitted=state.txComplete=true;state.sinceMs=100;state.managementAttempts=1;
        state.associationComeback.pending=true;state.associationComeback.intervalTU=1000;
        if(cancel==0)state.cancelRequested=true;
        if(cancel==1)state.disconnect=Ath10k::DisconnectStage::Drain;
        if(cancel==2)state.stage=LinkStage::Failed;
        assert(!Ath10k::serviceAssociationComeback(state,200,waiting) && !waiting && !state.associationComeback.pending && state.submitted);
    }
    // Honor a valid interval beyond five seconds, within one fixed request
    // deadline. A later caller cannot extend the original request lifetime.
    state={};state.stage=LinkStage::Assoc;state.sinceMs=100;state.submitted=state.txComplete=true;state.managementAttempts=1;
    state.associationComeback.pending=true;state.associationComeback.intervalTU=10000;
    assert(!Ath10k::serviceAssociationComeback(state,200,waiting,20000) && waiting && state.associationComeback.untilMs==10440 && state.associationDeadlineMs==20000);
    assert(!Ath10k::serviceAssociationComeback(state,10440,waiting,30000) && !waiting && !state.submitted && state.associationDeadlineMs==20000);
    state.submitted=true;state.associationComeback.pending=true;state.associationComeback.intervalTU=10000;
    assert(Ath10k::serviceAssociationComeback(state,10450,waiting,30000) && state.submitted && state.associationDeadlineMs==20000);
    // Actual RX parser binds one wait to this in-flight request. Duplicate
    // temporary replies cannot move its deadline, and success is immutable.
    ConnectionDriver model;model.connect();auto response=model._connection;response.stage=LinkStage::Assoc;response.submitted=true;response.assocReply=false;
    auto packet=comebackResponse(response,1000);UInt32 bytes=Ath10k::wmiReadLE32(packet.data()+32);
    Ath10k::receiveStationManagement(response,packet.data()+60,bytes,0,response.operatingChannel);
    assert(response.stage==LinkStage::Assoc && response.associationComeback.pending && response.diagnostics.associationComebacks==1 && !response.assocReply);
    response.sinceMs=100;assert(!Ath10k::serviceAssociationComeback(response,200,waiting));const UInt64 deadline=response.associationComeback.untilMs;
    packet=comebackResponse(response,4000);Ath10k::receiveStationManagement(response,packet.data()+60,Ath10k::wmiReadLE32(packet.data()+32),0,response.operatingChannel);
    assert(response.associationComeback.untilMs==deadline && response.associationComeback.intervalTU==1000 && response.diagnostics.associationComebacks==1);
    packet=managementResponse(response,true);Ath10k::receiveStationManagement(response,packet.data()+60,30,0,response.operatingChannel);
    assert(response.assocReply && !response.associationComeback.pending);
    packet=comebackResponse(response,1000);Ath10k::receiveStationManagement(response,packet.data()+60,Ath10k::wmiReadLE32(packet.data()+32),0,response.operatingChannel);
    assert(response.assocReply && response.associationStatus==0 && !response.associationComeback.pending && response.diagnostics.associationComebacks==1);
    model.releaseWMIRuntime();
    // Full production radio service waits, retries without reopening Auth or
    // recreating peers, then completes the original association normally.
    ConnectionDriver d;d.temporaryAssociationRejects=1;d.comebackTU=10000;d.connect();assert(!d.networkUp && d._connection.associationComeback.armed);
    const UInt64 retryAt=d._connection.associationComeback.untilMs;const unsigned packets=d.packets,commands=d.commands;
    for(UInt64 now=1800;now<retryAt;++now)d.tick(now);
    assert(d.packets==packets && d.commands==commands && !d.networkUp);
    for(UInt64 now=retryAt;now<retryAt+500 && !d.networkUp;now+=10)d.tick(now);
    assert(d.networkUp && d.packets==packets+1 && !d._connection.disconnectCount && d._connection.diagnostics.associationComebacks==1 && d._connection.diagnostics.lastAssociationStatus==30);d.releaseWMIRuntime();
    ConnectionDriver exhausted;exhausted.temporaryAssociationRejects=4;exhausted.connect();
    for(UInt64 now=1800;now<7000;now+=10)exhausted.tick(now);
    assert(!exhausted.networkUp && exhausted._connection.stage==LinkStage::Disabled && exhausted._connection.disconnectCount==1 && exhausted._connection.diagnostics.associationComebacks==3);exhausted.releaseWMIRuntime();
}
static void associationIdentifierTests(){
    ConnectionDriver d;d.connect();assert(d.networkUp);
    // IEEE 802.11 AID is the lower eleven bits; all five high bits are reserved.
    // This golden field interpretation is independent of the driver parser.
    for(unsigned reserved=0;reserved<32;++reserved){
        auto state=d._connection;state.stage=LinkStage::Assoc;state.submitted=true;state.assocReply=false;
        auto packet=managementResponse(state,true);const UInt16 raw=UInt16(7u|(reserved<<11));
        Ath10k::htcWriteLE16(packet.data()+88,raw);
        Ath10k::receiveStationManagement(state,packet.data()+60,Ath10k::wmiReadLE32(packet.data()+32),0,state.operatingChannel);
        assert(state.stage==LinkStage::Assoc && state.assocReply && state.aid==7 && state.associationStatus==0);
    }
    // Reject both AP-denied status and invalid low-bit AIDs; preserve raw
    // diagnostics across teardown and a later successful association.
    auto denied=d._connection;denied.stage=LinkStage::Assoc;denied.submitted=true;denied.assocReply=false;
    auto packet=managementResponse(denied,true,17);Ath10k::htcWriteLE16(packet.data()+88,0xffff);
    Ath10k::receiveStationManagement(denied,packet.data()+60,30,0,denied.operatingChannel);
    assert(denied.stage==LinkStage::Failed && denied.diagnostics.associationRejects==1);
    assert(denied.diagnostics.lastAssociationStatus==17 && denied.diagnostics.lastAssociationRawAID==0xffff);
    Ath10k::resetDisconnected(denied);assert(denied.diagnostics.associationRejects==1 && denied.diagnostics.lastAssociationStatus==17);
    auto next=d._connection;next.diagnostics=denied.diagnostics;next.stage=LinkStage::Assoc;next.submitted=true;next.assocReply=false;
    packet=managementResponse(next,true);Ath10k::receiveStationManagement(next,packet.data()+60,30,0,next.operatingChannel);
    assert(next.assocReply && next.associationStatus==0 && next.diagnostics.lastAssociationStatus==17 && next.diagnostics.associationRejects==1);
    for(UInt16 raw:{UInt16(0),UInt16(0xf800),UInt16(2008),UInt16(0xffff)}){
        auto invalid=d._connection;invalid.stage=LinkStage::Assoc;invalid.submitted=true;invalid.assocReply=false;
        packet=managementResponse(invalid,true);Ath10k::htcWriteLE16(packet.data()+88,raw);
        Ath10k::receiveStationManagement(invalid,packet.data()+60,30,0,invalid.operatingChannel);
        assert(invalid.stage==LinkStage::Failed && invalid.diagnostics.associationRejects==1);
        assert(invalid.diagnostics.lastAssociationStatus==0 && invalid.diagnostics.lastAssociationRawAID==raw);
    }
    auto ignored=d._connection;ignored.stage=LinkStage::Assoc;ignored.submitted=true;
    packet=managementResponse(ignored,true,17);packet[70]^=2; // Foreign transmitter cannot overwrite diagnostics.
    Ath10k::receiveStationManagement(ignored,packet.data()+60,30,0,ignored.operatingChannel);
    assert(!ignored.diagnostics.associationRejects);
    d.releaseWMIRuntime();
}
static void oweAssociationTests(){
    ConnectionDriver d;d.connect();assert(d.networkUp);
    auto base=d._connection;base.stage=LinkStage::Assoc;base.submitted=true;base.assocReply=false;
    base.htEnabled=base.vhtEnabled=false;base.securityAKM=18;base.secure=base.pmfRequired=true;
    base.wepSelected=base.wpa1Selected=false;base.pairCipher=base.groupCipher=4;base.oweResponseReady=false;
    UInt8 x[32]{};x[31]=1; // Format-only; worker must reject invalid curve points.
    assert(AthSecurity::encodeOWEGroup19Parameter(x,32,base.oweRequest,37));base.oweRequestReady=true;
    UInt8 rsn[28];size_t rsnBytes=0;assert(AthSecurity::buildOWEStationRSN(rsn,sizeof(rsn),rsnBytes));
    base.ap.rsnPresent=true;base.ap.rsnLength=rsnBytes;memcpy(base.ap.rsn,rsn,rsnBytes);
    UInt8 request[512];auto length=Ath10k::buildStationManagement(request,sizeof(request),base);assert(length);
    unsigned dhCount=0,rsnCount=0;for(unsigned p=28;p<length;p+=2+request[p+1]){
        if(request[p]==255){++dhCount;assert(request[p+1]==35 && !memcmp(request+p,base.oweRequest,37));}
        if(request[p]==48){++rsnCount;assert(!memcmp(request+p,rsn,28));}
    }assert(dhCount==1 && rsnCount==1);
    auto missing=base;missing.oweRequestReady=false;assert(!Ath10k::buildStationManagement(request,sizeof(request),missing));
    auto packet=managementResponse(base,true);std::vector<UInt8> response(packet.begin()+60,packet.begin()+90);
    response.insert(response.end(),rsn,rsn+28);response.insert(response.end(),base.oweRequest,base.oweRequest+37);
    for(unsigned scenario=0;scenario<7;++scenario){auto state=base;auto frame=response;
        if(scenario==1)frame.resize(58); // Missing DH.
        if(scenario==2)frame.insert(frame.end(),base.oweRequest,base.oweRequest+37); // Duplicate DH.
        if(scenario==3)frame[61]=20; // Unsupported group.
        if(scenario==4)frame.pop_back(); // Truncated element.
        if(scenario==5)frame.erase(frame.begin()+30,frame.begin()+58); // Missing RSN.
        if(scenario==6)frame[10]^=2; // Wrong sender.
        Ath10k::receiveStationManagement(state,frame.data(),frame.size(),0,state.operatingChannel);
        assert(state.assocReply==(scenario==0) && state.oweResponseReady==(scenario==0));
        if(!scenario){assert(!memcmp(state.oweResponse,base.oweRequest,37));
            frame.back()^=1;Ath10k::receiveStationManagement(state,frame.data(),frame.size(),0,state.operatingChannel);
            assert(!memcmp(state.oweResponse,base.oweRequest,37));}
    }
    auto cleared=base;cleared.oweResponseReady=true;Ath10k::resetDisconnected(cleared);
    assert(!cleared.oweRequestReady && !cleared.oweResponseReady);
    d.releaseWMIRuntime();
}
int main(){
    oweAssociationTests();
    {UInt8 wire[32];
     for(UInt8 index=0;index<4;++index){memset(wire,0x5a,sizeof(wire));
      assert(Ath10k::buildWEPTransmitIndexWMI(wire,sizeof(wire),2,17,index)==28);
      assert(wire[0]==2 && wire[5]==17 && Ath10k::htcReadLE16(wire+2)==20);
      assert(Ath10k::connLE32(wire+8)==0x5008 && Ath10k::htcReadLE16(wire+12)==12 && Ath10k::htcReadLE16(wire+14)==95);
      assert(!Ath10k::connLE32(wire+16) && Ath10k::connLE32(wire+20)==0x21 && Ath10k::connLE32(wire+24)==index);
      for(unsigned i=28;i<sizeof(wire);++i)assert(wire[i]==0x5a);
     }
     for(unsigned n=0;n<28;++n){memset(wire,0x5a,sizeof(wire));assert(!Ath10k::buildWEPTransmitIndexWMI(wire,n,2,0,0));for(auto b:wire)assert(b==0x5a);}
     for(UInt8 endpoint:{UInt8(0),UInt8(255)})assert(!Ath10k::buildWEPTransmitIndexWMI(wire,sizeof(wire),endpoint,0,0));
     assert(!Ath10k::buildWEPTransmitIndexWMI(wire,sizeof(wire),2,0,4));
    }

    { // Programming and receipt cipher namespaces must never be interchanged.
     struct Case{UInt8 selected,wmi,htt,length;};
     for(const auto c:{Case{1,1,3,5},Case{5,1,2,13},Case{2,2,4,32},Case{4,4,6,16}}){
      const auto spec=Ath10k::firmwareKeyCipher(c.selected);
      assert(spec.wmi==c.wmi && spec.htt==c.htt && spec.length==c.length);
      UInt8 frame[160]{},key[32]{},peer[6]={2,1,2,3,4,5};
      for(UInt32 flags:{0u,1u,2u,3u}){
       assert(Ath10k::buildKeyWMI(frame,sizeof(frame),2,1,peer,3,flags,spec.wmi,key,spec.length));
       assert(Ath10k::connLE32(frame+36)==c.wmi && Ath10k::connLE32(frame+96)==c.length);
       assert(Ath10k::connLE32(frame+32)==flags && Ath10k::connLE32(frame+28)==3);
      }
      Ath10k::ConnectionState state{};state.pairCipher=state.groupCipher=c.selected;
      for(UInt8 phase:{UInt8(1),UInt8(2)}){
       state.securityPhase=phase;
       const auto expected=Ath10k::expectedSecurityIndication(state);
       assert(expected==((c.selected==1 || c.selected==5)?0xff:UInt8(c.htt|(phase==1?0x80:0))));
      }
     }
     for(unsigned cipher=0;cipher<256;++cipher)if(cipher!=1 && cipher!=2 && cipher!=4 && cipher!=5){
      const auto spec=Ath10k::firmwareKeyCipher(UInt8(cipher));assert(!spec.wmi && !spec.htt && !spec.length);
     }
    }

    {UInt8 command[160],key[32]{},peer[6]={2,1,2,3,4,5};
     const UInt8 rsc[6]={0x01,0x23,0x45,0x67,0x89,0xab};
     for(unsigned i=0;i<32;++i)key[i]=UInt8(0x80+i);
     for(UInt8 endpoint:{UInt8(0),UInt8(255)}){
      memset(command,0x5a,sizeof(command));
      assert(!Ath10k::buildKeyWMI(command,sizeof(command),endpoint,7,peer,0,0,4,key,16));
      for(auto byte:command)assert(byte==0x5a);
     }
     for(UInt32 n:{5u,13u,16u,32u}){
      const UInt32 cipher=n==16?4:n==32?2:1,expected=112+((n+3)&~3u);
      memset(command,0x5a,sizeof(command));
      assert(!Ath10k::buildKeyWMI(command,expected-1,2,7,peer,3,1,cipher,key,n));
      for(auto byte:command)assert(byte==0x5a);
      assert(Ath10k::buildKeyWMI(command,expected,2,7,peer,3,1,cipher,key,n)==expected);
      assert(command[expected]==0x5a && Ath10k::connLE32(command+96)==n);
      assert(Ath10k::htcReadLE16(command+108)==((n+3)&~3u));
      for(UInt32 at=112+n;at<expected;++at)assert(!command[at]);
      assert(!memcmp(command+112,key,n) && !memcmp(command+20,peer,6));
      assert(command[0]==2 && command[5]==7 && Ath10k::htcReadLE16(command+2)==expected-8);
      assert(Ath10k::buildKeyWMI(command,expected,2,7,peer,3,1,cipher,key,n,rsc)==expected);
      assert(!memcmp(command+40,rsc,6) && !command[46] && !command[47]);
      assert(Ath10k::buildKeyWMI(command,160,2,7,peer,3,1,0,nullptr,n)==expected);
      for(UInt32 at=112;at<expected;++at)assert(!command[at]);
     }
     assert(!Ath10k::buildKeyWMI(command,160,2,7,peer,4,1,1,key,5));
     assert(!Ath10k::buildKeyWMI(command,160,2,7,peer,0,4,1,key,5));
     assert(!Ath10k::buildKeyWMI(command,160,2,7,peer,0,0,0,key,5));
     assert(!Ath10k::buildKeyWMI(command,160,2,7,peer,0,0,1,nullptr,5));
    }

    associationComebackTests();
    associationIdentifierTests();
    rsnxeBSSScanTests();
    pmfFirmwarePolicy();
    sharedWEPSubmission();
    protectedManagementTransport();
    deferredDataWakeTests();
    partialCancelTests();
    blockAckTests();
    htTests();
    pipelineTests();
    statsEventTests();
    disconnectTests();
    secureConnectionTests();secureConnectionTests(true);
    startResponseTests();
    peerMapTests();
    rxLayoutTests();
    pauseTests();
    paddrTests();
    peerStateTests();
    mgmtCompletionTests();
    (void)mgmtPacket();
    ConnectionDriver good;good.connect();assert(good.networkUp && good._connection.stage==LinkStage::Connected);
    assert(good.commands==11 && good.packets==2 && !good._connection.txOwned && !good._connection.wmiOwned);
    UInt8 ethernet[60]{};ethernet[0]=0xff;memcpy(ethernet+6,good._connection.local,6);ethernet[12]=8;ethernet[13]=6;
    assert(!good.submitNetworkPacket(ethernet,sizeof(ethernet),false,1800));assert(good._connection.txOwned);
    good.tick(1810);assert(!good._connection.txOwned && good._connection.txPackets==1);rxTests(good._connection);amsduTests(good._connection);
    // Independent receipt ownership through the actual submission/retirement path.
    using Purpose=Ath10k::ConnectionState::EAPOLPurpose;
    assert(good.submitNetworkPacket(ethernet,sizeof(ethernet),false,1811,AthSecurity::ManagementTX::Plain,Purpose::MICReport));
    assert(!good._connection.txOwned && !good._connection.micReportCompletion.pending);
    ethernet[12]=0x88;ethernet[13]=0x8e;
    good._connection.eapolCompletion.begin(900);
    good._connection.tkipDataBlocked=true;good._connection.secure=true;
    assert(!Ath10k::dataTXAdmissionOpen(good._connection));
    UInt8 htt[256]{};
    assert(Ath10k::buildHTTPacket(htt,sizeof(htt),ethernet,sizeof(ethernet),0x1000,0x2000,1,good._connection,false));
    assert(htt[9]==0x42); // Key authorization survives the ordinary-data block.
    ethernet[12]=8;ethernet[13]=6;
    assert(!Ath10k::buildHTTPacket(htt,sizeof(htt),ethernet,sizeof(ethernet),0x1000,0x2000,1,good._connection,false));
    ethernet[12]=0x88;ethernet[13]=0x8e;
    assert(!good.submitNetworkPacket(ethernet,sizeof(ethernet),false,1812,AthSecurity::ManagementTX::Plain,Purpose::MICReport));
    const auto micID=good._connection.txId;
    good.tick(1813);
    assert(!good._connection.txOwned && good._connection.micReportCompletion.complete);
    assert(good._connection.micReportCompletion.id==micID);
    assert(good._connection.eapolCompletion.id==900 && !good._connection.eapolCompletion.complete);
    assert(!good._connection.authorizeRequested && !good._connection.eapolTxFailed);
    assert(good.submitNetworkPacket(ethernet,sizeof(ethernet),false,1814,AthSecurity::ManagementTX::Plain,Purpose::MICReport));
    assert(!good._connection.txOwned); // Unconsumed result cannot be overwritten.
    good._connection.micReportCompletion.clear();good._connection.eapolCompletion.clear();
    UInt8 micDeauth[26]{};micDeauth[0]=0xc0;Ath10k::htcWriteLE16(micDeauth+24,14);
    memcpy(micDeauth+4,good._connection.bssid,6);memcpy(micDeauth+10,good._connection.local,6);memcpy(micDeauth+16,good._connection.bssid,6);
    assert(!good.submitNetworkPacket(micDeauth,sizeof(micDeauth),true,1815,AthSecurity::ManagementTX::Plain,Purpose::MICDeauth));
    good.tick(1816);assert(good._connection.micReportCompletion.complete && !good._connection.eapolCompletion.pending);
    good._connection.micReportCompletion.clear();micDeauth[24]=3;
    assert(good.submitNetworkPacket(micDeauth,sizeof(micDeauth),true,1817,AthSecurity::ManagementTX::Plain,Purpose::MICDeauth));
    good._connection.tkipDataBlocked=false;good._connection.secure=false;
    auto deauth=managementResponse(good._connection,false);deauth[60]=0xc0;
    good.deliver(2,deauth);good.tick(1820);assert(good._wmiLive.active && !good.networkUp && good._connection.disconnect!=Ath10k::DisconnectStage::None);good.releaseWMIRuntime();
    chainedRxTests();
    // Reproduce hardware log: AP advertises channel 1, last reception on 3.
    ConnectionDriver adjacent;adjacent._wmiBSS.entries[0].rxChannel=3;
    adjacent._wmiBSS.entries[0].advertisedChannel=1;
    auto &cs=adjacent._connection;
    cs.apDisconnect.valid=true;cs.apDisconnect.reason=15;cs.apDisconnect.disassociation=true;
    assert(!Ath10k::selectOpenBSS(cs,adjacent._wmiBSS));
    assert(!cs.apDisconnect.valid && !cs.apDisconnect.reason && !cs.apDisconnect.disassociation);
    assert(cs.operatingChannel==1 && cs.ap.rxChannel==3 && cs.ap.advertisedChannel==1);
    UInt8 wire[256];cs.stage=LinkStage::Start;
    assert(Ath10k::buildConnectionWMI(wire,sizeof(wire),2,cs)==120);
    assert(Ath10k::wmiReadLE32(wire+92)==2412 && Ath10k::wmiReadLE32(wire+96)==2412);
    { // The selected protocol controls AP admission, including mixed-mode APs.
      auto selected=cs;selected.secure=true;selected.wpa1Selected=true;selected.pairCipher=2;selected.securityAKM=2;
      auto ap=adjacent._wmiBSS.entries[0];ap.privacy=true;ap.capabilities|=0x10;
      UInt8 wpa[]={221,22,0,0x50,0xf2,1,1,0,0,0x50,0xf2,2,1,0,0,0x50,0xf2,2,1,0,0,0x50,0xf2,2};
      memcpy(ap.wpa,wpa,sizeof(wpa));ap.wpaLength=sizeof(wpa);ap.wpaPresent=true;
      memcpy(ap.rsn,AthSecurity::stationRSN,sizeof(AthSecurity::stationRSN));ap.rsnLength=sizeof(AthSecurity::stationRSN);ap.rsnPresent=true;
      const auto before=selected;Ath10k::CandidateConfiguration prepared{};
      assert(!Ath10k::prepareBSSCandidate(selected,ap,prepared));
      assert(prepared.groupCipher==2 && prepared.pairCipher==2 && !prepared.htEnabled);
      assert(!memcmp(&before,&selected,sizeof(selected)));
      ap.wpaLength=0;ap.wpaPresent=false;
      assert(Ath10k::prepareBSSCandidate(selected,ap,prepared)); // RSNE cannot substitute for requested WPA1.
      ap.wpaLength=sizeof(wpa);ap.wpaPresent=true;ap.rsnLength=0;ap.rsnPresent=false;
      selected.wpa1Selected=false;selected.pairCipher=4;
      assert(Ath10k::prepareBSSCandidate(selected,ap,prepared)); // WPA IE cannot substitute for requested WPA2.
    }
    { // Explicit WEP cannot select open or RSN/WPA profiles by privacy alone.
      for(UInt8 cipher:{UInt8(1),UInt8(5)}){
       auto selected=cs;selected.secure=selected.wepSelected=true;selected.pairCipher=cipher;
       auto ap=adjacent._wmiBSS.entries[0];ap.privacy=true;ap.capabilities|=0x10;
       ap.rsnPresent=ap.wpaPresent=false;ap.rsnLength=ap.wpaLength=0;
       Ath10k::CandidateConfiguration prepared{};assert(!Ath10k::prepareBSSCandidate(selected,ap,prepared));
       assert(prepared.groupCipher==cipher && !prepared.htEnabled && !prepared.vhtEnabled);
       Ath10k::applyBSSCandidate(selected,prepared);selected.stage=LinkStage::Assoc;
       UInt8 frame[320]{};const auto n=Ath10k::buildStationManagement(frame,sizeof(frame),selected);assert(n && (frame[24]&16));
       for(unsigned at=28;at<n;at+=2+frame[at+1])assert(frame[at]!=48 && !(frame[at]==221 && frame[at+1]>=4 && frame[at+5]==1));
       ap.privacy=false;assert(Ath10k::prepareBSSCandidate(selected,ap,prepared));ap.privacy=true;
       ap.rsnPresent=true;assert(Ath10k::prepareBSSCandidate(selected,ap,prepared));ap.rsnPresent=false;
       ap.wpaPresent=true;assert(Ath10k::prepareBSSCandidate(selected,ap,prepared));ap.wpaPresent=false;
       selected.wepSelected=false;assert(Ath10k::prepareBSSCandidate(selected,ap,prepared));
      }
    }
    { // Reject unsupported basic rates before touching the selected AP.
      auto candidate=adjacent._wmiBSS;
      candidate.entries[0].advertisedChannel=6;
      candidate.entries[0].rates[0]=0xff;
      const auto before=cs;
      assert(!strcmp(Ath10k::selectOpenBSS(cs,candidate),"unsupported-basic-rate"));
      assert(!memcmp(&before,&cs,sizeof(cs)));
    }
    { auto candidate=adjacent._wmiBSS;
      candidate.entries[0].advertisedChannel=6;
      candidate.entries[0].powerConstraintDb=255;
      const auto before=cs;
      assert(!strcmp(Ath10k::selectOpenBSS(cs,candidate),"invalid-channel-definition"));
      assert(!memcmp(&before,&cs,sizeof(cs)));
    }
    { auto ap=adjacent._wmiBSS.entries[0];ap.bssid[5]^=0x40;ap.advertisedChannel=6;
      const auto before=cs;Ath10k::CandidateConfiguration prepared{};
      assert(!Ath10k::prepareBSSCandidate(cs,ap,prepared));
      assert(prepared.operatingChannel==6 && !memcmp(prepared.ap.bssid,ap.bssid,6));
      assert(!memcmp(&before,&cs,sizeof(cs)));
      ap.ssid[0]^=1;
      assert(!strcmp(Ath10k::prepareBSSCandidate(cs,ap,prepared),"candidate-ssid-mismatch"));
      assert(!memcmp(&before,&cs,sizeof(cs)));
    }
    { const auto original=adjacent._wmiBSS.entries[0];
      const auto before=cs;Ath10k::CandidateConfiguration prepared{};
      for(unsigned length=33;length<256;++length){
          auto ap=original;ap.ssidLength=length;
          assert(!strcmp(Ath10k::prepareBSSCandidate(cs,ap,prepared),"invalid-ssid-length"));
          ap=original;ap.rateCount=length;
          assert(!strcmp(Ath10k::prepareBSSCandidate(cs,ap,prepared),"bss-missing-valid-rates"));
      }
      auto ap=original;ap.privacy=true;
      assert(!strcmp(Ath10k::prepareBSSCandidate(cs,ap,prepared),"protected-network-not-supported"));
      assert(!memcmp(&before,&cs,sizeof(cs)));
      // Configuration application must not overwrite keys, BSSID or queue ownership.
      assert(!Ath10k::prepareBSSCandidate(cs,original,prepared));
      auto destination=cs;destination.installedPair[0]=0x5a;destination.pairPN[0]=123;
      destination.wmiOwned=destination.txOwned=true;destination.bssid[5]^=0x80;
      const auto lastBSSID=destination.bssid[5];
      Ath10k::applyBSSCandidate(destination,prepared);
      assert(destination.installedPair[0]==0x5a && destination.pairPN[0]==123);
      assert(destination.wmiOwned && destination.txOwned && destination.bssid[5]==lastBSSID);
    }
    adjacent._wmiBSS.entries[0].advertisedChannel=169;
    assert(!strcmp(Ath10k::selectOpenBSS(cs,adjacent._wmiBSS),"bss-channel-unsupported"));
    adjacent._wmiBSS.entries[0].advertisedChannel=36;
    assert(!strcmp(Ath10k::selectOpenBSS(cs,adjacent._wmiBSS),"bss-channel-band-mismatch"));
    adjacent._wmiBSS.entries[0].advertisedChannel=0;
    assert(!Ath10k::selectOpenBSS(cs,adjacent._wmiBSS) && cs.operatingChannel==3);
    for(unsigned ch:{52u,64u,100u,112u,144u}){
        adjacent._wmiBSS.entries[0].rxChannel=ch;
        adjacent._wmiBSS.entries[0].advertisedChannel=ch;
        assert(!strcmp(Ath10k::selectOpenBSS(cs,adjacent._wmiBSS),"dfs-connection-not-supported"));
    }
    adjacent.releaseWMIRuntime();
    ConnectionDriver hold;hold.suppressCompletion=true;hold.connect();
    assert(!hold.networkUp && hold._connection.authReply && hold._connection.txOwned);
    hold.tick(8000);assert(!hold._wmiLive.active && !hold.networkUp);hold.releaseWMIRuntime();
    ConnectionDriver reject;reject.rejectAssociation=true;reject.connect();
    assert(!reject.networkUp && reject._wmiLive.active && reject._connection.stage==LinkStage::Disabled && reject._connection.disconnectCount==1);reject.releaseWMIRuntime();
    ConnectionDriver bad;bad.wrongID=true;bad.connect();assert(!bad.networkUp && !bad._wmiLive.active);bad.releaseWMIRuntime();
    ConnectionDriver protectedAP;protectedAP._wmiBSS.entries[0].privacy=true;protectedAP.connect();
    assert(protectedAP.commands==0 && !protectedAP.networkUp);protectedAP.releaseWMIRuntime();
    ConnectionDriver failure;failure._regs.tx3Fail=true;failure.resetOK=false;failure.connect();
    assert(failure._connection.wmiOwned && failure._dmaQuarantine && !failure.networkUp);failure.releaseWMIRuntime();
}

#endif

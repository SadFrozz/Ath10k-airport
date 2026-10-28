#define ATH10K_AP_MAINTENANCE_TEST
#include "test_connection.cpp"
#include <cstdio>

class WatchdogDriver : public ConnectionDriver {
public:
    UInt8 frame[64]{};
    WatchdogDriver(){
        connect();assert(networkUp && _wmiLive.active);
        _regs.tx4Consume=[](){};frame[12]=8;
        for(unsigned i=0;i<Ath10k::kDataTxSlots;++i){
            auto &b=_dataBuffers[i];b.payload.isAllocated=b.command.isAllocated=b.fragments.isAllocated=false;
            b.payload.iovm=0x2000000+i*0x10000;b.command.iovm=b.payload.iovm+0x1000;b.fragments.iovm=b.payload.iovm+0x2000;
        }
    }
    UInt16 submit(UInt64 now){assert(!submitDataPacket(frame,sizeof(frame),now));return _connection.txId;}
    void complete(UInt16 id){auto p=completion(id);assert(!Ath10k::parseHTTSetup(p.data(),p.size(),1,_wmi.credits,_rxSetup,&_connection));}
    void fill(){for(unsigned i=0;i<Ath10k::kDataTxSlots;++i)submit(1800);assert(!serviceDataTX(1810));}
};

int main(){
    { WatchdogDriver d;d.fill();auto &s=d._connection;
      s.radio.appliedPS=s.radio.configuredPS=true;s.radio.requestedPS=false;d._regs.tx3Consume=[](){};
      assert(!d.serviceRadioMaintenance(3000));
      assert(s.radio.step==6 && s.dataPending==Ath10k::kDataTxSlots); // Wake must not wait for the payloads it is supposed to release.
      d.releaseWMIRuntime(); }

    // Reproduce the incident's full queue while station PS is applied. Wake
    // uses CE3 and the real credit/ECHO barrier, retaining every CE4 payload.
    { WatchdogDriver d;d.fill();auto &s=d._connection;
      s.radio.appliedPS=s.radio.configuredPS=s.radio.requestedPS=true;
      s.ap.timPresent=true;s.radio.appliedDTIM=s.ap.dtimPeriod;s.radio.appliedBeacon=s.ap.beaconInterval;
      const auto previous=d._regs.tx3Consume;std::vector<UInt32> wakeCommands;
      d._regs.tx3Consume=[&](){
        if(!s.radio.step){previous();return;}
        const auto *f=static_cast<const UInt8 *>(d._connectionCommand.virtualAddress());wakeCommands.push_back(Ath10k::wmiReadLE32(f+8));
        if(s.radio.step==8)d.deliver(2,echoPacket(Ath10k::radioCookie(s)));
        else d.deliver(1,{0,2,8,0,8,0,0,0,1,4,0,0,2,1,0,0});
      };
      assert(!d.serviceDataTX(2809) && !s.radio.txWakeRequested);
      assert(!d.serviceDataTX(2810) && s.radio.txWakeRequested && s.radio.txWakeRequests==1);
      for(unsigned t=2820;t<=3020;t+=10)d.tick(t);
      assert(d._wmiLive.active && !s.radio.appliedPS && !s.radio.step && !s.radio.wakeOnly);
      assert(wakeCommands==std::vector<UInt32>({0x9001,0x1d001}));
      assert(s.dataPending==Ath10k::kDataTxSlots && !s.dataTimeouts);
      for(const auto &slot:s.dataTX){assert(slot.owned && slot.ceConsumed && !slot.complete);d.complete(slot.id);}
      assert(!d.serviceDataTX(3030) && !s.dataPending && !s.radio.txWakeRequested && s.radio.txWakeHoldUntilMs==4030);
      assert(!d.serviceRadioMaintenance(4029) && !s.radio.step && !s.radio.appliedPS);
      assert(!d.serviceRadioMaintenance(4030) && s.radio.step==6 && s.radio.targetPS);d.releaseWMIRuntime(); }
    // Waking does not disable the original full-queue timeout if the firmware
    // never returns HTT completions, and explicit pauses never trigger it early.
    { WatchdogDriver d;d.fill();auto &s=d._connection;s.radio.appliedPS=s.radio.requestedPS=true;
      assert(!d.serviceDataTX(2810) && s.radio.txWakeRequested);
      assert(!strcmp(d.serviceDataTX(6810),"data-tx-completion-timeout") && !strcmp(s.dataWatchdogReason,"queue-stalled"));d.releaseWMIRuntime(); }
    { WatchdogDriver d;d.fill();auto &s=d._connection;s.radio.appliedPS=s.radio.requestedPS=true;s.txPauseMask=1;
      assert(!d.serviceDataTX(5000) && !s.radio.txWakeRequested);s.txPauseMask=0;
      assert(!d.serviceDataTX(5010));assert(!d.serviceDataTX(6009) && !s.radio.txWakeRequested);
      assert(!d.serviceDataTX(6010) && s.radio.txWakeRequested);d.releaseWMIRuntime(); }
    // Firmware retains one payload while newer traffic completes normally.
    // Age alone must not reset the driver, free DMA, or reuse this ID/buffer.
    {
        WatchdogDriver d;const auto old=d.submit(1800);assert(!d.serviceDataTX(1810));
        const auto retainedAddress=d._dataBuffers[0].payload.dmaAddress();
        assert(!d.serviceDataTX(7000));assert(d._connection.dataPending==1);
        assert(d._connection.dataTX[0].owned && d._connection.dataTX[0].ceConsumed && !d._connection.dataTX[0].complete);
        assert(d._connection.dataDelayed==1 && !d._connection.dataTimeouts);
        const auto fresh=d.submit(7010);assert(fresh!=old);d.complete(fresh);
        assert(!d.serviceDataTX(7020) && d._connection.dataPending==1 && d._connection.txPackets>0);
        assert(d._dataBuffers[0].payload.dmaAddress()==retainedAddress && d._connection.dataTX[0].owned);
        assert(!d.serviceDataTX(60000) && d._connection.dataDelayed==1);
        d.complete(old);assert(!d.serviceDataTX(60010));assert(!d._connection.dataPending);
        assert(!d._connection.dataStallArmed && !d._connection.dataPauseArmed && !d._connection.dataTimeouts);
        d.releaseWMIRuntime();
    }
    // A CE transport stall still fails at five seconds, including during scan.
    for(bool scanning:{false,true}){
        WatchdogDriver d;d._regs.tx4Timeout=true;d.submit(1800);
        d._wmiScan.completed=!scanning;
        assert(!d.serviceDataTX(6799));
        assert(!strcmp(d.serviceDataTX(6800),"data-tx-completion-timeout"));
        assert(d._connection.dataPending==1 && d._connection.dataTX[0].owned && !d._connection.dataTX[0].ceConsumed);
        assert(d._connection.dataTimeouts==1);d.releaseWMIRuntime();
    }
    // HTT alone never releases a buffer whose command is still owned by CE.
    {
        WatchdogDriver d;d._regs.tx4Timeout=true;const auto id=d.submit(1800);d.complete(id);
        assert(!d.serviceDataTX(1810) && d._connection.dataPending==1);
        assert(d.serviceDataTX(6800) && d._connection.dataTX[0].owned);
        d.releaseWMIRuntime();
    }
    // Full queue with no progress keeps the five-second recovery bound.
    {
        WatchdogDriver d;d.fill();assert(d._connection.dataStallArmed);
        assert(!d.serviceDataTX(6809));
        assert(!strcmp(d.serviceDataTX(6810),"data-tx-completion-timeout"));
        assert(d._connection.dataPending==Ath10k::kDataTxSlots && d._connection.dataTimeouts==1);
        for(const auto &slot:d._connection.dataTX)assert(slot.owned && !slot.complete);
        d.releaseWMIRuntime();
    }
    // Genuine completions drain/wake the queue even if its first ID is old.
    {
        WatchdogDriver d;d.fill();const auto old=d._connection.dataTX[0].id;
        d.queueEnabled=true;d._dataTXStalled=true;
        for(unsigned i=1;i<Ath10k::kDataTxSlots;++i)d.complete(d._connection.dataTX[i].id);
        assert(!d.serviceDataTX(6810));assert(d._connection.dataPending==1 && d.queue.wakes==1);
        d._connection.txId=static_cast<UInt16>((old+1055)%1056);
        assert(d.submit(6820)!=old && d._connection.dataTX[0].owned);
        assert(!d.serviceDataTX(6830) && !d._connection.dataStallArmed);
        d.releaseWMIRuntime();
    }
    // Legitimate firmware/scan pauses defer the firmware queue watchdog only.
    // A stuck pause is bounded; resume receives a fresh stall window.
    for(bool scanning:{false,true}){
        WatchdogDriver d;d.fill();
        if(scanning)d._wmiScan.completed=false;else d._connection.txPauseMask=2;
        assert(!d.serviceDataTX(2000) && d._connection.dataPauseArmed && !d._connection.dataStallArmed);
        assert(!d.serviceDataTX(20000));
        d._wmiScan.completed=true;d._connection.txPauseMask=0;
        assert(!d.serviceDataTX(20010) && !d._connection.dataPauseArmed);
        assert(!d.serviceDataTX(25009));assert(d.serviceDataTX(25010));d.releaseWMIRuntime();
        WatchdogDriver hung;hung.fill();
        if(scanning)hung._wmiScan.completed=false;else hung._connection.txPauseMask=2;
        const UInt64 deadline=2000+(scanning?Ath10k::kWMIScanHostMs:30000);
        assert(!hung.serviceDataTX(2000));assert(!hung.serviceDataTX(deadline-1));
        assert(!strcmp(hung.serviceDataTX(deadline),"data-tx-pause-timeout"));
        assert(hung._connection.dataPending==Ath10k::kDataTxSlots);hung.releaseWMIRuntime();
    }
    // Teardown cannot pretend that a retained firmware payload has completed.
    {
        WatchdogDriver d;d.submit(1800);assert(!d.serviceDataTX(1810));
        assert(Ath10k::requestDisconnect(d._connection,2000));
        assert(!d.serviceDataTX(6999));
        assert(d.serviceDataTX(7000) && d._connection.dataTX[0].owned && d._connection.dataPending==1);
        d.releaseWMIRuntime();
    }
    // Closing a long-lived link starts a fresh drain window. An old payload
    // may still complete safely; packet age alone must not force quarantine.
    for(bool complete:{false,true}){
        WatchdogDriver d;const auto id=d.submit(1800);assert(!d.serviceDataTX(1810));
        assert(!d.serviceDataTX(60000));
        assert(Ath10k::requestDisconnect(d._connection,60001));
        assert(!d.serviceDataTX(60001));
        assert(d._connection.dataPending==1 && d._connection.dataTX[0].owned);
        if(complete){
            d.complete(id);assert(!d.serviceDataTX(60002));
            assert(!d._connection.dataPending && !d._connection.dataTX[0].owned);
        }else{
            assert(!d.serviceDataTX(65000));
            assert(!strcmp(d.serviceDataTX(65001),"data-tx-completion-timeout"));
            assert(d._connection.dataTX[0].owned && d._connection.dataPending==1);
        }
        d.releaseWMIRuntime();
    }
    std::puts("TX watchdog passed: late HTT ownership, progressing traffic, CE stalls, full-queue stalls, bounded pauses, ID retention, wakeup and teardown.");
}

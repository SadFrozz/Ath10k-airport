import unittest
from pathlib import Path

class NativeLockOrder(unittest.TestCase):
    def test_stop_and_partial_free_drain_all_control_work_before_radio_release(self):
        source=(Path(__file__).resolve().parents[1]/"src/kext/Ath10kPCIDevice.cpp").read_text()
        drain=source.split("void Ath10kPCIDevice::drainControlWorkers()",1)[1].split("void Ath10kPCIDevice::stop",1)[0]
        self.assertLess(drain.index("cancelDeferredProbe();"),drain.index("stopNativeRequests();"))
        for entry in ["void Ath10kPCIDevice::stop(IOService *provider)","void Ath10kPCIDevice::free()"]:
            body=source.split(entry,1)[1].split("\nvoid ",1)[0]
            self.assertLess(body.index("drainControlWorkers();"),body.index("releasePowerNotifications();"))
            self.assertLess(body.index("drainControlWorkers();"),body.index("releaseWMIRuntime();"))
            self.assertLess(body.index("drainControlWorkers();"),body.index("stopDMAForRelease();"))

    def test_sleep_interest_precedes_probe_and_barrier_excludes_pm_calls(self):
        root=Path(__file__).resolve().parents[1]
        driver=(root/"src/kext/Ath10kPCIDevice.cpp").read_text()
        start=driver.split("bool Ath10kPCIDevice::start(IOService *provider)",1)[1].split("void Ath10kPCIDevice::deferredProbeCall",1)[0]
        self.assertLess(start.index("preparePowerNotifications()"),start.index("thread_call_enter(_deferredProbeCall)"))
        probe=driver.split("void Ath10kPCIDevice::runDeferredProbe()",1)[1].split("void Ath10kPCIDevice::cancelDeferredProbe()",1)[0]
        self.assertLess(probe.index("IOLockLock(_probePowerLock)"),probe.index("powerIOBlocked()"))
        self.assertLess(probe.index("powerIOBlocked()"),probe.index("probeTarget()"))
        self.assertLess(probe.index("prepareNetwork()"),probe.rindex("IOLockUnlock(_probePowerLock)"))
        self.assertLess(probe.rindex("IOLockUnlock(_probePowerLock)"),probe.index("PMinit()"))
        free=driver.split("void Ath10kPCIDevice::free()",1)[1].split("\nvoid ",1)[0]
        self.assertLess(free.index("super::free()"),free.index("IOLockFree(probePowerLock)"))
        arm=driver.split("IOReturn Ath10kPCIDevice::controlWMIRuntime(",1)[1].split("void Ath10kPCIDevice::",1)[0]
        self.assertLess(arm.index("powerIOBlocked()"),arm.index("setTimeoutMS(10)"))
        shutdown=driver.split("void Ath10kPCIDevice::systemWillShutdown(",1)[1].split("void Ath10kPCIDevice::",1)[0]
        self.assertLess(shutdown.index("requestPowerEvent(Ath10k::PowerEvent::DeviceOff)"),shutdown.index("super::systemWillShutdown"))

    def test_native_user_clients_inherit_wcl_not_radio_workloop(self):
        root=Path(__file__).resolve().parents[1]
        header=(root/"src/kext/native/Ath10kNativeInterface.hpp").read_text()
        native=(root/"src/kext/native/Ath10kNative.cpp").read_text()
        network=(root/"src/kext/Ath10kNetwork.cpp").read_text()
        self.assertIn("IOWorkLoop *getWorkLoop() const override;",header)
        interface=native.split("IOWorkLoop *Ath10kNativeInterface::getWorkLoop() const",1)[1].split("IOReturn Ath10kNativeInterface::perform",1)[0]
        self.assertIn("controller->getWorkQueue()",interface)
        bsd=native.split("class Ath10kBSDInterface",1)[1].split("OSDefineMetaClassAndStructors(Ath10kBSDInterface",1)[0]
        self.assertIn("wifi->controller->getWorkLoop()",bsd)
        self.assertIn("Ath10kPCIDevice::getWorkLoop() const {return _networkWorkLoop;}",network)

    def test_current_bss_is_independent_of_scan_scratch_lifetime(self):
        native=(Path(__file__).resolve().parents[1]/"src/kext/native/Ath10kNative.cpp").read_text()
        query=native.split("case N::getWCL_BSS_INFO:",1)[1].split("case N::",1)[0]
        self.assertNotIn("_nativeBSSBytes",query)
        self.assertIn("nativeBSSMessage(s.ap,",query)
        self.assertIn("LinkStage::Connected",query)
        self.assertIn("s.beaconFrameBytes",query)
        self.assertNotIn("_nativeBeaconSent",query)

    def test_security_progress_does_not_wait_for_notification_allocation(self):
        native=(Path(__file__).resolve().parents[1]/"src/kext/native/Ath10kNative.cpp").read_text()
        worker=native.split("void Ath10kPCIDevice::serviceNative(UInt64 now) {",1)[1].split("void Ath10kPCIDevice::serviceNativeNotifications",1)[0]
        self.assertLess(worker.index("sec->supplicant.receive"),worker.index("serviceNativeNotifications(now)"))
        self.assertNotIn("postMessage(",worker)

    def test_new_transactions_wait_for_terminal_notifications(self):
        native=(Path(__file__).resolve().parents[1]/"src/kext/native/Ath10kNative.cpp").read_text()
        for name in ["MACSet", "setWCL_SCAN_REQ", "setWCL_ASSOCIATE"]:
            case=native.split("case N::"+name+":",1)[1].split("case N::",1)[0]
            self.assertIn("_nativeAbortRequested",case)
            self.assertIn("_nativeLinkUpSent",case)

    def test_radio_worker_uses_queued_wcl_notifications(self):
        source=(Path(__file__).resolve().parents[1]/"src/kext/native/Ath10kNative.cpp").read_text()
        worker=source.split("void Ath10kPCIDevice::serviceNative(UInt64 now) {",1)[1].split("const char *Ath10kPCIDevice::serviceNativeMAC(",1)[0]
        for call in ["->setLQM(","->setCurrentApAddress(","->setLinkState(","->runAction("]:
            self.assertNotIn(call,worker,call+" would synchronously acquire the WCL gate under the network gate")
        self.assertIn("post(AirportWCL::LqmUpdate",worker)
        self.assertIn("post(AirportWCL::LinkStatus",worker)

    def test_bridge_enters_wcl_before_network_gate(self):
        root=Path(__file__).resolve().parents[1]
        native=(root/"src/kext/native/Ath10kNative.cpp").read_text()
        runtime=(root/"src/kext/Ath10kPCIDevice.cpp").read_text().split("const char *Ath10kPCIDevice::serviceRuntime()",1)[1].split("void Ath10kPCIDevice::wmiTimerFired",1)[0]
        self.assertIn("requestNativeService();",runtime)
        self.assertNotIn("serviceNative(",runtime)
        scheduler=native.split("void Ath10kPCIDevice::requestNativeService()",1)[1].split("void Ath10kPCIDevice::nativeServiceThread",1)[0]
        self.assertIn("thread_call_enter",scheduler)
        self.assertNotIn("runAction",scheduler)
        thread=native.split("void Ath10kPCIDevice::nativeServiceThread",1)[1].split("IOReturn Ath10kPCIDevice::nativeServiceWCLAction",1)[0]
        self.assertIn("_nativeBSDGate->attemptAction(nativeServiceWCLAction)",thread)
        wcl=native.split("IOReturn Ath10kPCIDevice::nativeServiceWCLAction",1)[1].split("IOReturn Ath10kPCIDevice::nativeServiceRadioAction",1)[0]
        self.assertIn("_nativeGate->attemptAction(nativeServiceRadioAction)",wcl)
        stop=native.split("void Ath10kPCIDevice::stopNativeRequests()",1)[1].split("void Ath10kPCIDevice::releaseNativeInterface()",1)[0]
        self.assertLess(stop.index("runAction(nativeStopAction)"),stop.index("thread_call_cancel_wait"))
        self.assertLess(stop.index("thread_call_cancel_wait"),stop.index("thread_call_free"))

    def test_postoffice_is_only_called_inside_wcl_bridge(self):
        native=(Path(__file__).resolve().parents[1]/"src/kext/native/Ath10kNative.cpp").read_text()
        before,worker=native.split("void Ath10kPCIDevice::serviceNative(UInt64 now) {",1)
        after=worker.split("const char *Ath10kPCIDevice::serviceNativeMAC(",1)[1]
        self.assertNotIn("postMessage(_nativeInterface",before)
        self.assertNotIn("postMessage(_nativeInterface",after)
        self.assertIn("THREAD_CALL_OPTIONS_ONCE",native)

    def test_runtime_failure_schedules_terminal_notifications(self):
        source=(Path(__file__).resolve().parents[1]/"src/kext/Ath10kPCIDevice.cpp").read_text()
        end=source.split("void Ath10kPCIDevice::endWMIRuntime(",1)[1].split("void Ath10kPCIDevice::releaseWMIRuntime()",1)[0]
        self.assertLess(end.index("quiesceTargetAfterBMI()"),end.index("requestNativeService()"))
        self.assertIn("_wmiScan.failed=true;_wmiScan.completed=true",end)

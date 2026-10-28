import unittest
from pathlib import Path

class NativeLockOrder(unittest.TestCase):
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

#!/usr/bin/env python3
"""Focused portable regressions; not a substitute for a macOS kext/hardware test."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', type=Path, help='Zig executable for Windows host tests')
    parser.add_argument('--cxx', default=os.environ.get('CXX', 'c++'))
    parser.add_argument('--only', nargs='+', help='Run selected portable C++ tests; this is not a full-suite result')
    args = parser.parse_args()
    out = ROOT / 'build/development-tests'
    out.mkdir(parents=True, exist_ok=True)
    passed = []
    # UBSan otherwise recovers and can leave a successful process exit code.
    # A sanitizer finding must fail the regression, including in CI.
    test_env = dict(os.environ)
    test_env['UBSAN_OPTIONS'] = test_env.get('UBSAN_OPTIONS', '') + ':halt_on_error=1'
    def run(name, command):
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, errors='replace', env=test_env)
        (out / (name + '.log')).write_text(result.stdout + result.stderr, encoding='utf-8')
        if result.returncode:
            raise RuntimeError(f'{name} failed; see {out / (name + ".log")}')
        print('PASS', name, flush=True)
        passed.append(name)
    run('prepare-native-headers', [sys.executable, 'scripts/build/prepare-native-headers.py'])
    run('prepare-firmware', [sys.executable, 'scripts/build/prepare-firmware.py'])
    run('payload-python', [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_payload.py', '-v'])
    run('kext-symbols', [sys.executable, 'tests/macos/test_kext_symbols.py', '-v'])
    run('kernel-collection-inclusion', [sys.executable, 'tests/macos/test_kernel_collection.py', '-v'])
    run('p256-diagnostic-config', [sys.executable, 'tests/macos/test_p256_diagnostic_config.py', '-v'])
    run('native-lock-order', [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_native_lock_order.py', '-v'])
    run('diagnostic-privacy', [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_native_preflight.py', '-v'])
    if args.zig:
        compiler = [str(args.zig.resolve()), 'c++', '-target', 'x86_64-windows-gnu']
    else:
        compiler = shlex.split(args.cxx)
    flags = ['-std=c++17', '-O2', '-UNDEBUG', '-Wall', '-Wextra', '-Werror', '-Wno-nullability-completeness']
    with tempfile.TemporaryDirectory(prefix='ath10k-tests-') as tmp:
        include = Path(tmp)
        (include/'IOKit').mkdir()
        (include/'IOKit/IOLib.h').write_bytes((ROOT/'tests/support/mock_iolib.h').read_bytes())
        (include/'IOKit/IOTypes.h').write_text('#pragma once\n#include <cstdint>\nusing UInt8=uint8_t;using UInt16=uint16_t;using UInt32=uint32_t;using UInt64=uint64_t;\n')
        run('extract-production', [sys.executable, 'tests/support/extract-production.py', str(include/'driver_methods.inc')])
        power=(ROOT/'src/macos/controller/Ath10kPower.cpp').read_text()
        (include/'power_methods.inc').write_text(power[power.index('bool Ath10kPCIDevice::powerIOBlocked('):])
        notifications=(ROOT/'src/macos/controller/Ath10kPowerNotifications.cpp').read_text()
        (include/'power_notification_methods.inc').write_text(notifications[notifications.index('bool Ath10kPCIDevice::preparePowerNotifications('):])
        (include/'power_notification_callback.inc').write_text(power[power.index('IOReturn Ath10kPCIDevice::powerNotification('):])
        native=(ROOT/'src/macos/native/Ath10kNative.cpp').read_text()
        driver=(ROOT/'src/macos/controller/Ath10kPCIDevice.cpp').read_text()
        (include/'controller_shutdown.inc').write_text(driver[driver.index('void Ath10kPCIDevice::systemWillShutdown('):driver.index('void Ath10kPCIDevice::publishWMIRuntimeProperties(')])
        scan_service=driver[driver.index('const char *Ath10kPCIDevice::serviceWMIScan(UInt64 nowMs)'):]
        scan_service=scan_service[:scan_service.index('    if (!state.attempted && (_connection.stats.step')]
        (include/'native_scan_start.inc').write_text(scan_service+'    (void)nowMs;++submissions;return nullptr;\n}\n')
        (include/'native_termination_power.inc').write_text(power[power.index('void Ath10kPCIDevice::blockPowerIOForTermination()'):power.index('bool Ath10kPCIDevice::controllerPowerClosed()')])
        (include/'native_termination_controller.inc').write_text(native[native.index('void Ath10kPCIDevice::prepareNativeInterfaceTermination('):native.index('void Ath10kPCIDevice::stopNativeRequests()')])
        (include/'native_termination_notifier.inc').write_text(native[native.index('bool Ath10kNativeInterface::prepareTerminationNotification()'):native.index('bool Ath10kNativeInterface::prepareRegistrationInfo(')])
        (include/'native_bsd_reference.inc').write_text(native[native.index('IOReturn Ath10kNativeInterface::prepareBSDInterface('):native.index('bool Ath10kNativeInterface::prepareTerminationNotification()')])
        (include/'native_termination_free.inc').write_text(native[native.index('void Ath10kNativeInterface::free()'):native.index('IOReturn Ath10kNativeInterface::deregisterLogicalLink()')])

        (include/'native_release_method.inc').write_text(native[native.index('void Ath10kPCIDevice::releaseNativeInterface()'):native.index('IOReturn Ath10kPCIDevice::nativeRequest(')])
        (include/'native_registration_methods.inc').write_text(native[native.index('bool Ath10kNativeInterface::prepareRegistrationInfo('):native.index('IOWorkLoop *Ath10kNativeInterface::getWorkLoop() const')])
        crypto=(ROOT/'src/macos/native/Ath10kKernelCrypto.hpp').read_text()
        (include/'native_hmac_md5_provider.inc').write_text(crypto[crypto.index('    static bool hmacMD5('):crypto.index('    static bool hash256(')])
        (include/'native_security_class.inc').write_text(native[native.index('class Ath10kPCIDevice::NativeSecurity {'):native.index('IO80211WorkQueue *Ath10kPCIDevice::getWorkQueue()')])
        terminal=native[native.index('    if(sec && (',native.index('    // A completed radio-side teardown')):native.index('    serviceNativeEAP(now);')]
        (include/'native_security_terminal_cleanup.inc').write_text('void Ath10kPCIDevice::discardIfStopped(UInt64 now){auto sec=_nativeSecurity;auto &s=_connection;\n'+terminal+'}\n')
        (include/'native_eap_callback.inc').write_text(native[native.index('IOReturn Ath10kPCIDevice::nativeSetCipherKey('):native.index('// Exact Sequoia getRSN_XE contract:')])
        network_source=(ROOT/'src/macos/controller/Ath10kNetwork.cpp').read_text()
        completion=native[native.index('        // Bound delivery even when an earlier WCL event'):native.index('        if(sec->keysPending && !s.wmiOwned')]
        (include/'native_eap_integration_completion.inc').write_text('void Ath10kPCIDevice::serviceEAPCompletion(UInt64 now){auto sec=_nativeSecurity;auto &s=_connection;\n'+completion+'}\n')
        key_rx=native[native.index('        if(!sec->replyPending && !sec->keysPending && !sec->authorizePending && !sec->ptkUpdatePending && !sec->eapTXInFlight &&'):native.index('        if(sec->supplicant.pairwisePending()){')]
        (include/'native_eap_key_rx.inc').write_text('void Ath10kPCIDevice::serviceEAPKeyFrames(){auto sec=_nativeSecurity;auto &s=_connection;\n'+key_rx+'}\n')
        key_stage=native[native.index('        if(sec->keysPending && !s.wmiOwned'):native.index('        if(sec->replyPending && !sec->eapTXInFlight && !sec->keysPending')]
        (include/'native_initial_key_stage.inc').write_text('void stageNativeKeys(Ath10kPCIDevice &d,UInt64 now){auto sec=d._nativeSecurity;auto &s=d._connection;auto &_wmiScan=d._wmiScan;auto &_wmi=d._wmi;\n'+key_stage+'}\n')
        (include/'native_eapol_completion.inc').write_text('void Driver::service(UInt64 now){auto sec=&security;auto &s=state;\n'+completion+'}\n')
        retirement=network_source[network_source.index('            s.txOwned=false;'):network_source.index('            if(s.txStatus){',network_source.index('            s.txOwned=false;'))]
        (include/'native_eapol_retirement.inc').write_text('void retire(Ath10k::ConnectionState &s){\n'+retirement+'}\n')

        (include/'network_carrier.inc').write_text(network_source[network_source.index('void Ath10kPCIDevice::networkLink('):network_source.index('bool Ath10kPCIDevice::prepareNetwork(')])
        medium_constants=network_source[network_source.index('#ifdef ATH10K_NATIVE'):network_source.index('const OSString *')]
        medium_select=network_source[network_source.index('IOReturn Ath10kPCIDevice::selectMedium('):network_source.index('IOReturn Ath10kPCIDevice::setPromiscuousMode(')]
        (include/'network_medium.inc').write_text(medium_constants+medium_select)
        sae_stage=network_source[network_source.index('    if(s.stage==LinkStage::Auth && s.secure && (s.securityAKM==2 || s.securityAKM==6)){'):]
        sae_stage=sae_stage[:sae_stage.index('#endif')]
        (include/'native_sae_stage.inc').write_text('bool Ath10kPCIDevice::advanceSAEAuth(UInt64 nowMs){using Ath10k::LinkStage;auto &s=_connection;bool advanced=false;auto stage=[&]()->const char *{\n'+sae_stage+'\nadvanced=true;return nullptr;};stage();return advanced;}\n')
        before_key_build=network_source[:network_source.index('            UInt32 bytes=Ath10k::buildSecurityWMI(')]
        firmware_guard=before_key_build[before_key_build.rindex('            if(s.securityPhase==3 && !nativePMFPortReady())'):].splitlines()[0]
        (include/'native_pmf_firmware_guard.inc').write_text('const char *Ath10kPCIDevice::beforeFirmwareAuthorization(unsigned phase){struct {unsigned securityPhase;} s{phase};\n'+firmware_guard+'\nreturn nullptr;}\n')
        (include/'native_pmf_receive.inc').write_text(native[native.index('bool Ath10kPCIDevice::nativePMFManagement('):native.index('// OWE uses open authentication')] + native[native.index('// The common Auth state waits'):native.index('// Invoked by the radio-gated data-key state machine')])
        (include/'native_pmf_key_hooks.inc').write_text(native[native.index('bool Ath10kPCIDevice::nativeStageManagementKey('):native.index('// These packet hooks run under the radio gate')])
        (include/'native_rsnxe_query.inc').write_text(native[native.index('bool Ath10kPCIDevice::nativeAssociationRSNXE('):native.index('// Radio-gated terminal cleanup.')])
        (include/'native_security_discard.inc').write_text(native[native.index('void Ath10kPCIDevice::discardNativeSecurity()'):native.index('IOReturn Ath10kPCIDevice::nativeStopAction(')])
        leave=native[native.index('    case N::setWCL_JOIN_ABORT:case N::setWCL_LEAVE_NETWORK:'):native.index('    case N::setCLEAR_PMKSA_CACHE:')]
        (include/'native_leave.inc').write_text(leave)
        (include/'native_radio_power.inc').write_text(native[native.index('    case N::PowerSet:'):native.index('    case N::CountryGet:')])
        request=native[native.index('IOReturn Ath10kPCIDevice::nativeRequest('):native.index('IOReturn Ath10kPCIDevice::nativeCurrentAPInfo(')]
        prefix=native[native.index('IOReturn Ath10kPCIDevice::nativeRequestGated('):native.index('    auto &s=_connection;using N=AthNativeOp;',native.index('IOReturn Ath10kPCIDevice::nativeRequestGated('))]
        (include/'native_request_admission.inc').write_text(request+prefix+'    (void)op;(void)data;++accepted;return kIOReturnSuccess;\n}\n')

        entry=driver[driver.index('void Ath10kPCIDevice::runDeferredProbe()'):driver.index('    ATH10K_TRACE("Ath10kMac: deferred target probe begin') ]
        (include/'first_probe_run.inc').write_text(entry+'    ++starts;IOLockUnlock(_probePowerLock);\n}\n')
        (include/'first_probe_pci.inc').write_text(driver[driver.index('bool Ath10kPCIDevice::preparePoweredPCI()'):driver.index('void Ath10kPCIDevice::queueDeferredProbe()')])
        recovery=(ROOT/'src/macos/controller/Ath10kRecovery.cpp').read_text()
        (include/'wake_recovery_methods.inc').write_text(recovery[recovery.index('void Ath10kPCIDevice::queueWakeRecovery()'):])
        (include/'restore_aspm_methods.inc').write_text(driver[driver.index('bool Ath10kPCIDevice::disableASPMForBringup()'):driver.index('void Ath10kPCIDevice::logMSIState(')])
        (include/'first_probe_scheduler.inc').write_text(driver[driver.index('void Ath10kPCIDevice::queueDeferredProbe()'):driver.index('void Ath10kPCIDevice::deferredProbeCall(')])
        (include/'first_probe_callback.inc').write_text(driver[driver.index('void Ath10kPCIDevice::deferredProbeCall('):driver.index('void Ath10kPCIDevice::runDeferredProbe()')])
        (include/'first_probe_cancel.inc').write_text(driver[driver.index('void Ath10kPCIDevice::cancelDeferredProbe()'):driver.index('bool Ath10kPCIDevice::stopDMAForRelease()')])
        (include/'pci_match_method.inc').write_text(driver[driver.index('static bool ath10kRegistryPCIID('):driver.index('bool Ath10kPCIDevice::start(')])
        (include/'control_drain_method.inc').write_text(driver[driver.index('void Ath10kPCIDevice::drainControlWorkers()'):driver.index('void Ath10kPCIDevice::stop(IOService *provider)')])
        (include/'native_policy_admission.inc').write_text(native[native.index('    case N::setWCL_FAST_LANE:'):native.index('    case N::setWCL_SCAN_REQ:')])
        (include/'native_policy_dispatch.inc').write_text(native[native.index('IOReturn Ath10kNativeInterface::perform('):native.index('IOReturn Ath10kNativeInterface::setMacAddress(')])
        protocol=native[native.index('IOWorkLoop *Ath10kNativeInterface::getWorkLoop() const'):native.index('IOReturn Ath10kNativeInterface::perform')]
        bsd=native.split('class Ath10kBSDInterface',1)[1].split('    static IOReturn prepare(',1)[0]
        bsd=bsd.split('    IOWorkLoop *getWorkLoop() const override {',1)[1].rsplit('    }',1)[0]
        (include/'native_provider_methods.inc').write_text(protocol+'\nIOWorkLoop *Ath10kBSDInterface::getWorkLoop() const {'+bsd+'}\n')
        (include/'native_mac_method.inc').write_text(native[native.index('const char *Ath10kPCIDevice::serviceNativeMAC('):native.index('const char *Ath10kPCIDevice::nativeSelectBSS(')])
        (include/'native_bridge_methods.inc').write_text(native[native.index('void Ath10kPCIDevice::requestNativeService()'):native.index('bool Ath10kPCIDevice::nativeRecordTKIPMIC(')])
        (include/'native_bridge_stop.inc').write_text(native[native.index('IOReturn Ath10kPCIDevice::nativeStopAction('):native.index('void Ath10kPCIDevice::releaseNativeInterface()')])
        (include/'native_security_snapshot.inc').write_text(native[native.index('void Ath10kPCIDevice::publishNativeSecurityState('):native.index('// Called only with WCL and radio gates held, in that order.')])
        (include/'native_join_request.inc').write_text(native[native.index('bool Ath10kPCIDevice::nativeRetainSystemLink('):native.index('IOReturn Ath10kPCIDevice::nativeRequestGated(')])
        ioctl=(ROOT/'build/generated/itlwm/Airport/apple80211_ioctl.h').read_text()
        var=(ROOT/'build/generated/itlwm/Airport/apple80211_var.h').read_text()
        caps=ioctl[ioctl.index('struct apple80211_capability_data'):ioctl.index('#elif __IO80211_TARGET >= __MAC_14_0',ioctl.index('struct apple80211_capability_data'))]
        enum=var[var.index('enum apple80211_card_capability'):var.index('#define APPLE80211_CAP_MAX')]
        (include/'native_capability_abi.inc').write_text('#define APPLE80211_VERSION 1\n#ifndef __offsetof\n#define __offsetof __builtin_offsetof\n#endif\n'+caps+enum)
        (include/'native_card_capabilities.inc').write_text(native[native.index('IOReturn Ath10kPCIDevice::getCARD_CAPABILITIES('):native.index('IOReturn Ath10kPCIDevice::getPOWER(')])
        (include/'native_phy_capabilities.inc').write_text(native[native.index('IOReturn Ath10kPCIDevice::nativePHYCapabilities('):native.index('bool Ath10kPCIDevice::nativeRetainSystemLink(')])
        (include/'native_link_metrics.inc').write_text(native[native.index('IOReturn Ath10kPCIDevice::nativeLinkMetrics('):native.index('static_assert(sizeof(apple80211_key)',native.index('IOReturn Ath10kPCIDevice::nativeLinkMetrics('))])
        (include/'native_link_state.inc').write_text(native[native.index('IOReturn Ath10kPCIDevice::nativeCurrentAPInfo('):native.index('static UInt32 channelFlags(')])
        (include/'native_notifications.inc').write_text(native[native.index('void Ath10kPCIDevice::serviceNativeNotifications('):native.index('// Runs under the network workloop gate;',native.index('void Ath10kPCIDevice::serviceNativeNotifications('))])
        worker_header=(ROOT/'src/macos/native/Ath10kSAEWorker.hpp').read_text()
        worker_source=(ROOT/'src/macos/native/Ath10kSAEWorker.cpp').read_text()
        worker='\n'.join(line for line in (worker_header+'\n'+worker_source).splitlines()
                         if not line.startswith('#include') and line!='#pragma once')
        (include/'sae_worker.inc').write_text(worker+'\n')
        session_sources=[ROOT/'src/macos/native/Ath10kSAESession.hpp', ROOT/'src/macos/native/Ath10kSAESession.cpp']
        session='\n'.join(line for source in session_sources for line in source.read_text().splitlines()
                          if not line.startswith('#include') and line!='#pragma once')
        (include/'sae_session.inc').write_text(session+'\n')
        preparation_sources=[ROOT/'src/macos/native/Ath10kNativeSAEPreparation.hpp',ROOT/'src/macos/native/Ath10kNativeSAEPreparation.cpp']
        preparation='\n'.join(line for source in preparation_sources for line in source.read_text().splitlines()
                               if not line.startswith('#include') and line!='#pragma once')
        (include/'native_sae_preparation.inc').write_text(preparation+'\n')
        psk_sources=[ROOT/'src/macos/native/Ath10kNativePSKPreparation.hpp',ROOT/'src/macos/native/Ath10kNativePSKPreparation.cpp']
        psk='\n'.join(line for source in psk_sources for line in source.read_text().splitlines()
                      if not line.startswith('#include') and line!='#pragma once')
        (include/'native_psk_preparation.inc').write_text(psk+'\n')
        owe_sources=[ROOT/'src/macos/native/Ath10kNativeOWEJob.hpp',ROOT/'src/macos/native/Ath10kNativeOWEJob.cpp']
        owe='\n'.join(line for source in owe_sources for line in source.read_text().splitlines()
                      if not line.startswith('#include') and line!='#pragma once')
        (include/'native_owe_job.inc').write_text(owe+'\n')
        (include/'native_owe_service.inc').write_text(native[native.index('bool Ath10kPCIDevice::serviceNativeOWE('):native.index('// The common Auth state waits')])
        p256_sources=[ROOT/'src/macos/native/Ath10kP256CheckJob.hpp',ROOT/'src/macos/native/Ath10kP256CheckJob.cpp']
        p256='\n'.join(line for source in p256_sources for line in source.read_text().splitlines()
                       if not line.startswith('#include') and line!='#pragma once')
        (include/'p256_check.inc').write_text(p256+'\n')
        p256_registry_sources=[ROOT/'src/macos/native/Ath10kP256RegistryJob.hpp',ROOT/'src/macos/native/Ath10kP256RegistryJob.cpp']
        p256_registry='\n'.join(line for source in p256_registry_sources for line in source.read_text().splitlines()
                                if not line.startswith('#include') and line!='#pragma once')
        (include/'p256_registry.inc').write_text(p256_registry+'\n')
        pmf_sources=[ROOT/'src/macos/native/Ath10kPMFSession.hpp',ROOT/'src/macos/native/Ath10kPMFSession.cpp']
        pmf='\n'.join(line for source in pmf_sources for line in source.read_text().splitlines()
                      if not line.startswith('#include') and line!='#pragma once')
        (include/'pmf_session.inc').write_text(pmf+'\n')
        waiting=native[native.index('bool Ath10kPCIDevice::nativeEAPWaiting() const {'):native.index('bool Ath10kPCIDevice::nativePMFStartupQueryEnabled() const {')]
        timeout_start=network_source.index('        // Native EAP owner enforces its own bounded server/MSK deadline.')
        timeout=network_source[timeout_start:network_source.index('        if(!s.securityPhase',timeout_start)].replace('#endif','')
        (include/'native_eap_timeout.inc').write_text(waiting+'const char *Ath10kPCIDevice::serviceEAPDeadline(UInt64 nowMs){auto &s=_connection;\n'+timeout+'return nullptr;}\n')
        (include/'native_eap_queue.inc').write_text(native[native.index('void Ath10kPCIDevice::nativeSetEAPQueue('):native.index('void Ath10kPCIDevice::serviceNativeEAP(')])
        (include/'native_wep_service.inc').write_text(native[native.index('void Ath10kPCIDevice::serviceNativeWEP('):native.index('bool Ath10kPCIDevice::nativeEAPWaiting(')])
        (include/'native_eap_service.inc').write_text(native[native.index('void Ath10kPCIDevice::serviceNativeEAP('):native.index('// Borrowed OS buffer')])
        (include/'native_eap_packets.inc').write_text(native[native.index('UInt32 Ath10kPCIDevice::nativeEAPOutput('):native.index('// The shared BSD output queue')])
        preflight=network_source[network_source.index('    UInt32 eapols=0;'):network_source.index('    if(!Ath10k::acceptSecureRX(s,b.descriptor')].replace('return;', 'return false;')
        (include/'native_eap_preflight.inc').write_text('bool Ath10kPCIDevice::preflight(Ath10k::RXBatch &b){auto &s=_connection;\n'+preflight+'return true;}\n')
        (include/'native_address_dispatch.inc').write_text(native[native.index('    case N::setIPV4_PARAMS:{'):native.index('    case N::setCIPHER_KEY:return nativeSetCipherKey(data);')])
        (include/'native_tkip_mic_service.inc').write_text(native[native.index('bool Ath10kPCIDevice::nativeRecordTKIPMIC('):native.index('void Ath10kPCIDevice::serviceNative(UInt64')])
        (include/'native_mic_persistence.inc').write_text(native[native.index('bool Ath10kPCIDevice::saveNativeMICWindow('):native.index('bool Ath10kPCIDevice::prepareNativeInterface(')])
        names=['native_wep_service', 'native_wep_execution', 'native_mic_persistence', 'native_tkip_mic_service', 'tkip_mic_owner', 'wpa1_key_data', 'network_rx', 'rx_pipeline', 'key_transaction', 'native_policy_dispatch', 'linux_parity', 'native_address', 'native_eap_packets', 'native_eap_service', 'native_eap_callback', 'native_eap_owner', 'native_eapol_completion', 'wmi_scan', 'wmi_bss', 'network_medium', 'transition_disable_delivery','regulatory','dma_radio','wmi_radio','native_leave', 'connection', 'tx_watchdog', 'security_disconnect', 'rx_security_diagnostics', 'reconnect_090', 'station_maintenance', 'channel_switch', 'ap_maintenance', 'runtime_power', 'wmi_notifications', 'restore_aspm', 'wake_recovery', 'first_probe', 'pci_match', 'native_bsd_reference', 'native_termination', 'native_release', 'native_registration', 'native_request_admission', 'native_security_lifecycle', 'power', 'power_notifications', 'control_drain', 'native_provider', 'native_bridge', 'native_notifications', 'native_link_state', 'native_link_metrics', 'native_phy_capabilities', 'native_join', 'native_mac', 'native_scan', 'rsn_policy', 'pmf_transport', 'pmf_inbox', 'sa_query', 'sae_wire', 'sae_exchange', 'sae_worker', 'lunnen_payload', 'security', 'native_wire', 'native_profile', 'native_status', 'native_capture']
        if sys.platform == 'darwin': names.extend(['eap_sha256','owe_eapol','owe','native_shared_wep','wep_auth','wpa1_key_auth','psk_password','p256_backend','sha256_supplicant','sae_session','sae_eapol','pmf_ccmp','pmf_session','native_pmf_receive','native_key_stage','native_sae_radio','native_rsnxe_query'])
        if args.only:
            unknown = sorted(set(args.only) - set(names))
            if unknown: parser.error('Unknown/unavailable tests: ' + ', '.join(unknown))
            names = [name for name in names if name in args.only]
        for name in names:
            executable = out / ('test_' + name + ('.exe' if os.name == 'nt' else ''))
            libraries = ['-lbcrypt'] if name == 'security' and os.name == 'nt' else (
                ['-lcrypto'] if name == 'security' and sys.platform != 'darwin' else [])
            run(name + '-compile', compiler + flags + (['-DATH10K_TEST_SHUTDOWN=1'] if name == 'power' else []) + (['-pthread'] if name in ['p256_backend','sae_session','pmf_session','native_pmf_receive','sae_worker','power','power_notifications','native_termination','native_bridge','first_probe','wake_recovery','connection','tx_watchdog','security_disconnect','reconnect_090','station_maintenance','channel_switch','ap_maintenance','runtime_power','wmi_notifications'] else []) + ['-Wno-unused-function', '-I' + str(include), '-Isrc/core', '-Isrc/macos/controller', '-Isrc/macos/native', '-Itests/support', '-Itests/fixtures', '-Ibuild/generated/itlwm',
                str(next((ROOT/'tests').glob('*/test_' + name + '.cpp')))] + libraries + ['-o', str(executable)])
            run(name, [str(executable)])
    (out / 'summary.json').write_text(json.dumps({
        'passed': passed, 'assertions_enabled': True,
        'full_development_suite': args.only is None, 'selected_tests': names,
        'macos_kext_build': False, 'hardware_validation': False,
        'native_adapter_present': True, 'feature_status': 'docs/development/NATIVE-STATUS.md',
    }, indent=2) + '\n')

if __name__ == '__main__':
    main()

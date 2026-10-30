#!/usr/bin/env python3
"""Generate a legacy or Sequoia native personality without editing an EFI."""
import argparse
from pathlib import Path
import plistlib


def prepare(native, destination, diagnostic_stage=0, p256_diagnostic=False, native_sae_experimental=False, native_pmf_probe=False):
    if diagnostic_stage not in range(5):
        raise ValueError('unknown diagnostic stage')
    if p256_diagnostic != (diagnostic_stage == 4) or (p256_diagnostic and not native):
        raise ValueError('stage 4 requires native build and explicit P-256 diagnostic compilation')
    if native_sae_experimental and (not native or diagnostic_stage != 0 or p256_diagnostic):
        raise ValueError('experimental SAE requires the normal native controller')
    if native_pmf_probe and not native_sae_experimental:
        raise ValueError('PMF probe requires explicit experimental SAE')
    root = Path(__file__).resolve().parents[2]
    info = plistlib.loads((root / 'packaging/Ath10kMac.kext/Contents/Info.plist').read_bytes())
    if native:
        info['OSBundleLibraries'].update({
            'com.apple.iokit.IO80211Family': '1200.13.1',
            'com.apple.iokit.IOSkywalkFamily': '1.0',
            'com.apple.driver.corecapture': '1.0.0', 'com.apple.kec.corecrypto': '1.0',
        })
        personality = info['IOKitPersonalities']['QCA9377']
        personality.update({
            'IOMatchCategory': 'WiFiDriver', 'IONetworkRootType': 'airport',
            'Ath10kNativeExperimental': True, 'IOPCISecondaryMatch': '0x2b511a3b',
            'Ath10kDiagnosticStage': diagnostic_stage, 'Ath10kProbeOnly': False, 'Ath10kStationDFS': True,
        })
        personality.pop('Ath10kNativeSAEExperimental', None)
        personality.pop('Ath10kNativePMFStartupQuery', None)
        if native_sae_experimental:
            personality['Ath10kNativeSAEExperimental'] = True
        if native_pmf_probe:
            personality['Ath10kNativePMFStartupQuery'] = True
        if p256_diagnostic:
            # This isolated service cannot provide a network-root device.
            info.pop('OSBundleRequired', None)
            info['OSBundleLibraries'] = {key: info['OSBundleLibraries'][key] for key in (
                'com.apple.iokit.IOPCIFamily', 'com.apple.kpi.iokit', 'com.apple.kpi.libkern',
                'com.apple.kpi.mach', 'com.apple.kec.corecrypto')}
            personality.update({'IOClass': 'Ath10kP256DiagnosticService', 'Ath10kP256SelfTest': True})
            personality.pop('IONetworkRootType', None)
            personality.pop('Ath10kNativeExperimental', None)
        info['IOKitPersonalities'] = {'Lunnen-QCA9377': personality}
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(plistlib.dumps(info, sort_keys=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('native', type=int, choices=[0, 1])
    parser.add_argument('destination', type=Path)
    parser.add_argument('--diagnostic-stage', type=int, choices=[0, 1, 2, 3, 4], default=0)
    parser.add_argument('--p256-diagnostic', action='store_true')
    parser.add_argument('--native-sae-experimental', action='store_true')
    parser.add_argument('--native-pmf-probe', action='store_true')
    args = parser.parse_args()
    prepare(bool(args.native), args.destination, args.diagnostic_stage, args.p256_diagnostic, args.native_sae_experimental, args.native_pmf_probe)

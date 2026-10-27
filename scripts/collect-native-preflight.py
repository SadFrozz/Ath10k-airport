#!/usr/bin/env python3
"""Read-only macOS preflight for the Lunnen native Wi-Fi port. No network/upload."""
import datetime
import hashlib
import json
import platform
import plistlib
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PCI_KEYS = ('vendor-id', 'device-id', 'subsystem-vendor-id', 'subsystem-id', 'revision-id')

def command(args):
    try:
        result = subprocess.run(args, capture_output=True, timeout=40)
        return result.returncode, result.stdout, result.stderr
    except (OSError, subprocess.TimeoutExpired) as error:
        return -1, b'', str(error).encode()

def pci_number(value):
    if isinstance(value, bytes) and len(value) <= 8:
        return int.from_bytes(value, 'little')
    return value if isinstance(value, int) else None

def find_adapter(nodes):
    """Only export explicitly allowed PCI identifiers, never MACs/SSIDs/serials."""
    found = []
    def visit(node):
        if isinstance(node, list):
            for child in node:
                visit(child)
        elif isinstance(node, dict):
            if pci_number(node.get('vendor-id')) == 0x168c and pci_number(node.get('device-id')) == 0x42:
                found.append({key: pci_number(node.get(key)) for key in PCI_KEYS})
            visit(node.get('IORegistryEntryChildren', []))
    visit(nodes)
    return found

def kext_record(path):
    try:
        info = plistlib.loads((path / 'Contents/Info.plist').read_bytes())
        result = {key: info.get(key) for key in ('CFBundleIdentifier', 'CFBundleVersion', 'OSBundleLibraries')}
        binary = path / 'Contents/MacOS' / info.get('CFBundleExecutable', '')
        if binary.is_file():
            result['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        return result
    except (OSError, plistlib.InvalidFileException, ValueError) as error:
        return {'unavailable': type(error).__name__}

def collect():
    if sys.platform != 'darwin':
        raise RuntimeError('Run this collector in macOS Sequoia; it does not install or change anything.')
    report = {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'machine': platform.machine(), 'kernel': platform.release(),
              'privacy': 'No SSIDs, BSSIDs, MAC addresses, passwords, serials or full IORegistry dumps collected.'}
    for key, args in {
        'macos': ['/usr/bin/sw_vers'],
        'developer_directory': ['/usr/bin/xcode-select', '-p'],
        'sdk': ['/usr/bin/xcrun', '--show-sdk-path'],
        'compiler': ['/usr/bin/xcrun', 'clang++', '--version'],
    }.items():
        code, stdout, stderr = command(args)
        report[key] = {'exit_code': code, 'stdout': stdout.decode(errors='replace')[:2000]}
        if code:
            report[key]['error'] = stderr.decode(errors='replace')[:1000]
    code, stdout, _ = command(['/usr/sbin/ioreg', '-a', '-r', '-c', 'IOPCIDevice'])
    try:
        report['qca9377'] = find_adapter(plistlib.loads(stdout)) if code == 0 else []
    except (ValueError, plistlib.InvalidFileException):
        report['qca9377'] = []
    code, stdout, stderr = command(['/usr/bin/kmutil', 'showloaded'])
    keywords = ('ath10k', 'io80211', 'ioskywalk', 'airport', 'itlwm', 'amfipass', 'rtwlan')
    report['loaded_network_drivers'] = [line for line in stdout.decode(errors='replace').splitlines()
                                        if any(word in line.lower() for word in keywords)]
    report['loaded_network_drivers_exit_code'] = code
    # The loaded versions and on-disk versions can differ after root patches.
    extensions = Path('/System/Library/Extensions')
    report['network_bundles'] = {}
    for name in ('IO80211Family.kext', 'IO80211FamilyLegacy.kext', 'IOSkywalkFamily.kext'):
        path = extensions / name
        report['network_bundles'][name] = kext_record(path)
        plugins = path / 'Contents/PlugIns'
        if plugins.is_dir():
            for plugin in sorted(plugins.glob('*.kext')):
                report['network_bundles'][name + '/' + plugin.name] = kext_record(plugin)
    report['implemented_in_this_branch'] = {
        'lunnen_board_profile': True, 'rsn_parser_and_no_downgrade_policy': True,
        'native_skywalk_interface': False, 'sae_authentication': False,
        'pmf_key_install_and_validation': False, 'awdl': False,
    }
    return report

def main():
    report = collect()
    out = ROOT / 'build/diagnostics'
    out.mkdir(parents=True, exist_ok=True)
    target = out / ('native-preflight-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '.json')
    target.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('Read-only report saved:', target)
    print('No driver, boot setting, network connection or system file was changed.')

if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)

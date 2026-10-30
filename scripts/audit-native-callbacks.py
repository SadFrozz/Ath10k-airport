#!/usr/bin/env python3
"""Inventory inline native protocol overrides; unsupported does not mean optional."""
import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / 'NATIVE-CALLBACK-MATRIX.json'
HEADER = ROOT / 'src/kext/native/Ath10kNativeInterface.hpp'


def inventory():
    source = HEADER.read_text()
    matches = list(re.finditer(r'IOReturn\s+(\w+)\(([^\n]*)\)\s+override\s*\{([^{}]*)\}', source))
    declared = re.findall(r'IOReturn\s+\w+\([^\n]*\)\s+override\s*\{', source)
    if len(matches) != len(declared):
        raise ValueError("Unparsed inline overrides require manual classification")
    aliases = {"setWCL_SET_SCAN_HOME_AWAY_TIME": "setWCL_SCAN_TIMING",
               "setWCL_UPDATE_FAST_LANE": "setWCL_FAST_LANE"}
    rows = []
    for match in matches:
        name, parameters, body = match.groups()
        forward = re.fullmatch(r'\s*return perform\(AthNativeOp::(\w+),data\);\s*', body)
        rejected = re.fullmatch(r'\s*return kIOReturnUnsupported;\s*', body)
        if not forward and not rejected:
            raise ValueError(f'{name}: unfamiliar override body requires manual classification')
        if forward and forward[1] != aliases.get(name, name):
            raise ValueError(f'{name}: dispatch differs from callback name: {forward[1]}')
        row = dict(callback=name, parameters=parameters,
                   implementation='forwarded' if forward else 'unsupported',
                   operation=forward[1] if forward else None,
                   queue_contract='WCL caller -> gated radio dispatcher' if forward else 'inline rejection; no radio access',
                   requirement_audit='implemented contract; kernel/hardware behavior unverified' if forward else 'caller evidence required; do not classify as optional',
                   stock_consumer_evidence=[])
        if name in ('getCUR_PMK', 'setCIPHER_KEY', 'setCLEAR_PMKSA_CACHE'):
            evidence = {
                'getCUR_PMK': ('0xffffff800163e294', 'Stock getter requires development/internal CSR and allowWiFiDebug gates before exporting PMK; rejection is normal outside these gates. Not an ordinary association prerequisite.'),
                'setCIPHER_KEY': ('0xffffff800160dc76', 'Core forwards to AppleBCMWLANJoinAdapter::setKey at 0xffffff8001586450 with argument true and null auxiliary data. Native external-key ownership and caller requirements remain unresolved.'),
                'setCLEAR_PMKSA_CACHE': ('0xffffff80015ec6e4', 'Core and infrastructure wrapper obtain an address through vtable offset 0xcf0 and call setCurEtheraddr. Downstream cache and address lifetime must be traced; function name alone does not prove active PTK destruction.')
            }[name]
            row['stock_producer_evidence'] = [dict(
                module='AppleBCMWLANCoreMac', uuid='4C3822FC-8902-3AF6-A791-DD4A8D9E9C66',
                producer='AppleBCMWLANCore::'+name, address=evidence[0], semantics=evidence[1])]
            if name == 'setCIPHER_KEY':
                row['stock_consumer_evidence'] = [dict(
                    module='IO80211Family', uuid='0D5AC570-04D4-38B6-8577-9F21350CDD50',
                    consumer='setCIPHER_KEY ioctl handler', address='0xffffff8002218330',
                    record_bytes=148, internal_command='0x802869c8', operation=3,
                    validation='Requires exact record size and nonnull pointer. Interface-kind 1 first gets auth type; cipher mask 0x340 admits 6/8/9 with auth-dependent length clamp 32 or 48, mask 0x6 admits 1/2; other ciphers rejected on this path.',
                    dispatch='WCL dispatch, falling back to typed protocol only if unhandled or 0xe082280f',
                    limitation='Other interface kinds bypass that cipher filter. This is not proof that the current personal SAE path requires this callback.')]
                row['stock_producer_evidence'][0]['join_adapter_dispatch'] = {
                    'jump_table': '0xffffff8001586ad4',
                    'selector_offset': 8,
                    'none_0': 'returns success without key installation',
                    'pmk_6_msk_9': 'programPMK path; nonempty input with core flag true enables supplicant events and 6000 ms timeout',
                    'pmksa_7': 'feature/logging branch returns success without programPMK or data-key installation in this exact build',
                    'password_10': 'separate credential path, not a data-key install',
                    'other_types': 'mapAppleKeyToBcomKey then firmware programming; mapping may reject unsupported types',
                    'limitation': 'Producer dispatch reconstructed; caller state ownership and host-supplicant interoperability remain pending'}
            row['requirement_audit'] = (
                'stock debug-gated PMK export; retain unsupported, no PMK exposure added' if name == 'getCUR_PMK' else
                'external key installation ownership unresolved; keep explicitly unsupported' if name == 'setCIPHER_KEY' else
                'no cross-association PMKSA cache implemented; successful no-op does not claim stock address side effects')
        if name in ('getHT_CAPABILITY', 'getVHT_CAPABILITY'):
            row['stock_consumer_evidence'] = [dict(
                module='IO80211Family', uuid='0D5AC570-04D4-38B6-8577-9F21350CDD50',
                consumer='IO80211PeerManager::getHtCapabilityIE' if name == 'getHT_CAPABILITY' else 'IO80211PeerManager::getVHtCapabilityIE',
                address='0xffffff80021e7220' if name == 'getHT_CAPABILITY' else '0xffffff80021e7452',
                failure_effect='clears cached HT capability length' if name == 'getHT_CAPABILITY' else 'clears cached VHT-capable flag')]
        if name == 'setWCL_REASSOC':
            row['requirement_audit'] = 'host-requested cached-candidate reassociation integrated with retirement and ordered success/failure completion; local production-path tests only; physical inter-AP validation unavailable'
            row['stock_consumer_evidence'] = [dict(
                module='IO80211Family', uuid='0D5AC570-04D4-38B6-8577-9F21350CDD50',
                consumer='WCLNetManager::sendReassocCommand',
                address='0xffffff800212933e', command=0x1aa, input_bytes=0xbc,
                observed_fields=dict(channel_count=0x94, flags=0x98, ssid=0x99, ssid_length=0xb9),
                failure_effect='nonzero cmdIouc result triggers compensating bulletin-board message; full state semantics not yet established')]
        if name == 'setWCL_ROAM_USER_CACHE':
            row['requirement_audit'] = 'mandatory post-roam clear/disable and empty readback implemented; nonempty autonomous firmware cache and override enable explicitly unsupported'
            row['stock_consumer_evidence'] = [dict(
                module='IO80211Family', uuid='0D5AC570-04D4-38B6-8577-9F21350CDD50',
                consumer='WCLAdaptiveRoam::configureUserRoamCache', address='0xffffff80022dee46',
                command=0x1af, input_bytes=128,
                semantics='successful roam issues empty clear plus override disable; channel-offload policy remains a separate unsupported capability')]
        if name in ('getRSN_XE', 'setRSN_XE'):
            row['requirement_audit'] = ('read-only native association encoder integrated; host lifecycle/ABI tests, pending hardware verification' if name == 'getRSN_XE' else 'stock setter reconstructed; next-join binding and update/cancellation semantics pending; still explicitly unsupported')
            row['stock_producer_evidence'] = [dict(
                module='AppleBCMWLANCoreMac', uuid='4C3822FC-8902-3AF6-A791-DD4A8D9E9C66',
                producer='AppleBCMWLANCore::'+name,
                address='0xffffff80015f462e' if name == 'getRSN_XE' else '0xffffff8001610d64',
                adapter='AppleBCMWLANJoinAdapter::getAssocRSNXE' if name == 'getRSN_XE' else 'AppleBCMWLANJoinAdapter::setAssocRSNXE',
                adapter_address='0xffffff80015894be' if name == 'getRSN_XE' else '0xffffff8001589794',
                data_fields=dict(length_offset=4, length_bytes=2, element_offset=6, maximum_element_bytes=257),
                feature_gates=[0x6d, 0x41], additional_context_flag=0x40,
                semantics='Reads or replaces the outgoing association RSNXE cache; zero-length set clears it; separate firmware-associated RSNXE cache is not returned',
                limitation=('Getter is a current prepared association snapshot, not an arbitrary writable cache; hardware callback verification pending' if name == 'getRSN_XE' else 'No safe setter-to-next-association lifetime mapping; setter remains explicitly unsupported'))]
        if name == 'getRSN_XE':
            row['stock_consumer_evidence'] = [dict(
                module='IO80211Family', uuid='0D5AC570-04D4-38B6-8577-9F21350CDD50',
                consumer='getRSN_XE(IO80211Controller*, IO80211SkywalkInterface*, apple80211req*)',
                address='0xffffff80022137d6', ioctl_operation=457, input_output_bytes=264,
                protocol_wrapper='0xffffff80021faca3', protocol_vtable_byte_offset=0x1068,
                failure_effect='rejects record sizes other than 264; delegates through WCL or the typed protocol callback')]
            row['stock_consumer_evidence'].append(dict(
                module='IO80211.framework', uuid='D6F428E5-23D1-3240-9E20-5D29BD41DC85',
                consumer='Apple80211Get public userland dispatch', ioctl_operation=457,
                disposition='unsupported in this public dispatcher before kernel I/O',
                evidence='exact-UUID bounded dispatch reconstruction and process-owned synthetic context probe',
                synthetic_probe_result=-3903, synthetic_payload_unchanged=True,
                live_bind_result=-1, live_callback_verified=False,
                limitation='Public API rejection and failed interface binding do not test the implemented kernel callback; internal WCL dispatch remains distinct'))
        if name == 'setRSN_XE':
            row['stock_consumer_evidence'] = [dict(
                module='IO80211Family', uuid='0D5AC570-04D4-38B6-8577-9F21350CDD50',
                consumer='setRSN_XE(IO80211Controller*, IO80211SkywalkInterface*, apple80211req*)',
                address='0xffffff800221f389', ioctl_operation=457, input_output_bytes=264,
                internal_command='0x802869c8', protocol_wrapper='0xffffff80021fff5a',
                protocol_vtable_byte_offset=0x12b8,
                failure_effect='rejects non-264-byte or null records; WCL dispatch falls back to the typed callback only when unhandled or returning 0xe082280f',
                limitation='Dispatch reconstruction does not establish setter-to-next-join lifetime or admission requirements')]
        if name in ('setIPV4_PARAMS', 'setIPV6_PARAMS'):
            row['requirement_audit'] = 'stock address/offload state propagation confirmed; caller failure policy and firmware implementation pending; not proven optional'
            row['stock_producer_evidence'] = [dict(
                module='AppleBCMWLANCoreMac', uuid='4C3822FC-8902-3AF6-A791-DD4A8D9E9C66',
                producer='AppleBCMWLANCore::'+name,
                address='0xffffff8001643b3c' if name == 'setIPV4_PARAMS' else '0xffffff8001643e80',
                observed_behavior=('copies request fields at offsets 0, 4, 8 and 12 into core state; calls handleIPv4AddressNotificationGated; conditionally calls handleKeepaliveDataNotificationGated' if name == 'setIPV4_PARAMS' else 'reads count at offset 0 and clamps to 10; processes entries at 16-byte strides starting offset 4; subsequent offload flow needs further reconstruction'),
                limitation='Provider disassembly does not establish WCL caller admission, required capability bits, or safe success-without-offload semantics')]
        if name in ('setIPV4_PARAMS', 'setIPV6_PARAMS'):
            row['stock_consumer_evidence'] = [dict(
                module='IO80211Family', uuid='0D5AC570-04D4-38B6-8577-9F21350CDD50',
                consumer='WCLNetManager::'+name,
                address='0xffffff8002128a58' if name == 'setIPV4_PARAMS' else '0xffffff8002128ac4',
                behavior=('issues cmdIouc 0x1e9, ignores its return value, then calls receivedIPv4Address with request words 0 and 4; non-null request returns success' if name == 'setIPV4_PARAMS' else 'copies up to ten 16-byte addresses from request+4 and calls receivedIPv6Address; no driver command in this handler'),
                limitation='Only this bulletin-board path inspected; ioctl paths and downstream address handlers remain distinct')]
            row['requirement_audit'] = 'address propagation inspected; unsupported does not block the inspected WCL handler; firmware offload and other entry paths remain unimplemented/unverified'
        rows.append(row)
    if not rows or len({r['callback'] for r in rows}) != len(rows):
        raise ValueError('Missing or duplicate callbacks')
    operations = (ROOT / 'src/kext/native/Ath10kNativeOps.hpp').read_text().split('enum class AthNativeOp {', 1)[1].split('}', 1)[0]
    driver = (ROOT / 'src/kext/native/Ath10kNative.cpp').read_text()
    start = driver.index('IOReturn Ath10kPCIDevice::nativeRequestGated(')
    driver = driver[start:driver.index('void Ath10kPCIDevice::requestNativeService(', start)]
    for row in rows:
        if row['operation'] and (not re.search(r'\b'+row['operation']+r'\b', operations) or
                                 'case N::'+row['operation']+':' not in driver):
            raise ValueError(f'{row["callback"]}: missing enum/dispatcher branch')
    return dict(schema=1, abi='Sequoia 15.2+ native adapter',
                scope='Inline IOReturn protocol overrides only; lifecycle/non-inline methods are covered separately in NATIVE-CONTRACT.md',
                source='src/kext/native/Ath10kNativeInterface.hpp',
                hardware_validation=False,
                counts=dict(total=len(rows), forwarded=sum(r['implementation']=='forwarded' for r in rows),
                            unsupported=sum(r['implementation']=='unsupported' for r in rows)),
                callbacks=rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--write', action='store_true', help='Update the committed matrix')
    group.add_argument('--check', action='store_true', help='Reject a missing/stale committed matrix')
    args = parser.parse_args()
    result = inventory()
    text = json.dumps(result, indent=2) + '\n'
    if args.write:
        MATRIX.write_text(text)
    elif args.check:
        if not MATRIX.exists() or MATRIX.read_text() != text:
            raise SystemExit('Native callback matrix is missing/stale; audit and regenerate with --write')
    else:
        print(text, end='')
    if args.check or args.write:
        print(json.dumps(result['counts']))


if __name__ == '__main__':
    main()

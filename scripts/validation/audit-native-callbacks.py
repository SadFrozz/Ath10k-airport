#!/usr/bin/env python3
"""Inventory inline native protocol overrides; unsupported does not mean optional."""
import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / 'docs/development/NATIVE-CALLBACK-MATRIX.json'
HEADER = ROOT / 'src/macos/native/Ath10kNativeInterface.hpp'


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
                'setCIPHER_KEY': ('0xffffff800160dc76', 'Core forwards to AppleBCMWLANJoinAdapter::setKey at 0xffffff8001586450 with argument true and null auxiliary data. The setKey jump table distinguishes traffic keys, PMK/MSK (6/9), PMKSA (7) and password (10). Traffic keys map through mapAppleKeyToBcomKey, then runtime-selected async/sync firmware programming. External owner and completion contracts remain unresolved; see docs/development/NATIVE-CONNECTION-AUDIT.md.'),
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
                'gated MSK-only callback for an active WPA2 EAP owner; enterprise join not yet admitted, traffic keys/PMKSA/password remain rejected' if name == 'setCIPHER_KEY' else
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
        if name in ('setWCL_UPDATE_FAST_LANE', 'setCONGESTION_CTRL_IND', 'setBATTERY_POWERSAVE_CONFIG', 'setPOWERSAVE'):
            policy = {
                'setWCL_UPDATE_FAST_LANE': ('0xffffff8001550ac0', 'Byte0 updates IOSkywalkNetworkInterface::setFastlaneCapable; byte0 AND byte1 additionally invokes asynchronous ACM override. Local host marking now applies outside radio within WCL; link-down resets marking. Existing WCL termination fence protects synchronous calls. Enabled ACM override is rejected before mutation. Focused tests/native build passed; offline linking and radio evidence pending.'),
                'setCONGESTION_CTRL_IND': ('0xffffff8001643dee', 'Stores normalized byte0 at core+0x791a. Inspected collectRealTimeAppCongestionState consumer at 0xffffff800163f7ca returns false unless traffic-engineering gate +0x74cc equals one. Caller failure handling and other consumers remain open.'),
                'setBATTERY_POWERSAVE_CONFIG': ('0xffffff8001643812', 'Forwards u32 mode to PowerManager at 0xffffff800157d402. Feature bit 0x2c and a runtime state gate precede storage and possible configureMRCThreshold. Not equivalent to ordinary station powersave; capability and OS caller semantics remain open.'),
                'setPOWERSAVE': ('0xffffff800160ff60', 'Stock accepts only word+4 zero/one; greater values return 0x66. Current boolean domain agrees; this does not certify application timing or every power transition.')
            }[name]
            row['requirement_audit'] = policy[1]
            if name == 'setWCL_UPDATE_FAST_LANE':
                row['queue_contract'] = 'WCL caller -> gated validation -> WCL-only host marking; reject entry while radio held'
            row['stock_producer_evidence'] = [dict(module='AppleBCMWLANCoreMac', uuid='4C3822FC-8902-3AF6-A791-DD4A8D9E9C66', address=policy[0], evidence='outputs/NATIVE-traffic-policy-contract-20261030/queue-power-producers.json')]
        if name == 'setTRAFFIC_ENG_PARAMS':
            row['requirement_audit'] = 'Stock feature-gated capability acknowledgement, not a parameter setter. Unsupported matches disabled traffic-engineering mode; enabling the separate monitor/queue policy remains unimplemented'
            row['stock_producer_evidence'] = [dict(
                module='AppleBCMWLANCoreMac', uuid='4C3822FC-8902-3AF6-A791-DD4A8D9E9C66',
                producer='AppleBCMWLANInfraProtocol::setTRAFFIC_ENG_PARAMS', address='0xffffff8001550892',
                semantics='Null returns 0xe00002bc; no payload read. Returns zero only when core+0x74cc is nonzero, otherwise 0xe00002c7. initTrafficEngineering starts gate at zero and reads wlan.trafficengineering.enabled; debug override separately starts/stops monitor')]
            row['stock_consumer_evidence'] = [dict(
                module='IO80211Family', uuid='0D5AC570-04D4-38B6-8577-9F21350CDD50',
                consumer='set ioctl handler', address='0xffffff8002220c05', ioctl_operation=0x202, input_bytes=4,
                semantics='Exact record size and nonnull; WCL dispatch and typed fallback; propagates return status. Does not establish all traffic-policy callbacks optional')]
        if name == 'setEAP_FILTER_CONFIG':
            row['requirement_audit'] = 'stock producer stores a WoW EAPOL-filter option; not evidence of ordinary EAP-port startup. Wake-filter behavior and caller failure handling remain unverified; rejected rather than fake success'
            row['stock_producer_evidence'] = [dict(
                module='AppleBCMWLANCoreMac', uuid='4C3822FC-8902-3AF6-A791-DD4A8D9E9C66',
                producer='AppleBCMWLANCore::setEAP_FILTER_CONFIG', address='0xffffff8001643cfa',
                semantics='Nonnull record: copies first u32 to core-context +0x4c90, diagnostic identifies WoWEapolFilterEnable; returns success. Null returns 0xe00002bc. No immediate packet delivery or client startup call in this setter.',
                limitation='Setter alone does not establish when configureEapolFilter uses the option or whether a consumer requires success')]
        if name in ('setIPV4_PARAMS', 'setIPV6_PARAMS', 'setDHCP_RENEWAL_DATA'):
            address, semantics = {
                'setIPV4_PARAMS': ('0xffffff8001643b3c', 'Copies address/gateway words and six-byte peer address; forwards to IO80211InfraInterface::setIPv4Params at 0xffffff80022dbd50 (copies 16 bytes); calls handleIPv4AddressNotificationGated and conditional handleKeepaliveDataNotificationGated. IPv4 notification can set up traffic monitoring.'),
                'setIPV6_PARAMS': ('0xffffff8001643e80', 'Forwards to IO80211InfraInterface::setIPv6Params at 0xffffff80022dbd92 (copies 164 bytes), clamps count to ten, updates address context and invokes gated handleIPv6AddressNotificationGated. Host record layout recovered; radio offload remains separately unimplemented.'),
                'setDHCP_RENEWAL_DATA': ('0xffffff8001643764', 'Stores whether the first input byte is nonzero at core-context+0x1a52. Diagnostic identifies active-during-sleep support. No DHCP packet construction in this setter; downstream uses and caller failure handling require recovery.')
            }[name]
            row['requirement_audit'] = ('Host parameter cache forwarding implemented locally with validated/zeroed records and propagated OS status; 69-test sanitized regression and exact-UUID offline inclusion passed; installed 1.0.110 boot verified. Individual callback invocation remains unobserved; radio offload remains separate and unsupported' if name != 'setDHCP_RENEWAL_DATA' else 'Sleep activity hint under review; rejected, not an implemented no-op. Downstream alias consumers remain open')
            row['stock_producer_evidence'] = [dict(
                module='AppleBCMWLANCoreMac', uuid='4C3822FC-8902-3AF6-A791-DD4A8D9E9C66',
                producer='AppleBCMWLANCore::'+name, address=address, semantics=semantics,
                limitation='Producer inspection does not establish optionality, consumer acceptance or native radio interoperability')]
        if name in ('setIPV4_PARAMS', 'setIPV6_PARAMS', 'setDHCP_RENEWAL_DATA'):
            handler, operation, length = {
                'setIPV4_PARAMS': ('0xffffff8002220006', 0x1e9, 16),
                'setIPV6_PARAMS': ('0xffffff8002220950', 0x1fe, 164),
                'setDHCP_RENEWAL_DATA': ('0xffffff800221f5e7', 0x1d6, 1)
            }[name]
            row['stock_consumer_evidence'] = [dict(
                module='IO80211Family', uuid='0D5AC570-04D4-38B6-8577-9F21350CDD50',
                consumer='set ioctl handler', address=handler, ioctl_operation=operation,
                input_bytes=length,
                semantics='Validates exact size and nonnull payload; WCL dispatch falls back to typed protocol when unhandled or status 0xe082280f. This does not make every driver error a disconnect.')]
            if name == 'setIPV4_PARAMS':
                row['stock_consumer_evidence'].append(dict(
                    consumer='WCLNetManager::setIPV4_PARAMS', address='0xffffff8002128a58',
                    semantics='Calls cmdIouc(0x1e9), then receivedIPv4Address without testing returned eax; nonnull message payload path returns zero and marks message handled. No claim about unrelated firmware side effects.'))
            if name == 'setIPV6_PARAMS':
                row['stock_consumer_evidence'].append(dict(
                    consumer='WCLNetManager::setIPV6_PARAMS', address='0xffffff8002128ac4',
                    semantics='Clamps address count to ten, copies 16-byte entries and calls receivedIPv6Address. No cmdIouc call in this handler; allocation failure returns 0xe00002c2. Other callers remain distinct.'))
        if name in ('setOFFLOAD_ARP', 'setOFFLOAD_NDP'):
            row['requirement_audit'] = 'Legacy host address record translated into stock interface cache; empty replacement and partial IPv4 updates handled. No firmware offload capability enabled. Published in add6acf; 69-test sanitized regression passed and installed 1.0.110 boot verified. Individual callback invocation and firmware offload remain unverified'
            arp = name == 'setOFFLOAD_ARP'
            row['stock_consumer_evidence'] = [dict(
                module='IO80211Family', uuid='0D5AC570-04D4-38B6-8577-9F21350CDD50',
                consumer='set ioctl handler', address='0xffffff800221a8d4' if arp else '0xffffff800221a9d7',
                ioctl_operation=0xbf if arp else 0xc0, input_bytes=24 if arp else 72,
                semantics='Exact size and nonnull payload required; WCL dispatch and typed protocol fallback; return status propagated on inspected path')]
            row['stock_producer_evidence'] = [dict(
                module='AppleBCMWLANCoreMac', uuid='4C3822FC-8902-3AF6-A791-DD4A8D9E9C66',
                producer='AppleBCMWLANCore::'+name, address='0xffffff80016065de' if arp else '0xffffff8001606878',
                semantics=('Input word+4 gates local IPv4 replacement from+8; zero preserves prior local IPv4. Gateway+12 and MAC+16 always update. Copies a 16-byte record to IO80211InfraInterface and conditionally runs keepalive handler; not a proven global disable flag' if arp else 'Reads count at+4, clamps to four, copies 16-byte IPv6 entries from+8. Zero count still forwards to IO80211InfraInterface cache; distinct from ten-entry IPV6_PARAMS record. Gated IPv6 handler has diagnostic iteration and no immediate firmware command'),
                limitation='Host replacement/cache behavior recovered; downstream firmware programming and caller requirements still open')]
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
    operations = (ROOT / 'src/macos/native/Ath10kNativeOps.hpp').read_text().split('enum class AthNativeOp {', 1)[1].split('}', 1)[0]
    driver = (ROOT / 'src/macos/native/Ath10kNative.cpp').read_text()
    start = driver.index('IOReturn Ath10kPCIDevice::nativeRequestGated(')
    driver = driver[start:driver.index('void Ath10kPCIDevice::requestNativeService(', start)]
    for row in rows:
        if row['operation'] and (not re.search(r'\b'+row['operation']+r'\b', operations) or
                                 'case N::'+row['operation']+':' not in driver):
            raise ValueError(f'{row["callback"]}: missing enum/dispatcher branch')
    return dict(schema=1, abi='Sequoia 15.2+ native adapter',
                scope='Inline IOReturn protocol overrides only; lifecycle/non-inline methods are covered separately in docs/contracts/NATIVE-CONTRACT.md',
                source='src/macos/native/Ath10kNativeInterface.hpp',
                feature_status='docs/development/NATIVE-STATUS.md',
                hardware_validation_scope='False means the entire callback inventory is not hardware-certified; see feature_status for positive bounded evidence',
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

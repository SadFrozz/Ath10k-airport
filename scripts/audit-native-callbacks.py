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
        if name in ('getHT_CAPABILITY', 'getVHT_CAPABILITY'):
            row['stock_consumer_evidence'] = [dict(
                module='IO80211Family', uuid='0D5AC570-04D4-38B6-8577-9F21350CDD50',
                consumer='IO80211PeerManager::getHtCapabilityIE' if name == 'getHT_CAPABILITY' else 'IO80211PeerManager::getVHtCapabilityIE',
                address='0xffffff80021e7220' if name == 'getHT_CAPABILITY' else '0xffffff80021e7452',
                failure_effect='clears cached HT capability length' if name == 'getHT_CAPABILITY' else 'clears cached VHT-capable flag')]
        if name == 'setWCL_REASSOC':
            row['requirement_audit'] = 'stock caller confirmed; request partially reconstructed; roaming implementation and completion contract pending'
            row['stock_consumer_evidence'] = [dict(
                module='IO80211Family', uuid='0D5AC570-04D4-38B6-8577-9F21350CDD50',
                consumer='WCLNetManager::sendReassocCommand',
                address='0xffffff800212933e', command=0x1aa, input_bytes=0xbc,
                observed_fields=dict(channel_count=0x94, flags=0x98, ssid=0x99, ssid_length=0xb9),
                failure_effect='nonzero cmdIouc result triggers compensating bulletin-board message; full state semantics not yet established')]
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

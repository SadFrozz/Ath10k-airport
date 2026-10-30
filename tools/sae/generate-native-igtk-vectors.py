#!/usr/bin/env python3
"""Synthetic BIP fixtures using the independent cryptography CMAC provider."""
from pathlib import Path
import re
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms

text = (Path(__file__).resolve().parents[2] / 'tests/fixtures/sae_eapol_vectors.inc').read_text()
def value(name):
    found = re.search(r'\b' + name + r'\[\]\s*=\s*\{([^}]*)\}', text)
    assert found, name
    return bytes(int(v.strip(), 0) for v in found[1].split(',') if v.strip())

ap = value('w_ap')
print('// Independent CMAC fixtures bound to synthetic SAE EAPOL keys; no device data.')
for name, key_name, key_id, ipn in [('n_igtk4', 'w_igtk', 4, 7), ('n_igtk5', 'w_next_igtk', 5, 7), ('n_igtk4_next', 'w_third_igtk', 4, 8)]:
    frame = bytes.fromhex('c0000000') + bytes([255])*6 + ap + ap + bytes(2)
    frame += bytes.fromhex('06004c10') + key_id.to_bytes(2, 'little') + ipn.to_bytes(6, 'little') + bytes(8)
    cmac = CMAC(algorithms.AES(value(key_name)))
    cmac.update(frame[:2] + frame[4:22] + frame[24:])
    frame = frame[:-8] + cmac.finalize()[:8]
    print(f'static constexpr uint8_t {name}[]={{' + ','.join(f'0x{x:02x}' for x in frame) + '};')

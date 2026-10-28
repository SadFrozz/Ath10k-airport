#!/usr/bin/env python3
"""Public P-256 vectors from pinned cryptography/OpenSSL, not CoreCrypto.
Requires tests/requirements-fixtures.txt. No real credentials are used.
"""
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import subprocess
import re

ROOT = Path(__file__).resolve().parents[1]
text = subprocess.check_output(['openssl', 'ecparam', '-name', 'prime256v1', '-param_enc', 'explicit', '-text', '-noout'], text=True)
def parameter(start, end):
    raw = text.split(start, 1)[1].split(end, 1)[0]
    return bytes.fromhex(''.join(re.findall(r'\b[0-9a-fA-F]{2}\b', raw)))
order = int.from_bytes(parameter('Order:', 'Cofactor:'), 'big')
prime = int.from_bytes(parameter('Prime:', 'A:'), 'big')
generator = parameter('Generator (uncompressed):', 'Order:')
def point(k):
    return ec.derive_private_key(k % order, ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]
assert generator == b'\x04' + point(1)
def scalar(k): return k.to_bytes(32, 'big').hex()
pairs = [(1,1),(2,1),(3,1),(7,19),(19,7),(0x123456789abcdef,17),
         (order-1,1),(order-1,order-1),(order//2,3),(2**255,11),
         (int('a5'*32,16) % (order-1)+1,23),(65537,257)]
lines = ['#pragma once', '// Generated public test vectors. Standards for Efficient Cryptography 2 (SEC 2), secp256r1.',
         '// https://www.secg.org/sec2-v2.pdf section 2.4.2; generator tool uses independent OpenSSL/cryptography.',
         'namespace P256Fixtures {',
         'struct Multiply { const char *scalar,*point,*result; };',
         'static constexpr Multiply multiply[]={']
for k, a in pairs:
    lines.append('    {"'+scalar(k)+'","'+point(a).hex()+'","'+point(k*a).hex()+'"},')
lines += ['};', 'struct Combine { const char *a,*b,*sum,*difference; };', 'static constexpr Combine combine[]={']
for a,b in [(1,2),(2,1),(7,19),(19,7),(3,17),(order-2,7),(2**254,2**253)]:
    lines.append('    {"'+point(a).hex()+'","'+point(b).hex()+'","'+point(a+b).hex()+'","'+point(a-b).hex()+'"},')
lines += ['};', 'static constexpr const char *generator="'+point(1).hex()+'";',
          'static constexpr const char *negativeGenerator="'+point(order-1).hex()+'";',
          'static constexpr const char *order="'+scalar(order)+'";',
          'static constexpr const char *aboveOrder="'+scalar(order+1)+'";',
          'static constexpr const char *prime="'+scalar(prime)+'";', '}']
(ROOT/'tests/p256_corecrypto_fixtures.hpp').write_text('\n'.join(lines)+'\n')
print('Generated 12 multiplication and 7 add/subtract vectors with cryptography/OpenSSL')

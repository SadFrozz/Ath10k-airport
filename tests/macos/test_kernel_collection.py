#!/usr/bin/env python3
"""Exercise collection inclusion, stale binaries and malformed command bounds."""
import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location('collection_verifier', Path(__file__).resolve().parents[2] / 'scripts/validation/verify-kernel-collection.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
BUNDLE = 'br.com.jonasw8.driver.ath10kmac'


def image(commands):
    return struct.pack('<8I', 0xfeedfacf, 0x1000007, 3, 2, len(commands), sum(map(len, commands)), 0, 0) + b''.join(commands)


def binary(value=1):
    return image([struct.pack('<II', 0x1b, 24) + bytes([value]) * 16])


def collection(name=BUNDLE, value=1, duplicate=False):
    raw = name.encode() + b'\0'
    length = (32 + len(raw) + 7) & ~7
    command = struct.pack('<IIQQII', 0x80000035, length, 0, 512, 32, 0) + raw
    command = command.ljust(length, b'\0')
    return image([command] * (2 if duplicate else 1)).ljust(512, b'\0') + binary(value)


class Inclusion(unittest.TestCase):
    def test_exact_image(self):
        self.assertTrue(m.verify(collection(), binary(), BUNDLE)['included'])

    def test_kernel_only_is_failure(self):
        with self.assertRaisesRegex(ValueError, 'found 0'):
            m.verify(collection('com.apple.kernel'), binary(), BUNDLE)

    def test_old_candidate_is_failure(self):
        with self.assertRaisesRegex(ValueError, 'UUID mismatch'):
            m.verify(collection(value=2), binary(), BUNDLE)

    def test_duplicate_id_is_failure(self):
        with self.assertRaisesRegex(ValueError, 'found 2'):
            m.verify(collection(duplicate=True), binary(), BUNDLE)

    def test_truncated_entry_is_failure(self):
        with self.assertRaises(ValueError):
            m.verify(collection()[:520], binary(), BUNDLE)

    def test_bad_command_length_is_failure(self):
        data = bytearray(collection())
        struct.pack_into('<I', data, 36, 0xffffffff)
        with self.assertRaises(ValueError):
            m.verify(data, binary(), BUNDLE)

    def test_bad_identifier_offset_is_failure(self):
        data = bytearray(collection())
        struct.pack_into('<I', data, 56, 8)
        with self.assertRaises(ValueError):
            m.verify(data, binary(), BUNDLE)


if __name__ == '__main__':
    unittest.main()

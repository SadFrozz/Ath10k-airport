import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('native_preflight', ROOT / 'scripts/diagnostics/collect-native-preflight.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

class PreflightTests(unittest.TestCase):
    def test_only_matching_adapter_identifiers_leave_ioreg(self):
        device = {'vendor-id': b'\x8c\x16\0\0', 'device-id': b'\x42\0\0\0',
                  'subsystem-vendor-id': b'\x3b\x1a\0\0', 'subsystem-id': b'\x51\x2b\0\0',
                  'revision-id': b'\x31\0\0\0', 'IOMACAddress': b'SECRET',
                  'SSID': 'private-network', 'SystemSerialNumber': 'private-serial',
                  'IORegistryEntryChildren': [{'SSID': 'another-private-network'}]}
        unrelated = dict(device, **{'vendor-id': b'\x86\x80\0\0'})
        result = p.find_adapter([{'IORegistryEntryChildren': [device, unrelated]}])
        self.assertEqual(result, [{
            'vendor-id': 0x168c, 'device-id': 0x42, 'subsystem-vendor-id': 0x1a3b,
            'subsystem-id': 0x2b51, 'revision-id': 0x31}])
        self.assertNotIn('private', repr(result))
        self.assertNotIn('SECRET', repr(result))

    def test_unexpected_pci_types_are_not_exported(self):
        self.assertIsNone(p.pci_number('a-device-name'))
        self.assertIsNone(p.pci_number(b'x'*9))
        self.assertEqual(p.find_adapter(None), [])

if __name__ == '__main__':
    unittest.main()

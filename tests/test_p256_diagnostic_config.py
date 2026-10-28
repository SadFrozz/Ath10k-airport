import importlib.util
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prepare_kext_info', ROOT/'scripts/prepare-kext-info.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class DiagnosticConfiguration(unittest.TestCase):
    def test_separate_service_requires_explicit_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'Info.plist'
            module.prepare(True, output, 4, True)
            info = plistlib.loads(output.read_bytes())
            self.assertEqual(len(info['IOKitPersonalities']), 1)
            entry = next(iter(info['IOKitPersonalities'].values()))
            self.assertEqual(entry['IOClass'], 'Ath10kP256DiagnosticService')
            self.assertTrue(entry['Ath10kP256SelfTest'])
            self.assertEqual(entry['Ath10kDiagnosticStage'], 4)
            self.assertNotIn('IONetworkRootType', entry)
            self.assertNotIn('Ath10kNativeExperimental', entry)
            self.assertEqual(info['OSBundleRequired'], 'Network-Root')
            self.assertEqual(set(info['OSBundleLibraries']), {'com.apple.iokit.IOPCIFamily', 'com.apple.kpi.iokit', 'com.apple.kpi.libkern', 'com.apple.kpi.mach', 'com.apple.kec.corecrypto'})

    def test_default_personality_does_not_enable_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'Info.plist'
            for stage in range(4):
                module.prepare(True, output, stage)
                entry = next(iter(plistlib.loads(output.read_bytes())['IOKitPersonalities'].values()))
                self.assertEqual(entry['IOClass'], 'Ath10kPCIDevice')
                self.assertNotIn('Ath10kP256SelfTest', entry)

    def test_invalid_combinations_do_not_overwrite_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'Info.plist'
            output.write_bytes(b'preserve')
            for native, stage, enabled in [(True, 4, False), (False, 4, True), (True, 0, True), (True, 5, False), (True, -1, False)]:
                with self.assertRaises(ValueError):
                    module.prepare(native, output, stage, enabled)
                self.assertEqual(output.read_bytes(), b'preserve')

    def test_make_rejects_flag_mismatch(self):
        for args in [('NATIVE=1', 'DIAGNOSTIC_STAGE=4'), ('NATIVE=0', 'DIAGNOSTIC_STAGE=4', 'P256_DIAGNOSTIC=1'),
                     ('NATIVE=1', 'DIAGNOSTIC_STAGE=0', 'P256_DIAGNOSTIC=1'), ('P256_DIAGNOSTIC=2',)]:
            result = subprocess.run(['make', '-n', *args], cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, args)


if __name__ == '__main__':
    unittest.main()

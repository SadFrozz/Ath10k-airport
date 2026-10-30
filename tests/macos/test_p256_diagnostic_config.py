import importlib.util
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('prepare_kext_info', ROOT/'scripts/build/prepare-kext-info.py')
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
            self.assertNotIn('OSBundleRequired', info)
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

    def test_sae_opt_in_is_normal_native_only(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'Info.plist'
            for enabled in (False, True):
                module.prepare(True, output, native_sae_experimental=enabled)
                entry = next(iter(plistlib.loads(output.read_bytes())['IOKitPersonalities'].values()))
                self.assertEqual(entry.get('Ath10kNativeSAEExperimental', False), enabled)
            for native, stage, diagnostic in [(False,0,False),(True,1,False),(True,4,True)]:
                output.write_bytes(b'preserve')
                with self.assertRaises(ValueError):
                    module.prepare(native, output, stage, diagnostic, True)
                self.assertEqual(output.read_bytes(), b'preserve')
            for args in [('NATIVE=0','NATIVE_SAE_EXPERIMENTAL=1'),('DIAGNOSTIC_STAGE=1','NATIVE_SAE_EXPERIMENTAL=1'),('NATIVE_SAE_EXPERIMENTAL=2',)]:
                result=subprocess.run(['make','-n',*args],cwd=ROOT,capture_output=True,text=True)
                self.assertNotEqual(result.returncode,0,args)

    def test_make_rejects_flag_mismatch(self):
        for args in [('NATIVE=1', 'DIAGNOSTIC_STAGE=4'), ('NATIVE=0', 'DIAGNOSTIC_STAGE=4', 'P256_DIAGNOSTIC=1'),
                     ('NATIVE=1', 'DIAGNOSTIC_STAGE=0', 'P256_DIAGNOSTIC=1'), ('P256_DIAGNOSTIC=2',)]:
            result = subprocess.run(['make', '-n', *args], cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, args)

    def test_pmf_probe_requires_explicit_normal_sae(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'Info.plist'
            for enabled in (False, True):
                module.prepare(True, output, native_sae_experimental=True, native_pmf_probe=enabled)
                entry = next(iter(plistlib.loads(output.read_bytes())['IOKitPersonalities'].values()))
                self.assertEqual(entry.get('Ath10kNativePMFStartupQuery', False), enabled)
            for native, stage, p256, sae in [(True,0,False,False),(False,0,False,False),(False,0,False,True),
                                             (True,1,False,True),(True,4,True,True)]:
                output.write_bytes(b'preserve')
                with self.assertRaises(ValueError):
                    module.prepare(native, output, stage, p256, sae, True)
                self.assertEqual(output.read_bytes(), b'preserve')
            for args in [('NATIVE_PMF_PROBE=1',),('NATIVE_PMF_PROBE=2',),
                         ('NATIVE=0','NATIVE_SAE_EXPERIMENTAL=1','NATIVE_PMF_PROBE=1'),
                         ('DIAGNOSTIC_STAGE=1','NATIVE_SAE_EXPERIMENTAL=1','NATIVE_PMF_PROBE=1')]:
                result=subprocess.run(['make','-n',*args],cwd=ROOT,capture_output=True,text=True)
                self.assertNotEqual(result.returncode,0,args)


if __name__ == '__main__':
    unittest.main()

import importlib.util
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("prepare", ROOT / "scripts/build/prepare-firmware.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def ie(tag, data):
    return struct.pack("<II", tag, len(data)) + data + b"x" * (-len(data) % 4)


def container(magic, data):
    return magic + b"m" * (-len(magic) % 4) + data


def board_entry(key, value):
    return ie(0, ie(0, key.encode()) + ie(1, value))


class PayloadTests(unittest.TestCase):
    def test_lunnen_board_is_exact_and_does_not_reuse_dell_calibration(self):
        import json
        folder = ROOT / 'firmware/QCA9377/hw1.0'
        files, header, entry = p.prepare_profile(
            ROOT, folder, 'Ath10kPayload9377Lunnen', p.LUNNEN_QCA9377_BOARD_KEY,
            'QCA9377/hw1.1-Lunnen-1a3b-2b51',
            ('0x0042', '0x1a3b', '0x2b51', '1', '0x05020001u'), True,
            'QCA9377-Lunnen', True, 'Ath10kPayload9377')
        manifest = json.loads(files[ROOT / 'firmware/prepared/QCA9377-Lunnen/manifest.json'])
        self.assertEqual(manifest['board_selection'], 'board-api2-exact')
        self.assertEqual(manifest['board_key'], p.LUNNEN_QCA9377_BOARD_KEY)
        self.assertEqual(manifest['board_sha256'],
                         'ba14e9b4d189bf213e144ad1936f16cbb2b5286f152d394c9d3f1750a723d991')
        self.assertNotEqual(files[ROOT / 'firmware/prepared/QCA9377-Lunnen/board.bin'],
                            p.select_board((folder / 'board-2.bin').read_bytes(), p.QCA9377_BOARD_KEY))
        self.assertIn('0x1a3b, 0x2b51', entry)
        generated = '\n'.join(header)
        self.assertIn('using Ath10kPayload9377::kFirmware;', generated)
        self.assertFalse(manifest['mfp_support_feature'])
        self.assertIn('using Ath10kPayload9377::kSupportsMFP;', generated)
        self.assertIn('Ath10kPayload9377Lunnen::kSupportsMFP', entry)
        self.assertNotIn('static constexpr UInt8 kFirmware[]', generated)

    def test_lunnen_missing_board_must_not_fall_back(self):
        import tempfile
        import shutil
        folder = ROOT / 'firmware/QCA9377/hw1.0'
        with tempfile.TemporaryDirectory() as temp:
            tmp = Path(temp)
            for name in ('firmware-6.bin', 'board.bin'):
                shutil.copyfile(folder / name, tmp / name)
            # A valid Dell board and a valid generic fallback are both present.
            # Neither is a substitute for the selected Lunnen subsystem.
            (tmp / 'board-2.bin').write_bytes(container(p.BOARD_MAGIC, board_entry(
                p.QCA9377_BOARD_KEY, b'a' * 8124)))
            with self.assertRaises(p.BoardNotFound):
                p.prepare_profile(ROOT, tmp, 'Lunnen', p.LUNNEN_QCA9377_BOARD_KEY,
                    'Lunnen', ('0x0042', '0x1a3b', '0x2b51', '1', '0x05020001u'),
                    True, 'QCA9377-Lunnen', True)

    def test_real_inputs(self):
        board = p.select_board((ROOT / "firmware/board-2.bin").read_bytes())
        self.assertEqual(len(board), 8124)
        parts, version = p.parse_firmware((ROOT / "firmware/firmware-6.bin").read_bytes())
        self.assertEqual(version, "WLAN.RM.4.4.1-00309-")
        self.assertEqual(len(parts[3]), 681821)
        self.assertEqual(len(parts[4]), 24429)
        self.assertTrue(p.ignore_otp_result(parts))
        self.assertFalse(p.supports_skip_clock_init(parts))
        segments, entry = p.parse_segments(parts[3])
        self.assertEqual(entry, 0xa0400)
        self.assertEqual(len(segments), 6)
        self.assertEqual(sum(s['length'] for s in segments), 681749)

    def test_qca9377_profile(self):
        folder = ROOT / 'firmware/QCA9377/hw1.0'
        selected = p.select_board((folder / 'board-2.bin').read_bytes(), p.QCA9377_BOARD_KEY)
        self.assertEqual(p.sha(selected), 'b2713b77c725b0ff81af75c85c3aeba97885d0f40174f715b1e39d5a9d50f4e7')
        files, header, entry = p.prepare_profile(ROOT, folder, 'Ath10kPayload9377',
            p.QCA9377_BOARD_KEY, 'QCA9377/hw1.1',
            ('0x0042', '0x1028', '0x1810', '1', '0x05020001u'), True)
        import json
        manifest = json.loads(files[ROOT / 'firmware/prepared/QCA9377/manifest.json'])
        self.assertEqual(manifest['board_selection'], 'board-api2-exact')
        self.assertEqual(manifest['firmware_version'], 'WLAN.TF.2.1-00021-QCARMSWP-1')
        self.assertEqual(manifest['otp_bytes'], 24193)
        self.assertEqual(manifest['firmware_bytes'], 727125)
        self.assertEqual(manifest['firmware_segment_data_bytes'], 727053)
        self.assertEqual(manifest['board_sha256'],
            'b2713b77c725b0ff81af75c85c3aeba97885d0f40174f715b1e39d5a9d50f4e7')

    def test_exact_board_rejects_corrupt_container_and_foreign_firmware(self):
        import json
        import tempfile
        import shutil
        folder = ROOT / 'firmware/QCA9377/hw1.0'
        with tempfile.TemporaryDirectory() as temp:
            tmp = Path(temp)
            for name in ('board-2.bin', 'board.bin', 'firmware-6.bin'):
                shutil.copyfile(folder / name, tmp / name)
            args = (ROOT, tmp, 'Ath10kPayload9377', p.QCA9377_BOARD_KEY, 'QCA9377/hw1.1',
                ('0x0042', '0x1028', '0x1810', '1', '0x05020001u'), True)
            bad = [b'corrupt', container(p.BOARD_MAGIC, board_entry(p.QCA9377_BOARD_KEY,b'a'*8124)*2),
                   container(p.BOARD_MAGIC,board_entry(p.QCA9377_BOARD_KEY,b'a'*8000))]
            for data in bad:
                (tmp/'board-2.bin').write_bytes(data)
                with self.assertRaises(ValueError): p.prepare_profile(*args)
            foreign = container(p.BOARD_MAGIC, board_entry(
                'bus=pci,vendor=168c,device=0042,subsystem-vendor=17aa,subsystem-device=0901',b'a'*8124))
            (tmp/'board-2.bin').write_bytes(foreign)
            self.assertEqual(json.loads(p.prepare_profile(*args)[0][ROOT / 'firmware/prepared/QCA9377/manifest.json'])
                             ['board_selection'], 'board-api1-fallback')
            shutil.copyfile(folder/'board-2.bin',tmp/'board-2.bin')
            (tmp/'board.bin').write_bytes((ROOT/'firmware/prepared/board.bin').read_bytes())
            p.prepare_profile(*args)  # exact API2 match must not consume the fallback board
            shutil.copyfile(folder/'board.bin',tmp/'board.bin')
            shutil.copyfile(ROOT/'firmware/firmware-6.bin',tmp/'firmware-6.bin')
            with self.assertRaises(ValueError): p.prepare_profile(*args)

    def test_segmented_image_validation(self):
        header = struct.pack('<II', 0x544d4753, 0)
        segment = struct.pack('<II', 0x500000, 5) + b'abcde'
        entry = struct.pack('<II', 0x500000, 0xfffffffd)
        done = struct.pack('<II', 0, 0xffffffff)
        self.assertEqual(p.parse_segments(header + segment + entry + done)[0][0]['length'], 5)
        invalid = [b'', header + segment, header + segment + done,
                   header + segment + entry + done + b'x',
                   header + segment + entry + entry + done,
                   header + struct.pack('<II', 0x500000, 0xfffffffc),
                   header + struct.pack('<II', 0x500000, 1000) + b'abc',
                   header + segment + segment + entry + done,
                   header + struct.pack('<II', 0xfffffffc, 5) + b'abcde' + entry + done,
                   header + struct.pack('<II', 0x400800, 5) + b'abcde' + entry + done,
                   header + segment + struct.pack('<II', 0x600000, 0xfffffffd) + done]
        for data in invalid:
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                p.parse_segments(data)

    def test_otp_feature_bit(self):
        self.assertFalse(p.ignore_otp_result({}))
        self.assertFalse(p.ignore_otp_result({2: b""}))
        self.assertFalse(p.ignore_otp_result({2: b"\x40\x80"}))
        self.assertTrue(p.ignore_otp_result({2: b"\x80"}))

    def test_mfp_feature_is_exact_firmware_ie_bit_12(self):
        self.assertFalse(p.supports_mfp({}))
        for bit in range(24):
            features = (1 << bit).to_bytes(3, 'little')
            self.assertEqual(p.supports_mfp({2: features}), bit == 12)
        for value in (b"", b"\x10", b"\xc0", b"\xc0\x02"):
            self.assertFalse(p.supports_mfp({2: value}))
        self.assertTrue(p.supports_mfp({2: b"\xc0\x10"}))

    def test_skip_clock_feature_bit(self):
        for value in (b"", b"\x02", b"\xc0\x10"):
            self.assertFalse(p.supports_skip_clock_init({2: value}))
        self.assertFalse(p.supports_skip_clock_init({}))
        self.assertTrue(p.supports_skip_clock_init({2: b"\xc0\x12"}))

    def test_exact_not_prefix_match(self):
        data = container(p.BOARD_MAGIC,
            board_entry(p.BOARD_KEY + ",variant=other", b"b" * 8124) +
            board_entry(p.BOARD_KEY, b"a" * 8124))
        self.assertEqual(p.select_board(data), b"a" * 8124)

    def test_missing_duplicate_wrong_size(self):
        entries = [board_entry("other", b"a" * 8124),
                   board_entry(p.BOARD_KEY, b"a" * 8124) * 2,
                   board_entry(p.BOARD_KEY, b"a" * 8123)]
        for entry in entries:
            with self.subTest(size=len(entry)), self.assertRaises(ValueError):
                p.select_board(container(p.BOARD_MAGIC, entry))

    def test_truncated_and_hostile_lengths(self):
        for data in (b"", p.BOARD_MAGIC, container(p.BOARD_MAGIC, b"a"),
                     container(p.BOARD_MAGIC, struct.pack("<II", 0, 0xffffffff)),
                     container(p.BOARD_MAGIC, ie(0, struct.pack("<II", 1, 8000)))):
            with self.subTest(data=data[:25]), self.assertRaises(ValueError):
                p.select_board(data)

    def test_firmware_rejects_missing_duplicate_codeswap_wrong_ops(self):
        good = ie(0, b"version") + ie(3, b"firmware") + ie(4, b"otp") + ie(5, struct.pack("<I", 4)) + ie(6, struct.pack("<I", 3))
        for body in (good + ie(3, b"second"), good + ie(7, b"swap"),
                     ie(0, b"version"), good.replace(struct.pack("<I", 4), struct.pack("<I", 9))):
            with self.subTest(size=len(body)), self.assertRaises(ValueError):
                p.parse_firmware(container(p.FW_MAGIC, body))


if __name__ == "__main__":
    unittest.main()

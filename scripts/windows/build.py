#!/usr/bin/env python3
"""Build a complete Sequoia native kext on Windows with Zig and Apple ld64."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for tool in ['zig', 'ld64', 'cygwin-bin', 'codesign']:
        p.add_argument('--' + tool, type=Path, required=True)
    p.add_argument('--diagnostic-stage', type=int, choices=range(4), default=0)
    p.add_argument('--kernel-collection', type=Path)
    p.add_argument('--output', type=Path, default=ROOT / 'build/windows-native')
    args = p.parse_args()
    out = args.output.resolve()
    if not out.is_relative_to((ROOT / 'build').resolve()):
        p.error('--output must be inside this checkout\'s build directory')
    bundle = out / 'Ath10kMac.kext'
    if bundle.exists():
        p.error('bundle exists; choose a new --output under build/')
    for tool in [args.zig, args.ld64, args.codesign, args.cygwin_bin / 'cygwin1.dll']:
        if not tool.is_file():
            p.error(f'missing tool: {tool}')
    objects, logs = out / 'objects', out / 'logs'
    objects.mkdir(parents=True, exist_ok=True)
    logs.mkdir(exist_ok=True)
    env = os.environ.copy()
    env['PATH'] = str(args.cygwin_bin.resolve()) + os.pathsep + env.get('PATH', '')
    commands = []

    def run(name, command):
        command = [str(x) for x in command]
        r = subprocess.run(command, cwd=ROOT, env=env, capture_output=True)
        (logs / (name + '.log')).write_bytes(r.stdout + r.stderr)
        commands.append({'step': name, 'command': command, 'exit': r.returncode})
        if r.returncode:
            raise RuntimeError(f'{name} failed; see {logs / (name + ".log")}')
        print('PASS', name, flush=True)

    run('prepare-firmware', [sys.executable, ROOT / 'scripts/prepare-firmware.py'])
    flags = ['-target', 'x86_64-macos.11.0', '-O2', '-fstack-usage',
             '-Wframe-larger-than=4096', '-Werror=frame-larger-than', '-mkernel',
             '-fno-stack-check', '-fno-stack-protector', '-DKERNEL', '-DATH10K_NATIVE=1',
             '-I' + str(ROOT / 'MacKernelSDK/Headers'), '-I' + str(ROOT / 'vendor/itlwm'),
             '-Wno-deprecated-declarations', '-Wno-nullability-completeness',
             '-Wno-invalid-offsetof', '-mllvm', '-disable-atexit-based-global-dtor-lowering']
    defines = {'PAYLOAD_CACHE': 1, 'RUNTIME_IRQ': 1, 'RX_BATCH': 1, 'RX_RESERVE': 1,
               'MAX_WIDTH': 80, 'MAX_NSS': 2, 'AMPDU_LIMIT': 64, 'AMSDU_LIMIT': 3,
               'HT_VHT': 1, 'DATA_TX_SLOTS': 64}
    flags += [f'-DATH10K_{k}={v}' for k, v in defines.items()]
    sources = ['native/Ath10kNative.cpp', 'Ath10kUserClient.cpp', 'Ath10kNetwork.cpp',
               'Ath10kRuntime.cpp', 'Ath10kPower.cpp', 'Ath10kRecovery.cpp', 'Ath10kPCIDevice.cpp', 'kmod_info.c']

    def compile_source(name):
        source = ROOT / 'src/kext' / name
        command = [args.zig.resolve(), 'cc' if source.suffix == '.c' else 'c++', *flags]
        if source.suffix != '.c':
            command += ['-fapple-kext', '-fno-exceptions', '-fno-rtti', '-std=c++17']
        run(source.stem, command + ['-c', source, '-o', objects / (source.stem + '.o')])

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(compile_source, sources))
    binary = bundle / 'Contents/MacOS/Ath10kMac'
    binary.parent.mkdir(parents=True)
    run('prepare-info', [sys.executable, ROOT / 'scripts/prepare-kext-info.py', '1',
                         bundle / 'Contents/Info.plist', '--diagnostic-stage', str(args.diagnostic_stage)])

    def cyg(path):
        path = Path(path).resolve()
        return '/cygdrive/' + path.drive[0].lower() + path.as_posix()[2:]

    inputs = [ROOT / 'MacKernelSDK/Library/x86_64/libkmod.a',
              ROOT / 'MacKernelSDK/Library/universal/libkmodc++.a',
              *[objects / (Path(s).stem + '.o') for s in sources]]
    run('link', [args.ld64.resolve(), '-arch', 'x86_64', '-static', '-kext',
                 '-macosx_version_min', '11.0', '-o', cyg(binary), *map(cyg, inputs)])
    run('sign', [args.codesign.resolve(), 'sign', bundle])
    verify = [sys.executable, ROOT / 'scripts/windows/validate.py', bundle]
    if args.kernel_collection:
        verify += ['--kernel-collection', args.kernel_collection.resolve()]
    run('validate', verify)
    (out / 'commands.json').write_text(json.dumps(commands, indent=2))
    manifest = {str(f.relative_to(bundle)): hashlib.sha256(f.read_bytes()).hexdigest()
                for f in bundle.rglob('*') if f.is_file()}
    (out / 'SHA256.json').write_text(json.dumps(manifest, indent=2))
    print('Built:', bundle)
    print('Offline checks passed; no EFI changes, installation, or reboot performed.')


if __name__ == '__main__':
    main()

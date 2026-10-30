#!/usr/bin/env python3
"""Materialize pinned upstream ABI headers plus reviewed local overrides."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]

def main():
    recipe = json.loads((ROOT / 'scripts/build/native-headers.json').read_text())
    upstream = ROOT / 'vendor/itlwm-upstream'
    if not (upstream / '.git').exists():
        raise SystemExit('Missing itlwm submodule. Run git submodule update --init --recursive.')
    head = subprocess.check_output(['git', '-C', str(upstream), 'rev-parse', 'HEAD'], text=True).strip()
    if head != recipe['commit']:
        raise SystemExit('Unexpected itlwm revision; initialize the pinned submodule.')
    output = ROOT / 'build/generated/itlwm'
    for name, item in recipe['files'].items():
        source = (ROOT / 'src/macos/abi/overrides/itlwm' / name
                  if name in recipe['overrides'] else upstream / item['upstream'])
        data = source.read_bytes()
        if hashlib.sha256(data).hexdigest() != item['sha256']:
            raise SystemExit('Native header differs from reviewed manifest: ' + name)
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists() or destination.read_bytes() != data:
            destination.write_bytes(data)
    print('Native headers verified:', len(recipe['files']), 'files;', len(recipe['overrides']), 'local overrides')

if __name__ == '__main__':
    main()

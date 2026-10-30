#!/usr/bin/env python3
"""Verify that a linked fileset includes the exact candidate Mach-O UUID.

A successful kmutil exit alone does not establish inclusion or KPI availability.
This verifier reads files; it never loads drivers or modifies kernel collections.
"""
import argparse
import json
import mmap
from pathlib import Path
import struct
import sys
import uuid


def commands(data, offset=0):
    if offset < 0 or offset + 32 > len(data):
        raise ValueError('truncated Mach-O header')
    magic, = struct.unpack_from('<I', data, offset)
    if magic != 0xfeedfacf:
        raise ValueError('expected little-endian 64-bit Mach-O')
    count, size = struct.unpack_from('<II', data, offset + 16)
    pos, end = offset + 32, offset + 32 + size
    if end > len(data) or count > size // 8:
        raise ValueError('invalid load-command extent')
    for _ in range(count):
        if pos + 8 > end:
            raise ValueError('truncated load command')
        command, length = struct.unpack_from('<II', data, pos)
        if length < 8 or length % 4 or pos + length > end:
            raise ValueError('invalid load-command length')
        yield command, pos, length
        pos += length
    if pos != end:
        raise ValueError('load-command size mismatch')


def image_uuid(data, offset=0):
    values = []
    for command, pos, length in commands(data, offset):
        if command == 0x1b:
            if length != 24:
                raise ValueError('invalid UUID command')
            values.append(str(uuid.UUID(bytes=bytes(data[pos + 8:pos + 24]))).upper())
    if len(values) != 1:
        raise ValueError('image must have exactly one UUID')
    return values[0]


def verify(collection, candidate, bundle_id):
    expected = image_uuid(candidate)
    matches = []
    entries = []
    for command, pos, length in commands(collection):
        if command != 0x80000035:
            continue
        if length < 32:
            raise ValueError('truncated fileset entry')
        file_offset, name_offset = struct.unpack_from('<QI', collection, pos + 16)
        if not 32 <= name_offset < length:
            raise ValueError('invalid fileset identifier offset')
        raw = bytes(collection[pos + name_offset:pos + length])
        if b'\0' not in raw:
            raise ValueError('unterminated fileset identifier')
        name = raw.split(b'\0', 1)[0].decode('utf-8')
        entries.append(name)
        if name == bundle_id:
            matches.append(image_uuid(collection, file_offset))
    if len(matches) != 1:
        raise ValueError(f'expected exactly one {bundle_id} entry, found {len(matches)}')
    if matches[0] != expected:
        raise ValueError(f'candidate UUID mismatch: expected {expected}, found {matches[0]}')
    return {'bundle_id': bundle_id, 'candidate_uuid': expected,
            'collection_uuid': matches[0], 'included': True, 'fileset_entries': entries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('candidate', type=Path, help='kext executable, not bundle directory')
    parser.add_argument('--bundle-id', default='br.com.jonasw8.driver.ath10kmac')
    args = parser.parse_args()
    try:
        with args.collection.open('rb') as kc, args.candidate.open('rb') as binary:
            with mmap.mmap(kc.fileno(), 0, access=mmap.ACCESS_READ) as data:
                result = verify(data, binary.read(), args.bundle_id)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, struct.error, UnicodeError) as error:
        print(f'Kernel collection inclusion FAILED: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

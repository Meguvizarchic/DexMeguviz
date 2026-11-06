"""Independent shared and unreferenced encoded-array metadata checks.

The fixed input is project-original. New output files are never overwritten.
Structural acceptance is not an ART, runtime, or complete DEX verification claim.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import subprocess
import zlib
import time

BASE_SHA = 'e1059582b6c893690880403d00f6b5be8dfceb7be282793e2117bdf15b14e77a'
CLASS_TABLE = 252
FIELD_TABLE = 212
BASE_CLASS = CLASS_TABLE + 3 * 32
CHILD_CLASS = CLASS_TABLE + 4 * 32
CHILD_DATA = 615
ARRAY = 625
MAP = 644


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checksum(data):
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into('<I', data, 8, zlib.adler32(data[12:]) & 0xffffffff)


def u32(data, at):
    return struct.unpack_from('<I', data, at)[0]


def set_array_count(data, count):
    map_offset = u32(data, 52)
    for i in range(u32(data, map_offset)):
        item = map_offset + 4 + i * 12
        if struct.unpack_from('<H', data, item)[0] == 0x2005:
            struct.pack_into('<I', data, item + 4, count)
            return
    raise ValueError('encoded_array map item absent')


def shared_long(base, version):
    data = bytearray(base)
    data[4:7] = version.encode('ascii')
    # Base.shared is a static J field. Convert Child.shared I from instance to
    # static J without changing item lengths: the two declarations then admit
    # the same one-element VALUE_LONG encoded_array, not merely an empty array.
    struct.pack_into('<H', data, FIELD_TABLE + 2 * 8 + 2, 1)  # type_id J
    data[CHILD_DATA:CHILD_DATA + 4] = b'\x01\x00\x00\x01'
    data[CHILD_DATA + 5] = 0x09  # public static
    data[ARRAY:ARRAY + 3] = b'\x01\x06\x00'  # one VALUE_LONG zero
    struct.pack_into('<I', data, CHILD_CLASS + 28, ARRAY)
    return data


def arrays(base, child_offset, referenced=True, malformed=False):
    data = bytearray(base)
    # Empty shared first item plus an independent empty unreferenced second item.
    # bytes[627] is alignment padding before the following 4-byte-aligned item.
    data[ARRAY:ARRAY + 3] = b'\x00\x01\x00' if malformed else b'\x00\x00\x00'
    set_array_count(data, 2)
    struct.pack_into('<I', data, BASE_CLASS + 28, ARRAY if referenced else 0)
    struct.pack_into('<I', data, CHILD_CLASS + 28, child_offset if referenced else 0)
    return data


def ensure_fixture_structure(data):
    assert len(data) == 804 and sha(data) == BASE_SHA and data[:8] == b'dex\n035\0'
    assert u32(data, 52) == MAP and u32(data, 96) == 5 and u32(data, 100) == CLASS_TABLE
    assert u32(data, BASE_CLASS) == 2 and u32(data, CHILD_CLASS) == 3
    assert u32(data, BASE_CLASS + 24) == 607 and u32(data, CHILD_CLASS + 24) == CHILD_DATA
    assert u32(data, BASE_CLASS + 28) == ARRAY and u32(data, CHILD_CLASS + 28) == 0
    assert struct.unpack_from('<HHI', data, FIELD_TABLE + 8) == (2, 1, 12)
    assert struct.unpack_from('<HHI', data, FIELD_TABLE + 16) == (3, 0, 12)
    assert data[607:625] == bytes.fromhex('01 01 00 00 01 09 00 01 00 01 00 01 02 01 00 81 08 00')
    assert data[ARRAY:ARRAY + 3] == b'\x00\x00\x00'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--exe', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--root', type=Path)
    args = parser.parse_args()
    if args.output is None:
        if args.root is None: parser.error('one of --output or --root is required')
        args.output = args.root / 'docs/evidence/shared-static' / ('run-' + str(time.time_ns()))
    base = args.fixture.read_bytes()
    ensure_fixture_structure(base)
    exe_hash = sha(args.exe.read_bytes())
    cases = []

    def add(name, state, data, expected_error=None, offsets=None):
        checksum(data)
        assert data[12:32] == hashlib.sha1(data[32:]).digest()
        assert u32(data, 8) == zlib.adler32(data[12:]) & 0xffffffff
        if offsets is not None:
            assert (u32(data, BASE_CLASS + 28), u32(data, CHILD_CLASS + 28)) == offsets
        cases.append((name, state, data, expected_error, offsets))

    for version in ['035', '038']:
        data = shared_long(base, version)
        assert data[ARRAY:ARRAY+3] == b'\x01\x06\x00'
        assert struct.unpack_from('<HHI', data, FIELD_TABLE + 8) == (2, 1, 12)
        assert struct.unpack_from('<HHI', data, FIELD_TABLE + 16) == (3, 1, 12)
        assert data[CHILD_DATA:CHILD_DATA+6] == b'\x01\x00\x00\x01\x02\x09'
        add('shared-long-' + version, 'Complete', data, offsets=(ARRAY, ARRAY))
        for name, at in [('base', BASE_CLASS), ('child', CHILD_CLASS)]:
            invalid = bytearray(data)
            struct.pack_into('<I', invalid, at + 28, ARRAY + 1)
            pointers = (ARRAY + 1, ARRAY) if name == 'base' else (ARRAY, ARRAY + 1)
            add(name + '-interior-' + version, 'CorruptInput', invalid,
                'offset does not reference an encoded array item start', pointers)

    add('two-classes-share-empty-with-unreferenced', 'Complete', arrays(base, ARRAY), offsets=(ARRAY, ARRAY))
    add('two-classes-distinct-empty', 'Complete', arrays(base, ARRAY + 1), offsets=(ARRAY, ARRAY + 1))
    add('both-arrays-unreferenced', 'Complete', arrays(base, 0, referenced=False), offsets=(0, 0))
    add('malformed-unreferenced-after-shared', 'CorruptInput', arrays(base, ARRAY, malformed=True),
        'range exceeds the containing section', (ARRAY, ARRAY))
    add('malformed-both-unreferenced', 'CorruptInput', arrays(base, 0, referenced=False, malformed=True),
        'range exceeds the containing section', (0, 0))

    args.output.mkdir(parents=True, exist_ok=False)
    records = []
    for name, expected, data, expected_error, offsets in cases:
        path = args.output / (name + '.dex')
        with path.open('xb') as stream:
            stream.write(data)
        proc = subprocess.run([str(args.exe), 'inspect', str(path), '--json'], capture_output=True, timeout=60)
        stdout = proc.stdout.decode('utf-8', 'replace')
        stderr = proc.stderr.decode('utf-8', 'replace')
        try:
            output = json.loads(stdout)
            actual = output.get('execution_status')
        except (ValueError, AttributeError):
            output = None
            actual = stderr.split(':', 1)[0]
        exit_expected = {'Complete': 0, 'CorruptInput': 2}[expected]
        valid = actual == expected and proc.returncode == exit_expected
        if expected_error:
            valid = valid and expected_error in stderr
        if expected == 'Complete':
            valid = valid and output['source_count'] == 1 and output['counts']['classes'] == 5
        records.append({'name': name, 'expected_status': expected, 'actual_status': actual,
                        'expected_exit': exit_expected, 'actual_exit': proc.returncode,
                        'sha256': sha(data), 'base_child_array_offsets': offsets,
                        'valid': valid, 'stderr': stderr[:1000]})
    after = sha(args.exe.read_bytes())
    failures = [x['name'] for x in records if not x['valid']]
    if exe_hash != after:
        failures.append('executable-changed')
    summary = {'scope': 'original DEX structural metadata; no ART/runtime/bootstrap or static-value field-type verifier claim',
               'baseline_fixture_sha256': BASE_SHA, 'exe_sha256_before': exe_hash, 'exe_sha256_after': after,
               'passed': len(cases) - sum(not x['valid'] for x in records), 'failed': len(failures),
               'failures': failures, 'cases': records}
    (args.output / 'results.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'cases': len(cases), 'passed': summary['passed'], 'failed': len(failures), 'failures': failures}))
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())

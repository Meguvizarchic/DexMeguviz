"""038 call-site/handle structure cases; no ART or bootstrap execution claim.

Run with --exe <dexmeguviz> --fixture <invoke-domains-038.dex> --output <new-dir>.
Input is pinned; every output is freshly created and its DEX checksums recomputed.
"""
import argparse
import hashlib
import json
import struct
import subprocess
import zlib
import time
from pathlib import Path

ORIGINAL_SHA = 'ecf85d163c87d58f065335f0d932442be48b91b5efa3858e319a1c1cdf7313b0'
CALL, HANDLE, ARRAY, MAP = 472, 476, 484, 492
BASE_ARRAY = bytes.fromhex('03 16 00 17 0b 15 00')


def checksum(data):
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into('<I', data, 8, zlib.adler32(data[12:]) & 0xffffffff)


def with_array(original, payload):
    # Replace the whole encoded_array section and keep map_list aligned.
    padding = bytes((-len(payload)) % 4)
    data = bytearray(original[:ARRAY] + payload + padding + original[MAP:])
    new_map = ARRAY + len(payload) + len(padding)
    struct.pack_into('<I', data, 32, len(data))
    struct.pack_into('<I', data, 52, new_map)
    struct.pack_into('<I', data, 104, len(data) - struct.unpack_from('<I', data, 108)[0])
    for i in range(struct.unpack_from('<I', data, new_map)[0]):
        at = new_map + 4 + 12 * i
        if struct.unpack_from('<H', data, at)[0] == 0x1000:
            struct.pack_into('<I', data, at + 8, new_map)
            break
    else:
        raise ValueError('map_list missing')
    return data


def with_empty_static_values(original, inside=False):
    # A second encoded_array_item contains zero static values for the one field.
    data = with_array(original, BASE_ARRAY + b'\x00')
    struct.pack_into('<I', data, 236 + 28, ARRAY + 1 if inside else ARRAY + 7)
    new_map = struct.unpack_from('<I', data, 52)[0]
    for i in range(struct.unpack_from('<I', data, new_map)[0]):
        at = new_map + 4 + i * 12
        if struct.unpack_from('<H', data, at)[0] == 0x2005:
            struct.pack_into('<I', data, at + 4, 2)
            return data
    raise ValueError('encoded_array map missing')


def two_calls(original, descending=False):
    # Two call_site_ids precede one handle. Array item starts are 488 and 495.
    arrays = BASE_ARRAY + (BASE_ARRAY if descending else b'')
    pad = bytes((-len(arrays)) % 4)
    array_at = ARRAY + 4
    pointers = (array_at + len(BASE_ARRAY), array_at) if descending else (array_at, array_at)
    data = bytearray(original[:CALL] + struct.pack('<II', *pointers) + original[HANDLE:ARRAY] + arrays + pad + original[MAP:])
    new_map = array_at + len(arrays) + len(pad)
    struct.pack_into('<I', data, 32, len(data))
    struct.pack_into('<I', data, 52, new_map)
    struct.pack_into('<I', data, 104, len(data) - struct.unpack_from('<I', data, 108)[0])
    changes = {7: (2, CALL), 8: (1, HANDLE + 4), 0x2005: (2 if descending else 1, array_at), 0x1000: (1, new_map)}
    for i in range(struct.unpack_from('<I', data, new_map)[0]):
        at = new_map + 4 + 12 * i
        kind = struct.unpack_from('<H', data, at)[0]
        if kind in changes:
            struct.pack_into('<II', data, at + 4, *changes[kind])
    return data


def run():
    ap = argparse.ArgumentParser()
    ap.add_argument('--exe', type=Path, required=True)
    ap.add_argument('--fixture', type=Path, required=True)
    ap.add_argument('--output', type=Path)
    ap.add_argument('--root', type=Path)
    args = ap.parse_args()
    if args.output is None:
        if args.root is None: ap.error('one of --output or --root is required')
        args.output = args.root / 'docs/evidence/dex038-metadata' / ('run-' + str(time.time_ns()))
    original = args.fixture.read_bytes()
    if hashlib.sha256(original).hexdigest() != ORIGINAL_SHA:
        raise SystemExit('Unexpected input fixture SHA-256')
    if len(original) != 664 or original[ARRAY:ARRAY + 7] != BASE_ARRAY:
        raise SystemExit('Unexpected fixed fixture layout')
    args.output.mkdir(parents=True, exist_ok=False)
    cases = []

    def add(name, valid, data):
        checksum(data)
        cases.append((name, valid, data))

    add('baseline', True, bytearray(original))
    add('duplicate-call-offset', True, two_calls(original))
    add('descending-call-offset', False, two_calls(original, descending=True))
    data = bytearray(original)
    struct.pack_into('<H', data, HANDLE + 2, 0x1234)
    struct.pack_into('<H', data, HANDLE + 6, 0xabcd)
    add('nonzero-unused-fields', True, data)
    add('empty-static-values', True, with_empty_static_values(original))
    add('static-values-inside-other-array', False, with_empty_static_values(original, inside=True))
    for kind in range(9):
        data = bytearray(original)
        struct.pack_into('<H', data, HANDLE, kind)
        struct.pack_into('<H', data, HANDLE + 4, 0 if kind < 4 else 4)
        add('handle-kind-' + str(kind), True, data)
    for name, kind, index in [('field-index-1', 0, 1), ('method-index-5', 4, 5), ('handle-kind-9', 9, 0)]:
        data = bytearray(original)
        struct.pack_into('<H', data, HANDLE, kind)
        struct.pack_into('<H', data, HANDLE + 4, index)
        add(name, False, data)
    for name, pointer in [('zero', 0), ('interior', ARRAY + 1), ('end', ARRAY + 7), ('map', MAP), ('beyond-file', len(original))]:
        data = bytearray(original)
        struct.pack_into('<I', data, CALL, pointer)
        add('call-offset-' + name, False, data)
    for name, payload in [
        ('call-zero-args', b'\x00'),
        ('call-two-args', bytes.fromhex('02 16 00 17 0b')),
        ('first-type-string', bytes.fromhex('03 17 00 17 0b 15 00')),
        ('second-type-handle', bytes.fromhex('03 16 00 16 00 15 00')),
        ('third-type-string', bytes.fromhex('03 16 00 17 0b 17 00')),
        ('handle-index-1', bytes.fromhex('03 16 01 17 0b 15 00')),
        ('string-index-12', bytes.fromhex('03 16 00 17 0c 15 00')),
        ('proto-index-1', bytes.fromhex('03 16 00 17 0b 15 01')),
        ('truncated-uleb', b'\x80\x80\x80\x80'),
        ('truncated-value', bytes.fromhex('03 16 00 17 0b 75 00')),
        ('length-127', bytes.fromhex('7f 16 00 17 0b 15 00')),
        ('nested-array-truncated', bytes.fromhex('04 16 00 17 0b 15 00 1c 02 04 01 75')),
        ('annotation-names-descending', bytes.fromhex('04 16 00 17 0b 15 00 1d 01 02 03 17 00 00 17 01')),
        ('annotation-names-duplicate', bytes.fromhex('04 16 00 17 0b 15 00 1d 01 02 00 17 00 00 17 01')),
        ('annotation-name-invalid', bytes.fromhex('04 16 00 17 0b 15 00 1d 01 01 01 17 00')),
        ('annotation-name-index-12', bytes.fromhex('04 16 00 17 0b 15 00 1d 01 01 0c 17 00')),
        ('annotation-type-index-4', bytes.fromhex('04 16 00 17 0b 15 00 1d 04 01 00 17 00')),
        ('annotation-type-nonclass', bytes.fromhex('04 16 00 17 0b 15 00 1d 00 01 00 17 00')),
        ('annotation-string-index-12', bytes.fromhex('04 16 00 17 0b 15 00 1d 01 01 00 17 0c')),
    ]:
        add(name, False, with_array(original, payload))
    # Extra arguments can contain nested encoded arrays and null values.
    add('nested-array', True, with_array(original, bytes.fromhex('04 16 00 17 0b 15 00 1c 02 04 01 1e')))
    add('nested-annotation', True, with_array(original, bytes.fromhex('04 16 00 17 0b 15 00 1d 01 02 00 17 00 03 17 01')))
    add('extra-method-handle', True, with_array(original, bytes.fromhex('04 16 00 17 0b 15 00 16 00')))
    add('extra-method-handle-out-of-range', False, with_array(original, bytes.fromhex('04 16 00 17 0b 15 00 16 01')))
    # These are this reader's resource limits, not DEX format limits.
    prefix = bytes.fromhex('04 16 00 17 0b 15 00')
    add('implementation-depth-1023', True, with_array(original, prefix + bytes.fromhex('1c 01') * 1023 + b'\x1e'))
    add('implementation-depth-over-budget', 'BudgetExceeded', with_array(original, prefix + bytes.fromhex('1c 01') * 1025 + b'\x1e'))
    records = []
    for name, expected, data in cases:
        path = args.output / (name + '.dex')
        with path.open('xb') as stream:
            stream.write(data)
        result = subprocess.run([str(args.exe), 'inspect', str(path), '--json'], capture_output=True, timeout=30)
        stdout = result.stdout.decode('utf-8', 'replace')
        stderr = result.stderr.decode('utf-8', 'replace')
        try:
            status = json.loads(stdout).get('execution_status')
        except (ValueError, AttributeError):
            status = None
        if status is None and ':' in stderr:
            status = stderr.split(':', 1)[0].strip()
        expected_status = 'Complete' if expected is True else 'CorruptInput' if expected is False else expected
        expected_exit = {'Complete': 0, 'CorruptInput': 2, 'BudgetExceeded': 3}[expected_status]
        records.append({'name': name, 'expected_status': expected_status, 'actual_status': status,
                        'expected_exit': expected_exit, 'actual_exit': result.returncode,
                        'sha256': hashlib.sha256(data).hexdigest(),
                        'stderr': stderr[:1000]})
    failed = [r for r in records if r['actual_exit'] != r['expected_exit'] or r['actual_status'] != r['expected_status']]
    with (args.output / 'results.json').open('x', encoding='utf-8') as stream:
        json.dump({'scope': 'structural samples only; no ART/bootstrap execution', 'cases': records,
                   'failed': len(failed)}, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'cases': len(records), 'failed': len(failed), 'failed_cases': [r['name'] for r in failed]}))
    return bool(failed)


if __name__ == '__main__':
    raise SystemExit(run())

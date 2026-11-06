"""Authored DEX debug-info structure cases, separate from runtime/debugger semantics."""
import argparse
import hashlib
import json
import struct
import subprocess
import time
import zlib
from pathlib import Path

SHA = 'ea6e44ec68dfbb6c68a88171c5c64b77dca38b73bfdf0cc1b820d4d1e5ccb062'
DEBUG = 500
QUIET_CODE = 408
USES_CODE = 428
STREAM = bytes.fromhex('0a 00 01 01 02 7f 03 00 06 03 04 00 06 03 06 05 00 06 00 07 08 09 06 0a 00')


def build(original, payload=STREAM, count=1, gap=b''):
    data = bytearray(original[:DEBUG])
    data.extend(payload + gap)
    data.extend(bytes(-len(data) % 4))
    map_at = len(data)
    entries = []
    for i in range(struct.unpack_from('<I', original, DEBUG)[0]):
        kind, unused, size, offset = struct.unpack_from('<HHII', original, DEBUG + 4 + i * 12)
        if kind == 0x1000:
            offset = map_at
        entries.append((kind, unused, size, offset))
    entries.append((0x2003, 0, count, DEBUG))
    data.extend(struct.pack('<I', len(entries)))
    for item in sorted(entries, key=lambda value: value[3]):
        data.extend(struct.pack('<HHII', *item))
    struct.pack_into('<I', data, QUIET_CODE + 8, DEBUG)
    struct.pack_into('<I', data, 32, len(data))
    struct.pack_into('<I', data, 52, map_at)
    struct.pack_into('<I', data, 104, len(data) - struct.unpack_from('<I', data, 108)[0])
    return data


def checksum(data):
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into('<I', data, 8, zlib.adler32(data[12:]) & 0xffffffff)


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument('--exe', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    original = args.fixture.read_bytes()
    if hashlib.sha256(original).hexdigest() != SHA:
        raise SystemExit('Unexpected Q03 fixture')
    cases = []

    def add(name, valid, payload=STREAM, count=1, gap=b''):
        cases.append((name, valid, build(original, payload, count, gap)))

    add('all-supported-opcodes', True)
    add('extra-zero-section-gap', True, gap=bytes(9))
    add('nonzero-section-gap', False, gap=bytes.fromhex('00 01 00'))
    add('unknown-optional-references', True, bytes.fromhex('01 00 03 00 00 00 04 00 00 00 00 09 00 00'))
    add('nonminimal-unsigned-leb', True, bytes.fromhex('81 00 00 01 81 00 00'))
    add('parameter-name-out-of-range', False, bytes.fromhex('01 01 0d 00'))
    add('local-name-out-of-range', False, bytes.fromhex('01 00 03 00 0d 00 00'))
    add('local-type-out-of-range', False, bytes.fromhex('01 00 03 00 00 06 00'))
    add('signature-out-of-range', False, bytes.fromhex('01 00 04 00 00 00 0d 00'))
    add('filename-out-of-range', False, bytes.fromhex('01 00 09 0d 00'))
    add('register-over-16-bit', False, bytes.fromhex('01 00 05 80 80 04 00'))
    add('unterminated-sequence', False, bytes.fromhex('01 00 07 07'))
    add('truncated-operand', False, bytes.fromhex('01 00 07 01'))
    add('signed-leb-overflow', False, bytes.fromhex('01 00 02 80 80 80 80 08 00'))
    add('unsigned-leb-overflow', False, bytes.fromhex('80 80 80 80 10 00'))
    add('parameters-over-limit', False, bytes.fromhex('01 81 80 04 00'))
    add('debug-op-budget', 'BudgetExceeded', bytes.fromhex('01 00') + bytes([7]) * 1_000_000 + bytes([0]))
    second = bytes.fromhex('01 00 00')
    add('two-items', True, STREAM + second, count=2)
    data = build(original, STREAM + second, count=2)
    struct.pack_into('<I', data, USES_CODE + 8, DEBUG + len(STREAM))
    cases.append(('second-item-reference', True, data))
    data = build(original)
    struct.pack_into('<I', data, USES_CODE + 8, DEBUG)
    cases.append(('shared-debug-start', True, data))
    data = build(original)
    struct.pack_into('<I', data, QUIET_CODE + 8, DEBUG + 1)
    cases.append(('interior-debug-offset', False, data))
    data = build(original)
    struct.pack_into('<I', data, QUIET_CODE + 8, 0)
    cases.append(('orphan-structural-item', True, data))

    output = args.root / 'docs/evidence/debug-info-structure' / ('run-' + str(time.time_ns()))
    output.mkdir(parents=True, exist_ok=False)
    records = []
    for name, valid, data in cases:
        checksum(data)
        path = output / (name + '.dex')
        path.write_bytes(data)
        result = subprocess.run([str(args.exe), 'inspect', str(path), '--json'], capture_output=True, timeout=30)
        stdout, stderr = result.stdout.decode('utf-8', 'replace'), result.stderr.decode('utf-8', 'replace')
        try:
            status = json.loads(stdout).get('execution_status')
        except (ValueError, AttributeError):
            status = None
        if status is None and ':' in stderr:
            status = stderr.split(':', 1)[0].strip()
        expected = 'Complete' if valid is True else 'CorruptInput' if valid is False else valid
        records.append({'name': name, 'expected': expected, 'actual': status, 'exit': result.returncode,
                        'sha256': hashlib.sha256(data).hexdigest(), 'stderr': stderr[:1000]})
    expected_exits = {'Complete': 0, 'CorruptInput': 2, 'BudgetExceeded': 3}
    failed = [r for r in records if r['actual'] != r['expected'] or r['exit'] != expected_exits[r['expected']]]
    (output / 'results.json').write_text(json.dumps({'cases': records, 'failed': len(failed)}, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'cases': len(records), 'failed': [r['name'] for r in failed]}))
    return bool(failed)


if __name__ == '__main__':
    raise SystemExit(run())

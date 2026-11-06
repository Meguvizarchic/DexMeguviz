"""Deterministic annotation structure cases based on the pinned authored Q03 DEX."""
import argparse
import hashlib
import json
import struct
import subprocess
import time
import zlib
from pathlib import Path

SHA = 'ea6e44ec68dfbb6c68a88171c5c64b77dca38b73bfdf0cc1b820d4d1e5ccb062'


def checksum(data):
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into('<I', data, 8, zlib.adler32(data[12:]) & 0xffffffff)


def build(original, first=bytes.fromhex('01 02 01 05 17 06'), annotation_gap=b'',
          set_gap=b'', ref_gap=b'', directory_gap=b''):
    # Layout and values are authored independently of the native reader.
    data = bytearray(original[:464])
    annotations = len(data)
    data.extend(first + bytes.fromhex('00 03 00') + annotation_gap)
    static = len(data)
    data.extend(original[470:473])
    data.extend(bytes(-len(data) % 4))
    aset = len(data)
    data.extend(struct.pack('<III', 2, annotations, annotations + len(first)))
    data.extend(set_gap)
    ref = len(data)
    # quiet() has no parameters; the second, unreferenced list exercises nullable set references.
    data.extend(struct.pack('<IIII', 0, 2, aset, 0))
    data.extend(ref_gap)
    directory = len(data)
    data.extend(struct.pack('<4I', aset, 1, 2, 1))
    data.extend(struct.pack('<8I', 0, aset, 0, aset, 1, aset, 0, ref))
    data.extend(directory_gap)
    map_at = len(data)
    old_map = 500
    entries = []
    for i in range(struct.unpack_from('<I', original, old_map)[0]):
        kind, unused, count, offset = struct.unpack_from('<HHII', original, old_map + 4 + 12 * i)
        replacement = {0x2004: (2, annotations), 0x2005: (1, static),
                       0x1003: (1, aset), 0x2006: (1, directory), 0x1000: (1, map_at)}
        count, offset = replacement.get(kind, (count, offset))
        entries.append((kind, unused, count, offset))
    entries.append((0x1002, 0, 2, ref))
    data.extend(struct.pack('<I', len(entries)))
    for item in sorted(entries, key=lambda x: x[3]):
        data.extend(struct.pack('<HHII', *item))
    class_at = struct.unpack_from('<I', data, 100)[0]
    struct.pack_into('<II', data, class_at + 20, directory, struct.unpack_from('<I', data, class_at + 24)[0])
    struct.pack_into('<I', data, class_at + 28, static)
    struct.pack_into('<I', data, 32, len(data))
    struct.pack_into('<I', data, 52, map_at)
    struct.pack_into('<I', data, 104, len(data) - struct.unpack_from('<I', data, 108)[0])
    return data, {'annotation': annotations, 'set': aset, 'ref': ref, 'directory': directory,
                  'class': class_at}


def run():
    ap = argparse.ArgumentParser()
    ap.add_argument('--exe', type=Path, required=True)
    ap.add_argument('--fixture', type=Path, required=True)
    ap.add_argument('--root', type=Path, required=True)
    args = ap.parse_args()
    original = args.fixture.read_bytes()
    if hashlib.sha256(original).hexdigest() != SHA:
        raise SystemExit('Unexpected Q03 fixture')
    base, pos = build(original)
    cases = [('baseline', True, bytearray(base))]
    nested, _ = build(original, bytes.fromhex('01 02 01 05 1d 03 01 05 17 06'))
    cases.append(('nested-annotation', True, nested))
    duplicate, _ = build(original, bytes.fromhex('01 02 02 05 1e 05 1e'))
    cases.append(('duplicate-element-name', False, duplicate))
    zero_gap, _ = build(original, annotation_gap=bytes(7))
    cases.append(('extra-zero-section-gap', True, zero_gap))
    nonzero_gap, _ = build(original, annotation_gap=bytes.fromhex('00 01 00'))
    cases.append(('nonzero-section-gap', False, nonzero_gap))
    for part in ('set', 'ref', 'directory'):
        for valid in (True, False):
            gap = bytes(4) if valid else bytes.fromhex('00 01 00 00')
            image, _ = build(original, **{part + '_gap': gap})
            cases.append((part + ('-zero-gap' if valid else '-nonzero-gap'), valid, image))

    def byte(name, offset, value):
        data = bytearray(base); data[offset] = value; cases.append((name, False, data))

    def word(name, offset, value, valid=False):
        data = bytearray(base); struct.pack_into('<I', data, offset, value); cases.append((name, valid, data))

    def halfword(name, offset, value):
        data = bytearray(base); struct.pack_into('<H', data, offset, value); cases.append((name, False, data))

    a, s, r, d, c = (pos[k] for k in ('annotation', 'set', 'ref', 'directory', 'class'))
    byte('visibility', a, 3)
    byte('annotation-type-not-class', a + 1, 4)
    byte('annotation-name-invalid', a + 3, 0)
    byte('annotation-string-out-of-range', a + 5, 12)
    word('set-interior', s + 4, a + 1)
    word('set-missing', s + 4, 0)
    word('set-duplicate-type', s + 8, a)
    descending = bytearray(base)
    struct.pack_into('<II', descending, s + 4, a + 6, a)
    cases.append(('set-descending-type', False, descending))
    word('reference-interior', r + 8, s + 4)
    word('reference-null-is-valid', r + 8, 0, True)
    word('directory-class-interior', d, s + 4)
    word('directory-field-index', d + 16, 1)
    word('directory-field-null', d + 20, 0)
    word('directory-method-duplicate', d + 32, 0)
    word('directory-method-index', d + 32, 2)
    word('directory-parameter-interior', d + 44, r + 8)
    # quiet() has zero declared parameters; this points to the second, valid
    # ref-list containing two entries. Structural metadata-open must not
    # silently invent an exact count rule: older dexers may omit or add
    # annotation entries for implicit constructor parameters.
    method_table = struct.unpack_from('<I', base, 92)[0]
    proto_table = struct.unpack_from('<I', base, 76)[0]
    proto_index = struct.unpack_from('<H', base, method_table + 2)[0]
    assert proto_index == 0 and struct.unpack_from('<I', base, proto_table + proto_index * 12 + 8)[0] == 0
    assert struct.unpack_from('<I', base, d + 40)[0] == 0 and struct.unpack_from('<I', base, r + 4)[0] == 2
    word('parameter-count-mismatch-structural', d + 44, r + 4, True)
    word('directory-count-overflow', d + 4, 0xffffffff)
    word('class-directory-interior', c + 20, d + 4)
    word('class-directory-null', c + 20, 0, True)
    halfword('field-owner-mismatch', struct.unpack_from('<I', base, 84)[0], 2)
    halfword('method-owner-mismatch', struct.unpack_from('<I', base, 92)[0], 2)

    output = args.root / 'docs/evidence/annotation-structure' / ('run-' + str(time.time_ns()))
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
        expected = 'Complete' if valid else 'CorruptInput'
        expected_detail = {'field-owner-mismatch': 'field annotation owner mismatch',
                           'method-owner-mismatch': 'method annotation owner mismatch'}.get(name)
        records.append({'name': name, 'expected': expected, 'actual': status, 'exit': result.returncode,
                        'expected_detail': expected_detail, 'sha256': hashlib.sha256(data).hexdigest(), 'stderr': stderr[:1000]})
    failed = [r for r in records if r['actual'] != r['expected'] or r['exit'] != (0 if r['expected'] == 'Complete' else 2)
              or (r['expected_detail'] and r['expected_detail'] not in r['stderr'])]
    (output / 'results.json').write_text(json.dumps({'positions': pos, 'cases': records, 'failed': len(failed)}, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'cases': len(records), 'failed': [r['name'] for r in failed]}))
    return bool(failed)


if __name__ == '__main__':
    raise SystemExit(run())

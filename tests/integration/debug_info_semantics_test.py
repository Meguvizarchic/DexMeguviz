"""Static debug association checks with shared code and wide parameter prototypes."""
import argparse
import hashlib
import json
import struct
import subprocess
import time
import zlib
from pathlib import Path

SHA = '135c62685a5265e10388353873bbd41d18ffd0ac871329d42eb46eefd9f34734'
DATA_END, OLD_MAP = 717, 720
CODE_A, CODE_B, METHOD_IDS = 636, 656, 284
BASE_CLASS_DATA = 689


def build_double(parameters):
    # A separate authored 035 DEX: static m(D)V has two incoming words but one parameter.
    names = sorted(('D', 'Ldouble/Test;', 'Ljava/lang/Object;', 'V', 'VD', 'm'))
    strings = {name: i for i, name in enumerate(names)}
    descriptors = sorted(('D', 'Ldouble/Test;', 'Ljava/lang/Object;', 'V'), key=strings.__getitem__)
    types = {name: i for i, name in enumerate(descriptors)}
    data = bytearray(112)
    sections = [(0, 1, 0)]

    def table(kind, count, width):
        at = len(data); data.extend(bytes(count * width)); sections.append((kind, count, at)); return at

    def leb(value):
        result = bytearray()
        while True:
            byte = value & 127; value >>= 7; result.append(byte | (128 if value else 0))
            if not value: return bytes(result)

    string_at = table(1, len(names), 4)
    type_at = table(2, len(descriptors), 4)
    proto_at = table(3, 1, 12)
    method_at = table(5, 1, 8)
    class_at = table(6, 1, 32)
    data_at = len(data)
    type_list = len(data); sections.append((0x1001, 1, type_list))
    data.extend(struct.pack('<IH', 1, types['D']))
    sections.append((0x2002, len(names), len(data)))
    for i, name in enumerate(names):
        struct.pack_into('<I', data, string_at + 4 * i, len(data))
        data.extend(leb(len(name)) + name.encode('ascii') + b'\0')
    data.extend(bytes(-len(data) % 4))
    code = len(data); sections.append((0x2001, 1, code))
    data.extend(struct.pack('<HHHHIIH', 2, 2, 0, 0, 0, 1, 0x000e))
    class_data = len(data); sections.append((0x2000, 1, class_data))
    data.extend(bytes.fromhex('00 00 01 00 00 09') + leb(code))
    debug = len(data); sections.append((0x2003, 1, debug))
    data.extend(b'\x01' + leb(parameters) + bytes(parameters) + b'\x03\x00\x00' + leb(types['D'] + 1) + b'\x00')
    data.extend(bytes(-len(data) % 4))
    map_at = len(data); sections.append((0x1000, 1, map_at))
    data.extend(struct.pack('<I', len(sections)))
    for kind, count, offset in sorted(sections, key=lambda item: item[2]):
        data.extend(struct.pack('<HHII', kind, 0, count, offset))
    for i, name in enumerate(descriptors): struct.pack_into('<I', data, type_at + 4 * i, strings[name])
    struct.pack_into('<III', data, proto_at, strings['VD'], types['V'], type_list)
    struct.pack_into('<HHI', data, method_at, types['Ldouble/Test;'], 0, strings['m'])
    struct.pack_into('<8I', data, class_at, types['Ldouble/Test;'], 1, types['Ljava/lang/Object;'],
                     0, 0xffffffff, 0, class_data, 0)
    struct.pack_into('<I', data, code + 8, debug)
    data[:8] = b'dex\n035\0'
    struct.pack_into('<20I', data, 32, len(data), 112, 0x12345678, 0, 0, map_at,
                     len(names), string_at, len(descriptors), type_at, 1, proto_at, 0, 0,
                     1, method_at, 1, class_at, len(data) - data_at, data_at)
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into('<I', data, 8, zlib.adler32(data[12:]) & 0xffffffff)
    return data


def verify_double_bytes(data, expected_parameters):
    # Independent byte-level check of the authored single-method DEX.
    def u32(offset): return struct.unpack_from('<I', data, offset)[0]
    def uleb(offset):
        value = 0
        for shift in range(0, 35, 7):
            byte = data[offset]; offset += 1; value |= (byte & 127) << shift
            if byte < 128: return value, offset
        raise ValueError('invalid fixture LEB')
    names = []
    for i in range(u32(56)):
        offset = u32(u32(60) + 4 * i); length, offset = uleb(offset)
        end = data.index(0, offset); name = data[offset:end].decode('ascii')
        assert len(name) == length; names.append(name)
    types = [names[u32(u32(68) + 4 * i)] for i in range(u32(64))]
    method_proto = struct.unpack_from('<H', data, u32(92) + 2)[0]
    proto = u32(76) + 12 * method_proto
    assert types[u32(proto + 4)] == 'V'
    parameter_list = u32(proto + 8)
    assert u32(parameter_list) == 1
    assert types[struct.unpack_from('<H', data, parameter_list + 4)[0]] == 'D'
    map_at = u32(52)
    sections = {struct.unpack_from('<H', data, map_at + 4 + i * 12)[0]:
                u32(map_at + 12 + i * 12) for i in range(u32(map_at))}
    code = sections[0x2001]
    assert struct.unpack_from('<HH', data, code) == (2, 2)
    assert u32(code + 8) == sections[0x2003]
    _, position = uleb(sections[0x2003]); count, _ = uleb(position)
    assert count == expected_parameters


def build(original, streams, link_a=None, link_b=None, methods='original'):
    data = bytearray(original[:DATA_END])
    if methods == 'static-wide':
        # alpha, beta, wide become direct static (J,I)V, sharing code_a (ins_size=3).
        data[BASE_CLASS_DATA + 2:BASE_CLASS_DATA + 4] = b'\x03\x00'
        data[705:707] = b'\x01\x09'
        struct.pack_into('<H', data, METHOD_IDS + 3 * 8 + 2, 3)
    elif methods == 'instance-wide':
        # alpha, beta, wide become virtual (J)V, sharing code_a (this+J = 3 words).
        data[BASE_CLASS_DATA + 2:BASE_CLASS_DATA + 4] = b'\x00\x03'
        data[698] = data[702] = data[706] = 1
        data[705] = 1
        struct.pack_into('<H', data, METHOD_IDS + 1 * 8 + 2, 2)
        struct.pack_into('<H', data, METHOD_IDS + 2 * 8 + 2, 2)
    elif methods != 'original':
        raise ValueError(methods)
    offsets = []
    for stream in streams:
        offsets.append(len(data))
        data.extend(stream)
    data.extend(bytes(-len(data) % 4))
    map_at = len(data)
    entries = []
    for i in range(struct.unpack_from('<I', original, OLD_MAP)[0]):
        kind, unused, count, offset = struct.unpack_from('<HHII', original, OLD_MAP + 4 + i * 12)
        if kind == 0x1000:
            offset = map_at
        entries.append((kind, unused, count, offset))
    entries.append((0x2003, 0, len(streams), DATA_END))
    data.extend(struct.pack('<I', len(entries)))
    for entry in sorted(entries, key=lambda value: value[3]):
        data.extend(struct.pack('<HHII', *entry))
    for code, selected in ((CODE_A, link_a), (CODE_B, link_b)):
        struct.pack_into('<I', data, code + 8, 0 if selected is None else offsets[selected])
    struct.pack_into('<I', data, 32, len(data))
    struct.pack_into('<I', data, 52, map_at)
    struct.pack_into('<I', data, 104, len(data) - struct.unpack_from('<I', data, 108)[0])
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into('<I', data, 8, zlib.adler32(data[12:]) & 0xffffffff)
    return data


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument('--exe', type=Path, required=True)
    parser.add_argument('--default-exe', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    original = args.fixture.read_bytes()
    if hashlib.sha256(original).hexdigest() != SHA:
        raise SystemExit('Unexpected extended fixture')
    assert struct.unpack_from('<HH', original, CODE_A) == (3, 3)
    assert struct.unpack_from('<HH', original, CODE_B) == (1, 0)
    assert bytes(original[689:693]) == b'\x01\x01\x02\x01'
    assert struct.unpack_from('<H', original, METHOD_IDS + 1 * 8 + 2)[0] == 3
    assert struct.unpack_from('<H', original, METHOD_IDS + 3 * 8 + 2)[0] == 2

    p2_reg2 = bytes.fromhex('01 02 00 00 03 02 00 00 00')
    p1_reg2 = bytes.fromhex('01 01 00 03 02 00 00 00')
    p0_reg0 = bytes.fromhex('01 00 03 00 00 00 00')
    p0_reg1 = bytes.fromhex('01 00 05 01 00')
    p0_reg2 = bytes.fromhex('01 00 06 02 00')
    p0_reg1_then0 = bytes.fromhex('01 00 05 01 06 00 00')
    p0_no_reg = bytes.fromhex('01 00 00')
    p2_no_reg = bytes.fromhex('01 02 00 00 00')
    p3_no_reg = bytes.fromhex('01 03 00 00 00 00')
    double_one = build_double(1)
    double_two = build_double(2)
    verify_double_bytes(double_one, 1)
    verify_double_bytes(double_two, 2)
    assert hashlib.sha256(double_one).hexdigest() == '79d4950cfef936ee2166fbea6d262360bff81ed4c39f5cd7eae80a11fb40830a'
    assert hashlib.sha256(double_two).hexdigest() == '1d21f16f4cabb59e9433dcd87764e58462444012e597c28398b537ce75fdc91d'
    cases = [
        ('static-wide-two-parameters', True, None, build(original, [p2_reg2], 0, None, 'static-wide')),
        ('instance-wide-one-parameter', True, None, build(original, [p1_reg2], 0, None, 'instance-wide')),
        ('separate-code-debug-items', True, None, build(original, [p2_reg2, p0_reg0], 0, 1, 'static-wide')),
        ('orphan-not-checked-against-signature', True, None, build(original, [p3_no_reg])),
        ('shared-code-later-method-param-mismatch', False, 'debug parameter count', build(original, [p2_reg2], 0)),
        ('wide-count-is-not-register-words', False, 'debug parameter count', build(original, [p3_no_reg], 0, None, 'static-wide')),
        ('instance-missing-parameter', False, 'debug parameter count', build(original, [p0_no_reg], 0, None, 'instance-wide')),
        ('code-b-register-valid', True, None, build(original, [p0_reg0], None, 0)),
        ('code-b-register-out-of-range', False, 'debug register exceeds code register count', build(original, [p0_reg1], None, 0)),
        ('shared-debug-per-code-registers', False, 'debug register exceeds code register count', build(original, [p0_reg2], 0, 0, 'static-wide')),
        ('shared-debug-per-method-parameters', False, 'debug parameter count', build(original, [p0_no_reg], 0, 0, 'static-wide')),
        ('shared-debug-later-method-param-mismatch', False, 'debug parameter count', build(original, [p2_no_reg], 0, 0, 'static-wide')),
        ('largest-register-precedes-smaller', False, 'debug register exceeds code register count', build(original, [p0_reg1_then0], None, 0)),
        ('double-wide-one-parameter', True, None, double_one),
        ('double-wide-words-not-parameters', False, 'debug parameter count', double_two),
    ]
    output = args.root / 'docs/evidence/debug-info-semantics' / ('run-' + str(time.time_ns()))
    output.mkdir(parents=True, exist_ok=False)
    records = []
    for name, valid, detail, data in cases:
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
        default = subprocess.run([str(args.default_exe), 'inspect', str(path), '--json'], capture_output=True, timeout=30)
        try:
            default_status = json.loads(default.stdout.decode('utf-8', 'replace')).get('execution_status')
        except (ValueError, AttributeError):
            default_status = None
        records.append({'name': name, 'expected': expected, 'actual': status, 'exit': result.returncode,
                        'default_status': default_status, 'default_exit': default.returncode,
                        'expected_detail': detail, 'sha256': hashlib.sha256(data).hexdigest(), 'stderr': stderr[:1000]})
    failed = [r for r in records if r['actual'] != r['expected'] or r['exit'] != (0 if r['expected'] == 'Complete' else 2)
              or r['default_status'] != 'Complete' or r['default_exit'] != 0
              or (r['expected_detail'] and r['expected_detail'] not in r['stderr'])]
    (output / 'results.json').write_text(json.dumps({'cases': records, 'failed': len(failed)}, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'cases': len(records), 'failed': [r['name'] for r in failed]}))
    return bool(failed)


if __name__ == '__main__':
    raise SystemExit(run())

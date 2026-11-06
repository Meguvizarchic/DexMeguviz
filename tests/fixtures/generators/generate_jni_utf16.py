"""Original single-class DEX with valid supplementary characters in names."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zlib

OWNER = 'Lsample/Owner\U0001f600;'
PARAMETER = 'Lsample/Arg\U00010400;'
NAME = 'method\U0001f600'
OBJECT = 'Ljava/lang/Object;'


def units(value):
    raw = value.encode('utf-16le', 'surrogatepass')
    return struct.unpack('<' + 'H' * (len(raw) // 2), raw)


def leb(value):
    data = bytearray()
    while True:
        b = value & 0x7f; value >>= 7
        data.append(b | (0x80 if value else 0))
        if not value: return bytes(data)


def mutf(value):
    out = bytearray(leb(len(units(value))))
    for c in units(value):
        if 0 < c < 0x80: out.append(c)
        elif c < 0x800: out.extend((0xc0 | (c >> 6), 0x80 | (c & 0x3f)))
        else: out.extend((0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f)))
    out.append(0)
    return out


def build():
    strings = sorted({OWNER, PARAMETER, NAME, OBJECT, 'V', 'VL'}, key=units)
    sid = {value: i for i, value in enumerate(strings)}
    types = sorted([OBJECT, OWNER, PARAMETER, 'V'], key=sid.__getitem__)
    tid = {value: i for i, value in enumerate(types)}
    data = bytearray(112); sections = [(0, 1, 0)]

    def table(kind, count, width):
        at = len(data); data.extend(bytes(count * width)); sections.append((kind, count, at)); return at

    strings_at = table(1, len(strings), 4)
    types_at = table(2, len(types), 4)
    protos_at = table(3, 1, 12)
    methods_at = table(5, 1, 8)
    classes_at = table(6, 1, 32)
    data_at = len(data)
    if data_at % 4: raise AssertionError('type list must be aligned')
    param_at = len(data); sections.append((0x1001, 1, param_at))
    data.extend(struct.pack('<IH', 1, tid[PARAMETER]))
    string_data = len(data); sections.append((0x2002, len(strings), string_data))
    for i, value in enumerate(strings):
        struct.pack_into('<I', data, strings_at + 4 * i, len(data)); data.extend(mutf(value))
    class_data = len(data); sections.append((0x2000, 1, class_data))
    data.extend(b'\x00\x00\x01\x00' + leb(0) + leb(0x109) + leb(0))
    data.extend(bytes(-len(data) % 4))
    map_at = len(data); sections.append((0x1000, 1, map_at))
    data.extend(struct.pack('<I', len(sections)))
    for kind, count, offset in sorted(sections, key=lambda x: x[2]):
        data.extend(struct.pack('<HHII', kind, 0, count, offset))
    for i, value in enumerate(types): struct.pack_into('<I', data, types_at + 4 * i, sid[value])
    struct.pack_into('<III', data, protos_at, sid['VL'], tid['V'], param_at)
    struct.pack_into('<HHI', data, methods_at, tid[OWNER], 0, sid[NAME])
    struct.pack_into('<8I', data, classes_at, tid[OWNER], 1, tid[OBJECT], 0, 0xffffffff, 0, class_data, 0)
    data[:8] = b'dex\n035\0'
    struct.pack_into('<20I', data, 32, len(data), 112, 0x12345678, 0, 0, map_at,
                     len(strings), strings_at, len(types), types_at, 1, protos_at,
                     0, 0, 1, methods_at, 1, classes_at, len(data) - data_at, data_at)
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into('<I', data, 8, zlib.adler32(data[12:]) & 0xffffffff)
    return bytes(data), {'owner_units': units(OWNER), 'name_units': units(NAME),
                         'prototype_units': units('(' + PARAMETER + ')V'), 'method_index': 0,
                         'class_data_offset': class_data, 'method_declaration_offset': class_data + 4}


def main():
    p = argparse.ArgumentParser(); p.add_argument('--output', type=Path, required=True); args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    data, expected = build(); expected['sha256'] = hashlib.sha256(data).hexdigest()
    (args.output / 'supplementary-names.dex').write_bytes(data)
    (args.output / 'expected.json').write_text(json.dumps(expected, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'bytes': len(data), **expected}))


if __name__ == '__main__': main()

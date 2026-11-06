"""Generate one original DEX with packed and sparse switch payloads."""
import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path


def leb(value):
    out = bytearray()
    while True:
        byte = value & 127
        value >>= 7
        out.append(byte | (128 if value else 0))
        if not value:
            return bytes(out)


def build():
    strings = sorted(('Larrayfacts/Subject;', 'Ljava/lang/Object;', 'V', 'run'))
    sid = {value: index for index, value in enumerate(strings)}
    types = sorted(strings[:3], key=sid.__getitem__)
    tid = {value: index for index, value in enumerate(types)}
    image = bytearray(112)
    sections = [(0, 1, 0)]

    def table(kind, count, width):
        at = len(image); image.extend(bytes(count * width)); sections.append((kind, count, at)); return at

    def align():
        image.extend(bytes(-len(image) % 4))

    string_at = table(1, len(strings), 4)
    type_at = table(2, len(types), 4)
    proto_at = table(3, 1, 12)
    method_at = table(5, 1, 8)
    class_at = table(6, 1, 32)
    data_at = len(image); sections.append((0x2002, len(strings), data_at))
    for i, value in enumerate(strings):
        struct.pack_into('<I', image, string_at + 4 * i, len(image))
        image.extend(leb(len(value)) + value.encode('ascii') + b'\0')
    align()
    code_at = len(image); sections.append((0x2001, 1, code_at))
    words = (0x002b, 8, 0, 0x002c, 13, 0, 0x000e, 0, 0x0100, 2, 0xffff, 0xffff, 6, 0, 6, 0, 0x0200, 2, 0, 0x8000, 0xffff, 0x7fff, 3, 0, 3, 0)
    image.extend(struct.pack('<HHHHII', 1, 0, 0, 0, 0, len(words)))
    image.extend(struct.pack('<26H', *words))
    class_data = len(image); sections.append((0x2000, 1, class_data))
    image.extend(b'\0\0\1\0\0\x09' + leb(code_at))
    align()
    map_at = len(image); sections.append((0x1000, 1, map_at))
    image.extend(struct.pack('<I', len(sections)))
    for kind, count, at in sorted(sections, key=lambda item: item[2]):
        image.extend(struct.pack('<HHII', kind, 0, count, at))
    for i, value in enumerate(types):
        struct.pack_into('<I', image, type_at + 4 * i, sid[value])
    struct.pack_into('<III', image, proto_at, sid['V'], tid['V'], 0)
    struct.pack_into('<HHI', image, method_at, tid['Larrayfacts/Subject;'], 0, sid['run'])
    struct.pack_into('<8I', image, class_at, tid['Larrayfacts/Subject;'], 1, tid['Ljava/lang/Object;'], 0, 0xffffffff, 0, class_data, 0)
    image[:8] = b'dex\n035\0'
    struct.pack_into('<20I', image, 32, len(image), 112, 0x12345678, 0, 0, map_at,
                     len(strings), string_at, len(types), type_at, 1, proto_at, 0, 0,
                     1, method_at, 1, class_at, len(image) - data_at, data_at)
    image[12:32] = hashlib.sha1(image[32:]).digest()
    struct.pack_into('<I', image, 8, zlib.adler32(image[12:]) & 0xffffffff)
    return bytes(image), code_at


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    image, code_at = build()
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'switch-facts.dex').write_bytes(image)
    (args.output / 'expected.json').write_text(json.dumps({
        'sha256': hashlib.sha256(image).hexdigest(), 'code_offset': code_at,
        'cases': [[0, 8, -1, 6], [0, 8, 0, 6], [3, 16, -2147483648, 6], [3, 16, 2147483647, 6]],
        'scope': 'original DEX byte layout; not runtime control flow or execution'
    }, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()

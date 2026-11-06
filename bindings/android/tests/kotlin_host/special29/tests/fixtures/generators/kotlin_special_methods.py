"""Generate an original DEX to exercise method-kind and owner-flag predicates.

This is a checked-metadata/CLI fixture, not an ART verifier or runtime fixture.
"""
import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path


def uleb(value):
    out = bytearray()
    while True:
        part = value & 127
        value >>= 7
        out.append(part | (128 if value else 0))
        if not value:
            return bytes(out)


def build():
    first, final, obj = 'Lflags/Ordinary;', 'Lflags/Final;', 'Ljava/lang/Object;'
    names = ['<clinit>', '<init>', 'alpha', 'beta']
    strings = sorted({first, final, obj, 'V', *names})
    sid = {s: i for i, s in enumerate(strings)}
    types = sorted([first, final, obj, 'V'], key=sid.__getitem__)
    tid = {s: i for i, s in enumerate(types)}
    methods = sorted([(first, '<clinit>'), (first, '<init>'), (first, 'alpha'), (final, 'beta')],
                     key=lambda pair: (tid[pair[0]], sid[pair[1]]))
    mid = {item: index for index, item in enumerate(methods)}
    image = bytearray(112)
    sections = [(0, 1, 0)]

    def table(kind, count, width):
        at = len(image)
        image.extend(bytes(count * width))
        sections.append((kind, count, at))
        return at

    def align():
        image.extend(bytes(-len(image) % 4))

    strings_at = table(1, len(strings), 4)
    types_at = table(2, len(types), 4)
    protos_at = table(3, 1, 12)
    methods_at = table(5, len(methods), 8)
    classes = sorted([first, final], key=tid.__getitem__)
    classes_at = table(6, len(classes), 32)
    data_at = len(image)
    sections.append((0x2002, len(strings), data_at))
    for index, value in enumerate(strings):
        struct.pack_into('<I', image, strings_at + 4 * index, len(image))
        image.extend(uleb(len(value)) + value.encode('ascii') + b'\0')
    align()
    sections.append((0x2001, len(methods), len(image)))
    codes = {}
    for owner, name in methods:
        align()
        codes[(owner, name)] = len(image)
        ins = 1 if name == '<init>' else 0
        image.extend(struct.pack('<HHHHIIH', max(1, ins), ins, 0, 0, 0, 1, 0x000e))
    sections.append((0x2000, len(classes), len(image)))
    class_data = {}
    for owner in classes:
        class_data[owner] = len(image)
        owned = [entry for entry in methods if entry[0] == owner]
        image.extend(b'\0\0' + uleb(len(owned)) + b'\0')
        previous = 0
        for entry in owned:
            name = entry[1]
            flags = 0x10001 if name == '<init>' else 0x10008 if name == '<clinit>' else 9
            current = mid[entry]
            image.extend(uleb(current - previous) + uleb(flags) + uleb(codes[entry]))
            previous = current
    align()
    map_at = len(image)
    sections.append((0x1000, 1, map_at))
    image.extend(struct.pack('<I', len(sections)))
    for kind, count, offset in sorted(sections, key=lambda item: item[2]):
        image.extend(struct.pack('<HHII', kind, 0, count, offset))
    for index, value in enumerate(types):
        struct.pack_into('<I', image, types_at + 4 * index, sid[value])
    struct.pack_into('<III', image, protos_at, sid['V'], tid['V'], 0)
    for index, (owner, name) in enumerate(methods):
        struct.pack_into('<HHI', image, methods_at + 8 * index, tid[owner], 0, sid[name])
    for index, owner in enumerate(classes):
        flags = 0x11 if owner == final else 1
        struct.pack_into('<8I', image, classes_at + 32 * index,
                         tid[owner], flags, tid[obj], 0, 0xffffffff, 0, class_data[owner], 0)
    image[:8] = b'dex\n035\0'
    struct.pack_into('<20I', image, 32, len(image), 112, 0x12345678, 0, 0, map_at,
                     len(strings), strings_at, len(types), types_at, 1, protos_at,
                     0, 0, len(methods), methods_at, len(classes), classes_at,
                     len(image) - data_at, data_at)
    image[12:32] = hashlib.sha1(image[32:]).digest()
    struct.pack_into('<I', image, 8, zlib.adler32(image[12:]) & 0xffffffff)
    return bytes(image), {'classes': {first: 1, final: 17}, 'methods': methods, 'code_offsets': list(codes.values())}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    data, model = build()
    (args.output / 'special-methods.dex').write_bytes(data)
    model.update({'sha256': hashlib.sha256(data).hexdigest(),
                  'scope': 'authored metadata and query fixture; no Android runtime or ART verifier claim'})
    (args.output / 'expected.json').write_text(json.dumps(model, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(model))

"""Original multi-DEX hierarchy fixtures. Structural tests only; no ART claim."""
import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path

CHILD = 'Lfixture/Child;'
BASE = 'Lfixture/Base;'
ALT = 'Lfixture/Alt;'
ROOT = 'Ljava/lang/Object;'
SPECS = {
    'child.dex': (CHILD, BASE, [('childOnly', 1), ('shared', 1)]),
    'base-a.dex': (BASE, ROOT, [('packageOnly', 0), ('parentOnly', 1), ('privateOnly', 2), ('shared', 1)]),
    'base-b.dex': (BASE, ALT, [('variant', 1)]),
    'base-cycle.dex': (BASE, CHILD, [('cycleField', 1)]),
    'alt.dex': (ALT, ROOT, [('altField', 1)]),
    'root.dex': (ROOT, None, []),
}

def leb(n):
    out = bytearray()
    while True:
        b = n & 127
        n >>= 7
        out.append(b | (128 if n else 0))
        if not n:
            return bytes(out)

def build(owner, parent, fields):
    strings = sorted({owner, 'I', *(name for name, _ in fields), *([parent] if parent else [])})
    sid = {s: i for i, s in enumerate(strings)}
    types = sorted({owner, 'I', *([parent] if parent else [])}, key=sid.__getitem__)
    tid = {s: i for i, s in enumerate(types)}
    fields = sorted(fields, key=lambda x: sid[x[0]])
    out = bytearray(112)
    sections = [(0, 1, 0)]
    def table(kind, count, width):
        if not count:
            return 0
        at = len(out)
        out.extend(bytes(count * width))
        sections.append((kind, count, at))
        return at
    def align():
        out.extend(bytes(-len(out) % 4))
    string_at = table(1, len(strings), 4)
    type_at = table(2, len(types), 4)
    field_at = table(4, len(fields), 8)
    class_at = table(6, 1, 32)
    data_at = len(out)
    sections.append((0x2002, len(strings), data_at))
    for i, text in enumerate(strings):
        struct.pack_into('<I', out, string_at + 4*i, len(out))
        out.extend(leb(len(text)) + text.encode('ascii') + b'\0')
    class_data = 0
    if fields:
        class_data = len(out)
        sections.append((0x2000, 1, class_data))
        out.extend(b'\0' + leb(len(fields)) + b'\0\0')
        prev = 0
        for i, (_, flags) in enumerate(fields):
            out.extend(leb(i - prev) + leb(flags))
            prev = i
    align()
    map_at = len(out)
    sections.append((0x1000, 1, map_at))
    out.extend(struct.pack('<I', len(sections)))
    for kind, count, at in sorted(sections, key=lambda s: s[2]):
        out.extend(struct.pack('<HHII', kind, 0, count, at))
    for i, text in enumerate(types):
        struct.pack_into('<I', out, type_at + 4*i, sid[text])
    for i, (name, _) in enumerate(fields):
        struct.pack_into('<HHI', out, field_at + 8*i, tid[owner], tid['I'], sid[name])
    struct.pack_into('<8I', out, class_at, tid[owner], 1, tid[parent] if parent else 0xffffffff,
                     0, 0xffffffff, 0, class_data, 0)
    out[:8] = b'dex\n035\0'
    struct.pack_into('<20I', out, 32, len(out), 112, 0x12345678, 0, 0, map_at,
                     len(strings), string_at, len(types), type_at, 0, 0, len(fields), field_at,
                     0, 0, 1, class_at, len(out) - data_at, data_at)
    out[12:32] = hashlib.sha1(out[32:]).digest()
    struct.pack_into('<I', out, 8, zlib.adler32(out[12:]) & 0xffffffff)
    return bytes(out)

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    entries = {}
    for name, spec in SPECS.items():
        data = build(*spec)
        (args.output / name).write_bytes(data)
        entries[name] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    (args.output / 'manifest.json').write_text(json.dumps(entries, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(entries))

if __name__ == '__main__':
    main()

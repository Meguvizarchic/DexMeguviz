"""Independent byte-level inspection for the isolated hierarchy fixture."""
import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path

EXPECTED = {
    'child.dex': ('Lfixture/Child;', 'Lfixture/Base;', {'childOnly': 1, 'shared': 1}),
    'base-a.dex': ('Lfixture/Base;', 'Ljava/lang/Object;', {'packageOnly': 0, 'parentOnly': 1, 'privateOnly': 2, 'shared': 1}),
    'base-b.dex': ('Lfixture/Base;', 'Lfixture/Alt;', {'variant': 1}),
    'base-cycle.dex': ('Lfixture/Base;', 'Lfixture/Child;', {'cycleField': 1}),
    'alt.dex': ('Lfixture/Alt;', 'Ljava/lang/Object;', {'altField': 1}),
    'root.dex': ('Ljava/lang/Object;', None, {}),
}

def uleb(data, pos):
    n = 0
    for shift in range(0, 35, 7):
        byte = data[pos]
        pos += 1
        n |= (byte & 127) << shift
        if not byte & 128:
            return n, pos
    raise ValueError('invalid uleb')

def inspect(data):
    assert data[:8] == b'dex\n035\0'
    assert struct.unpack_from('<I', data, 32)[0] == len(data)
    assert data[12:32] == hashlib.sha1(data[32:]).digest()
    assert struct.unpack_from('<I', data, 8)[0] == zlib.adler32(data[12:]) & 0xffffffff
    u32 = lambda at: struct.unpack_from('<I', data, at)[0]
    strings_count, strings_off = u32(56), u32(60)
    type_count, type_off = u32(64), u32(68)
    fields_count, fields_off = u32(80), u32(84)
    assert u32(96) == 1
    class_off = u32(100)
    strings = []
    for i in range(strings_count):
        pos = u32(strings_off + 4*i)
        size, pos = uleb(data, pos)
        end = data.index(0, pos)
        value = data[pos:end].decode('ascii')
        assert size == len(value)
        strings.append(value)
    types = [strings[u32(type_off + 4*i)] for i in range(type_count)]
    refs = []
    for i in range(fields_count):
        owner, field_type, name = struct.unpack_from('<HHI', data, fields_off + 8*i)
        refs.append((types[owner], types[field_type], strings[name]))
    owner_id, _, parent_id, _, _, _, class_data, _ = struct.unpack_from('<8I', data, class_off)
    owner = types[owner_id]
    parent = None if parent_id == 0xffffffff else types[parent_id]
    fields = {}
    if class_data:
        pos = class_data
        counts = []
        for _ in range(4):
            n, pos = uleb(data, pos)
            counts.append(n)
        assert counts[0] == counts[2] == counts[3] == 0
        index = 0
        for _ in range(counts[1]):
            delta, pos = uleb(data, pos)
            flags, pos = uleb(data, pos)
            index += delta
            field_owner, field_type, name = refs[index]
            assert field_owner == owner and field_type == 'I'
            fields[name] = flags
    assert len(fields) == fields_count
    return owner, parent, fields

def main():
    p = argparse.ArgumentParser()
    p.add_argument('fixtures', type=Path)
    args = p.parse_args()
    manifest = json.loads((args.fixtures / 'manifest.json').read_text(encoding='utf-8'))
    assert set(manifest) == set(EXPECTED)
    for name, expected in EXPECTED.items():
        raw = (args.fixtures / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == manifest[name]['sha256']
        assert inspect(raw) == expected, name
    print('PASS independent raw DEX oracle: 6 distinct images, parents and declared fields')

if __name__ == '__main__':
    main()

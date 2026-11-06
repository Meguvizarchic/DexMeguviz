"""Independently inspect the fixed DEX bytes used by the Kotlin query test."""
import argparse
import hashlib
import struct
import zlib
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--fixture', required=True, type=Path)
args = parser.parse_args()
data = args.fixture.read_bytes()
assert hashlib.sha256(data).hexdigest() == 'f3cf5a3b20041d69508b6841ab46b9e8f7168862bf7d34d2afbb70127eda49a7'
assert data[:8] == b'dex\n035\0' and data[12:32] == hashlib.sha1(data[32:]).digest()
assert struct.unpack_from('<I', data, 8)[0] == zlib.adler32(data[12:]) & 0xffffffff
u32 = lambda offset: struct.unpack_from('<I', data, offset)[0]
assert u32(32) == len(data) and u32(36) == 112

def leb(at):
    result = 0
    for shift in range(0, 35, 7):
        part = data[at]; at += 1
        result |= (part & 127) << shift
        if not part & 128:
            return result, at
    raise AssertionError('bad uleb128')

strings = []
for index in range(u32(56)):
    at = u32(u32(60) + 4 * index)
    length, at = leb(at)
    end = data.index(0, at)
    text = data[at:end].decode('ascii')
    assert len(text) == length
    strings.append(text)
types = [strings[u32(u32(68) + 4 * i)] for i in range(u32(64))]
methods = []
for index in range(u32(88)):
    owner, proto, name = struct.unpack_from('<HHI', data, u32(92) + 8 * index)
    assert proto == 0
    methods.append((types[owner], strings[name]))
definitions = {}
owners = {}
for index in range(u32(96)):
    at = u32(100) + 32 * index
    owner, flags = struct.unpack_from('<II', data, at)
    owner = types[owner]
    owners[owner] = flags
    cursor = u32(at + 24)
    static_fields, cursor = leb(cursor)
    instance_fields, cursor = leb(cursor)
    direct_methods, cursor = leb(cursor)
    virtual_methods, cursor = leb(cursor)
    assert static_fields == instance_fields == virtual_methods == 0
    method_index = 0
    for _ in range(direct_methods):
        delta, cursor = leb(cursor)
        access, cursor = leb(cursor)
        code, cursor = leb(cursor)
        method_index += delta
        method = methods[method_index]
        assert method[0] == owner
        registers, ins, outs, tries, debug, words, opcode = struct.unpack_from('<HHHHIIH', data, code)
        assert registers >= ins and outs == tries == debug == 0 and words == 1 and opcode == 0x000e
        assert ins == (1 if method[1] == '<init>' else 0)
        assert method not in definitions
        definitions[method] = access

assert owners == {'Lflags/Ordinary;': 1, 'Lflags/Final;': 17}
assert definitions == {
    ('Lflags/Ordinary;', '<init>'): 0x10001,
    ('Lflags/Ordinary;', '<clinit>'): 0x10008,
    ('Lflags/Ordinary;', 'alpha'): 9,
    ('Lflags/Final;', 'beta'): 9,
}
print('PASS fixed DEX SHA, checksums, method IDs, declarations, flags and code bytes')

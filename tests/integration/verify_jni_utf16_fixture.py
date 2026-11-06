"""Independent fixed-byte DEX check; no Android or ART execution claim."""
import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path

EXPECTED_SHA = 'd9eac2a91992305eb36bc7fdfde2ad65299ea564a96dbd055c11ad3437c4b575'
OWNER = [76,115,97,109,112,108,101,47,79,119,110,101,114,55357,56832,59]
NAME = [109,101,116,104,111,100,55357,56832]
PARAMETER = [76,115,97,109,112,108,101,47,65,114,103,55297,56320,59]


def leb(data, at):
    value = 0
    for shift in range(0, 35, 7):
        part = data[at]; at += 1; value |= (part & 0x7f) << shift
        if part < 0x80: return value, at
    raise ValueError('invalid LEB')


def mutf(data, at):
    length, at = leb(data, at); output = []
    while data[at]:
        a = data[at]; at += 1
        if a < 0x80: value = a
        elif a & 0xe0 == 0xc0:
            b = data[at]; at += 1; assert b & 0xc0 == 0x80
            value = ((a & 0x1f) << 6) | (b & 0x3f)
        else:
            assert a & 0xf0 == 0xe0
            b, c = data[at], data[at + 1]; at += 2
            assert b & 0xc0 == c & 0xc0 == 0x80
            value = ((a & 0x0f) << 12) | ((b & 0x3f) << 6) | (c & 0x3f)
        output.append(value)
    assert len(output) == length
    return output


def main():
    p = argparse.ArgumentParser(); p.add_argument('--fixture', type=Path, required=True); args = p.parse_args()
    d = args.fixture.read_bytes(); u32 = lambda at: struct.unpack_from('<I', d, at)[0]
    assert hashlib.sha256(d).hexdigest() == EXPECTED_SHA
    assert d[:8] == b'dex\n035\0' and u32(32) == len(d)
    assert d[12:32] == hashlib.sha1(d[32:]).digest() and u32(8) == zlib.adler32(d[12:]) & 0xffffffff
    strings = [mutf(d, u32(u32(60) + 4 * i)) for i in range(u32(56))]
    assert strings.count(OWNER) == strings.count(NAME) == strings.count(PARAMETER) == 1
    types = [strings[u32(u32(68) + 4 * i)] for i in range(u32(64))]
    assert u32(88) == u32(96) == 1
    method = u32(92); owner, proto, name = struct.unpack_from('<HHI', d, method)
    assert types[owner] == OWNER and strings[name] == NAME and proto == 0
    shorty, return_type, params_at = struct.unpack_from('<III', d, u32(76))
    assert strings[shorty] == [86,76] and types[return_type] == [86]
    assert u32(params_at) == 1 and types[struct.unpack_from('<H', d, params_at + 4)[0]] == PARAMETER
    class_at = u32(100); assert u32(class_at) == owner
    class_data = u32(class_at + 24); cursor = class_data; counts = []
    for _ in range(4): v, cursor = leb(d, cursor); counts.append(v)
    declaration = cursor; index, cursor = leb(d, cursor); flags, cursor = leb(d, cursor); code, cursor = leb(d, cursor)
    assert counts == [0,0,1,0] and index == 0 and flags == 0x109 and code == 0 and declaration == 297
    assert d.count(bytes.fromhex('ed a0 bd ed b8 80')) == 2
    assert d.count(bytes.fromhex('ed a0 81 ed b0 80')) == 1
    print(json.dumps({'fixture_sha256': EXPECTED_SHA, 'declaration_offset': declaration,
                      'scope': 'original DEX byte and name rules only; no ART/runtime execution'}))


if __name__ == '__main__': main()

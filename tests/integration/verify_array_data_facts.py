"""Independently read authored array-data DEX bytes and check reproducibility."""
import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

EXPECTED = '3fa9edce6b40beee5ccb89befc54d0369e94cec1b969103932e29a6afbe977cd'


def leb(data, cursor):
    value = 0
    for shift in range(0, 35, 7):
        byte = data[cursor]; cursor += 1; value |= (byte & 127) << shift
        if byte < 128:
            return value, cursor
    raise ValueError('invalid uleb')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    fixture = args.root / 'tests/fixtures/generated/array-data-facts'
    data = (fixture / 'array-data.dex').read_bytes()
    assert hashlib.sha256(data).hexdigest() == EXPECTED
    u32 = lambda at: struct.unpack_from('<I', data, at)[0]
    assert data[:8] == b'dex\n035\0' and u32(32) == len(data)
    assert data[12:32] == hashlib.sha1(data[32:]).digest()
    assert u32(8) == zlib.adler32(data[12:]) & 0xffffffff
    assert u32(96) == 1 and u32(88) == 1
    class_at = u32(100); class_data = u32(class_at + 24)
    cursor = class_data
    counts = []
    for _ in range(4):
        value, cursor = leb(data, cursor); counts.append(value)
    assert counts == [0, 0, 1, 0]
    method, cursor = leb(data, cursor); flags, cursor = leb(data, cursor); code, cursor = leb(data, cursor)
    assert (method, flags, code) == (0, 9, 244)
    assert u32(code + 12) == 12
    words = struct.unpack_from('<12H', data, code + 16)
    assert words[:4] == (0x0026, 4, 0, 0x000e)
    assert words[4:8] == (0x0300, 4, 2, 0)
    assert struct.unpack_from('<II', data, code + 16 + 8 * 2) == (0x12345678, 0x80000001)
    expected = json.loads((fixture / 'expected.json').read_text(encoding='utf-8'))
    assert expected['sha256'] == EXPECTED and expected['code_offset'] == code
    with tempfile.TemporaryDirectory(prefix='dmg-array-facts-') as temporary:
        target = Path(temporary) / 'rebuilt'
        generator = args.root / 'tests/fixtures/generators/array_data_facts.py'
        subprocess.run([sys.executable, '-B', str(generator), '--output', str(target)], check=True, timeout=30)
        assert (target / 'array-data.dex').read_bytes() == data
        assert (target / 'expected.json').read_bytes() == (fixture / 'expected.json').read_bytes()
    print('PASS independent DEX bytes, relative payload, 32-bit little-endian values and fixture rebuild')


if __name__ == '__main__':
    main()

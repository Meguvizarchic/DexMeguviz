"""Build fixed local DEX variants with isolated UTF-16 surrogate code units."""
import argparse
import hashlib
import importlib.util
import json
import struct
import zlib
from pathlib import Path

CASES = {
    'lone-high.dex': ('\ud800', [0xd800], bytes.fromhex('01 ed a0 80 00')),
    'lone-low.dex': ('\udc00', [0xdc00], bytes.fromhex('01 ed b0 80 00')),
    'mixed-unpaired.dex': ('\ud800x\udc00\x00\U0001f600',
        [0xd800, 0x78, 0xdc00, 0, 0xd83d, 0xde00],
        bytes.fromhex('06 ed a0 80 78 ed b0 80 c0 80 ed a0 bd ed b8 80 00')),
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--generator', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location('dmg_fixture_generator', args.generator)
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    result = {}
    for name, (text, units, raw) in CASES.items():
        generator.TEXT = text
        image, expected = generator.build_dex('035')
        assert expected['unicode_string_utf16'] == units
        # Manually pinned bytes and checksums form an oracle independent of the reader.
        assert image.count(raw) == 1
        assert hashlib.sha1(image[32:]).digest() == image[12:32]
        assert zlib.adler32(image[12:]) & 0xffffffff == struct.unpack_from('<I', image, 8)[0]
        (args.output / name).write_bytes(image)
        result[name] = {'sha256': hashlib.sha256(image).hexdigest(), 'units': units, 'mutf_bytes_hex': raw.hex()}
    (args.output / 'expected.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'files': len(result), 'generator_sha256': hashlib.sha256(args.generator.read_bytes()).hexdigest()}))

if __name__ == '__main__':
    main()

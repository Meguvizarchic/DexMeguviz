"""Create a static query fixture; this is not an ART/verifier claim."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zlib

import generate_q08


def build():
    source = generate_q08.build()
    assert hashlib.sha256(source).hexdigest() == '83bca6b796f3e343b84b29ddef6949dade9b8c66c2807b6bb89f15b03981e8a8'
    image = bytearray(source)
    code = 444
    assert struct.unpack_from('<I', image, code + 12)[0] == 9
    assert struct.unpack_from('<9H', image, code + 16) == (0x60, 1, 0x67, 1, 0x60, 3, 0x67, 3, 0x0e)
    # access(): invoke-static Base.baseProbe; const/16 v0,-1; three nops; return.
    struct.pack_into('<9H', image, code + 16, 0x71, 0, 0, 0x13, 0xffff, 0, 0, 0, 0x0e)
    image[12:32] = hashlib.sha1(image[32:]).digest()
    struct.pack_into('<I', image, 8, zlib.adler32(image[12:]) & 0xffffffff)
    return bytes(image)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    image = build()
    (args.output / 'composite.dex').write_bytes(image)
    manifest = {'sha256': hashlib.sha256(image).hexdigest(), 'code_offset': 444,
                'invoke_pc': 0, 'numeric_pc': 3,
                'scope': 'static synthetic input; no runtime or verifier claim'}
    (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')

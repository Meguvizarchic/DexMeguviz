"""Generate a large, metadata-only DEX for the explicit JNI limits test."""

import argparse
import hashlib
from pathlib import Path
import struct
import zlib


def uleb(value: int) -> bytes:
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new output file; existing files are not replaced")
    output = parser.parse_args().output
    count, units = 10, 900001
    data = bytearray(112 + count * 4)
    ids, data_offset = 112, len(data)
    sections = [(0, 1, 0), (1, count, ids), (0x2002, count, data_offset)]
    for i in range(count):
        struct.pack_into("<I", data, ids + 4 * i, len(data))
        data.extend(uleb(units))
        data.append(65 + i)
        data.extend(b"\xc3\xa9" * 900000)
        data.append(0)
    data.extend(bytes(-len(data) % 4))
    map_offset = len(data)
    sections.append((0x1000, 1, map_offset))
    data.extend(struct.pack("<I", len(sections)))
    for kind, count_items, offset in sections:
        data.extend(struct.pack("<HHII", kind, 0, count_items, offset))
    data[:8] = b"dex\n035\x00"
    struct.pack_into("<20I", data, 32, len(data), 112, 0x12345678, 0, 0, map_offset,
                     count, ids, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, len(data) - data_offset, data_offset)
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xffffffff)
    with output.open("xb") as stream:
        stream.write(data)
    print(f"bytes={len(data)} sha256={hashlib.sha256(data).hexdigest()}")


if __name__ == "__main__":
    main()

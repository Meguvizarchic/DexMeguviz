"""Derive the numeric code-item fixture from the original method-facts DEX."""
import argparse, hashlib, json, struct, zlib
from pathlib import Path

def generate(source: Path, expected: Path, destination: Path) -> str:
    data = bytearray(source.read_bytes())
    meta = json.loads(expected.read_text(encoding="utf-8"))
    if hashlib.sha256(data).hexdigest() != meta["sha256"]:
        raise ValueError("source fixture does not match recorded SHA-256")
    off = meta["uses"]["code_offset"]
    if meta["uses"]["code_units"] != 8:
        raise ValueError("unexpected original code item")
    # v0 = -1; v0/v1 = -2L; v0 = raw 0x80000000; const-string v0; return.
    struct.pack_into("<H", data, off, 2)
    struct.pack_into("<8H", data, off + 16, 0xf012, 0x0016, 0xfffe,
                     0x0015, 0x8000, 0x001a, 10, 0x000e)
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xffffffff)
    digest = hashlib.sha256(data).hexdigest()
    if destination.exists():
        if destination.read_bytes() != data:
            raise FileExistsError(f"destination exists with different content: {destination}")
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    return digest

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--expected", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(generate(args.input, args.expected, args.output))

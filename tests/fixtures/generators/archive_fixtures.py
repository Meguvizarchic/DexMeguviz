"""Deterministic ZIP fixtures using Python stdlib and explicit ZIP64 records."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import struct
import warnings
import zipfile
import zlib

def pack(entries, method=zipfile.ZIP_STORED, descriptor=False, force_zip64=False):
    class Stream(io.BytesIO):
        def seek(self, *_):
            raise io.UnsupportedOperation("nonseekable fixture")
    out = Stream() if descriptor else io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(out, "w", compression=method, allowZip64=True) as archive:
            for name, payload in entries:
                item = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
                item.compress_type = method
                item.external_attr = 0o100644 << 16
                with archive.open(item, "w", force_zip64=force_zip64) as target:
                    target.write(payload)
    return out.getvalue()

def zip64(payload, descriptor=False):
    name = b"classes.dex"
    crc = zlib.crc32(payload)
    flag = 8 if descriptor else 0
    ext = struct.pack("<HHQQ", 1, 16, 0 if descriptor else len(payload), 0 if descriptor else len(payload))
    local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 45, flag, 0, 0, 0,
                        0 if descriptor else crc, 0xFFFFFFFF, 0xFFFFFFFF, len(name), len(ext))
    data = local + name + ext + payload
    if descriptor:
        data += struct.pack("<IIQQ", 0x08074B50, crc, len(payload), len(payload))
    central_offset = len(data)
    ext = struct.pack("<HHQQQ", 1, 24, len(payload), len(payload), 0)
    central = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 45, 45, flag, 0, 0, 0,
                          crc, 0xFFFFFFFF, 0xFFFFFFFF, len(name), len(ext), 0, 0, 0, 0, 0xFFFFFFFF) + name + ext
    data += central
    end64_offset = len(data)
    data += struct.pack("<IQHHIIQQQQ", 0x06064B50, 44, 45, 45, 0, 0, 1, 1, len(central), central_offset)
    data += struct.pack("<IIQI", 0x07064B50, 0, end64_offset, 1)
    data += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
    return data

def mutate(raw, field, value):
    data = bytearray(raw)
    central = data.index(b"PK\x01\x02")
    if field == "crc":
        struct.pack_into("<I", data, 14, value)
        struct.pack_into("<I", data, central+16, value)
    elif field == "method":
        struct.pack_into("<H", data, 8, value)
        struct.pack_into("<H", data, central+10, value)
    elif field == "flags":
        struct.pack_into("<H", data, 6, value)
        struct.pack_into("<H", data, central+8, value)
    elif field == "size":
        struct.pack_into("<I", data, 22, value)
        struct.pack_into("<I", data, central+24, value)
    elif field == "name":
        data[30] = value
    elif field == "nul":
        data[30] = data[central+46] = 0
    return bytes(data)

def local_padding(raw, padding, replace=False):
    data = bytearray(raw)
    name_length, extra_length = struct.unpack_from('<HH', data, 26)
    extra_start = 30 + name_length
    extra = bytes(padding) if replace else bytes(data[extra_start:extra_start+extra_length]) + bytes(padding)
    delta = len(extra) - extra_length
    central_offset = struct.unpack_from('<I', data, len(data)-6)[0]
    data[extra_start:extra_start+extra_length] = extra
    struct.pack_into('<H', data, 28, len(extra))
    struct.pack_into('<I', data, len(data)-6, central_offset+delta)
    return bytes(data)

def central_padding(raw, padding):
    data = bytearray(raw)
    central = struct.unpack_from('<I', data, len(data)-6)[0]
    directory_size = struct.unpack_from('<I', data, len(data)-10)[0]
    name_length, extra_length = struct.unpack_from('<HH', data, central+28)
    at = central+46+name_length+extra_length
    data[at:at] = padding
    struct.pack_into('<H', data, central+30, extra_length+len(padding))
    struct.pack_into('<I', data, len(data)-10, directory_size+len(padding))
    return bytes(data)

def main():
    parser = argparse.ArgumentParser()
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("--dex", type=Path, default=root / "generated" / "minimal.dex")
    parser.add_argument("--out", type=Path, default=root / "generated" / "archive")
    args = parser.parse_args()
    dex = args.dex.read_bytes()
    if not dex.startswith(b"dex\n"):
        raise SystemExit("Expected a generated real DEX fixture")
    base = pack([("classes.dex", dex)])
    deflated = pack([("classes.dex", dex)], zipfile.ZIP_DEFLATED)
    long_name = "assets/" + "x" * 600
    blobs = {
        "stored.apk": base,
        "deflated.apk": deflated,
        "multidex.apk": pack([("classes.dex", dex), ("classes2.dex", dex)], zipfile.ZIP_DEFLATED),
        "descriptor.apk": pack([("classes.dex", dex)], zipfile.ZIP_DEFLATED, descriptor=True),
        "local-zip64.apk": pack([("classes.dex", dex)], force_zip64=True),
        "zip64.apk": zip64(dex),
        "zip64-descriptor.apk": zip64(dex, descriptor=True),
        "long-name.zip": pack([(long_name, b"long"), (long_name+"y", b"distinct")]),
        "empty.zip": pack([]),
        "zero-entry.zip": pack([("empty.bin", b"")]),
        "many.apk": pack([("classes.dex", dex), ("classes2.dex", dex), ("assets/large.bin", bytes(range(256))*4096)], zipfile.ZIP_DEFLATED),
        "duplicate.apk": pack([("classes.dex", dex), ("classes.dex", dex)]),
        "duplicate-long.zip": pack([(long_name, b"a"), (long_name, b"b")]),
        "crc-mismatch.apk": mutate(deflated, "crc", (zlib.crc32(dex)+1) & 0xFFFFFFFF),
        "unsupported-method.apk": mutate(base, "method", 99),
        "encrypted.apk": mutate(base, "flags", 1),
        "size-too-large.apk": mutate(deflated, "size", len(dex)+1),
        "size-too-small.apk": mutate(deflated, "size", len(dex)-1),
        "local-name-mismatch.apk": mutate(base, "name", ord("x")),
        "embedded-nul.apk": mutate(base, "nul", 0),
        "truncated.apk": base[:-11],
    }
    bad_offset = bytearray(base)
    struct.pack_into("<I", bad_offset, len(base)-6, 0xFFFFFFFE)
    blobs["directory-offset-overflow.apk"] = bytes(bad_offset)
    bad_zip64 = bytearray(blobs["zip64.apk"])
    end64 = bad_zip64.index(b"PK\x06\x06")
    struct.pack_into("<Q", bad_zip64, end64+4, 0xFFFFFFFFFFFFFFFF)
    blobs["zip64-size-overflow.apk"] = bytes(bad_zip64)
    for length in [1, 3, 7]:
        blobs[f'zipalign-padding-{length}.apk'] = local_padding(base, bytes(length))
    blobs['zipalign-after-extra.apk'] = local_padding(base, struct.pack('<HHB', 0xBEEF, 1, 7) + bytes(3))
    blobs['zipalign-after-zip64.apk'] = local_padding(pack([('classes.dex', dex)], force_zip64=True), bytes(3))
    blobs['local-extra-nonzero-tail.apk'] = local_padding(base, b'\0\0\x01')
    blobs['central-extra-zero-tail.apk'] = central_padding(base, bytes(3))
    blobs['zip64-required-field-missing.apk'] = local_padding(pack([('classes.dex', dex)], force_zip64=True), bytes(3), replace=True)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, data in blobs.items():
        (args.out / name).write_bytes(data)
    manifest = {"schema_version": 1, "generator": "Python stdlib zipfile/zlib plus explicit documented ZIP64 records",
                "source_dex_sha256": hashlib.sha256(dex).hexdigest(), "dex_bytes": len(dex),
                "files": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in blobs.items()}}
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"fixtures": len(blobs), "out": str(args.out)}))

if __name__ == "__main__":
    main()

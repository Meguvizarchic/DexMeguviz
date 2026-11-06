"""Deterministic metadata-only DEX fixtures; uses only Python's standard library."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
import zlib


VERSIONS = ("035", "037", "038", "039", "040")
SPEC = "https://source.android.com/docs/core/runtime/dex-format"
PROVENANCE_LICENSE = "Project-original; distribution license pending owner decision"
OWNER = "Lsample/Example;"
TEXT = "雪😀\x00tail"


def units(text: str) -> tuple[int, ...]:
    encoded = text.encode("utf-16-le", errors="surrogatepass")
    return struct.unpack("<" + "H" * (len(encoded) // 2), encoded)


def uleb(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("ULEB value outside uint32")
    output = bytearray()
    while True:
        part = value & 0x7F
        value >>= 7
        output.append(part | (0x80 if value else 0))
        if not value:
            return bytes(output)


def mutf(text: str) -> bytes:
    output = bytearray(uleb(len(units(text))))
    for value in units(text):
        if 0 < value < 0x80:
            output.append(value)
        elif value < 0x800:
            output.extend((0xC0 | value >> 6, 0x80 | value & 0x3F))
        else:
            output.extend((0xE0 | value >> 12, 0x80 | value >> 6 & 0x3F, 0x80 | value & 0x3F))
    output.append(0)
    return bytes(output)


def repair_checksums(data: bytearray) -> None:
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xFFFFFFFF)


def build_dex(version: str) -> tuple[bytes, dict]:
    if version not in VERSIONS:
        raise ValueError("Generator only emits stable metadata versions")
    strings = sorted({"Example.java", "Ljava/lang/Object;", OWNER, "V", "external", "locate", "second", TEXT}, key=units)
    string_index = {value: index for index, value in enumerate(strings)}
    types = sorted(["Ljava/lang/Object;", OWNER, "V"], key=string_index.__getitem__)
    type_index = {value: index for index, value in enumerate(types)}
    method_specs = [
        {"owner": "Ljava/lang/Object;", "name": "external", "prototype": "()V"},
        {"owner": OWNER, "name": "locate", "prototype": "()V"},
        {"owner": OWNER, "name": "second", "prototype": "()V"},
    ]
    method_specs.sort(key=lambda item: (type_index[item["owner"]], string_index[item["name"]], 0))
    method_index = {item["name"]: index for index, item in enumerate(method_specs)}
    image = bytearray(112)
    sections = [(0x0000, 1, 0)]

    def table(kind: int, count: int, width: int) -> int:
        offset = len(image)
        image.extend(bytes(count * width))
        sections.append((kind, count, offset))
        return offset

    string_ids_off = table(0x0001, len(strings), 4)
    type_ids_off = table(0x0002, len(types), 4)
    proto_ids_off = table(0x0003, 1, 12)
    method_ids_off = table(0x0005, len(method_specs), 8)
    class_defs_off = table(0x0006, 1, 32)
    data_off = len(image)
    sections.append((0x2002, len(strings), data_off))
    string_offsets = []
    for index, value in enumerate(strings):
        string_offsets.append(len(image))
        struct.pack_into("<I", image, string_ids_off + 4 * index, len(image))
        image.extend(mutf(value))
    for index, value in enumerate(types):
        struct.pack_into("<I", image, type_ids_off + 4 * index, string_index[value])
    struct.pack_into("<III", image, proto_ids_off, string_index["V"], type_index["V"], 0)
    for index, item in enumerate(method_specs):
        struct.pack_into("<HHI", image, method_ids_off + 8 * index, type_index[item["owner"]], 0, string_index[item["name"]])

    class_data_off = len(image)
    sections.append((0x2000, 1, class_data_off))
    image.extend(b"\x00\x00\x01\x01")
    direct_entry_off = len(image)
    image.extend(uleb(method_index["second"]) + uleb(0x109) + uleb(0))
    virtual_entry_off = len(image)
    image.extend(uleb(method_index["locate"]) + uleb(0x401) + uleb(0))
    struct.pack_into("<IIIIIIII", image, class_defs_off, type_index[OWNER], 0x401, type_index["Ljava/lang/Object;"], 0, string_index["Example.java"], 0, class_data_off, 0)
    image.extend(bytes((-len(image)) % 4))
    map_off = len(image)
    sections.append((0x1000, 1, map_off))
    image.extend(struct.pack("<I", len(sections)))
    for kind, count, offset in sorted(sections, key=lambda item: item[2]):
        image.extend(struct.pack("<HHII", kind, 0, count, offset))
    image[:8] = b"dex\n" + version.encode("ascii") + b"\x00"
    values = [len(image), 112, 0x12345678, 0, 0, map_off,
              len(strings), string_ids_off, len(types), type_ids_off,
              1, proto_ids_off, 0, 0, len(method_specs), method_ids_off,
              1, class_defs_off, len(image) - data_off, data_off]
    struct.pack_into("<20I", image, 32, *values)
    repair_checksums(image)
    expected = {
        "version": version, "method_reference_count": 3, "method_definition_count": 2,
        "definitions": [
            {"method_index": method_index["locate"], "owner": OWNER, "name": "locate", "prototype": "()V", "access_flags": 0x401, "declaration_offset": virtual_entry_off, "code_offset": 0, "kind": "virtual"},
            {"method_index": method_index["second"], "owner": OWNER, "name": "second", "prototype": "()V", "access_flags": 0x109, "declaration_offset": direct_entry_off, "code_offset": 0, "kind": "direct"},
        ],
        "external_references": [{"method_index": method_index["external"], **method_specs[method_index["external"]]}],
        "unicode_string_utf16": list(units(TEXT)),
        "layout": {"string_ids_off": string_ids_off, "string_offsets": string_offsets, "method_ids_off": method_ids_off, "class_defs_off": class_defs_off, "class_data_off": class_data_off, "direct_entry_off": direct_entry_off, "virtual_entry_off": virtual_entry_off, "map_off": map_off},
    }
    return bytes(image), expected


def write_corpus(destination: Path) -> dict:
    destination.mkdir(parents=True, exist_ok=True)
    entries = []
    expected_by_file = {}

    def write(name: str, data: bytes, outcome: str, reason: str) -> None:
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        entries.append({"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "expected": outcome, "reason": reason, "source": "generated locally; no APK or third-party bytecode", "license": PROVENANCE_LICENSE})

    for version in VERSIONS:
        data, expected = build_dex(version)
        name = f"generated/metadata-{version}.dex"
        write(name, data, "valid", "Two definitions and one external reference; no instruction capability required")
        expected_by_file[name] = expected
    base, expected = build_dex("035")
    write("generated/minimal.dex", base, "valid", "Stable smoke-test alias of metadata-035.dex")
    expected_by_file["generated/minimal.dex"] = expected
    layout = expected["layout"]

    def mutated(name: str, edit, reason: str, outcome: str = "InvalidDex") -> None:
        data = bytearray(base)
        edit(data)
        repair_checksums(data)
        write(f"malformed/{name}.dex", bytes(data), outcome, reason)

    write("malformed/truncated-header.dex", base[:80], "InvalidDex", "Header is shorter than 112 bytes")
    write("malformed/truncated-tail.dex", base[:-7], "InvalidDex", "Declared file_size exceeds input length")
    mutated("string-offset-oob", lambda data: struct.pack_into("<I", data, layout["string_ids_off"], len(data) + 4), "string_data offset lies outside input")
    mutated("method-name-index-oob", lambda data: struct.pack_into("<I", data, layout["method_ids_off"] + 4, 0xFFFFFFFF), "method name string index is out of range")
    mutated("uleb-overflow", lambda data: data.__setitem__(slice(layout["class_data_off"], layout["class_data_off"] + 6), b"\xff\xff\xff\xff\xff\x01"), "class_data ULEB exceeds uint32 and five bytes")
    mutated("mutf-length-mismatch", lambda data: data.__setitem__(layout["string_offsets"][0], 1), "string declares incorrect UTF-16 length")
    mutated("mutf-invalid-leading-byte", lambda data: data.__setitem__(layout["string_offsets"][0] + 1, 0xF0), "MUTF-8 rejects four-byte leading byte")
    mutated("method-delta-oob", lambda data: data.__setitem__(layout["direct_entry_off"], 0x7F), "method delta resolves beyond method_ids")
    mutated("duplicate-definition", lambda data: data.__setitem__(layout["virtual_entry_off"], 2), "direct and virtual entries define same method reference")

    def class_data_interior(data: bytearray) -> None:
        interior = layout["class_data_off"] + 8
        struct.pack_into("<I", data, layout["class_defs_off"] + 24, interior)
        data[interior:interior + 4] = b"\x00\x00\x00\x00"

    def string_data_interior(data: bytearray) -> None:
        interior = layout["string_offsets"][0] + 1
        struct.pack_into("<I", data, layout["string_ids_off"], interior)
        data[interior:interior + 2] = b"\x00\x00"

    mutated("class-data-interior", class_data_interior, "class_def references a zero-count interior item instead of the map-declared class_data start")
    mutated("string-data-interior", string_data_interior, "first string_id references a valid empty interior string instead of the map-declared string_data start")
    mutated("reverse-endian", lambda data: struct.pack_into("<I", data, 40, 0x78563412), "Reverse endian capability is not enabled", "Unsupported")
    mutated("version-041", lambda data: data.__setitem__(slice(4, 7), b"041"), "041 container capability is not enabled; version rejection precedes old-header parsing", "Unsupported")
    manifest = {"schema_version": 1, "generator": "generators/generate_dex.py", "suite_catalog": "catalog.json", "specification": SPEC, "license": PROVENANCE_LICENSE, "scope": "Metadata-only deterministic synthetic fixtures; no ART runtime or APK evidence", "entries": entries}
    (destination / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (destination / "expected.json").write_text(json.dumps({"schema_version": 1, "provenance": "Human-authored semantic model; physical offsets assigned by generator, never engine output", "files": expected_by_file}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    manifest = write_corpus(args.output.resolve())
    print(json.dumps({"generated": len(manifest["entries"]), "output": str(args.output.resolve())}))

"""Original small DEX fixture for method-use facts; no third-party bytecode."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zlib


def uleb(value: int) -> bytes:
    result = bytearray()
    while True:
        piece = value & 127
        value >>= 7
        result.append(piece | (128 if value else 0))
        if not value:
            return bytes(result)


def generate(destination: Path) -> dict:
    destination.mkdir(parents=True, exist_ok=True)
    owner, external = "Lfacts/Example;", "Ljava/lang/Object;"
    strings = sorted({owner, external, "I", "V", "abstractMethod", "nativeMethod", "quiet", "uses", "sink", "counter", "only-in-pool", "used-string"})
    string_id = {name: i for i, name in enumerate(strings)}
    types = sorted([owner, external, "I", "V"], key=string_id.__getitem__)
    type_id = {name: i for i, name in enumerate(types)}
    refs = sorted([(owner, n) for n in ["abstractMethod", "nativeMethod", "quiet", "uses"]] + [(external, "sink")], key=lambda item: (type_id[item[0]], string_id[item[1]]))
    method_id = {name: i for i, (_, name) in enumerate(refs)}
    image = bytearray(112)
    sections = [(0, 1, 0)]

    def table(kind: int, count: int, width: int) -> int:
        at = len(image)
        image.extend(bytes(count * width))
        sections.append((kind, count, at))
        return at

    def align() -> None:
        image.extend(bytes(-len(image) % 4))

    string_at = table(1, len(strings), 4)
    type_at = table(2, len(types), 4)
    proto_at = table(3, 1, 12)
    field_at = table(4, 1, 8)
    method_at = table(5, len(refs), 8)
    class_at = table(6, 1, 32)
    data_at = len(image)
    sections.append((0x2002, len(strings), data_at))
    for i, text in enumerate(strings):
        struct.pack_into("<I", image, string_at + i * 4, len(image))
        image.extend(uleb(len(text)) + text.encode("ascii") + b"\0")
    align()
    sections.append((0x2001, 2, len(image)))
    code_offsets = {}
    body = [0x001a, string_id["used-string"], 0x0071, method_id["sink"], 0, 0x0060, 0, 0x000e]
    for name, instructions in [("quiet", [0x000e]), ("uses", body)]:
        align()
        code_offsets[name] = len(image)
        image.extend(struct.pack("<HHHHII", 1, 0, 0, 0, 0, len(instructions)))
        image.extend(struct.pack("<" + "H" * len(instructions), *instructions))
    class_data = len(image)
    sections.append((0x2000, 1, class_data))
    image.extend(b"\x01\x00\x03\x01\x00\x09")
    previous = 0
    for name in sorted(["nativeMethod", "quiet", "uses"], key=method_id.__getitem__):
        current = method_id[name]
        image.extend(uleb(current - previous) + uleb(0x109 if name == "nativeMethod" else 0x9) + uleb(code_offsets.get(name, 0)))
        previous = current
    image.extend(uleb(method_id["abstractMethod"]) + uleb(0x401) + b"\0")
    align()
    map_at = len(image)
    sections.append((0x1000, 1, map_at))
    image.extend(struct.pack("<I", len(sections)))
    for kind, count, at in sorted(sections, key=lambda item: item[2]):
        image.extend(struct.pack("<HHII", kind, 0, count, at))
    for i, name in enumerate(types):
        struct.pack_into("<I", image, type_at + i * 4, string_id[name])
    struct.pack_into("<III", image, proto_at, string_id["V"], type_id["V"], 0)
    struct.pack_into("<HHI", image, field_at, type_id[owner], type_id["I"], string_id["counter"])
    for i, (defined_owner, name) in enumerate(refs):
        struct.pack_into("<HHI", image, method_at + i * 8, type_id[defined_owner], 0, string_id[name])
    struct.pack_into("<8I", image, class_at, type_id[owner], 0x401, type_id[external], 0, 0xffffffff, 0, class_data, 0)
    image[:8] = b"dex\n035\0"
    struct.pack_into("<20I", image, 32, len(image), 112, 0x12345678, 0, 0, map_at,
                     len(strings), string_at, len(types), type_at, 1, proto_at, 1, field_at,
                     len(refs), method_at, 1, class_at, len(image) - data_at, data_at)
    image[12:32] = hashlib.sha1(image[32:]).digest()
    struct.pack_into("<I", image, 8, zlib.adler32(image[12:]) & 0xffffffff)
    name = "method-uses.dex"
    (destination / name).write_bytes(image)
    expected = {
        "schema_version": 1, "path": name, "sha256": hashlib.sha256(image).hexdigest(),
        "license": "Project-original; distribution license pending owner decision",
        "specification": "https://source.android.com/docs/core/runtime/dex-format",
        "provenance": "Human-authored instruction words and expected PCs, not decoder output",
        "definitions": 4, "method_references": 5, "literal_only_in_pool": string_id["only-in-pool"],
        "uses": {"method_index": method_id["uses"], "code_offset": code_offsets["uses"], "code_units": 8,
                 "strings": [{"pc": 0, "index": string_id["used-string"]}],
                 "invokes": [{"pc": 2, "index": method_id["sink"], "kind": "method", "extra_proto": None}],
                 "fields": [{"pc": 5, "index": 0}]},
        "quiet": {"code_offset": code_offsets["quiet"], "code_units": 1, "strings": [], "invokes": [], "fields": []},
        "no_body": ["abstractMethod", "nativeMethod"],
    }
    (destination / "expected.json").write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")
    # A structural 038 fixture exercises reference domains; bootstrap/runtime types
    # deliberately remain outside this metadata/instruction test's acceptance scope.
    variant = bytearray(image[:map_at])
    call_sites_at = len(variant)
    variant.extend(bytes(4))
    handles_at = len(variant)
    variant.extend(struct.pack("<HHHH", 4, 0, method_id["sink"], 0))
    encoded_array_at = len(variant)
    variant.extend(bytes([3, 0x16, 0, 0x17, string_id["uses"], 0x15, 0]))
    struct.pack_into("<I", variant, call_sites_at, encoded_array_at)
    variant.extend(bytes(-len(variant) % 4))
    variant_map = len(variant)
    variant_sections = [(kind, count, offset) for kind, count, offset in sections if kind != 0x1000]
    variant_sections += [(7, 1, call_sites_at), (8, 1, handles_at), (0x2005, 1, encoded_array_at), (0x1000, 1, variant_map)]
    variant.extend(struct.pack("<I", len(variant_sections)))
    for kind, count, at in sorted(variant_sections, key=lambda item: item[2]):
        variant.extend(struct.pack("<HHII", kind, 0, count, at))
    struct.pack_into("<H", variant, code_offsets["uses"] + 4, 1)
    struct.pack_into("<8H", variant, code_offsets["uses"] + 16, 0x10fa, method_id["sink"], 0, 0, 0x00fc, 0, 0, 0x000e)
    variant[4:7] = b"038"
    struct.pack_into("<I", variant, 32, len(variant))
    struct.pack_into("<I", variant, 52, variant_map)
    struct.pack_into("<I", variant, 104, len(variant) - data_at)
    variant[12:32] = hashlib.sha1(variant[32:]).digest()
    struct.pack_into("<I", variant, 8, zlib.adler32(variant[12:]) & 0xffffffff)
    (destination / "invoke-domains-038.dex").write_bytes(variant)
    (destination / "invoke-domains-038.expected.json").write_text(json.dumps({
        "schema_version": 1, "sha256": hashlib.sha256(variant).hexdigest(),
        "scope": "Structural custom/polymorphic reference domains only; runtime/bootstrap/signature types not verified",
        "invokes": [{"pc": 0, "index": method_id["sink"], "kind": "method_and_proto", "extra_proto": 0},
                    {"pc": 4, "index": 0, "kind": "call_site", "extra_proto": None}],
    }, indent=2) + "\n", encoding="utf-8")
    return expected


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "generated" / "method_facts")
    args = parser.parse_args()
    result = generate(args.output.resolve())
    print(json.dumps({"fixture": str(args.output.resolve() / result["path"]), "sha256": result["sha256"]}))

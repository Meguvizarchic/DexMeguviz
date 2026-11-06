"""Original DEX fixture for class/field definitions and unresolved references."""
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


def checksum(data: bytearray) -> None:
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xffffffff)


def generate(output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    base, child = "Lcatalog/Base;", "Lcatalog/Child;"
    ia, ib = "Lcatalog/InterfaceA;", "Lcatalog/InterfaceB;"
    obj, external = "Ljava/lang/Object;", "Lacatalog/External;"
    types = sorted(["I", "J", "V", base, child, ia, ib, obj, external])
    strings = sorted(set(types + ["instanceField", "shared", "externalField", "abstractMethod"]))
    sid = {name: i for i, name in enumerate(strings)}
    types.sort(key=sid.__getitem__)
    tid = {name: i for i, name in enumerate(types)}
    fields = [(base, "instanceField", "I"), (base, "shared", "J"), (child, "shared", "I"), (external, "externalField", "I")]
    fields.sort(key=lambda f: (tid[f[0]], sid[f[1]], tid[f[2]]))
    fid = {(owner, name): i for i, (owner, name, _) in enumerate(fields)}
    order = [obj, ia, ib, base, child]
    image = bytearray(112)
    sections = [(0, 1, 0)]

    def table(kind: int, count: int, width: int) -> int:
        at = len(image); image.extend(bytes(count * width)); sections.append((kind, count, at)); return at

    def align() -> None:
        image.extend(bytes(-len(image) % 4))

    strings_at = table(1, len(strings), 4)
    types_at = table(2, len(types), 4)
    protos_at = table(3, 1, 12)
    fields_at = table(4, len(fields), 8)
    methods_at = table(5, 1, 8)
    classes_at = table(6, len(order), 32)
    data_at = len(image)
    sections.append((0x1001, 2, data_at))
    interfaces_base = len(image); image.extend(struct.pack("<IHH", 2, tid[ib], tid[ia]))
    interfaces_child = len(image); image.extend(struct.pack("<IH", 1, tid[ia]))
    sections.append((0x2002, len(strings), len(image)))
    for i, name in enumerate(strings):
        struct.pack_into("<I", image, strings_at + i * 4, len(image))
        image.extend(uleb(len(name)) + name.encode("ascii") + b"\0")
    sections.append((0x2000, 2, len(image)))
    class_data = {}
    definitions = []
    class_data[base] = len(image); image.extend(b"\x01\x01\x00\x00")
    for name, flags in [("shared", 9), ("instanceField", 1)]:
        at = len(image); index = fid[(base, name)]; image.extend(uleb(index) + uleb(flags))
        definitions.append({"field_ref_index": index, "access_flags": flags, "declaration_offset": at, "owner_type": tid[base], "owner": base, "name": name})
    class_data[child] = len(image); image.extend(b"\x00\x01\x00\x01")
    at = len(image); index = fid[(child, "shared")]; image.extend(uleb(index) + uleb(1))
    definitions.append({"field_ref_index": index, "access_flags": 1, "declaration_offset": at, "owner_type": tid[child], "owner": child, "name": "shared"})
    method_declaration = len(image); image.extend(b"\x00" + uleb(0x401) + b"\x00")
    values_at = len(image); sections.append((0x2005, 1, values_at)); image.extend(b"\x00")
    align()
    annotations_at = len(image); sections.append((0x2006, 1, annotations_at)); image.extend(bytes(16))
    align()
    map_at = len(image); sections.append((0x1000, 1, map_at))
    image.extend(struct.pack("<I", len(sections)))
    for kind, count, at in sorted(sections, key=lambda item: item[2]):
        image.extend(struct.pack("<HHII", kind, 0, count, at))
    for i, name in enumerate(types): struct.pack_into("<I", image, types_at + i * 4, sid[name])
    struct.pack_into("<III", image, protos_at, sid["V"], tid["V"], 0)
    for i, (owner, name, field_type) in enumerate(fields):
        struct.pack_into("<HHI", image, fields_at + i * 8, tid[owner], tid[field_type], sid[name])
    struct.pack_into("<HHI", image, methods_at, tid[child], 0, sid["abstractMethod"])
    class_expected = []
    for i, name in enumerate(order):
        parent = 0xffffffff if name == obj else tid[base] if name == child else tid[obj]
        flags = 0x601 if name in [ia, ib] else 0x401 if name == child else 1
        interfaces = interfaces_base if name == base else interfaces_child if name == child else 0
        annotations = annotations_at if name == base else 0
        values = values_at if name == base else 0
        at = classes_at + i * 32
        struct.pack_into("<8I", image, at, tid[name], flags, parent, interfaces, 0xffffffff, annotations, class_data.get(name, 0), values)
        class_expected.append({"name": name, "type_id": tid[name], "definition_offset": at, "access_flags": flags,
            "superclass_type": parent, "interfaces": [tid[ib], tid[ia]] if name == base else [tid[ia]] if name == child else [],
            "class_data_offset": class_data.get(name, 0), "annotations_offset": annotations, "static_values_offset": values})
    image[:8] = b"dex\n035\0"
    struct.pack_into("<20I", image, 32, len(image), 112, 0x12345678, 0, 0, map_at, len(strings), strings_at,
        len(types), types_at, 1, protos_at, len(fields), fields_at, 1, methods_at, len(order), classes_at, len(image) - data_at, data_at)
    checksum(image)
    files = []

    def write(name: str, data: bytearray, outcome: str) -> None:
        checksum(data); (output / name).write_bytes(data)
        files.append({"path": name, "expected": outcome, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})

    write("definitions.dex", image, "valid")
    def mutate(name: str, edit) -> None:
        data = bytearray(image); edit(data); write(name + ".dex", data, "CorruptInput")
    mutate("duplicate-class", lambda d: struct.pack_into("<I", d, classes_at + 4 * 32, tid[base]))
    mutate("duplicate-interface", lambda d: struct.pack_into("<H", d, interfaces_base + 6, tid[ib]))
    mutate("wrong-static-group", lambda d: d.__setitem__(definitions[0]["declaration_offset"] + 1, 1))
    mutate("wrong-field-owner", lambda d: d.__setitem__(definitions[2]["declaration_offset"], fid[(base, "shared")]))
    mutate("duplicate-field", lambda d: d.__setitem__(definitions[1]["declaration_offset"], fid[(base, "shared")]))
    manifest = {"schema_version": 1, "specification": "https://source.android.com/docs/core/runtime/dex-format",
        "license": "Project-original; distribution license pending owner decision", "classes": class_expected,
        "fields": definitions, "external_field_ref_index": fid[(external, "externalField")],
        "method_declaration_offset": method_declaration, "files": files,
        "scope": "Definition directory and checked metadata offsets; annotation/static-value contents and runtime types not verified"}
    (output / "expected.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "generated" / "definition_catalog")
    args = parser.parse_args(); result = generate(args.output.resolve())
    print(json.dumps({"fixtures": len(result["files"]), "output": str(args.output.resolve())}))


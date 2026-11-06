"""Original deterministic DEX metadata fixtures; no Android/runtime validation claim."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import zlib

SPEC = "https://source.android.com/docs/core/runtime/dex-format"


def uleb(value: int) -> bytes:
    result = bytearray()
    while True:
        byte = value & 127
        value >>= 7
        result.append(byte | (128 if value else 0))
        if not value:
            return bytes(result)


def checksums(data: bytearray) -> None:
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xffffffff)


def build() -> tuple[bytearray, dict]:
    base, child, marker = "Lsample/Base;", "Lsample/Child;", "Lsample/Marker;"
    obj, thrown = "Ljava/lang/Object;", "Ljava/lang/Throwable;"
    type_names = ["I", "J", "V", base, child, marker, obj, thrown]
    prototypes = [("I", ("J", "I")), ("V", ()), ("V", ("J",)), ("V", ("J", "I"))]
    method_specs = [(obj, "external", 0), (base, "alpha", 3), (base, "beta", 3), (base, "wide", 2), (child, "gamma", 1)]
    field_specs = [(base, "instanceField", "I"), (base, "staticField", "J")]
    names = set(type_names + ["IJI", "V", "VJ", "VJI", "Extended.java"])
    names.update(item[1] for item in method_specs + field_specs)
    strings = sorted(names)
    string_id = {name: i for i, name in enumerate(strings)}
    types = sorted(type_names, key=string_id.__getitem__)
    type_id = {name: i for i, name in enumerate(types)}
    prototypes.sort(key=lambda item: (type_id[item[0]], tuple(type_id[p] for p in item[1])))
    proto_id = {item: i for i, item in enumerate(prototypes)}
    # Replace the descriptive prototype indexes after DEX ordering is fixed.
    original_protos = [("I", ("J", "I")), ("V", ()), ("V", ("J",)), ("V", ("J", "I"))]
    method_specs = [(owner, name, proto_id[original_protos[p]]) for owner, name, p in method_specs]
    method_specs.sort(key=lambda item: (type_id[item[0]], string_id[item[1]], item[2]))
    field_specs.sort(key=lambda item: (type_id[item[0]], string_id[item[1]], type_id[item[2]]))
    method_id = {name: i for i, (_, name, _) in enumerate(method_specs)}
    field_id = {name: i for i, (_, name, _) in enumerate(field_specs)}
    image = bytearray(112)
    sections = [(0, 1, 0)]
    layout = {}

    def table(kind: int, count: int, width: int) -> int:
        at = len(image)
        image.extend(bytes(count * width))
        sections.append((kind, count, at))
        return at

    def align() -> None:
        image.extend(bytes(-len(image) % 4))

    string_at = table(1, len(strings), 4)
    type_at = table(2, len(types), 4)
    proto_at = table(3, len(prototypes), 12)
    field_at = table(4, len(field_specs), 8)
    method_at = table(5, len(method_specs), 8)
    class_at = table(6, 3, 32)
    data_at = len(image)
    sections.append((0x1001, 3, len(image)))
    list_offsets = {}
    for parameters in [("J", "I"), ("J",), (marker,)]:
        align()
        list_offsets[parameters] = len(image)
        image.extend(struct.pack("<I", len(parameters)))
        image.extend(struct.pack("<" + "H" * len(parameters), *(type_id[x] for x in parameters)))
    sections.append((0x2002, len(strings), len(image)))
    for i, text in enumerate(strings):
        struct.pack_into("<I", image, string_at + i * 4, len(image))
        image.extend(uleb(len(text)) + text.encode("ascii") + b"\0")
    align()
    sections.append((0x2001, 2, len(image)))
    code_a = len(image)
    image.extend(struct.pack("<HHHHIIH", 3, 3, 0, 0, 0, 1, 0x000e))
    align()
    code_b = len(image)
    image.extend(struct.pack("<HHHHIIHH", 1, 0, 0, 1, 0, 2, 0, 0x000e))
    try_at = len(image)
    image.extend(struct.pack("<IHH", 0, 1, 1))
    handlers_at = len(image)
    image.extend(b"\x01\x7f" + uleb(type_id[thrown]) + b"\x01\x01")
    sections.append((0x2000, 2, len(image)))
    class_data = {}
    encoded_methods = {}
    class_data[base] = len(image)
    image.extend(b"\x01\x01\x02\x01")
    image.extend(uleb(field_id["staticField"]) + uleb(0x9))
    image.extend(uleb(field_id["instanceField"]) + uleb(0x1))
    for name, delta in [("alpha", method_id["alpha"]), ("beta", method_id["beta"] - method_id["alpha"]), ("wide", method_id["wide"])]:
        encoded_methods[name] = len(image)
        image.extend(uleb(delta) + uleb(0x9 if name != "wide" else 0x1))
        encoded_methods[name + "_code"] = len(image)
        image.extend(uleb(code_a))
    class_data[child] = len(image)
    image.extend(b"\x00\x00\x01\x00")
    encoded_methods["gamma"] = len(image)
    image.extend(uleb(method_id["gamma"]) + uleb(0x9))
    encoded_methods["gamma_code"] = len(image)
    image.extend(uleb(code_b))
    align()
    map_at = len(image)
    sections.append((0x1000, 1, map_at))
    image.extend(struct.pack("<I", len(sections)))
    map_entries = {}
    for kind, count, offset in sorted(sections, key=lambda item: item[2]):
        map_entries[kind] = len(image)
        image.extend(struct.pack("<HHII", kind, 0, count, offset))
    for i, name in enumerate(types):
        struct.pack_into("<I", image, type_at + i * 4, string_id[name])
    for i, (result, parameters) in enumerate(prototypes):
        shorty = result + "".join(parameters)
        struct.pack_into("<III", image, proto_at + i * 12, string_id[shorty], type_id[result], list_offsets.get(parameters, 0))
    for i, (owner, name, field_type) in enumerate(field_specs):
        struct.pack_into("<HHI", image, field_at + i * 8, type_id[owner], type_id[field_type], string_id[name])
    for i, (owner, name, prototype) in enumerate(method_specs):
        struct.pack_into("<HHI", image, method_at + i * 8, type_id[owner], prototype, string_id[name])
    class_order = [marker, base, child]
    for i, name in enumerate(class_order):
        parent = base if name == child else obj
        flags = 0x601 if name == marker else 1
        interfaces = 0 if name == marker else list_offsets[(marker,)]
        struct.pack_into("<8I", image, class_at + i * 32, type_id[name], flags, type_id[parent], interfaces, string_id["Extended.java"], 0, class_data.get(name, 0), 0)
    image[:8] = b"dex\n035\0"
    struct.pack_into("<20I", image, 32, len(image), 112, 0x12345678, 0, 0, map_at,
                     len(strings), string_at, len(types), type_at, len(prototypes), proto_at,
                     len(field_specs), field_at, len(method_specs), method_at,
                     3, class_at, len(image) - data_at, data_at)
    checksums(image)
    layout.update(code_a=code_a, code_b=code_b, try_at=try_at, handlers_at=handlers_at,
                  type_list=list_offsets[("J", "I")], interface_list=list_offsets[(marker,)],
                  proto_at=proto_at, class_at=class_at, map_entries=map_entries,
                  encoded_methods=encoded_methods, type_id=type_id)
    return image, layout


def write_corpus(output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    base, layout = build()
    entries = []

    def write(name: str, data: bytearray, valid: bool, reason: str) -> None:
        checksums(data)
        (output / name).write_bytes(data)
        entries.append({"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                        "expected": "valid" if valid else "CorruptInput", "reason": reason})

    write("shared-items.dex", bytearray(base), True, "Shared parameter/interface lists and shared code item; valid local class topology; bounded catch-all metadata")

    def change(name: str, edits, reason: str) -> None:
        data = bytearray(base)
        edits(data)
        write(name + ".dex", data, False, reason)

    change("type-list-interior", lambda d: struct.pack_into("<I", d, layout["proto_at"] + 8, layout["type_list"] + 4), "Prototype references inside a type_list")
    change("type-list-count-low", lambda d: struct.pack_into("<I", d, layout["map_entries"][0x1001] + 4, 2), "Map omits the last declared type_list")
    change("type-list-count-high", lambda d: struct.pack_into("<I", d, layout["map_entries"][0x1001] + 4, 4), "Map counts a nonexistent type_list")
    def interior_code(data: bytearray) -> None:
        at = layout["encoded_methods"]["alpha_code"]
        replacement = uleb(layout["code_a"] + 4)
        assert len(replacement) == len(uleb(layout["code_a"]))
        data[at:at + len(replacement)] = replacement
    change("code-interior", interior_code, "Method references inside an indexed code_item")
    change("code-count-low", lambda d: struct.pack_into("<I", d, layout["map_entries"][0x2001] + 4, 1), "Map omits the second code_item")
    change("code-count-high", lambda d: struct.pack_into("<I", d, layout["map_entries"][0x2001] + 4, 3), "Map counts a nonexistent code_item")
    change("incoming-mismatch", lambda d: struct.pack_into("<H", d, layout["code_a"] + 2, 2), "Shared method code does not match signature word count")
    change("registers-too-small", lambda d: struct.pack_into("<H", d, layout["code_a"], 2), "Incoming arguments exceed registers")
    change("empty-code", lambda d: struct.pack_into("<I", d, layout["code_a"] + 12, 0), "Concrete method has an empty code array")
    change("handler-interior", lambda d: struct.pack_into("<H", d, layout["try_at"] + 6, 2), "try handler offset points inside an encoded handler")
    change("handler-address-oob", lambda d: d.__setitem__(layout["handlers_at"] + 3, 2), "Typed catch PC equals insns_size")
    change("catch-all-address-oob", lambda d: d.__setitem__(layout["handlers_at"] + 4, 2), "Catch-all PC equals insns_size")
    change("try-range-oob", lambda d: struct.pack_into("<H", d, layout["try_at"] + 4, 3), "Try range extends beyond code units")
    change("handlers-count-zero", lambda d: d.__setitem__(layout["handlers_at"], 0), "Try block has no encoded handlers")
    def wrong_order(data: bytearray) -> None:
        at = layout["class_at"] + 32
        first, second = bytes(data[at:at + 32]), bytes(data[at + 32:at + 64])
        data[at:at + 32], data[at + 32:at + 64] = second, first
    change("class-topology", wrong_order, "Subclass precedes its locally defined superclass")
    def interface_order(data: bytearray) -> None:
        at = layout["class_at"]
        first, second = bytes(data[at:at + 32]), bytes(data[at + 32:at + 64])
        data[at:at + 32], data[at + 32:at + 64] = second, first
    change("interface-topology", interface_order, "Implementing class precedes its locally defined interface")
    manifest = {"schema_version": 1, "generator": "metadata_extended.py", "specification": SPEC,
                "license": "Project-original; distribution license pending owner decision",
                "scope": "Metadata item indexes, shared references, class topology and code metadata; opcodes/CFG/runtime not verified",
                "expected_valid_methods": ["alpha", "beta", "gamma", "wide"], "layout": layout, "entries": entries}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "generated" / "extended")
    args = parser.parse_args()
    manifest = write_corpus(args.output.resolve())
    print(json.dumps({"generated": len(manifest["entries"]), "output": str(args.output.resolve())}))

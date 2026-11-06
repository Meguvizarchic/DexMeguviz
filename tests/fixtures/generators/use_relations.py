"""Project-original, fixed-size DEX instruction-use relation fixtures.

Both --source and --output are required.  The output directory must not exist;
no existing file is replaced and no cleanup is performed on failure.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import zlib

SOURCE_SHA256 = "8262d2b338e54a7965111b4cec1ef9e628ada9795ad2f6a555d717a2ba9546bc"
DOMAIN_DEX_SHA256 = "ecf85d163c87d58f065335f0d932442be48b91b5efa3858e319a1c1cdf7313b0"
LIMITATION = "Structural DEX instruction fixtures only; no ART loading, bytecode type, bootstrap, CFG, or runtime dispatch verification."


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def read_u16(data: bytes | bytearray, offset: int) -> int:
    require(0 <= offset <= len(data) - 2, "u16 outside input")
    return struct.unpack_from("<H", data, offset)[0]


def read_u32(data: bytes | bytearray, offset: int) -> int:
    require(0 <= offset <= len(data) - 4, "u32 outside input")
    return struct.unpack_from("<I", data, offset)[0]


def leb(data: bytes | bytearray, offset: int) -> tuple[int, int]:
    value = 0
    for i in range(5):
        require(offset + i < len(data), "truncated ULEB")
        byte = data[offset + i]
        require(i != 4 or byte <= 15, "ULEB overflow")
        value |= (byte & 127) << (i * 7)
        if byte < 128:
            return value, offset + i + 1
    raise ValueError("ULEB exceeds five bytes")


def validate_header(data: bytes | bytearray, version: bytes) -> None:
    require(len(data) >= 112 and bytes(data[:8]) == b"dex\n" + version + b"\0", "unexpected DEX magic")
    require(read_u32(data, 32) == len(data) and read_u32(data, 36) == 112, "invalid DEX file/header size")
    require(read_u32(data, 40) == 0x12345678, "unexpected endian tag")
    require(bytes(data[12:32]) == hashlib.sha1(data[32:]).digest(), "DEX SHA-1 mismatch")
    require(read_u32(data, 8) == (zlib.adler32(data[12:]) & 0xffffffff), "DEX Adler-32 mismatch")


def ascii_strings(data: bytes | bytearray) -> list[str]:
    count, offset = read_u32(data, 56), read_u32(data, 60)
    require(count <= 1000 and offset <= len(data) - 4 * count, "invalid fixture string table")
    strings = []
    for index in range(count):
        length, cursor = leb(data, read_u32(data, offset + index * 4))
        end = data.find(b"\0", cursor)
        require(end >= cursor, "unterminated fixture string")
        raw = bytes(data[cursor:end])
        require(len(raw) == length and all(0 < byte < 128 for byte in raw), "fixture string is not expected ASCII")
        strings.append(raw.decode("ascii"))
    return strings


def source_directory(data: bytes | bytearray) -> dict:
    """Read class_data and identifier tables directly; does not call native code."""
    strings = ascii_strings(data)
    count, method_at = read_u32(data, 88), read_u32(data, 92)
    require(count <= 1000 and method_at <= len(data) - count * 8, "invalid method ID table")
    names = []
    for i in range(count):
        name_id = read_u32(data, method_at + i * 8 + 4)
        require(name_id < len(strings), "invalid method name index")
        names.append(strings[name_id])
    class_count, class_at = read_u32(data, 96), read_u32(data, 100)
    require(class_count <= 1000 and class_at <= len(data) - class_count * 32, "invalid class table")
    definitions = []
    for i in range(class_count):
        cursor = read_u32(data, class_at + i * 32 + 24)
        if not cursor:
            continue
        counts = []
        for _ in range(4):
            count, cursor = leb(data, cursor)
            require(count <= 1000, "fixture class_data count exceeds bound")
            counts.append(count)
        for count in counts[:2]:
            for _ in range(count):
                _, cursor = leb(data, cursor)
                _, cursor = leb(data, cursor)
        for count in counts[2:]:
            reference = 0
            for _ in range(count):
                declaration = cursor
                delta, cursor = leb(data, cursor)
                flags, cursor = leb(data, cursor)
                code_offset, cursor = leb(data, cursor)
                reference += delta
                require(reference < len(names), "invalid encoded method reference")
                definitions.append({"ordinal": len(definitions), "method_ref_index": reference,
                                    "name": names[reference], "flags": flags,
                                    "declaration_offset": declaration, "code_offset": code_offset})
    uses = [item for item in definitions if item["name"] == "uses"]
    require(len(uses) == 1 and uses[0]["ordinal"] == 2 and uses[0]["method_ref_index"] == 3, "unexpected caller identity")
    require(names.index("sink") == 4 and strings.index("used-string") == 10 and strings.index("only-in-pool") == 7, "unexpected fixture identifiers")
    field_at, field_count = read_u32(data, 84), read_u32(data, 80)
    require(field_count == 1 and field_at <= len(data) - 8 and strings[read_u32(data, field_at + 4)] == "counter", "unexpected field directory")
    code = uses[0]["code_offset"]
    require(code == 416 and read_u32(data, code + 12) == 8 and code + 32 <= len(data), "unexpected caller code extent")
    return {"caller": uses[0], "target_method_ref": 4, "target_field_ref": 0,
            "used_string_index": 10, "pool_only_string_index": 7}


def decode_authored_body(data: bytes | bytearray, code: int) -> dict:
    """Independent bounded decoder for the opcodes authored in this fixture set."""
    count = read_u32(data, code + 12)
    require(count == 8 and code + 16 + count * 2 <= len(data), "unexpected code-item bounds")
    words = [read_u16(data, code + 16 + i * 2) for i in range(count)]
    events = []
    pc = 0
    while pc < count:
        opcode = words[pc] & 255
        if opcode in (0x00, 0x0e):
            require(words[pc] in (0, 0x000e), "unexpected nop/return encoding")
            pc += 1
        elif opcode == 0x1a:
            require(pc + 2 <= count and words[pc] == 0x001a, "invalid const-string encoding")
            events.append({"kind": "string_use", "pc": pc, "opcode": opcode, "target_index": words[pc + 1], "reference_kind": "string"})
            pc += 2
        elif opcode == 0x1b:
            require(pc + 3 <= count and words[pc] == 0x001b, "invalid const-string/jumbo encoding")
            events.append({"kind": "string_use", "pc": pc, "opcode": opcode, "target_index": words[pc + 1] | (words[pc + 2] << 16), "reference_kind": "string"})
            pc += 3
        elif opcode == 0x71:
            require(pc + 3 <= count and words[pc] == 0x0071 and words[pc + 2] == 0, "invalid invoke-static encoding")
            events.append({"kind": "invoke_site", "pc": pc, "opcode": opcode, "target_index": words[pc + 1], "reference_kind": "method", "extra_proto": None})
            pc += 3
        elif opcode in (0x60, 0x67):
            require(pc + 2 <= count and words[pc] == opcode, "invalid static field encoding")
            events.append({"kind": "field_use", "pc": pc, "opcode": opcode, "target_index": words[pc + 1], "reference_kind": "field", "access": "read" if opcode == 0x60 else "write"})
            pc += 2
        elif opcode == 0x73:
            require(words[pc] == 0x0073, "unexpected reserved-opcode encoding")
            return {"events_before_error": events, "terminal": "CorruptInput", "error_pc": pc, "error_opcode": opcode}
        else:
            raise ValueError(f"unexpected authored opcode 0x{opcode:02x} at pc {pc}")
    return {"events": events, "terminal": "Complete"}


def verify_domains(source: Path, caller: dict) -> dict:
    expected_path = source.with_name("invoke-domains-038.expected.json")
    dex_path = source.with_name("invoke-domains-038.dex")
    require(expected_path.is_file() and dex_path.is_file(), "source directory must contain original invoke-domains-038 DEX and expected JSON")
    expected_bytes = expected_path.read_bytes()
    expected = json.loads(expected_bytes.decode("utf-8"))
    dex = dex_path.read_bytes()
    validate_header(dex, b"038")
    require(sha256(dex) == DOMAIN_DEX_SHA256 and expected.get("sha256") == DOMAIN_DEX_SHA256, "original invoke-domains-038 identity mismatch")
    authored = [{"pc": 0, "index": 4, "kind": "method_and_proto", "extra_proto": 0},
                {"pc": 4, "index": 0, "kind": "call_site", "extra_proto": None}]
    require(expected.get("invokes") == authored, "unexpected original custom/polymorphic expectations")
    code = caller["code_offset"] + 16
    words = [read_u16(dex, code + i * 2) for i in range(8)]
    require(words == [0x10fa, 4, 0, 0, 0x00fc, 0, 0, 0x000e], "original custom/polymorphic bytes do not match expectations")
    return {"path_base": "directory containing --source", "dex_path": dex_path.name, "dex_sha256": sha256(dex),
            "expected_path": expected_path.name, "expected_sha256": sha256(expected_bytes),
            "caller_ordinal": caller["ordinal"], "method_ref_index": caller["method_ref_index"],
            "code_offset": caller["code_offset"], "invokes": authored,
            "scope": "Original structural reference-domain fixture; bootstrap and runtime semantics not verified."}


def seal(data: bytearray) -> None:
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xffffffff)


def variants(source: bytes, caller: dict) -> list[tuple[str, bytes, dict]]:
    target = 4
    string = 10
    cases = [
        ("two-invokes.dex", [0x0071, target, 0, 0x0071, target, 0, 0, 0x000e],
         {"events": [{"kind": "invoke_site", "pc": 0, "opcode": 0x71, "target_index": target, "reference_kind": "method", "extra_proto": None},
                     {"kind": "invoke_site", "pc": 3, "opcode": 0x71, "target_index": target, "reference_kind": "method", "extra_proto": None}], "terminal": "Complete"}),
        ("field-read-write.dex", [0x0060, 0, 0x0067, 0, 0, 0, 0, 0x000e],
         {"events": [{"kind": "field_use", "pc": 0, "opcode": 0x60, "target_index": 0, "reference_kind": "field", "access": "read"},
                     {"kind": "field_use", "pc": 2, "opcode": 0x67, "target_index": 0, "reference_kind": "field", "access": "write"}], "terminal": "Complete"}),
        ("string-normal-jumbo.dex", [0x001a, string, 0x001b, string, 0, 0, 0, 0x000e],
         {"events": [{"kind": "string_use", "pc": 0, "opcode": 0x1a, "target_index": string, "reference_kind": "string"},
                     {"kind": "string_use", "pc": 2, "opcode": 0x1b, "target_index": string, "reference_kind": "string"}], "terminal": "Complete"}),
        ("valid-then-corrupt.dex", [0x001a, string, 0x0071, target, 0, 0x0073, 0, 0x000e],
         {"events_before_error": [{"kind": "string_use", "pc": 0, "opcode": 0x1a, "target_index": string, "reference_kind": "string"},
                                  {"kind": "invoke_site", "pc": 2, "opcode": 0x71, "target_index": target, "reference_kind": "method", "extra_proto": None}],
          "terminal": "CorruptInput", "error_pc": 5, "error_opcode": 0x73}),
    ]
    output = []
    start = caller["code_offset"] + 16
    require(list(struct.unpack_from("<8H", source, start)) == [0x001a, 10, 0x0071, 4, 0, 0x0060, 0, 0x000e], "source caller body changed")
    for name, words, expected in cases:
        data = bytearray(source)
        struct.pack_into("<8H", data, start, *words)
        seal(data)
        require(len(data) == len(source), "variant length differs from source")
        require(all(data[i] == source[i] for i in range(len(data)) if not (8 <= i < 32 or start <= i < start + 16)), "unexpected byte outside checksum/body")
        validate_header(data, b"035")
        require(source_directory(data)["caller"] == caller, "variant changed caller metadata")
        require(decode_authored_body(data, caller["code_offset"]) == expected, "authored expected events do not match raw words")
        output.append((name, bytes(data), expected))
    return output


def generate(source_path: Path, output_path: Path) -> dict:
    require(source_path.is_file(), "source DEX does not exist")
    require(not output_path.exists() and not output_path.is_symlink(), "output directory already exists; refusing to overwrite")
    require(output_path.parent.is_dir(), "output parent directory must already exist")
    source = source_path.read_bytes()
    require(sha256(source) == SOURCE_SHA256, "source is not the pinned project-original method-uses.dex")
    validate_header(source, b"035")
    directory = source_directory(source)
    domains = verify_domains(source_path, directory["caller"])
    generated = variants(source, directory["caller"])
    files = []
    for name, data, expected in generated:
        files.append({"path": name, "bytes": len(data), "sha256": sha256(data),
                      "caller_ordinal": directory["caller"]["ordinal"], "caller_method_ref": directory["caller"]["method_ref_index"],
                      "code_offset": directory["caller"]["code_offset"], "code_units": 8, **expected})
    manifest = {"schema_version": 1, "source_path": source_path.name, "source_sha256": SOURCE_SHA256,
                "source_bytes": len(source), "caller": directory["caller"], "identifiers": {k: v for k, v in directory.items() if k != "caller"},
                "fixtures": files, "original_invoke_domains_038": domains, "scope": LIMITATION,
                "corrupt_case_note": "events_before_error describe raw earlier bytes only; a checked full-method collector must fail without publishing a complete event relation."}
    output_path.mkdir(exist_ok=False)
    for name, data, expected in generated:
        destination = output_path / name
        with destination.open("xb") as target:
            target.write(data)
        saved = destination.read_bytes()
        require(saved == data and sha256(saved) == next(item["sha256"] for item in files if item["path"] == name), "saved fixture differs from authored bytes")
        validate_header(saved, b"035")
        require(decode_authored_body(saved, directory["caller"]["code_offset"]) == expected, "saved bytes fail independent self-check")
    with (output_path / "expected.json").open("x", encoding="utf-8", newline="\n") as target:
        json.dump(manifest, target, ensure_ascii=False, indent=2)
        target.write("\n")
    require(json.loads((output_path / "expected.json").read_text(encoding="utf-8")) == manifest, "saved manifest differs from expectations")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True, help="Pinned project-original method-uses.dex; sibling invoke-domains-038 fixtures required")
    parser.add_argument("--output", type=Path, required=True, help="New output directory whose parent already exists")
    args = parser.parse_args()
    result = generate(args.source, args.output)
    print(json.dumps({"output": str(args.output.resolve()), "source_sha256": result["source_sha256"],
                      "fixtures": [{"path": f["path"], "sha256": f["sha256"], "terminal": f["terminal"]} for f in result["fixtures"]],
                      "original_domains_verified": True, "scope": LIMITATION}, indent=2))

"""Independent, bounded Python oracle for the raw-dex-metadata-v0 profile."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import zlib


class DexError(ValueError):
    def __init__(self, message: str, status: str = "InvalidDex"):
        super().__init__(message)
        self.status = status


def utf16_units(value: str) -> tuple[int, ...]:
    data = value.encode("utf-16-le", errors="surrogatepass")
    return tuple(int.from_bytes(data[index:index + 2], "little") for index in range(0, len(data), 2))


def parse_dex(source: Path | str | bytes) -> dict:
    data = source if isinstance(source, bytes) else Path(source).read_bytes()
    if len(data) > 64 * 1024 * 1024:
        raise DexError("Oracle input bound exceeded", "BudgetExceeded")

    def require(condition: bool, message: str) -> None:
        if not condition:
            raise DexError(message)

    def span(offset: int, count: int) -> bytes:
        require(0 <= offset <= len(data) and 0 <= count <= len(data) - offset, "Range outside input")
        return data[offset:offset + count]

    def word(offset: int, width: int = 4) -> int:
        return int.from_bytes(span(offset, width), "little")

    def leb(offset: int) -> tuple[int, int]:
        value = 0
        for index in range(5):
            byte = word(offset + index, 1)
            require(index != 4 or byte <= 15, "ULEB overflow")
            value |= (byte & 127) << (7 * index)
            if byte < 128:
                return value, offset + index + 1
        raise DexError("ULEB exceeds five bytes")

    def text(offset: int) -> tuple[str, int]:
        count, cursor = leb(offset)
        require(count <= 1048576, "Oracle string bound exceeded")
        decoded = []
        while True:
            first = word(cursor, 1)
            cursor += 1
            if first == 0:
                break
            if first < 128:
                unit = first
            elif first & 0xE0 == 0xC0:
                second = word(cursor, 1)
                cursor += 1
                require(second & 0xC0 == 0x80, "Invalid MUTF continuation")
                unit = ((first & 31) << 6) | (second & 63)
                require(unit >= 128 or (first == 0xC0 and second == 0x80), "Overlong MUTF sequence")
            elif first & 0xF0 == 0xE0:
                second, third = span(cursor, 2)
                cursor += 2
                require(second & 0xC0 == 0x80 and third & 0xC0 == 0x80, "Invalid MUTF continuation")
                unit = ((first & 15) << 12) | ((second & 63) << 6) | (third & 63)
                require(unit >= 2048, "Overlong MUTF sequence")
            else:
                raise DexError("Invalid MUTF leading byte")
            decoded.append(unit)
            require(len(decoded) <= count, "MUTF length mismatch")
        require(len(decoded) == count, "MUTF length mismatch")
        value = b"".join(unit.to_bytes(2, "little") for unit in decoded).decode("utf-16-le", errors="surrogatepass")
        return value, cursor

    require(len(data) >= 8 and data[:4] == b"dex\n" and data[7] == 0, "Invalid DEX magic")
    version = data[4:7].decode("ascii", errors="replace")
    if version not in {"035", "037", "038", "039", "040"}:
        raise DexError("Unsupported DEX version", "Unsupported")
    require(len(data) >= 112, "Truncated DEX header")
    if word(40) == 0x78563412:
        raise DexError("Reverse endian not supported", "Unsupported")
    require(word(40) == 0x12345678, "Invalid endian tag")
    require(word(32) == len(data) and word(36) == 112, "Header size mismatch")
    require(hashlib.sha1(data[32:]).digest() == data[12:32], "SHA1 mismatch")
    require(zlib.adler32(data[12:]) & 0xFFFFFFFF == word(8), "Adler32 mismatch")
    require(word(44) == 0 and word(48) == 0, "Linked DEX not in oracle profile")
    require(word(108) % 4 == 0 and word(108) >= 112, "Invalid data offset")
    require(word(104) == len(data) - word(108), "Invalid data size")

    table_specs = [(0x0001, 56, 4), (0x0002, 64, 4), (0x0003, 72, 12), (0x0004, 80, 8), (0x0005, 88, 8), (0x0006, 96, 32)]
    tables = {}
    occupied = [(0, 112)]
    for kind, header, width in table_specs:
        count, offset = word(header), word(header + 4)
        require(count <= 1000000, "Oracle table bound exceeded")
        if count:
            require(offset >= 112 and offset % 4 == 0, "Invalid ID table offset")
            span(offset, count * width)
            require(offset + count * width <= word(108), "ID table overlaps data")
            occupied.append((offset, offset + count * width))
        else:
            require(offset == 0, "Empty ID table has offset")
        tables[kind] = (count, offset)
    occupied.sort()
    require(all(left[1] <= right[0] for left, right in zip(occupied, occupied[1:])), "Overlapping ID tables")
    map_offset = word(52)
    require(map_offset >= word(108) and map_offset % 4 == 0, "Invalid map offset")
    map_count = word(map_offset)
    require(map_count <= 1000, "Oracle map bound exceeded")
    span(map_offset + 4, 12 * map_count)
    mapped = {}
    previous = -1
    for index in range(map_count):
        item = map_offset + 4 + index * 12
        kind, unused, count, offset = word(item, 2), word(item + 2, 2), word(item + 4), word(item + 8)
        require(kind not in mapped and unused == 0 and count > 0 and offset > previous, "Invalid map entry")
        span(offset, 1)
        mapped[kind] = (count, offset)
        previous = offset
    require(mapped.get(0) == (1, 0) and mapped.get(0x1000) == (1, map_offset), "Map/header mismatch")
    for kind, (count, offset) in tables.items():
        require(mapped.get(kind) == (count, offset) if count else kind not in mapped, "Map/table mismatch")

    def verify_item_ranges(kind: int, ranges: list[tuple[int, int]]) -> None:
        if not ranges:
            require(kind not in mapped, "Map declares unreferenced data items")
            return
        ordered = sorted(ranges)
        require(mapped.get(kind) == (len(ordered), ordered[0][0]), "Map/data first item or count mismatch")
        require(all(left[1] == right[0] for left, right in zip(ordered, ordered[1:])), "Data item references do not form contiguous boundaries")
        section_limit = min((offset for _, offset in mapped.values() if offset > ordered[0][0]), default=len(data))
        require(ordered[-1][1] <= section_limit, "Data items overlap next map section")

    count, offset = tables[1]
    strings, string_ranges = [], []
    for index in range(count):
        start = word(offset + 4 * index)
        value, end = text(start)
        strings.append(value)
        string_ranges.append((start, end))
    verify_item_ranges(0x2002, string_ranges)
    encoded = [utf16_units(value) for value in strings]
    require(all(left < right for left, right in zip(encoded, encoded[1:])), "Unsorted or duplicate strings")

    def at(values: list, index: int):
        require(0 <= index < len(values), "Index out of bounds")
        return values[index]

    count, offset = tables[2]
    type_indexes = [word(offset + index * 4) for index in range(count)]
    require(all(left < right for left, right in zip(type_indexes, type_indexes[1:])), "Unsorted type_ids")
    types = [at(strings, index) for index in type_indexes]
    count, offset = tables[3]
    prototypes, proto_keys = [], []
    for index in range(count):
        shorty, returned, params = [word(offset + 12 * index + part * 4) for part in range(3)]
        at(strings, shorty)
        parameter_ids = []
        if params:
            require(params % 4 == 0 and params >= word(108), "Invalid type_list offset")
            length = word(params)
            span(params + 4, 2 * length)
            parameter_ids = [word(params + 4 + 2 * position, 2) for position in range(length)]
        prototypes.append("(" + "".join(at(types, item) for item in parameter_ids) + ")" + at(types, returned))
        proto_keys.append((returned, parameter_ids))
    require(all(left < right for left, right in zip(proto_keys, proto_keys[1:])), "Unsorted proto_ids")
    count, offset = tables[4]
    fields = []
    for index in range(count):
        owner, field_type, name = word(offset + 8 * index, 2), word(offset + 8 * index + 2, 2), word(offset + 8 * index + 4)
        at(types, owner), at(types, field_type), at(strings, name)
        fields.append((owner, name, field_type))
    require(all(left < right for left, right in zip(fields, fields[1:])), "Unsorted field_ids")
    count, offset = tables[5]
    references, method_keys = [], []
    for index in range(count):
        owner, proto, name = word(offset + 8 * index, 2), word(offset + 8 * index + 2, 2), word(offset + 8 * index + 4)
        references.append({"method_index": index, "owner": at(types, owner), "name": at(strings, name), "prototype": at(prototypes, proto)})
        method_keys.append((owner, name, proto))
    require(all(left < right for left, right in zip(method_keys, method_keys[1:])), "Unsorted method_ids")

    count, offset = tables[6]
    definitions, defined, class_ids, class_data_ranges = [], set(), set(), []
    for index in range(count):
        owner_id = word(offset + 32 * index)
        owner = at(types, owner_id)
        require(owner_id not in class_ids, "Duplicate class definition")
        class_ids.add(owner_id)
        cursor = word(offset + 32 * index + 24)
        if not cursor:
            continue
        class_data_start = cursor
        require(cursor >= word(108), "class_data outside data")
        counts = []
        for _ in range(4):
            length, cursor = leb(cursor)
            require(length <= 1000000, "Oracle class_data bound exceeded")
            counts.append(length)
        for length in counts[:2]:
            accumulated = 0
            for position in range(length):
                delta, cursor = leb(cursor)
                _, cursor = leb(cursor)
                require(position == 0 or delta > 0, "Duplicate encoded field")
                accumulated += delta
                field = at(fields, accumulated)
                require(field[0] == owner_id, "Field definition owner mismatch")
        for kind, length in zip(("direct", "virtual"), counts[2:]):
            accumulated = 0
            for position in range(length):
                declaration_offset = cursor
                delta, cursor = leb(cursor)
                access_flags, cursor = leb(cursor)
                code_offset, cursor = leb(cursor)
                require(position == 0 or delta > 0, "Duplicate encoded method")
                accumulated += delta
                reference = at(references, accumulated)
                require(accumulated not in defined, "Duplicate method definition")
                require(reference["owner"] == owner, "Method definition owner mismatch")
                if access_flags & (0x100 | 0x400):
                    require(code_offset == 0, "Native/abstract method has code")
                else:
                    require(code_offset >= word(108) and code_offset % 4 == 0, "Invalid code offset")
                    span(code_offset, 16)
                    span(code_offset + 16, word(code_offset + 12) * 2)
                defined.add(accumulated)
                definitions.append({**reference, "access_flags": access_flags, "declaration_offset": declaration_offset, "code_offset": code_offset, "kind": kind})
        class_data_ranges.append((class_data_start, cursor))
    verify_item_ranges(0x2000, class_data_ranges)
    definitions.sort(key=lambda item: item["method_index"])
    return {"version": version, "source_sha256": hashlib.sha256(data).hexdigest(), "strings": strings, "references": references, "definitions": definitions, "scope": "metadata; no opcode, control-flow, ART load or runtime binding validation"}


def _text_value(spec: dict) -> tuple[int, ...]:
    if "u16" in spec:
        result = tuple(spec["u16"])
        if any(type(item) is not int or not 0 <= item <= 65535 for item in result):
            raise ValueError("Invalid u16 query value")
        return result
    return utf16_units(spec["value"])


def select_methods(parsed: dict, query: dict) -> list[dict]:
    if query.get("schema_version", 1) != 1 or query.get("relation", "method_defs") != "method_defs":
        raise ValueError("Unsupported oracle query relation")
    where = query.get("where", {})
    if set(where) - {"name", "owner", "flags_contains"}:
        raise ValueError("Unsupported oracle predicate")

    def matches(item: dict) -> bool:
        for key in ("name", "owner"):
            if key in where:
                spec, actual = where[key], utf16_units(item[key])
                wanted = _text_value(spec)
                operation = spec.get("op", "exact")
                if operation == "exact":
                    if actual != wanted:
                        return False
                elif operation == "contains":
                    if not any(actual[index:index + len(wanted)] == wanted for index in range(len(actual) - len(wanted) + 1)):
                        return False
                else:
                    raise ValueError("Unsupported text operation")
        mask = where.get("flags_contains", 0)
        return item["access_flags"] & mask == mask

    return [item for item in parsed["definitions"] if matches(item)]


def verify_result(source: Path | str | bytes, result: dict, query: dict) -> dict:
    parsed = parse_dex(source)
    matching = select_methods(parsed, query)
    expected = {item["method_index"]: item for item in matching}
    errors = []

    def check(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    check(result.get("schema_version") == 1, "schema_version mismatch")
    check(result.get("profile") in ("raw-dex-metadata-v0", "dex-method-metadata-v1", "dex-query-method-v1"), "profile mismatch")
    if result.get("profile") in ("dex-method-metadata-v1", "dex-query-method-v1"):
        check(result.get("source_count") == 1, "single-DEX oracle cannot validate a multi-source universe")
    check(result.get("source_sha256") == parsed["source_sha256"], "source SHA256 mismatch")
    seen = set()
    fields = ("method_index", "access_flags", "declaration_offset", "code_offset", "owner", "name", "prototype")
    for candidate in result.get("candidates", []):
        index = candidate.get("method_index")
        check(index in expected, "Candidate is not a matching definition")
        check(index not in seen, "Duplicate candidate")
        seen.add(index)
        if index in expected:
            for field in fields:
                check(candidate.get(field) == expected[index][field], "Candidate evidence mismatch: " + field)
    total, visited = result.get("total_methods"), result.get("visited_methods")
    check(total == len(parsed["definitions"]), "total_methods mismatch")
    check(type(visited) is int and 0 <= visited <= len(parsed["definitions"]), "Invalid visited_methods")
    coverage, execution = result.get("coverage"), result.get("execution_status")
    check(coverage in {"Complete", "Partial"}, "Invalid coverage")
    if coverage == "Complete":
        check(visited == total, "Complete coverage without visiting all definitions")
        check(execution == "Complete", "Failure cannot claim complete coverage")
    intent = query.get("intent", "enumerate")
    decision, reason = result.get("decision"), result.get("reason")
    if intent == "enumerate":
        check(decision == "NotApplicable", "Enumeration decision must be NotApplicable")
        if coverage == "Complete":
            check(seen == set(expected), "Complete enumeration omitted matching definitions")
    elif intent == "unique":
        if decision == "ProvenTrue":
            check(coverage == "Complete" and len(matching) == 1 and len(seen) == 1 and reason == "None", "Invalid uniqueness proof")
        elif decision == "ProvenFalse":
            check((len(seen) >= 2 and reason == "Ambiguous") or (coverage == "Complete" and not matching and not seen and reason == "NoMatch"), "Invalid non-unique/absence proof")
        else:
            check(decision == "Undetermined" and coverage == "Partial" and len(seen) < 2, "Invalid undetermined unique result")
    elif intent == "exists":
        if decision == "ProvenTrue":
            check(bool(seen) and reason == "Witness", "Existence proof lacks witness")
        elif decision == "ProvenFalse":
            check(coverage == "Complete" and not matching and not seen and reason == "NoMatch", "Invalid absence proof")
        else:
            check(decision == "Undetermined" and coverage == "Partial" and not seen, "Invalid undetermined existence result")
    else:
        errors.append("Unsupported intent")
    if errors:
        raise ValueError("; ".join(errors))
    return {"verified": True, "source_sha256": parsed["source_sha256"], "definition_count": len(parsed["definitions"]), "matching_count": len(matching), "candidate_count": len(seen), "coverage": coverage, "intent": intent, "independent_scope": parsed["scope"]}


def self_test(fixtures: Path) -> dict:
    manifest = json.loads((fixtures / "manifest.json").read_text(encoding="utf-8"))
    expected = json.loads((fixtures / "expected.json").read_text(encoding="utf-8"))["files"]
    count = 0
    for entry in manifest["entries"]:
        path = fixtures / entry["path"]
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise AssertionError("Fixture digest mismatch: " + entry["path"])
        if entry["expected"] == "valid":
            actual = parse_dex(data)
            golden = expected[entry["path"]]
            assert actual["definitions"] == golden["definitions"], entry["path"]
            assert len(actual["references"]) == golden["method_reference_count"]
            assert tuple(golden["unicode_string_utf16"]) in [utf16_units(value) for value in actual["strings"]]
        else:
            try:
                parse_dex(data)
            except DexError as error:
                assert error.status == entry["expected"], (entry["path"], error.status)
            else:
                raise AssertionError("Oracle accepted invalid/unsupported fixture: " + entry["path"])
        count += 1
    cases = json.loads((fixtures / "queries" / "declaration-cases.json").read_text(encoding="utf-8"))
    fixture = fixtures / cases["fixture"]
    parsed = parse_dex(fixture)
    for case in cases["cases"]:
        assert [item["name"] for item in select_methods(parsed, case["query"])] == case["expected_names"], case["id"]
    query = {"schema_version": 1, "relation": "method_defs", "where": {"name": {"op": "exact", "value": "locate"}}, "intent": "unique", "max_results": 10}
    result = {"schema_version": 1, "profile": "raw-dex-metadata-v0", "execution_status": "Complete", "coverage": "Complete", "decision": "ProvenTrue", "reason": "None", "visited_methods": 2, "total_methods": 2, "source_sha256": parsed["source_sha256"], "candidates": [parsed["definitions"][0]]}
    verify_result(fixture, result, query)
    mutations = [
        lambda item: item.update(source_sha256="0" * 64),
        lambda item: item["candidates"][0].update(declaration_offset=0),
        lambda item: item.update(coverage="Partial", visited_methods=1),
        lambda item: item["candidates"][0].update(method_index=0),
        lambda item: item.update(total_methods=3),
    ]
    for mutation in mutations:
        forged = copy.deepcopy(result)
        mutation(forged)
        try:
            verify_result(fixture, forged, query)
        except ValueError:
            pass
        else:
            raise AssertionError("Verifier accepted forged evidence")
    return {"fixture_cases_passed": count, "query_cases_passed": len(cases["cases"]), "valid_proofs_passed": 1, "forged_proofs_rejected": len(mutations), "failed": 0, "scope": "Generated corpus and verifier controls vs independent Python metadata parser; not engine validation"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", type=Path)
    parser.add_argument("--dex", type=Path)
    parser.add_argument("--result", type=Path)
    parser.add_argument("--query", type=Path)
    args = parser.parse_args()
    if args.self_test:
        output = self_test(args.self_test)
    elif args.dex and args.result and args.query:
        output = verify_result(args.dex, json.loads(args.result.read_text(encoding="utf-8")), json.loads(args.query.read_text(encoding="utf-8")))
    else:
        parser.error("Use --self-test FIXTURES, or --dex FILE --result JSON --query JSON")
    print(json.dumps(output, ensure_ascii=True, indent=2))

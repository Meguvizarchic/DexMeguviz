"""Independent synthetic SourceSet fixtures; no engine code or engine cache is read."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import warnings
import zipfile

sys.dont_write_bytecode = True


LICENSE = "Project-original; distribution license pending owner decision"


def load_generator(base_root: Path):
    path = base_root / "tests/fixtures/generators/generate_dex.py"
    spec = importlib.util.spec_from_file_location("independent_dex_fixture_generator", path)
    if spec is None or spec.loader is None:
        raise ValueError("Independent DEX generator is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, path


def zip_bytes(entries: list[tuple[str, bytes]], compression: int) -> bytes:
    output = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(output, "w") as archive:
            for name, data in entries:
                info = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
                info.compress_type = compression
                info.create_system = 0
                info.external_attr = 0
                archive.writestr(info, data)
    return output.getvalue()


def corrupt_entry_crc(original: bytes, target: str) -> bytes:
    data = bytearray(original)
    with zipfile.ZipFile(io.BytesIO(original)) as archive:
        info = archive.getinfo(target)
        struct.pack_into("<I", data, info.header_offset + 14, info.CRC ^ 1)
        cursor = archive.start_dir
        for entry in archive.infolist():
            if data[cursor:cursor + 4] != b"PK\x01\x02":
                raise ValueError("Unexpected central directory layout")
            name_length, extra_length, comment_length = struct.unpack_from("<HHH", data, cursor + 28)
            if entry.filename == target:
                struct.pack_into("<I", data, cursor + 16, info.CRC ^ 1)
            cursor += 46 + name_length + extra_length + comment_length
    return bytes(data)


def build_fixtures(base_root: Path, output: Path) -> dict:
    generator, generator_path = load_generator(base_root)
    dex035, expected035 = generator.build_dex("035")
    dex037, expected037 = generator.build_dex("037")
    dex040, expected040 = generator.build_dex("040")
    versions = {"035": (dex035, expected035), "037": (dex037, expected037), "040": (dex040, expected040)}
    # Central order is deliberately neither numeric nor lexical DEX order.
    reversed_entries = [("classes10.dex", dex040), ("assets/label.txt", b"synthetic resource"), ("classes2.dex", dex037), ("classes.dex", dex035)]
    canonical_stored = zip_bytes(reversed_entries, zipfile.ZIP_STORED)
    files = {
        "raw-a.dex": dex035,
        "raw-a-copy.dex": dex035,
        "raw-b.dex": dex037,
        "reverse-stored.apk": canonical_stored,
        "reverse-deflate.apk": zip_bytes(reversed_entries, zipfile.ZIP_DEFLATED),
        "resource-only.apk": zip_bytes([("assets/label.txt", b"resource-only synthetic split")], zipfile.ZIP_STORED),
        "one-corrupt-dex.apk": zip_bytes([("classes.dex", dex035), ("classes2.dex", dex037[:-7])], zipfile.ZIP_STORED),
        "bad-crc.apk": corrupt_entry_crc(canonical_stored, "classes2.dex"),
        "duplicate-entry.apk": zip_bytes([("classes.dex", dex035), ("classes.dex", dex035)], zipfile.ZIP_STORED),
        "classes1-only.apk": zip_bytes([("classes1.dex", dex035)], zipfile.ZIP_STORED),
        "classes01-only.apk": zip_bytes([("classes01.dex", dex035)], zipfile.ZIP_STORED),
        "noncanonical-with-canonical.apk": zip_bytes([("classes.dex", dex035), ("classes1.dex", dex035), ("classes01.dex", dex035)], zipfile.ZIP_STORED),
    }
    output.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (output / name).write_bytes(content)

    def input_(path: str, allow_no_dex: bool = False) -> dict:
        return {"path": path, "kind": "dex" if path.endswith(".dex") else "apk", "allow_no_dex": allow_no_dex}

    def occurrence(slot: int, name: str | None, central_index: int | None, version: str) -> dict:
        data, _ = versions[version]
        return {"input_index": slot, "entry_name": name, "central_index": central_index, "dex_sha256": hashlib.sha256(data).hexdigest(), "version": version, "method_definition_count": 2, "method_reference_count": 3}

    def query(name: str | None, intent: str = "unique") -> dict:
        return {"schema_version": 1, "relation": "method_defs", "where": {} if name is None else {"name": {"op": "exact", "value": name}}, "intent": intent, "max_results": 100}

    complete_two_queries = [
        {"id": "same_descriptor_is_two_occurrences", "query": query("locate"), "matching_count": 2, "decision": "ProvenFalse", "reason": "Ambiguous"},
        {"id": "external_is_reference_only", "query": query("external"), "matching_count": 0, "decision": "ProvenFalse", "reason": "NoMatch"},
    ]
    sorted_archive = [occurrence(0, "classes.dex", 3, "035"), occurrence(0, "classes2.dex", 2, "037"), occurrence(0, "classes10.dex", 0, "040")]
    cases = [
        {"id": "single_complete", "inputs": [input_("raw-a.dex")], "scope_complete": True, "expected_load_status": "Complete", "expected_occurrences": [occurrence(0, None, None, "035")], "queries": [{"id": "one_is_unique_in_complete_scope", "query": query("locate"), "matching_count": 1, "decision": "ProvenTrue", "reason": "None"}]},
        {"id": "numeric_order_stored", "inputs": [input_("reverse-stored.apk")], "scope_complete": True, "expected_load_status": "Complete", "expected_occurrences": sorted_archive, "queries": [{"id": "enumerate_six_definitions", "query": query(None, "enumerate"), "matching_count": 6, "decision": "NotApplicable", "reason": "None"}]},
        {"id": "numeric_order_deflate", "inputs": [input_("reverse-deflate.apk")], "scope_complete": True, "expected_load_status": "Complete", "expected_occurrences": sorted_archive, "queries": [{"id": "same_descriptor_three_occurrences", "query": query("locate"), "matching_count": 3, "decision": "ProvenFalse", "reason": "Ambiguous"}]},
        {"id": "identical_bytes_two_slots", "inputs": [input_("raw-a.dex"), input_("raw-a-copy.dex")], "scope_complete": True, "expected_load_status": "Complete", "expected_occurrences": [occurrence(0, None, None, "035"), occurrence(1, None, None, "035")], "queries": complete_two_queries},
        {"id": "same_path_two_slots", "inputs": [input_("raw-a.dex"), input_("raw-a.dex")], "scope_complete": True, "expected_load_status": "Complete", "expected_occurrences": [occurrence(0, None, None, "035"), occurrence(1, None, None, "035")], "queries": complete_two_queries},
        {"id": "different_dex_same_local_ids", "inputs": [input_("raw-a.dex"), input_("raw-b.dex")], "scope_complete": True, "expected_load_status": "Complete", "expected_occurrences": [occurrence(0, None, None, "035"), occurrence(1, None, None, "037")], "queries": complete_two_queries},
        {"id": "input_order_then_numeric_order", "inputs": [input_("raw-b.dex"), input_("reverse-stored.apk"), input_("raw-a.dex")], "scope_complete": True, "expected_load_status": "Complete", "expected_occurrences": [occurrence(0, None, None, "037")] + [{**item, "input_index": 1} for item in sorted_archive] + [occurrence(2, None, None, "035")], "queries": [{"id": "enumerate_ten_definitions", "query": query(None, "enumerate"), "matching_count": 10, "decision": "NotApplicable", "reason": "None"}]},
        {"id": "resource_split_allowed", "inputs": [input_("raw-a.dex"), input_("resource-only.apk", True)], "scope_complete": True, "expected_load_status": "Complete", "expected_occurrences": [occurrence(0, None, None, "035")], "queries": [{"id": "resource_slot_does_not_invent_code", "query": query("locate"), "matching_count": 1, "decision": "ProvenTrue", "reason": "None"}]},
        {"id": "resource_split_not_allowed", "inputs": [input_("raw-a.dex"), input_("resource-only.apk")], "scope_complete": True, "expected_load_status": "CorruptInput", "expected_occurrences": [], "queries": []},
        {"id": "incomplete_scope", "inputs": [input_("raw-a.dex")], "scope_complete": False, "expected_load_status": "Complete", "expected_occurrences": [occurrence(0, None, None, "035")], "queries": [
            {"id": "zero_is_undetermined", "query": query("external"), "matching_count": 0, "decision": "Undetermined", "reason": "SourceScopeIncomplete"},
            {"id": "one_is_undetermined", "query": query("locate"), "matching_count": 1, "decision": "Undetermined", "reason": "SourceScopeIncomplete"},
            {"id": "two_disprove_unique", "query": query(None), "matching_count": 2, "decision": "ProvenFalse", "reason": "Ambiguous"},
            {"id": "exists_zero_undetermined", "query": query("external", "exists"), "matching_count": 0, "decision": "Undetermined", "reason": "SourceScopeIncomplete"},
            {"id": "exists_witness_true", "query": query("locate", "exists"), "matching_count": 1, "decision": "ProvenTrue", "reason": "Witness"},
        ]},
    ]
    for filename in ["one-corrupt-dex.apk", "bad-crc.apk", "duplicate-entry.apk", "classes1-only.apk", "classes01-only.apk", "noncanonical-with-canonical.apk"]:
        cases.append({"id": filename.removesuffix(".apk"), "inputs": [input_("raw-a.dex"), input_(filename)], "scope_complete": True, "expected_load_status": "CorruptInput", "expected_occurrences": [], "queries": []})
    for case in cases:
        for source_index, item in enumerate(case["expected_occurrences"]):
            item["source_index"] = source_index
    manifest = {"schema_version": 1, "profile": "synthetic-multisource-metadata-fixtures-v1", "license": LICENSE, "independence": "Artificial source model and Python stdlib ZIP/DEX generator, not engine output or cache", "not_android_installable": True, "generator_dependency": {"path": "tests/fixtures/generators/generate_dex.py", "sha256": hashlib.sha256(generator_path.read_bytes()).hexdigest()}, "files": [{"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)} for name, data in files.items()], "manual_method_model": {"definitions": [{"method_index": 1, "owner": "Lsample/Example;", "name": "locate", "prototype": "()V", "access_flags": 1025, "code_offset": 0}, {"method_index": 2, "owner": "Lsample/Example;", "name": "second", "prototype": "()V", "access_flags": 265, "code_offset": 0}], "external_reference": {"method_index": 0, "owner": "Ljava/lang/Object;", "name": "external", "prototype": "()V", "is_definition": False}}, "cases": cases}
    (output / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-root", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "generated/multisource")
    args = parser.parse_args()
    result = build_fixtures(args.base_root.resolve(), args.output.resolve())
    print(json.dumps({"files": len(result["files"]), "cases": len(result["cases"]), "output": str(args.output.resolve())}))

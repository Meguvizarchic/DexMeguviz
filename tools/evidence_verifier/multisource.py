"""Independent SourceSet/ZIP oracle layered on the existing Python DEX oracle."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import struct
import sys
import zipfile

sys.dont_write_bytecode = True


class SourceError(ValueError):
    def __init__(self, message: str, status: str = "CorruptInput"):
        super().__init__(message)
        self.status = status


def load_base(base_root: Path):
    path = base_root / "tools/evidence_verifier/verify.py"
    spec = importlib.util.spec_from_file_location("dexmeguviz_independent_metadata_oracle", path)
    if spec is None or spec.loader is None:
        raise ValueError("Base metadata oracle unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def frame(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return str(len(encoded)).encode("ascii") + b":" + encoded


def occurrence_id(namespace: str, slot: str, role: str, entry_name: str | None, content_id: str) -> str:
    domain = "raw-input" if entry_name is None else "archive-entry"
    material = b"dmg:occurrence:v2:" + b"".join(frame(value) for value in (namespace, domain, slot, role, entry_name or "", content_id))
    return "occurrence:v2:" + sha(material)


def snapshot_id(namespace: str, scope_complete: bool, inputs: list[dict], sources: list[dict]) -> str:
    material = b"dmg:snapshot:source-set-v1:" + frame(namespace) + frame("complete" if scope_complete else "incomplete") + frame(str(len(inputs)))
    for item in inputs:
        material += b"".join(frame(value) for value in (item["slot_key"], item["role"], "1" if item["format"] == "RawDex" else "2", "1" if item["allow_no_dex"] else "0", item["content_id"]))
    material += frame(str(len(sources)))
    material += b"".join(frame(source["occurrence_id"]) for source in sources)
    return "snapshot:v2:" + sha(material)


def load_source_set(inputs: list[dict], fixture_root: Path, scope_complete: bool, base_root: Path, namespace: str = "cli-v1") -> dict:
    base = load_base(base_root)
    if not inputs or len(inputs) > 64:
        raise SourceError("Input count outside supported range", "InvalidArgument")
    loaded_inputs, sources = [], []
    for input_index, supplied in enumerate(inputs):
        path = (fixture_root / supplied["path"]).resolve()
        if not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
            raise SourceError("Fixture source missing or outside oracle byte bound")
        data = path.read_bytes()
        input_hash = sha(data)
        if supplied.get("expected_sha256") is not None and supplied["expected_sha256"] != input_hash:
            raise SourceError("Expected input digest mismatch", "SourceMismatch")
        role = "base" if input_index == 0 else "resource-split" if supplied.get("allow_no_dex") else "code-split"
        slot_key = supplied.get("slot_key", f"input:{input_index}:{path}")
        is_apk = supplied.get("kind") == "apk"
        pending = []
        if is_apk:
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    names = set()
                    dex_entries = []
                    for central_index, info in enumerate(archive.infolist()):
                        if info.filename in names:
                            raise SourceError("Duplicate central-directory entry name")
                        names.add(info.filename)
                        if info.filename == "classes.dex":
                            ordinal = 1
                        elif re.fullmatch(r"classes(?:[2-9]|[1-9][0-9]+)\.dex", info.filename):
                            ordinal = int(info.filename[7:-4])
                        elif re.fullmatch(r"classes[^/]*\.dex", info.filename):
                            raise SourceError("Noncanonical root DEX entry name")
                        else:
                            continue
                        if info.flag_bits & 1 or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                            raise SourceError("Unsupported archive entry encoding", "Unsupported")
                        if info.file_size > 64 * 1024 * 1024:
                            raise SourceError("Entry exceeds independent oracle bound", "BudgetExceeded")
                        dex_entries.append((ordinal, central_index, info))
                    if not dex_entries and not supplied.get("allow_no_dex", False):
                        raise SourceError("Code APK contains no canonical DEX entries")
                    for _, central_index, info in sorted(dex_entries):
                        # zipfile independently decompresses and verifies CRC while reading.
                        pending.append((archive.read(info), info.filename, central_index))
            except SourceError:
                raise
            except (zipfile.BadZipFile, RuntimeError, EOFError, OSError) as error:
                raise SourceError("ZIP parse/decompression/CRC failed: " + str(error)) from error
        else:
            pending.append((data, None, None))
        prepared = []
        for dex_bytes, entry_name, central_index in pending:
            try:
                parsed = base.parse_dex(dex_bytes)
            except ValueError as error:
                status = "Unsupported" if getattr(error, "status", None) == "Unsupported" else "CorruptInput"
                raise SourceError("DEX metadata invalid: " + str(error), status) from error
            counts = {"strings": struct.unpack_from("<I", dex_bytes, 56)[0], "types": struct.unpack_from("<I", dex_bytes, 64)[0], "classes": struct.unpack_from("<I", dex_bytes, 96)[0], "method_refs": len(parsed["references"]), "method_defs": len(parsed["definitions"])}
            content_id = f"sha256:raw-dex:v1:{len(dex_bytes)}:{parsed['source_sha256']}"
            logical_id = "logical-dex:v1:" + frame(content_id).decode("ascii") + "header-offset:0"
            occurrence = occurrence_id(namespace, slot_key, role, entry_name, content_id)
            prepared.append({"source_index": len(sources) + len(prepared), "input_index": input_index, "input_slot_key": slot_key, "slot_key": slot_key, "role": role, "entry_name": entry_name, "central_index": central_index, "source_sha256": parsed["source_sha256"], "content_id": content_id, "occurrence_id": occurrence, "logical_dex_id": logical_id, "archive_sha256": input_hash if is_apk else "", "version": parsed["version"], "source_bytes": len(dex_bytes), "counts": counts, "bytes": dex_bytes, "parsed": parsed})
        # Nothing is returned/published until every input and every DEX is valid.
        sources.extend(prepared)
        loaded_inputs.append({"input_index": input_index, "path": str(path), "slot_key": slot_key, "role": role, "format": "Apk" if is_apk else "RawDex", "source_sha256": input_hash, "content_id": f"sha256:{'apk' if is_apk else 'raw-dex'}:v1:{len(data)}:{input_hash}", "input_bytes": len(data), "source_count": len(prepared), "allow_no_dex": bool(supplied.get("allow_no_dex")), "expected_digest_verified": supplied.get("expected_sha256") is not None})
    if len(sources) > 1024:
        raise SourceError("Source count exceeds oracle bound", "BudgetExceeded")
    return {"inputs": loaded_inputs, "sources": sources, "scope_complete": bool(scope_complete), "source_namespace": namespace, "snapshot_id": snapshot_id(namespace, scope_complete, loaded_inputs, sources), "base_oracle": base}


def matching_definitions(dataset: dict, query: dict) -> list[dict]:
    matches = []
    for source in dataset["sources"]:
        for definition in dataset["base_oracle"].select_methods(source["parsed"], query):
            matches.append({**definition, "source_index": source["source_index"], "input_index": source["input_index"], "source_sha256": source["source_sha256"]})
    return matches


def check(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify_metadata(dataset: dict, output: dict) -> dict:
    check(output.get("schema_version") == 1 and output.get("profile") in ("dex-method-metadata-v1", "dex-query-method-v1"), "Unexpected SourceSet output schema/profile")
    expected_inputs, expected_sources = dataset["inputs"], dataset["sources"]
    check(output.get("input_count") == len(expected_inputs), "Input slot count mismatch")
    check(output.get("source_count") == len(expected_sources), "Logical source count mismatch")
    check(output.get("scope_complete") is dataset["scope_complete"], "Source scope flag mismatch")
    check(output.get("snapshot_id") == dataset["snapshot_id"], "Snapshot identity does not match independent framed input")
    check(output.get("input_bytes") == sum(item["input_bytes"] for item in expected_inputs), "Input byte accounting mismatch")
    check(output.get("dex_bytes") == sum(item["source_bytes"] for item in expected_sources), "DEX byte accounting mismatch")
    actual_inputs, actual_sources = output.get("inputs"), output.get("sources")
    check(isinstance(actual_inputs, list) and len(actual_inputs) == len(expected_inputs), "Input metadata list mismatch")
    check(isinstance(actual_sources, list) and len(actual_sources) == len(expected_sources), "Source metadata list mismatch")
    for expected, actual in zip(expected_inputs, actual_inputs):
        for field in ("input_index", "slot_key", "role", "format", "source_sha256", "content_id", "input_bytes", "source_count", "allow_no_dex", "expected_digest_verified"):
            check(actual.get(field) == expected[field], "Input metadata mismatch: " + field)
    occurrence_ids = []
    content_by_hash = {}
    for expected, actual in zip(expected_sources, actual_sources):
        for field in ("source_index", "input_index", "slot_key", "role", "source_sha256", "source_bytes", "archive_sha256", "content_id", "occurrence_id", "logical_dex_id", "counts"):
            check(actual.get(field) == expected[field], "Source metadata mismatch: " + field)
        check(actual.get("archive_entry_name") == (expected["entry_name"] or ""), "Archive entry name/numeric order mismatch")
        check(actual.get("archive_entry_index") == expected["central_index"], "Original central-directory index lost")
        check(actual.get("dex_version") == int(expected["version"]), "DEX version mismatch")
        check(actual.get("snapshot_id") == output["snapshot_id"], "Source snapshot binding mismatch")
        if expected["entry_name"] is None:
            check(actual.get("slot_key") == expected["input_slot_key"], "Raw source slot mismatch")
            check(actual.get("crc_verified") is False, "Raw DEX cannot claim archive CRC")
        else:
            check(actual.get("crc_verified") is True and actual.get("header_consistency_verified") is True, "Archive CRC/header verification missing")
        occurrence_ids.append(actual["occurrence_id"])
        previous_content = content_by_hash.setdefault(expected["source_sha256"], actual["content_id"])
        check(previous_content == actual["content_id"], "Identical DEX bytes have inconsistent content identities")
    check(len(set(occurrence_ids)) == len(occurrence_ids), "Distinct source appearances collapsed into one occurrence")
    single_raw = len(expected_inputs) == 1 and len(expected_sources) == 1 and expected_inputs[0]["format"] == "RawDex"
    compatibility = {field: expected_sources[0][field] if single_raw else None for field in ("source_sha256", "content_id", "occurrence_id", "logical_dex_id")}
    compatibility["dex_version"] = int(expected_sources[0]["version"]) if single_raw else None
    for field, expected in compatibility.items():
        check(field in output and output[field] == expected, "Top-level compatibility identity mismatch: " + field)
    if "counts" in output:
        aggregate = {name: sum(source["counts"][name] for source in expected_sources) for name in ("strings", "types", "classes", "method_refs", "method_defs")}
        check(output["counts"] == aggregate, "Aggregate counts lost a source occurrence")
    return {"input_count": len(expected_inputs), "source_count": len(expected_sources), "identity_fields_bound": True, "identity_digest_algorithms_recomputed": True}


def verify_source_set_result(dataset: dict, output: dict, query: dict) -> dict:
    report = verify_metadata(dataset, output)
    expected = {(item["source_index"], item["method_index"]): item for item in matching_definitions(dataset, query)}
    candidates = output.get("candidates")
    check(isinstance(candidates, list), "Candidates must be a list")
    total = sum(source["counts"]["method_defs"] for source in dataset["sources"])
    check(output.get("total_methods") == total, "Method total must include every logical source occurrence")
    visited = output.get("visited_methods")
    check(type(visited) is int and 0 <= visited <= total, "Invalid visited method count")
    groups = {}
    seen = set()
    for candidate in candidates:
        key = (candidate.get("source_index"), candidate.get("method_index"))
        check(key in expected and key not in seen, "Candidate is not a unique matching definition occurrence")
        seen.add(key)
        origin = output["sources"][key[0]]
        for field in ("source_index", "input_index", "source_sha256", "content_id", "occurrence_id", "logical_dex_id", "snapshot_id"):
            check(candidate.get(field) == origin.get(field), "Candidate origin mismatch: " + field)
        groups.setdefault(key[0], []).append(candidate)
    for source_index, projected_candidates in groups.items():
        source = dataset["sources"][source_index]
        # The established verifier checks provided rows against raw bytes. This synthetic
        # partial projection makes no local completeness claim; global proof is below.
        local = {"schema_version": 1, "profile": "raw-dex-metadata-v0", "execution_status": "Complete", "coverage": "Partial", "decision": "NotApplicable", "reason": "None", "visited_methods": source["counts"]["method_defs"], "total_methods": source["counts"]["method_defs"], "source_sha256": source["source_sha256"], "candidates": projected_candidates}
        dataset["base_oracle"].verify_result(source["bytes"], local, {**query, "intent": "enumerate"})
    coverage, decision, reason = output.get("coverage"), output.get("decision"), output.get("reason")
    check(coverage in {"Complete", "Partial"}, "Invalid coverage")
    if coverage == "Complete":
        check(dataset["scope_complete"] and visited == total and output.get("execution_status") == "Complete", "Complete coverage requires complete source scope and execution")
    intent = query.get("intent", "enumerate")
    if intent == "enumerate":
        check(decision == "NotApplicable", "Enumeration decision mismatch")
        if coverage == "Complete":
            check(seen == set(expected), "Complete enumeration omitted a definition occurrence")
        limit = query.get("max_results")
        if output.get("execution_status") == "Complete" and (limit is None or len(expected) < limit):
            check(visited == total and seen == set(expected), "Successful untruncated enumeration omitted known scope or candidates")
            check(coverage == ("Complete" if dataset["scope_complete"] else "Partial"), "Successful untruncated enumeration has wrong scope coverage")
    elif intent == "unique":
        if decision == "ProvenTrue":
            check(coverage == "Complete" and len(expected) == len(seen) == 1 and reason == "None", "Uniqueness claimed without complete scope")
        elif decision == "ProvenFalse":
            check((len(seen) >= 2 and reason == "Ambiguous") or (coverage == "Complete" and not expected and not seen and reason == "NoMatch"), "False uniqueness lacks accepted pair or complete absence proof")
        else:
            check(decision == "Undetermined" and coverage == "Partial" and len(seen) < 2, "Invalid undetermined uniqueness")
    elif intent == "exists":
        if decision == "ProvenTrue":
            check(bool(seen) and reason == "Witness", "Existence proof has no accepted witness")
        elif decision == "ProvenFalse":
            check(coverage == "Complete" and not expected and not seen and reason == "NoMatch", "Absence claimed without complete scope")
        else:
            check(decision == "Undetermined" and coverage == "Partial" and not seen, "Invalid undetermined existence")
    else:
        raise ValueError("Unsupported oracle result intent")
    if not dataset["scope_complete"] and visited == total and decision == "Undetermined" and output.get("execution_status") == "Complete":
        check(reason == "SourceScopeIncomplete", "Incomplete source scope lost explicit reason")
    if output.get("execution_status") == "Complete" and reason == "SourceScopeIncomplete":
        check(not dataset["scope_complete"] and visited == total, "Incomplete-scope reason requires exhausted known sources")
        if intent == "unique":
            check(len(expected) < 2 and seen == set(expected), "Incomplete-scope uniqueness dropped a known candidate or missed an ambiguity witness")
        elif intent == "exists":
            check(not expected and not seen, "Incomplete-scope existence missed a known witness")
        elif intent == "enumerate":
            check(seen == set(expected), "Incomplete-scope enumeration dropped known candidates")
    return {**report, "verified": True, "matching_occurrences": len(expected), "returned_candidates": len(seen), "scope_complete": dataset["scope_complete"], "decision": decision, "coverage": coverage, "verification_scope": "Independent archive/CRC/DEX bytes, framed content/occurrence/logical/snapshot identity derivation and query proof; no APK runtime"}


def verify_fixture_case(case: dict, fixtures: Path, base_root: Path) -> dict | None:
    try:
        dataset = load_source_set(case["inputs"], fixtures, case["scope_complete"], base_root)
    except SourceError as error:
        check(error.status == case["expected_load_status"], "Wrong fixture load outcome: " + case["id"])
        return None
    check(case["expected_load_status"] == "Complete", "Invalid fixture accepted: " + case["id"])
    actual = [{"input_index": source["input_index"], "source_index": source["source_index"], "entry_name": source["entry_name"], "central_index": source["central_index"], "dex_sha256": source["source_sha256"], "version": source["version"], "method_definition_count": source["counts"]["method_defs"], "method_reference_count": source["counts"]["method_refs"]} for source in dataset["sources"]]
    check(actual == case["expected_occurrences"], "Independent source order/count differs from manual expectation: " + case["id"])
    for query_case in case["queries"]:
        matches = matching_definitions(dataset, query_case["query"])
        check(len(matches) == query_case["matching_count"], "Independent match count differs from manual expectation")
    return dataset


def self_test(fixtures: Path, base_root: Path) -> dict:
    manifest = json.loads((fixtures / "manifest.json").read_text(encoding="utf-8"))
    for item in manifest["files"]:
        data = (fixtures / item["path"]).read_bytes()
        check(len(data) == item["bytes"] and sha(data) == item["sha256"], "Fixture hash drift")
    valid, rejected, queries = 0, 0, 0
    for case in manifest["cases"]:
        dataset = verify_fixture_case(case, fixtures, base_root)
        if dataset is None:
            rejected += 1
        else:
            valid += 1
            queries += len(case["queries"])
            for source in dataset["sources"]:
                for expected in manifest["manual_method_model"]["definitions"]:
                    definition = next(item for item in source["parsed"]["definitions"] if item["method_index"] == expected["method_index"])
                    check(all(definition[key] == value for key, value in expected.items()), "Manual method model mismatch")
                check(all(item["method_index"] != 0 for item in source["parsed"]["definitions"]), "External reference became definition")
    check(frame("雪") == b"3:\xe9\x9b\xaa", "Frame length must count UTF-8 bytes")
    content = "sha256:raw-dex:v1:448:" + "0" * 64
    raw = occurrence_id("cli-v1", "slot", "base", None, content)
    archive = occurrence_id("cli-v1", "slot", "base", "classes.dex", content)
    controlled_raw_slot = "archive-entry:" + frame("slot").decode() + frame("classes.dex").decode()
    check(raw != archive and occurrence_id("cli-v1", controlled_raw_slot, "base", None, content) != archive, "Raw/archive domain separator lost")
    check(frame("a:") + frame("b") != frame("a") + frame(":b"), "Framed concatenation ambiguity")
    return {"valid_source_cases": valid, "invalid_source_cases_rejected": rejected, "manual_query_counts_verified": queries, "fixture_files_hashed": len(manifest["files"]), "identity_framing_controls": 3, "engine_executed": False, "scope": "Independent ZIP+DEX fixture and identity specification self-check; not native integration proof"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", type=Path, default=Path(__file__).resolve().parents[2] / "tests/fixtures/generated/multisource")
    parser.add_argument("--base-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if not args.self_test:
        parser.error("Use --self-test; integration imports verify_source_set_result")
    print(json.dumps(self_test(args.fixtures.resolve(), args.base_root.resolve()), indent=2))

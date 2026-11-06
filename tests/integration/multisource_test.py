"""Behavioral CLI integration for ordered DEX/APK SourceSets using independent bytes."""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True


def load_oracle(project_root: Path):
    path = project_root / "tools/evidence_verifier/multisource.py"
    spec = importlib.util.spec_from_file_location("independent_multisource_oracle", path)
    if spec is None or spec.loader is None:
        raise ValueError("Multisource oracle unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_suite(exe: Path, fixtures: Path, project_root: Path, base_root: Path, run_id: str, results_root: Path) -> dict:
    oracle = load_oracle(project_root)
    fixture_report = oracle.self_test(fixtures, base_root)
    manifest_path = fixtures / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not re.fullmatch(r"[A-Za-z0-9_-]+", run_id):
        raise ValueError("Unsafe result run identifier")
    result_dir = results_root / run_id
    result_dir.mkdir(parents=True, exist_ok=False)
    query_dir = result_dir / "queries"
    query_dir.mkdir()
    records, datasets, inspect_outputs, query_outputs = [], {}, {}, {}
    executable_before = hashlib.sha256(exe.read_bytes()).hexdigest()

    def safe_id(value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            raise ValueError("Unsafe fixture identifier")
        return value

    def command(case: dict, operation: str, query_path: Path | None = None) -> list[str]:
        args = [str(exe), operation, str((fixtures / case["inputs"][0]["path"]).resolve()), "--json"]
        for item in case["inputs"][1:]:
            args.extend(["--resource-source" if item.get("allow_no_dex") else "--source", str((fixtures / item["path"]).resolve())])
        if not case["scope_complete"]:
            args.append("--scope-incomplete")
        if query_path is not None:
            args.extend(["--query", str(query_path)])
        return args

    def execute(identifier: str, args: list[str]) -> tuple[int, dict]:
        invocation = subprocess.run(args, capture_output=True, timeout=30)
        (result_dir / (identifier + ".stdout.json")).write_bytes(invocation.stdout)
        (result_dir / (identifier + ".stderr.txt")).write_bytes(invocation.stderr)
        records.append({"id": identifier, "command": args, "exit_code": invocation.returncode, "stdout_sha256": hashlib.sha256(invocation.stdout).hexdigest(), "stderr_sha256": hashlib.sha256(invocation.stderr).hexdigest()})
        (result_dir / "commands.json").write_text(json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        output = json.loads(invocation.stdout.decode("utf-8"))
        return invocation.returncode, output

    for case in manifest["cases"]:
        identifier = safe_id(case["id"])
        dataset = oracle.verify_fixture_case(case, fixtures, base_root)
        exit_code, output = execute(identifier + "-inspect", command(case, "inspect"))
        if dataset is None:
            oracle.check(exit_code != 0, "Invalid SourceSet returned success: " + identifier)
            oracle.check(output.get("execution_status") == case["expected_load_status"], "Wrong failure status: " + identifier)
            oracle.check(output.get("coverage") == "Partial" and output.get("decision") == "Undetermined", "Failed load produced a complete decision")
            oracle.check(not output.get("sources") and not output.get("candidates") and not output.get("snapshot_id"), "Atomic source load published partial data")
            continue
        oracle.check(exit_code == 0 and output.get("execution_status") == "Complete", "Valid SourceSet failed: " + identifier)
        oracle.verify_metadata(dataset, output)
        oracle.check(output.get("coverage") == ("Complete" if case["scope_complete"] else "Partial"), "Inspect scope coverage mismatch")
        oracle.check(output.get("reason") == ("None" if case["scope_complete"] else "SourceScopeIncomplete"), "Inspect scope reason mismatch")
        datasets[identifier] = dataset
        inspect_outputs[identifier] = output
        for query_case in case["queries"]:
            query_id = identifier + "-" + safe_id(query_case["id"])
            query_path = (query_dir / (query_id + ".json")).resolve()
            query_path.write_text(json.dumps(query_case["query"], ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            exit_code, output = execute(query_id, command(case, "query", query_path))
            oracle.check(exit_code == 0 and output.get("execution_status") == "Complete", "Fixture query execution failed: " + query_id)
            oracle.verify_source_set_result(dataset, output, query_case["query"])
            oracle.check(output.get("decision") == query_case["decision"] and output.get("reason") == query_case["reason"], "Manual expected decision mismatch: " + query_id)
            query_outputs[(identifier, query_case["id"])] = (output, query_case["query"])

    oracle.check(inspect_outputs["single_complete"]["snapshot_id"] != inspect_outputs["incomplete_scope"]["snapshot_id"], "Snapshot identity omitted source scope flag")
    oracle.check(inspect_outputs["single_complete"]["snapshot_id"] != inspect_outputs["resource_split_allowed"]["snapshot_id"], "Snapshot identity omitted resource-only input")
    for case_id in ("identical_bytes_two_slots", "same_path_two_slots"):
        sources = inspect_outputs[case_id]["sources"]
        oracle.check(len(sources) == 2 and sources[0]["source_sha256"] == sources[1]["source_sha256"] and sources[0]["content_id"] == sources[1]["content_id"], "Duplicate physical content was not represented consistently")
        oracle.check(sources[0]["occurrence_id"] != sources[1]["occurrence_id"], "Different slots with identical bytes lost occurrence identity")

    rejected_forgeries = []

    def must_reject(name: str, action) -> None:
        try:
            action()
        except ValueError:
            rejected_forgeries.append(name)
            return
        raise AssertionError("Independent verifier accepted forged output: " + name)

    real, query = query_outputs[("single_complete", "one_is_unique_in_complete_scope")]
    forged = copy.deepcopy(real)
    forged["candidates"][0]["declaration_offset"] = 0
    must_reject("candidate_declaration_offset", lambda: oracle.verify_source_set_result(datasets["single_complete"], forged, query))
    forged = copy.deepcopy(real)
    forged["coverage"] = "Partial"
    must_reject("partial_unique_claim", lambda: oracle.verify_source_set_result(datasets["single_complete"], forged, query))
    real, query = query_outputs[("identical_bytes_two_slots", "same_descriptor_is_two_occurrences")]
    forged = copy.deepcopy(real)
    forged["candidates"][1] = copy.deepcopy(forged["candidates"][0])
    must_reject("duplicate_method_occurrence", lambda: oracle.verify_source_set_result(datasets["identical_bytes_two_slots"], forged, query))
    forged = copy.deepcopy(inspect_outputs["numeric_order_stored"])
    forged["sources"][0], forged["sources"][1] = forged["sources"][1], forged["sources"][0]
    must_reject("wrong_numeric_source_order", lambda: oracle.verify_metadata(datasets["numeric_order_stored"], forged))
    forged = copy.deepcopy(inspect_outputs["numeric_order_stored"])
    forged["sources"][0]["archive_entry_index"] = 0
    must_reject("central_index_replaced_by_sorted_index", lambda: oracle.verify_metadata(datasets["numeric_order_stored"], forged))
    forged = copy.deepcopy(inspect_outputs["resource_split_allowed"])
    forged["inputs"].pop()
    forged["input_count"] = 1
    must_reject("resource_only_input_dropped", lambda: oracle.verify_metadata(datasets["resource_split_allowed"], forged))
    forged = copy.deepcopy(inspect_outputs["same_path_two_slots"])
    forged["sources"][1]["occurrence_id"] = forged["sources"][0]["occurrence_id"]
    must_reject("same_bytes_slots_deduplicated", lambda: oracle.verify_metadata(datasets["same_path_two_slots"], forged))
    forged = copy.deepcopy(inspect_outputs["single_complete"])
    forged["snapshot_id"] = "snapshot:v2:" + "0" * 64
    for source in forged["sources"]:
        source["snapshot_id"] = forged["snapshot_id"]
    must_reject("consistent_but_wrong_snapshot_hash", lambda: oracle.verify_metadata(datasets["single_complete"], forged))
    real, query = query_outputs[("numeric_order_stored", "enumerate_six_definitions")]
    forged = copy.deepcopy(real)
    forged["coverage"] = "Partial"
    forged["candidates"] = []
    must_reject("complete_enumeration_downgraded_to_partial_and_emptied", lambda: oracle.verify_source_set_result(datasets["numeric_order_stored"], forged, query))
    real, query = query_outputs[("incomplete_scope", "one_is_undetermined")]
    forged = copy.deepcopy(real)
    forged["candidates"] = []
    must_reject("incomplete_scope_known_candidate_dropped", lambda: oracle.verify_source_set_result(datasets["incomplete_scope"], forged, query))
    forged = copy.deepcopy(inspect_outputs["numeric_order_stored"])
    forged["content_id"] = forged["sources"][0]["content_id"]
    must_reject("multi_source_top_level_content_identity_invented", lambda: oracle.verify_metadata(datasets["numeric_order_stored"], forged))
    forged = copy.deepcopy(inspect_outputs["single_complete"])
    forged["occurrence_id"] = "occurrence:v2:" + "0" * 64
    must_reject("single_raw_top_level_occurrence_disagrees", lambda: oracle.verify_metadata(datasets["single_complete"], forged))
    executable_after = hashlib.sha256(exe.read_bytes()).hexdigest()
    oracle.check(executable_before == executable_after, "Executable changed during evidence run")
    report = {"schema_version": 1, "run_id": run_id, "result_directory": str(result_dir), "fixture_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(), "executable": str(exe), "executable_sha256": executable_after, "executable_stable_during_run": True, "fixture_self_check": fixture_report, "source_cases": len(manifest["cases"]), "query_cases": len(query_outputs), "CLI_invocations": len(records), "forged_evidence_rejected": rejected_forgeries, "snapshot_scope_and_resource_identity_checks": 2, "same_bytes_distinct_slot_cases": 2, "failed": 0, "commands": records, "scope": "Synthetic raw DEX/APK metadata SourceSet behavior; no real APK, Android execution, full opcode verifier, BIL runtime or performance acceptance"}
    (result_dir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    project = Path(__file__).resolve().parents[2]
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, default=project / "tests/fixtures/generated/multisource")
    parser.add_argument("--base-root", type=Path, default=project)
    parser.add_argument("--run-id", default=datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%S%fZ"))
    parser.add_argument("--results-root", type=Path)
    args = parser.parse_args()
    try:
        results_root = (args.results_root or args.base_root / "docs/evidence/multisource-cli").resolve()
        result = run_suite(args.exe.resolve(), args.fixtures.resolve(), project, args.base_root.resolve(), args.run_id, results_root)
        print(json.dumps({key: value for key, value in result.items() if key != "commands"}, ensure_ascii=False, indent=2))
    except (ValueError, OSError, subprocess.SubprocessError, AssertionError) as error:
        print(json.dumps({"failed": True, "reason": str(error)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(1)

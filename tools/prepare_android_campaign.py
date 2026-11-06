"""Prepare coordinator inputs from a finalized protocol; this does not run or authenticate a campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import sys

from analyze_benchmark import canonical, pointer

MAX_PROTOCOL_BYTES = 4 * 1024 * 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")
EXPECTED_ORDER = 'BACACBCABABCBACBACACBBACACBCBABCACABBCAABCCBACABCABCBAABCCBAABCBACCBAABCBCACABBCAACBACBBCA'
FIXED_CONTRACT = {'gate_lists': {'minimum_valid_pairs_per_required_case': 30, 'maximum_failed_or_excluded_or_missing_formal_records': 0, 'L0_zero_counters': ['native_scan_load_count', 'whole_APK_hash_count', 'source_open_count', 'scan_count', 'index_build_count'], 'external_gate_evidence_required': ['runtime_binding_and_33_rule_correctness', 'resource_lifecycle_cancel_close', 'BIL_and_portable_consumer_semantic_reuse'], 'absolute_regression_contrasts': ['A_to_C', 'B_to_C']}, 'statistics': {'method': 'paired_block_percentile', 'replicates': 10000, 'confidence': 0.95, 'seed': 20261027}, 'routes': {'time_primary': {'contrast': ['B', 'C'], 'case': 'cold_adaptation', 'metric': 'full_task_ms', 'minimum_reduction': 0.15, 'pass_if_ratio_CI_upper_at_most': 0.85}, 'memory_alternative': {'contrast': ['B', 'C'], 'case': 'cold_adaptation', 'metric': 'observed_incremental_peak_pss_bytes', 'minimum_reduction': 0.25, 'pass_if_ratio_CI_upper_at_most': 0.75, 'time_regression_maximum': 0.05, 'pass_if_time_ratio_CI_upper_at_most': 1.05}}}
REQUIRED_POINTERS = ('/finalized_at_utc', '/rule_manifest/sha256', '/run_identity/rule_manifest_sha256', '/run_identity/common_projection_schema_sha256', '/run_identity/runtime_verifier_profile_sha256', '/run_identity/expected_projection_sha256_by_case', '/run_identity/APK_sources_ordered', '/run_identity/backend_builds/A', '/run_identity/backend_builds/B', '/run_identity/backend_builds/C', '/run_identity/B_optimization_patch_sha256', '/run_identity/toolchain_and_dependency_lock_sha256', '/run_identity/device', '/run_identity/OS_build', '/run_identity/ABI', '/run_identity/page_size_bytes', '/run_identity/thread_count', '/run_identity/controlled_budget_bytes', '/run_identity/feature_flags', '/run_identity/enabled_capabilities', '/run_identity/foreground_script_sha256', '/run_identity/cache_reset_and_verification_script_sha256', '/run_identity/runner_sha256', '/run_identity/measurement_clock_and_instrumentation_sha256', '/run_identity/power_temperature_policy', '/run_identity/OS_page_cache_observation_policy', '/run_identity/LSPosed_module_and_host_identity', '/gates/L0_absolute_regression_tolerance_ms', '/gates/warm_absolute_regression_tolerance_ms', '/gates/foreground_p95_absolute_regression_tolerance_ms', '/gates/post_close_residual_tolerance_bytes')


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def prepare(data: bytes) -> dict:
    if not data or len(data) > MAX_PROTOCOL_BYTES:
        raise ValueError("protocol is empty or exceeds 4 MiB")
    protocol = json.loads(data.decode("utf-8-sig"), object_pairs_hook=_unique_object,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON number")))
    if not isinstance(protocol, dict) or type(protocol.get("schema_version")) is not int or protocol.get("schema_version") != 1:
        raise ValueError("unsupported protocol schema")
    if protocol.get("status") != "finalized_before_formal_C_results" or protocol.get("formal_runner_ready") is not True or protocol.get("formal_C_results_observed") is not False:
        raise ValueError("protocol is not finalized for formal collection")
    required = protocol.get("required_before_run")
    if not isinstance(required, list) or not required or any(not isinstance(x, str) or not x.startswith("/") for x in required):
        raise ValueError("invalid required field list")
    if not set(REQUIRED_POINTERS).issubset(required):
        raise ValueError("mandatory required field list has changed")
    missing = [x for x in required if pointer(protocol, x) is None or pointer(protocol, x) == "" or pointer(protocol, x) == {} or pointer(protocol, x) == []]
    if missing:
        raise ValueError("required protocol fields missing: " + ", ".join(missing))
    identity = protocol.get("run_identity")
    if not isinstance(identity, dict):
        raise ValueError("run identity missing")
    sampling = protocol.get("sampling")
    if not isinstance(sampling, dict) or sampling.get("paired_triplets_per_case") != 30 or sampling.get("warmup_triplets_per_case") != 5:
        raise ValueError("unsupported coordinator sampling")
    orders = sampling.get("run_order")
    if not isinstance(orders, list) or len(orders) != 30 or any(not isinstance(row, list) or len(row) != 3 or sorted(row) != ["A", "B", "C"] for row in orders):
        raise ValueError("invalid run order")
    if "".join("".join(row) for row in orders) != EXPECTED_ORDER:
        raise ValueError("run order differs from coordinator v1")
    if sampling.get("warm_queries_per_snapshot") != 10 or sampling.get("foreground_frames_minimum_per_run") != 1000:
        raise ValueError("unsupported warm-query or foreground sampling")
    routes = protocol.get("decision_routes")
    if not isinstance(routes, dict):
        raise ValueError("decision routes must be an object")
    if routes.get("acceptance_rule") != "time_and_memory_all_required_scenarios_v3" or routes.get("A_to_C_strict_superiority") != {"contrast": ["A", "C"], "case": "cold_adaptation", "metrics": ["full_task_ms", "observed_incremental_peak_pss_bytes"], "pass_if_ratio_CI_upper_strictly_below": 1.0} or routes.get("auxiliary_strict_superiority") != {"contrasts": ["A_to_C", "B_to_C"], "cases": {"full_L0_hit": "full_task_ms", "snapshot_warm_query": "warm_query_ms", "foreground_adaptation": "foreground_frame_p95_ms"}, "pass_if_difference_CI_upper_strictly_below_ms": 0.0}:
        raise ValueError("unsupported performance decision routes")
    if any(routes.get(key) != value for key, value in FIXED_CONTRACT["routes"].items()):
        raise ValueError("unsupported primary performance thresholds")
    fixed_gates = protocol.get("gates")
    if not isinstance(fixed_gates, dict) or any(fixed_gates.get(key) != value for key, value in FIXED_CONTRACT["gate_lists"].items()):
        raise ValueError("unsupported external, counter or comparison gates")
    stats = protocol.get("statistics")
    bootstrap = stats.get("bootstrap") if isinstance(stats, dict) else None
    if not isinstance(bootstrap, dict) or any(bootstrap.get(key) != value for key, value in FIXED_CONTRACT["statistics"].items()):
        raise ValueError("unsupported bootstrap contract")
    manifest = protocol.get("rule_manifest")
    if not isinstance(manifest, dict) or not isinstance(manifest.get("sha256"), str) or not HEX.fullmatch(manifest["sha256"]) or manifest.get("enum_count") != 33 or identity.get("rule_manifest_sha256") != manifest["sha256"]:
        raise ValueError("rule manifest identity mismatch")
    for key in ("BIL_commit", "OS_build", "ABI"):
        if not isinstance(identity.get(key), str) or not identity[key].strip():
            raise ValueError("nonempty identity text required: " + key)
    for key in ("power_temperature_policy", "OS_page_cache_observation_policy", "LSPosed_module_and_host_identity"):
        value = identity.get(key)
        if not ((isinstance(value, str) and value.strip()) or (isinstance(value, dict) and value)):
            raise ValueError("nonempty identity field required: " + key)
    for key in ("page_size_bytes", "thread_count", "controlled_budget_bytes"):
        if type(identity.get(key)) is not int or identity[key] <= 0:
            raise ValueError("invalid positive identity field: " + key)
    for key in ("device", "feature_flags", "enabled_capabilities"):
        if not isinstance(identity.get(key), dict) or (key != "enabled_capabilities" and not identity[key]):
            raise ValueError("identity object required: " + key)
    sources = identity.get("APK_sources_ordered")
    if not isinstance(sources, list) or not sources or any(not isinstance(x, dict) or not x for x in sources):
        raise ValueError("ordered source identity objects required")
    for source in sources:
        if not isinstance(source.get("slot"), str) or not source["slot"] or not isinstance(source.get("package"), str) or not source["package"] or not isinstance(source.get("versionName"), str) or type(source.get("versionCode")) is not int or source["versionCode"] < 0 or type(source.get("byte_length")) is not int or source["byte_length"] <= 0 or not isinstance(source.get("sha256"), str) or not HEX.fullmatch(source["sha256"]) or not isinstance(source.get("intake_revision"), str) or not source["intake_revision"]:
            raise ValueError("invalid ordered APK source identity")
    if len({source["slot"] for source in sources}) != len(sources):
        raise ValueError("duplicate source slot")
    for key in ("common_projection_schema_sha256", "runtime_verifier_profile_sha256", "B_optimization_patch_sha256", "toolchain_and_dependency_lock_sha256", "foreground_script_sha256", "cache_reset_and_verification_script_sha256", "runner_sha256", "measurement_clock_and_instrumentation_sha256"):
        if not isinstance(identity.get(key), str) or not HEX.fullmatch(identity[key]):
            raise ValueError("identity SHA-256 required: " + key)
    gates = protocol.get("gates")
    for key in ("L0_absolute_regression_tolerance_ms", "warm_absolute_regression_tolerance_ms", "foreground_p95_absolute_regression_tolerance_ms", "post_close_residual_tolerance_bytes"):
        value = gates.get(key) if isinstance(gates, dict) else None
        try:
            valid = type(value) in (int, float) and math.isfinite(value) and value >= 0
        except OverflowError:
            valid = False
        if not valid:
            raise ValueError("invalid numeric gate: " + key)
    builds = identity.get("backend_builds")
    if not isinstance(builds, dict) or any(not isinstance(builds.get(x), dict) or not builds[x] for x in "ABC"):
        raise ValueError("three backend build identities are required")
    for name in "ABC":
        build = builds[name]
        if not isinstance(build.get("source_commit"), str) or not build["source_commit"] or not isinstance(build.get("artifact_sha256"), str) or not HEX.fullmatch(build["artifact_sha256"]) or not isinstance(build.get("toolchain_lock_sha256"), str) or not HEX.fullmatch(build["toolchain_lock_sha256"]) or not isinstance(build.get("build_flags"), (dict, list)) or not (build.get("clean") is True or isinstance(build.get("dirty_patch_sha256"), str) and HEX.fullmatch(build["dirty_patch_sha256"])):
            raise ValueError("invalid backend build identity: " + name)
        if build.get("clean") is True and build.get("dirty_patch_sha256") not in (None, ""):
            raise ValueError("conflicting clean and dirty build identity: " + name)
    caps = identity.get("enabled_capabilities")
    if not isinstance(caps, dict) or type(caps.get("persistent_facts", False)) is not bool:
        raise ValueError("invalid persistent-facts capability")
    projections = identity.get("expected_projection_sha256_by_case")
    cases = protocol.get("cases")
    if not isinstance(cases, dict) or not isinstance(projections, dict):
        raise ValueError("cases or expected projections missing")
    expected_cases = ["cold_adaptation", "full_L0_hit", "snapshot_warm_query", "foreground_adaptation"]
    if caps.get("persistent_facts", False):
        expected_cases.append("persistent_fact_hit")
    for name in ("cold_adaptation", "full_L0_hit", "snapshot_warm_query", "foreground_adaptation"):
        if not isinstance(cases.get(name), dict) or cases[name].get("required") is not True:
            raise ValueError("required case mismatch: " + name)
    if not isinstance(cases.get("persistent_fact_hit"), dict) or cases["persistent_fact_hit"].get("required") is not False or cases["persistent_fact_hit"].get("required_if_capability") != "persistent_facts":
        raise ValueError("persistent case mismatch")
    if any(name not in ("cold_adaptation", "full_L0_hit", "snapshot_warm_query", "foreground_adaptation", "persistent_fact_hit") and (not isinstance(case, dict) or case.get("required") or case.get("required_if_capability")) for name, case in cases.items()):
        raise ValueError("unsupported additional active case")
    if any(name not in cases or not isinstance(projections.get(name), str) or not HEX.fullmatch(projections[name]) for name in expected_cases):
        raise ValueError("expected case projections must be lowercase SHA-256")
    identity_bytes = canonical(identity)
    return {"status": "prepared_not_authenticated", "protocol_sha256": hashlib.sha256(data).hexdigest(),
            "identity_sha256": hashlib.sha256(identity_bytes).hexdigest(),
            "identity_json": identity_bytes.decode("utf-8"),
            "declared_order": ["".join(row) for row in orders],
            "backend_builds": {name: builds[name] for name in "ABC"},
            "expected_projections": {name: projections[name] for name in expected_cases},
            "persistent_facts": caps.get("persistent_facts", False),
            "scope": "declared protocol only; no backend, device, correctness or performance authentication"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("protocol", type=Path)
    args = parser.parse_args()
    try:
        with args.protocol.open("rb") as file:
            data = file.read(MAX_PROTOCOL_BYTES + 1)
        print(json.dumps(prepare(data), ensure_ascii=False, separators=(",", ":")))
        return 0
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError, OverflowError) as error:
        print(json.dumps({"status": "rejected", "reason": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

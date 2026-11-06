"""Analyze identity-bound paired A/B/C records; synthetic controls never pass release gates."""

from __future__ import annotations

import argparse
import collections
import copy
import hashlib
import json
import math
from pathlib import Path
import random
import statistics
import sys
from unittest.mock import patch


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def read_json(path: Path) -> tuple[dict, str]:
    if path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError("Input exceeds 128 MiB analysis bound")
    data = path.read_bytes()
    value = json.loads(data.decode("utf-8-sig"), parse_constant=lambda token: (_ for _ in ()).throw(ValueError("Nonfinite JSON number: " + token)))
    if not isinstance(value, dict):
        raise ValueError("Expected JSON object")
    return value, hashlib.sha256(data).hexdigest()


def pointer(value: dict, path: str):
    try:
        for part in path.strip("/").split("/"):
            value = value[part]
        return value
    except (KeyError, TypeError):
        return None


def finite(value, positive: bool = False) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and (value > 0 if positive else value >= 0)


def quantile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    left, right = math.floor(position), math.ceil(position)
    return ordered[left] + (ordered[right] - ordered[left]) * (position - left)


def paired_summary(pairs: list[tuple[float, float]], protocol: dict, key: str, ratio: bool) -> dict:
    if not pairs:
        return {"estimable": False, "reason": "no_valid_complete_pairs", "pairs": 0}
    if ratio and any(left <= 0 or right <= 0 for left, right in pairs):
        return {"estimable": False, "reason": "nonpositive_ratio_operand", "pairs": len(pairs)}
    values = [math.log(right / left) if ratio else right - left for left, right in pairs]
    config = protocol["statistics"]["bootstrap"]
    seed = int.from_bytes(hashlib.sha256((str(config["seed"]) + ":" + key).encode()).digest()[:8], "big")
    generator = random.Random(seed)
    count = len(values)
    replicates = [sum(values[generator.randrange(count)] for _ in range(count)) / count for _ in range(config["replicates"])]
    convert = math.exp if ratio else lambda item: item
    alpha = (1 - config["confidence"]) / 2
    return {"estimable": True, "pairs": count, "estimator": "geometric_mean_paired_ratio" if ratio else "mean_paired_difference", "estimate": convert(statistics.mean(values)), "CI95": [convert(quantile(replicates, alpha)), convert(quantile(replicates, 1 - alpha))], "bootstrap_replicates": config["replicates"], "bootstrap_seed_derived": seed, "from_median": statistics.median(left for left, _ in pairs), "to_median": statistics.median(right for _, right in pairs)}


def external_gates(protocol: dict, raw: dict, identity_hash: str, evidence_root: Path | None) -> dict:
    outcomes = {}
    supplied = raw.get("external_gate_evidence") if isinstance(raw.get("external_gate_evidence"), dict) else {}
    for name in protocol["gates"]["external_gate_evidence_required"]:
        entry = supplied.get(name)
        reason = "missing_evidence"
        try:
            if not isinstance(entry, dict) or evidence_root is None:
                raise ValueError(reason)
            if entry.get("status") != "passed" or entry.get("complete") is not True or entry.get("identity_sha256") != identity_hash:
                raise ValueError("gate_status_or_identity_mismatch")
            relative = Path(entry["evidence_path"])
            base = evidence_root.resolve()
            path = (base / relative).resolve()
            if relative.is_absolute() or not path.is_relative_to(base):
                raise ValueError("gate_evidence_path_outside_raw_directory")
            payload, actual_hash = read_json(path)
            if actual_hash != entry.get("sha256"):
                raise ValueError("gate_file_digest_mismatch")
            if payload.get("status") != "passed" or payload.get("complete") is not True or payload.get("identity_sha256") != identity_hash:
                raise ValueError("gate_file_status_or_identity_mismatch")
            outcomes[name] = {"passed": True, "evidence_path": entry["evidence_path"], "sha256": actual_hash, "scope": "matched supplied evidence; analyzer did not execute this external gate"}
            continue
        except (ValueError, KeyError, OSError) as error:
            reason = str(error)
        outcomes[name] = {"passed": False, "reason": reason}
    return outcomes


def analyze(protocol: dict, raw: dict, protocol_hash: str, evidence_root: Path | None = None) -> dict:
    if protocol.get("decision_routes", {}).get("acceptance_rule") != "time_and_memory_all_required_scenarios_v3":
        raise ValueError("Unsupported acceptance rule; use the analyzer version bound to the historical protocol")
    if protocol["decision_routes"].get("A_to_C_strict_superiority") != {"contrast": ["A", "C"], "case": "cold_adaptation", "metrics": ["full_task_ms", "observed_incremental_peak_pss_bytes"], "pass_if_ratio_CI_upper_strictly_below": 1.0}:
        raise ValueError("Unsupported original DexKit superiority gate")
    strict_spec = {"contrasts": ["A_to_C", "B_to_C"], "cases": {"full_L0_hit": "full_task_ms", "snapshot_warm_query": "warm_query_ms", "foreground_adaptation": "foreground_frame_p95_ms"}, "pass_if_difference_CI_upper_strictly_below_ms": 0.0}
    if protocol["decision_routes"].get("auxiliary_strict_superiority") != strict_spec:
        raise ValueError("Unsupported strict L0, warm or foreground superiority gate")
    pending = [path for path in protocol["required_before_run"] if pointer(protocol, path) is None]
    registration_ready = not pending and protocol.get("status") == "finalized_before_formal_C_results" and protocol.get("formal_runner_ready") is True
    identity = protocol["run_identity"]
    identity_hash = digest(identity)
    integrity_errors = []
    if raw.get("schema_version") != 1:
        integrity_errors.append("raw_schema_version_mismatch")
    if raw.get("protocol_sha256") != protocol_hash:
        integrity_errors.append("protocol_digest_mismatch")
    if raw.get("identity") != identity:
        integrity_errors.append("campaign_identity_mismatch")
    if not isinstance(raw.get("campaign_id"), str) or not raw["campaign_id"]:
        integrity_errors.append("missing_campaign_id")
    if raw.get("data_kind") not in {"real", "synthetic_control"}:
        integrity_errors.append("invalid_data_kind")
    records = raw.get("records")
    if not isinstance(records, list) or len(records) > 100000:
        raise ValueError("records must be a bounded list")
    capabilities = identity.get("enabled_capabilities") or {}
    required_cases = [name for name, case in protocol["cases"].items() if case.get("required") or bool(capabilities.get(case.get("required_if_capability")))]
    selected_cases = set(required_cases)
    measured_count = protocol["sampling"]["paired_triplets_per_case"]
    warmup_count = protocol["sampling"]["warmup_triplets_per_case"]
    expected_keys = {(case, phase, triplet, backend) for case in required_cases for phase, total in (("measured", measured_count), ("warmup", warmup_count)) for triplet in range(1, total + 1) for backend in "ABC"}
    indexed = collections.defaultdict(list)
    failures = []
    statuses = collections.Counter()
    phase_counts = collections.Counter()
    reason_counts = collections.Counter()
    successful = {}

    for index, row in enumerate(records):
        reasons = []
        if not isinstance(row, dict):
            failures.append({"record_index": index, "reasons": ["record_not_object"]})
            reason_counts["record_not_object"] += 1
            continue
        case, phase, triplet, backend = row.get("case"), row.get("phase"), row.get("triplet_id"), row.get("backend")
        statuses[str(row.get("status", "missing"))] += 1
        phase_counts[str(phase)] += 1
        key = (case, phase, triplet, backend)
        valid_key_types = isinstance(case, str) and isinstance(phase, str) and type(triplet) is int and isinstance(backend, str)
        if not valid_key_types or case not in selected_cases or phase not in {"measured", "warmup"} or backend not in {"A", "B", "C"} or key not in expected_keys:
            reasons.append("unexpected_case_phase_triplet_or_backend")
        else:
            indexed[key].append(index)
            order = protocol["sampling"]["run_order"][triplet - 1]
            if type(row.get("order_position")) is not int or row.get("order_position") != order.index(backend) + 1:
                reasons.append("run_order_mismatch")
        expected_build = identity["backend_builds"].get(backend) if isinstance(backend, str) else None
        if row.get("identity_sha256") != identity_hash or row.get("backend_build_identity") != expected_build:
            reasons.append("record_identity_mismatch")
            integrity_errors.append("record_identity_mismatch:" + str(index))
        if row.get("complete") is not True:
            reasons.append("incomplete_execution")
        if row.get("status") != "ok":
            reasons.append("execution_failed")
        if row.get("correctness_passed") is not True:
            reasons.append("correctness_failed_or_unverified")
        expected_projection = (identity.get("expected_projection_sha256_by_case") or {}).get(case) if isinstance(case, str) else None
        if not expected_projection or row.get("projection_sha256") != expected_projection:
            reasons.append("product_projection_mismatch")
        if row.get("environment_valid") is not True:
            reasons.append("environment_invalid_or_unverified")
        exclusion = row.get("exclusion_reason")
        if exclusion is not None:
            reasons.append("excluded_record")
            if exclusion not in protocol["failures_exclusions_stopping"]["allowed_environmental_exclusion_reasons"]:
                reasons.append("unregistered_exclusion")
        metrics = row.get("metrics") if isinstance(row.get("metrics"), dict) else {}
        names = protocol["raw_schema"]["metrics"]
        if any(not finite(metrics.get(name), name == "full_task_ms") for name in names):
            reasons.append("invalid_or_missing_metrics")
        elif metrics["first_answer_ms"] > metrics["full_task_ms"] or metrics["prepare_ms"] + metrics["close_ms"] > metrics["full_task_ms"]:
            reasons.append("timer_envelope_inconsistent")
        if case == "full_L0_hit":
            counters = row.get("counters") if isinstance(row.get("counters"), dict) else {}
            if any(type(counters.get(name)) is not int or counters.get(name) != 0 for name in protocol["gates"]["L0_zero_counters"]):
                reasons.append("L0_performed_scan_preparation_or_missing_counter")
        if case == "snapshot_warm_query":
            samples = row.get("warm_query_samples_ms")
            if not isinstance(samples, list) or len(samples) != protocol["sampling"]["warm_queries_per_snapshot"] or any(not finite(value, True) for value in samples):
                reasons.append("incomplete_warm_samples")
            elif not finite(metrics.get("warm_query_ms")) or not math.isclose(statistics.median(samples), metrics["warm_query_ms"], rel_tol=1e-12, abs_tol=1e-12):
                reasons.append("warm_summary_does_not_match_raw_samples")
        if case == "foreground_adaptation":
            frames = row.get("foreground_frame_times_ms")
            if row.get("foreground_capture_complete") is not True or not isinstance(frames, list) or len(frames) < protocol["sampling"]["foreground_frames_minimum_per_run"] or any(not finite(value, True) for value in frames):
                reasons.append("foreground_tail_capture_incomplete")
            else:
                metrics = {**metrics, "foreground_frame_p95_ms": quantile(frames, .95)}
        if reasons:
            failures.append({"record_index": index, "case": case, "phase": phase, "triplet_id": triplet, "backend": backend, "reasons": reasons, "original_status": row.get("status"), "complete": row.get("complete"), "exclusion_reason": exclusion})
            reason_counts.update(reasons)
        elif valid_key_types:
            successful[key] = metrics

    duplicates = [{"key": list(key), "record_indices": positions} for key, positions in indexed.items() if len(positions) != 1]
    for entry in duplicates:
        successful.pop(tuple(entry["key"]), None)
    missing = sorted(expected_keys - set(indexed))
    if duplicates:
        integrity_errors.append("duplicate_record_keys")
    if any("unexpected_case_phase_triplet_or_backend" in item["reasons"] for item in failures):
        integrity_errors.append("unexpected_record_keys")
    statistics_allowed = registration_ready and not integrity_errors
    results = {}
    for case in required_cases:
        triples = []
        for triplet in range(1, measured_count + 1):
            keys = [(case, "measured", triplet, backend) for backend in "ABC"]
            if all(key in successful for key in keys):
                triples.append({backend: successful[key] for backend, key in zip("ABC", keys)})
        case_result = {"planned_triplets": measured_count, "valid_complete_triplets": len(triples), "invalid_or_missing_triplets": measured_count - len(triples), "contrasts": {}}
        if statistics_allowed:
            for left, right in protocol["comparison"]["contrasts"]:
                contrast = {}
                for metric in ("full_task_ms", "observed_incremental_peak_pss_bytes"):
                    pairs = [(item[left][metric], item[right][metric]) for item in triples]
                    contrast[metric] = paired_summary(pairs, protocol, f"{case}:{left}:{right}:{metric}", True)
                absolute_metric = {"full_L0_hit": "full_task_ms", "snapshot_warm_query": "warm_query_ms", "foreground_adaptation": "foreground_frame_p95_ms"}.get(case)
                if absolute_metric:
                    pairs = [(item[left][absolute_metric], item[right][absolute_metric]) for item in triples]
                    contrast[absolute_metric + "_difference"] = paired_summary(pairs, protocol, f"{case}:{left}:{right}:{absolute_metric}:difference", False)
                case_result["contrasts"][left + "_to_" + right] = contrast
        results[case] = case_result

    all_complete = not failures and not duplicates and not missing and all(result["valid_complete_triplets"] == measured_count for result in results.values())
    primary = results.get("cold_adaptation", {}).get("contrasts", {}).get("B_to_C", {})

    def upper_pass(summary: dict | None, threshold) -> bool:
        return bool(summary and summary.get("estimable") and summary["pairs"] == measured_count and finite(threshold) and summary["CI95"][1] <= threshold)

    time_summary = primary.get("full_task_ms")
    memory_summary = primary.get("observed_incremental_peak_pss_bytes")
    time_route = upper_pass(time_summary, protocol["decision_routes"]["time_primary"]["pass_if_ratio_CI_upper_at_most"])
    alternate = protocol["decision_routes"]["memory_alternative"]
    memory_route = upper_pass(memory_summary, alternate["pass_if_ratio_CI_upper_at_most"]) and upper_pass(time_summary, alternate["pass_if_time_ratio_CI_upper_at_most"])
    original = results.get("cold_adaptation", {}).get("contrasts", {}).get("A_to_C", {})
    def strictly_below_one(summary: dict | None) -> bool:
        return bool(summary and summary.get("estimable") and summary["pairs"] == measured_count and summary["CI95"][1] < 1.0)
    original_time = strictly_below_one(original.get("full_task_ms"))
    original_memory = strictly_below_one(original.get("observed_incremental_peak_pss_bytes"))
    auxiliary = {}
    for case, metric, limit in (("full_L0_hit", "full_task_ms", "L0_absolute_regression_tolerance_ms"), ("snapshot_warm_query", "warm_query_ms", "warm_absolute_regression_tolerance_ms"), ("foreground_adaptation", "foreground_frame_p95_ms", "foreground_p95_absolute_regression_tolerance_ms")):
        checks = {contrast: upper_pass(results.get(case, {}).get("contrasts", {}).get(contrast, {}).get(metric + "_difference"), protocol["gates"][limit]) for contrast in protocol["gates"]["absolute_regression_contrasts"]}
        auxiliary[case] = {"passed": all(checks.values()), "contrasts": checks, "tolerance": protocol["gates"][limit]}
    strict_auxiliary = {}
    for case, metric in strict_spec["cases"].items():
        checks = {}
        for contrast in strict_spec["contrasts"]:
            summary = results.get(case, {}).get("contrasts", {}).get(contrast, {}).get(metric + "_difference")
            checks[contrast] = bool(summary and summary.get("estimable") and summary["pairs"] == measured_count and summary["CI95"][1] < 0.0)
        strict_auxiliary[case] = {"passed": all(checks.values()), "contrasts": checks, "strict_upper_difference_ms": 0.0}
    residual_limit = protocol["gates"]["post_close_residual_tolerance_bytes"]
    residual_pass = finite(residual_limit) and bool(successful) and all(metrics["post_close_residual_bytes"] <= residual_limit for metrics in successful.values())
    ext = external_gates(protocol, raw, identity_hash, evidence_root)
    accepted = bool(raw.get("data_kind") == "real" and statistics_allowed and all_complete and (time_route and memory_route and original_time and original_memory) and all(item["passed"] for item in auxiliary.values()) and all(item["passed"] for item in strict_auxiliary.values()) and residual_pass and all(item["passed"] for item in ext.values()))
    return {
        "schema_version": 1, "campaign_id": raw.get("campaign_id"), "data_kind": raw.get("data_kind"),
        "protocol_sha256": protocol_hash, "identity_sha256": identity_hash,
        "registration_ready": registration_ready, "required_before_run_unselected": pending,
        "integrity_errors": integrity_errors, "statistics_allowed": statistics_allowed,
        "record_accounting": {"input_records_retained": len(records), "phase_counts": dict(phase_counts), "status_counts": dict(statuses), "failed_or_excluded_records": len(failures), "reason_counts": dict(reason_counts), "duplicate_keys": len(duplicates), "missing_records": len(missing)},
        "failures": failures, "duplicates": duplicates, "missing_record_keys": [list(key) for key in missing],
        "cases": results, "all_attempts_and_pairs_complete": all_complete,
        "net_value_routes": {"time_primary": {"threshold_met": time_route, "route_eligible": bool(time_route and all_complete and statistics_allowed)}, "memory_alternative": {"threshold_met": memory_route, "route_eligible": bool(memory_route and all_complete and statistics_allowed)}, "both_thresholds_met": bool(time_route and memory_route)},
        "original_dexkit_superiority": {"time": original_time, "memory": original_memory, "both": bool(original_time and original_memory), "strict_upper_bound": 1.0},
        "auxiliary_gates": auxiliary, "auxiliary_strict_superiority": strict_auxiliary, "post_close_residual_gate": bool(residual_pass), "external_gates": ext,
        "overall_acceptance": "passed_on_supplied_real_evidence" if accepted else "not_passed_or_unverified",
        "synthetic_results_are_not_performance_evidence": raw.get("data_kind") != "real",
        "analysis_scope": "Paired arithmetic on supplied immutable raw data plus identity/status gate checks. Does not prove runner execution, source truth, phone state, Hook/UI operation or independent external-gate truth. Original raw records are never edited or replaced."
    }


def self_test(protocol: dict) -> dict:
    fixture = copy.deepcopy(protocol)
    for path in fixture["required_before_run"]:
        parts = path.strip("/").split("/")
        target = fixture
        for part in parts[:-1]:
            target = target[part]
        if target[parts[-1]] is None:
            target[parts[-1]] = "synthetic-placeholder"
    fixture["status"] = "finalized_before_formal_C_results"
    fixture["formal_runner_ready"] = True
    fixture["statistics"]["bootstrap"]["replicates"] = 200
    fixture["run_identity"]["enabled_capabilities"] = {"persistent_facts": False}
    fixture["run_identity"]["expected_projection_sha256_by_case"] = {case: "synthetic-golden-" + case for case, value in fixture["cases"].items() if value["required"]}
    for name in ("L0_absolute_regression_tolerance_ms", "warm_absolute_regression_tolerance_ms", "foreground_p95_absolute_regression_tolerance_ms"):
        fixture["gates"][name] = .5
    fixture["gates"]["post_close_residual_tolerance_bytes"] = 1024
    identity_hash = digest(fixture["run_identity"])
    protocol_hash = digest(fixture)
    raw = {"schema_version": 1, "data_kind": "synthetic_control", "campaign_id": "unit-control-only", "protocol_sha256": protocol_hash, "identity": fixture["run_identity"], "records": [], "external_gate_evidence": {}}
    for case in fixture["run_identity"]["expected_projection_sha256_by_case"]:
        for phase, total in (("warmup", 5), ("measured", 30)):
            for triplet in range(1, total + 1):
                for position, backend in enumerate(fixture["sampling"]["run_order"][triplet - 1], 1):
                    full = {"A": 120., "B": 100., "C": 80.}[backend]
                    memory = {"A": 12000., "B": 10000., "C": 7000.}[backend]
                    warm = {"A": 3., "B": 2.5, "C": 2.}[backend]
                    frame = {"A": 18., "B": 17., "C": 16.}[backend]
                    raw["records"].append({"case": case, "phase": phase, "triplet_id": triplet, "backend": backend, "order_position": position, "identity_sha256": identity_hash, "backend_build_identity": fixture["run_identity"]["backend_builds"][backend], "complete": True, "status": "ok", "correctness_passed": True, "projection_sha256": fixture["run_identity"]["expected_projection_sha256_by_case"][case], "metrics": {"prepare_ms": 10., "first_answer_ms": 20., "warm_query_ms": warm, "full_task_ms": full, "close_ms": 1., "observed_incremental_peak_pss_bytes": memory, "post_close_residual_bytes": 0}, "counters": {name: 0 for name in fixture["gates"]["L0_zero_counters"]}, "environment_valid": True, "exclusion_reason": None, "warm_query_samples_ms": [warm] * 10, "foreground_frame_times_ms": [frame] * 1000 if case == "foreground_adaptation" else [], "foreground_capture_complete": case == "foreground_adaptation"})
    original = canonical(raw)
    report = analyze(fixture, raw, protocol_hash)
    ratio = report["cases"]["cold_adaptation"]["contrasts"]["B_to_C"]["full_task_ms"]
    assert math.isclose(ratio["estimate"], .8, abs_tol=1e-12)
    assert all(math.isclose(bound, .8, abs_tol=1e-12) for bound in ratio["CI95"])
    assert report["net_value_routes"]["time_primary"]["route_eligible"]
    assert report["overall_acceptance"] == "not_passed_or_unverified"
    assert canonical(raw) == original, "Analyzer mutated raw input"
    tests = ["known_0_8_ratio_and_degenerate_CI", "synthetic_never_accepts", "input_immutable"]
    variable = paired_summary([(100., 50.), (100., 200.)], fixture, "independent-pair-control", True)
    assert math.isclose(variable["estimate"], 1., abs_tol=1e-12)
    assert math.isclose(quantile([0., 10.], .95), 9.5, abs_tol=1e-12)
    tests.append("geometric_pair_estimator_not_ratio_of_means_and_quantile_control")
    measured_index = next(index for index, row in enumerate(raw["records"]) if row["case"] == "cold_adaptation" and row["phase"] == "measured" and row["backend"] == "C")
    altered = copy.deepcopy(raw)
    altered["records"][measured_index]["complete"] = False
    failed = analyze(fixture, altered, protocol_hash)
    assert failed["record_accounting"]["input_records_retained"] == len(raw["records"])
    assert failed["record_accounting"]["failed_or_excluded_records"] == 1
    assert failed["cases"]["cold_adaptation"]["valid_complete_triplets"] == 29
    assert not failed["net_value_routes"]["time_primary"]["route_eligible"]
    tests.append("incomplete_member_kept_and_whole_triplet_not_scored")
    altered = copy.deepcopy(raw)
    altered["records"][measured_index]["identity_sha256"] = "wrong"
    invalid = analyze(fixture, altered, protocol_hash)
    assert not invalid["statistics_allowed"] and invalid["record_accounting"]["failed_or_excluded_records"] == 1
    tests.append("identity_drift_refuses_statistics")
    altered = copy.deepcopy(raw)
    altered["records"].append(copy.deepcopy(altered["records"][measured_index]))
    duplicate = analyze(fixture, altered, protocol_hash)
    assert duplicate["record_accounting"]["duplicate_keys"] == 1 and not duplicate["statistics_allowed"]
    tests.append("duplicate_key_refuses_statistics")
    altered = copy.deepcopy(raw)
    altered["records"].pop(measured_index)
    missing = analyze(fixture, altered, protocol_hash)
    assert missing["record_accounting"]["missing_records"] == 1 and not missing["all_attempts_and_pairs_complete"]
    tests.append("missing_member_preserves_denominator")
    altered = copy.deepcopy(raw)
    altered["records"][measured_index].update(status="query_failed", correctness_passed=False)
    failed = analyze(fixture, altered, protocol_hash)
    assert failed["record_accounting"]["status_counts"]["query_failed"] == 1 and not failed["all_attempts_and_pairs_complete"]
    tests.append("failed_run_not_hidden_or_replaced")
    altered = copy.deepcopy(raw)
    altered["records"][measured_index]["metrics"]["full_task_ms"] = float("nan")
    invalid = analyze(fixture, altered, protocol_hash)
    assert invalid["record_accounting"]["reason_counts"]["invalid_or_missing_metrics"] == 1
    tests.append("nonfinite_metric_rejected")
    altered = copy.deepcopy(raw)
    altered["records"].append({"complete": False, "case": {"bad": "type"}, "backend": None, "metrics": []})
    malformed = analyze(fixture, altered, protocol_hash)
    assert malformed["record_accounting"]["input_records_retained"] == len(raw["records"]) + 1
    assert malformed["record_accounting"]["failed_or_excluded_records"] == 1 and not malformed["statistics_allowed"]
    tests.append("malformed_record_retained_in_failure_accounting")
    altered = copy.deepcopy(raw)
    altered["external_gate_evidence"] = []
    invalid_gates = analyze(fixture, altered, protocol_hash)
    assert not any(item["passed"] for item in invalid_gates["external_gates"].values())
    assert invalid_gates["record_accounting"]["input_records_retained"] == len(raw["records"])
    tests.append("malformed_external_gate_evidence_cannot_pass_or_drop_raw_counts")
    altered = copy.deepcopy(raw)
    for row in altered["records"]:
        if row["case"] == "cold_adaptation" and row["backend"] == "C":
            row["metrics"]["full_task_ms"] = 104.
    alternate_report = analyze(fixture, altered, protocol_hash)
    assert not alternate_report["net_value_routes"]["time_primary"]["threshold_met"]
    assert alternate_report["net_value_routes"]["memory_alternative"]["threshold_met"]
    tests.append("memory_alternative_does_not_relabel_failed_time_primary")
    # Test the acceptance predicate with every other gate passing. These inputs
    # and mocked gates are synthetic controls, never performance evidence.
    simulated_real = copy.deepcopy(raw)
    simulated_real["data_kind"] = "real"
    passed_gates = {name: {"passed": True} for name in fixture["gates"]["external_gate_evidence_required"]}
    with patch(__name__ + ".external_gates", return_value=passed_gates):
        both = analyze(fixture, simulated_real, protocol_hash)
        assert both["net_value_routes"]["both_thresholds_met"]
        assert both["overall_acceptance"] == "passed_on_supplied_real_evidence"
        simulated_memory_only = copy.deepcopy(simulated_real)
        for row in simulated_memory_only["records"]:
            if row["case"] == "cold_adaptation" and row["backend"] == "C":
                row["metrics"]["full_task_ms"] = 104.
        memory_only = analyze(fixture, simulated_memory_only, protocol_hash)
        assert not memory_only["net_value_routes"]["time_primary"]["threshold_met"]
        assert memory_only["net_value_routes"]["memory_alternative"]["threshold_met"]
        assert memory_only["net_value_routes"]["memory_alternative"]["route_eligible"]
        assert not memory_only["net_value_routes"]["both_thresholds_met"]
        assert memory_only["overall_acceptance"] == "not_passed_or_unverified"
        simulated_time_only = copy.deepcopy(simulated_real)
        for row in simulated_time_only["records"]:
            if row["case"] == "cold_adaptation" and row["backend"] == "C":
                row["metrics"]["observed_incremental_peak_pss_bytes"] = 9000.
        time_only = analyze(fixture, simulated_time_only, protocol_hash)
        assert time_only["net_value_routes"]["time_primary"]["threshold_met"]
        assert not time_only["net_value_routes"]["memory_alternative"]["threshold_met"]
        assert time_only["net_value_routes"]["time_primary"]["route_eligible"]
        assert not time_only["net_value_routes"]["both_thresholds_met"]
        assert time_only["overall_acceptance"] == "not_passed_or_unverified"
    tests.append("conjunctive_acceptance_requires_both_time_and_memory")
    with patch(__name__ + ".external_gates", return_value=passed_gates):
        for metric, baseline, label in (("full_task_ms", 75., "time"), ("observed_incremental_peak_pss_bytes", 6000., "memory"), ("full_task_ms", 80., "equal_boundary"), ("observed_incremental_peak_pss_bytes", 0., "zero_baseline")):
            control = copy.deepcopy(simulated_real)
            for row in control["records"]:
                if row["case"] == "cold_adaptation" and row["backend"] == "A":
                    row["metrics"][metric] = baseline
            outcome = analyze(fixture, control, protocol_hash)
            assert outcome["net_value_routes"]["both_thresholds_met"], label
            assert not outcome["original_dexkit_superiority"]["both"], label
            assert outcome["overall_acceptance"] == "not_passed_or_unverified", label
    tests.append("original_dexkit_time_and_memory_strictly_better_required")
    # The old tolerance gate alone would accept a small warm regression.
    # The new delivery gate must reject it, including exact ties and missing data.
    with patch(__name__ + ".external_gates", return_value=passed_gates):
        for value, label in ((2.6, "within_tolerance_regression"), (2.5, "exact_tie")):
            control = copy.deepcopy(simulated_real)
            for row in control["records"]:
                if row["case"] == "snapshot_warm_query" and row["backend"] == "C":
                    row["metrics"]["warm_query_ms"] = value
                    row["warm_query_samples_ms"] = [value] * 10
            outcome = analyze(fixture, control, protocol_hash)
            assert outcome["auxiliary_gates"]["snapshot_warm_query"]["passed"], label
            assert not outcome["auxiliary_strict_superiority"]["snapshot_warm_query"]["passed"], label
            assert outcome["overall_acceptance"] == "not_passed_or_unverified", label
        for case in ("full_L0_hit", "foreground_adaptation"):
            control = copy.deepcopy(simulated_real)
            for row in control["records"]:
                if row["case"] == case and row["backend"] == "C":
                    if case == "full_L0_hit":
                        row["metrics"]["full_task_ms"] = 100.
                    else:
                        row["foreground_frame_times_ms"] = [17.] * 1000
            outcome = analyze(fixture, control, protocol_hash)
            assert outcome["auxiliary_gates"][case]["passed"], case
            assert not outcome["auxiliary_strict_superiority"][case]["passed"], case
            assert outcome["overall_acceptance"] == "not_passed_or_unverified", case
        assert all(x["passed"] for x in both["auxiliary_strict_superiority"].values())
    tests.append("all_required_scenarios_strictly_faster_even_within_old_tolerance")
    draft_raw = copy.deepcopy(raw)
    draft_raw["identity"] = protocol["run_identity"]
    draft_raw["protocol_sha256"] = digest(protocol)
    draft = analyze(protocol, draft_raw, digest(protocol))
    assert not draft["registration_ready"] and not draft["statistics_allowed"]
    tests.append("unselected_protocol_does_not_claim_ready")
    return {"kind": "synthetic_behavior_controls_only", "passed": len(tests), "failed": 0, "tests": tests, "synthetic_records_per_control": len(raw["records"]), "bootstrap_replicates_in_controls": 200, "formal_bootstrap_replicates": protocol["statistics"]["bootstrap"]["replicates"], "actual_device_or_APK_or_performance_runs": 0}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, default=Path(__file__).resolve().parents[1] / "benchmarks/protocol.v1.json")
    parser.add_argument("--raw", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--write-draft-evidence", type=Path)
    args = parser.parse_args()
    protocol, protocol_hash = read_json(args.protocol)
    if args.self_test:
        report = self_test(protocol)
        if args.write_draft_evidence:
            report = {"task_id": "P0-08", "recommended_status": "in_progress", "protocol_sha256": protocol_hash, "analyzer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "formal_runner_ready": False, "unselected_before_run": [path for path in protocol["required_before_run"] if pointer(protocol, path) is None], "behavior_tests": report, "limits": ["No formal C measurement observed", "No real A/B baseline captured", "No device/APK/foreground/tolerance selection", "Relative thresholds/statistics fixed; environmental gates are not frozen"], "command": "python tools/analyze_benchmark.py --self-test --write-draft-evidence docs/evidence/benchmark-protocol-draft.json"}
            args.write_draft_evidence.parent.mkdir(parents=True, exist_ok=True)
            args.write_draft_evidence.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    elif args.raw:
        raw, raw_hash = read_json(args.raw)
        report = analyze(protocol, raw, protocol_hash, args.raw.resolve().parent)
        report["raw_file_sha256"] = raw_hash
        report["raw_file_bytes"] = args.raw.stat().st_size
    else:
        parser.error("Provide --raw RAW.json or --self-test")
    print(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, AssertionError) as error:
        print(json.dumps({"analysis_failed": True, "error": str(error)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(1)

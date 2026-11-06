"""Freeze/verify the P0-02 source audit; this does not run BIL or query a DEX."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(data) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def run_git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
    return result.stdout


def normalize(data: bytes) -> str:
    return data.decode("utf-8-sig").replace("\r\n", "\n")


def enum_entries(source: str) -> list[str]:
    body = source.split("internal enum class DexAssistQuery {", 1)[1].split("\n}", 1)[0]
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    body = re.sub(r"//[^\n]*", "", body)
    values = [part.strip() for part in body.split(",") if part.strip()]
    if not all(re.fullmatch(r"[A-Z][A-Z0-9_]*", value) for value in values):
        raise ValueError("Unexpected DexAssistQuery enum syntax")
    return values


def audit(manifest_path: Path, seal: bool) -> tuple[dict, dict]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    repository = Path(manifest["source_snapshot"]["repository"]).resolve()
    if not repository.is_dir():
        raise ValueError("BIL source checkout is not available")
    if seal and manifest.get("sealed"):
        raise ValueError("Manifest is already sealed; review a new source snapshot rather than silently resealing it")
    if not seal and not manifest.get("sealed"):
        raise ValueError("Manifest has not been sealed")
    head_before = run_git(repository, "rev-parse", "HEAD").decode().strip()
    branch = run_git(repository, "branch", "--show-current").decode().strip()
    status_before = run_git(repository, "status", "--porcelain=v1").decode("utf-8", errors="replace").splitlines()
    expected_head = manifest["source_snapshot"]["commit"]
    if head_before != expected_head:
        raise ValueError(f"Source HEAD changed: {head_before}; expected {expected_head}")
    if branch != manifest["source_snapshot"]["branch"]:
        raise ValueError("Source branch changed")
    sources = {}
    raw_hashes = {}
    checks = []
    for alias, record in manifest["source_files"].items():
        relative = Path(record["path"])
        path = (repository / relative).resolve()
        if relative.is_absolute() or not path.is_relative_to(repository):
            raise ValueError("Source path escapes BIL checkout")
        raw = path.read_bytes()
        source = normalize(raw)
        committed = run_git(repository, "show", f"{expected_head}:{record['path']}")
        if normalize(committed) != source:
            raise ValueError("Audited source contains working-tree changes: " + record["path"])
        blob = run_git(repository, "rev-parse", f"{expected_head}:{record['path']}").decode().strip()
        identity = {"sha256": sha256(raw), "normalized_sha256": sha256(source.encode("utf-8")), "git_blob": blob, "line_count": len(source.splitlines())}
        if seal:
            record.update(identity)
        elif any(record.get(key) != value for key, value in identity.items()):
            raise ValueError("Source identity drift: " + record["path"])
        raw_hashes[alias] = identity["sha256"]
        sources[alias] = source
    checks.append({"name": "source_files_match_pinned_HEAD_and_recorded_hashes", "passed": True, "count": len(sources)})

    actual_enum = enum_entries(sources["D"])
    ids = [rule["id"] for rule in manifest["rules"]]
    if len(actual_enum) != 33 or len(set(ids)) != 33 or ids != actual_enum:
        raise ValueError("Manifest IDs must equal all 33 actual enum values in exact order")
    matcher = sources["E"].split("private fun find(", 1)[1].split("private fun ensureNativeLoaded", 1)[0]
    branch_ids = set(re.findall(r"DexAssistQuery\.([A-Z_]+)", matcher))
    if branch_ids != set(actual_enum):
        raise ValueError("DexKit matcher branch coverage differs from enum")
    checks.append({"name": "exact_enum_order_unique_count_and_find_branch_set", "passed": True, "count": 33})

    reference_count = 0

    def references(refs: list) -> list:
        nonlocal reference_count
        resolved = []
        for ref in refs:
            if isinstance(ref, str):
                alias, bounds = ref.split(":", 1)
                start, end = map(int, bounds.split("-", 1))
            else:
                alias, start, end = ref["source_id"], ref["line_start"], ref["line_end"]
            lines = sources[alias].splitlines()
            if not 1 <= start <= end <= len(lines):
                raise ValueError(f"Invalid source range {alias}:{start}-{end}; file has {len(lines)} lines")
            excerpt = "\n".join(lines[start - 1:end]) + "\n"
            resolved_ref = {"source_id": alias, "line_start": start, "line_end": end, "file_sha256": raw_hashes[alias], "excerpt_sha256": sha256(excerpt.encode("utf-8"))}
            if not seal and ref != resolved_ref:
                raise ValueError("Source reference digest mismatch")
            resolved.append(resolved_ref)
            reference_count += 1
        return resolved

    manifest["shared_contract"]["source_refs"] = references(manifest["shared_contract"]["source_refs"])
    for rule in manifest["rules"]:
        for field in ("capabilities", "static_query", "static_output", "result_intent", "source_refs"):
            if not rule.get(field):
                raise ValueError("Missing rule contract: " + rule["id"] + "." + field)
        profile = rule.get("runtime_profile", {})
        for field in ("entrypoints", "acceptance", "effects"):
            if not profile.get(field):
                raise ValueError("Incomplete runtime profile: " + rule["id"])
        rule["source_refs"] = references(rule["source_refs"])
        query_text = "\n".join("\n".join(sources["E"].splitlines()[ref["line_start"] - 1:ref["line_end"]]) for ref in rule["source_refs"] if ref["source_id"] == "E")
        if "DexAssistQuery." + rule["id"] not in query_text:
            raise ValueError("Rule lacks its actual query branch reference: " + rule["id"])
        enum_line = next(index for index, line in enumerate(sources["D"].splitlines(), 1) if re.fullmatch(r"\s*" + re.escape(rule["id"]) + r",?\s*", line))
        enum_ref = references([f"D:{enum_line}-{enum_line}"])[0] if seal else rule["enum_source_ref"]
        if seal:
            rule["enum_source_ref"] = enum_ref
        else:
            references([enum_ref])
        expected_line = enum_ref["line_start"]
        if expected_line != enum_line:
            raise ValueError("Enum source line changed")
    checks.append({"name": "every_rule_has_source_hashed_filters_intent_capability_runtime_profile", "passed": True, "rules": 33, "references": reference_count})
    class_outputs = {rule["id"] for rule in manifest["rules"] if rule["static_output"] in {"constructor_owner_classes", "initializer_owner_classes"}}
    expected_classes = {"SPONSOR_CONTAINER_SCOPE", "SEARCH_HOME_STATE", "HOME_CHROME_SEMANTICS"}
    if class_outputs != expected_classes:
        raise ValueError("Constructor/clinit class projection contract changed")
    checks.append({"name": "constructor_and_initializer_Class_projection_set", "passed": True, "count": 3})
    if not re.search(r'^dexkit\s*=\s*"2\.3\.0"', sources["Versions"], re.M):
        raise ValueError("BIL DexKit version differs from the audited version")
    checks.append({"name": "BIL_declares_DexKit_2_3_0", "passed": True})

    baseline = manifest["source_snapshot"]["engineering_plan_baseline"]
    changed = run_git(repository, "diff", "--name-only", baseline, expected_head, "--", *[record["path"] for record in manifest["source_files"].values()]).decode().splitlines()
    if changed:
        raise ValueError("Engineering-plan baseline has audited source drift: " + ", ".join(changed))
    checks.append({"name": "baseline_to_current_audited_source_diff_empty", "passed": True})
    head_after = run_git(repository, "rev-parse", "HEAD").decode().strip()
    status_after = run_git(repository, "status", "--porcelain=v1").decode("utf-8", errors="replace").splitlines()
    if head_before != head_after or status_before != status_after:
        raise ValueError("Source checkout changed during verification")
    for alias, record in manifest["source_files"].items():
        if sha256((repository / record["path"]).read_bytes()) != raw_hashes[alias]:
            raise ValueError("Source bytes changed during verification")
    checks.append({"name": "read_only_before_after_HEAD_status_and_source_hashes_stable", "passed": True})
    if seal:
        manifest["sealed"] = True
        manifest["source_snapshot"]["dirty_status_observed"] = status_after
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    result = {
        "task_id": "P0-02", "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "validation_kind": "source_identity_and_manifest_completeness_audit",
        "repository": str(repository), "head": head_after, "branch": branch,
        "dirty_before": status_before, "dirty_after": status_after,
        "baseline_diff_paths": changed, "manifest_sha256": sha256(manifest_path.read_bytes()),
        "rule_count": len(ids), "rule_ids": ids, "checks": checks,
        "source_file_count": len(sources), "source_reference_count": reference_count,
        "runtime_effect_rules": [rule["id"] for rule in manifest["rules"] if any(effect.startswith(("read_host_static", "read_kotlin", "enumerate_host", "invoke_host")) for effect in rule["runtime_profile"]["effects"])],
        "P0_02_source_freeze_acceptance": "passed",
        "not_executed": ["BIL build or tests", "DEX query against real APK", "Android device operations", "host runtime verification profiles", "33-rule backend semantic parity", "Hook/UI validation", "performance benchmark"],
        "limitations": ["The script verifies source identity, enum equality and referenced audit completeness; it does not prove the prose predicates behaviorally equivalent.", "Legacy DexKit binding may drop unresolved candidates and has no exact scan-definition/runtime-origin proof; new SDK must retain unknown status.", "Upstream DSL source was retrieved independently at the pinned commit; package boundaries, interval edges and invoke multiplicity still require P2 compatibility fixtures."],
        "source_files": manifest["source_files"]
    }
    result["audit_record"] = manifest.get("audit_record", {})
    return manifest, result


def write_report(manifest: dict, target: Path) -> None:
    root = "https://github.com/jichuo1/Bilibili_Innocent_Lab/blob/" + manifest["source_snapshot"]["commit"] + "/"

    def reference(ref: dict) -> str:
        path = manifest["source_files"][ref["source_id"]]["path"]
        return f"[{ref['source_id']}:{ref['line_start']}-{ref['line_end']}]({root}{path}#L{ref['line_start']}-L{ref['line_end']})"

    lines = ["# BIL 33 项旧语义冻结（P0-02）", "", "本记录完成当前源码到迁移契约的冻结。它不表示 DexMeguviz 已实现 33 项查询，也不表示真实 APK、ClassLoader、Hook、UI 或性能验收已通过。", "", f"基线及当前 BIL HEAD 均为 `{manifest['source_snapshot']['commit']}`，分支 `main`；相关生产文件与该提交逐文件一致。用户已有 `docs/follow-feed-integration.md` 修改和 `runtime/` 未跟踪内容原样保留。", "", "## 核实路径与旧行为", "", "完整阅读 DexAssistEngine.kt、DexKitAssistEngine.kt，以及各条 source_refs 指向的业务 verifier；对被间接调用的 SponsorPlayerAccess、SponsorSeekAccess、FollowFeedHostAccess、PlayerSpeedLocator、KotlinMossBridgeMembers 等继续核实。每条规则保存 enum 行、筛选/转换行、runtime 接受行、文件 SHA-256 与规范化行段 SHA-256。机器台账为 `integrations/bil/rules/manifest.v1.json`。", "", "- `modifiers = STATIC` 的 setter 在固定 DexKit 提交中调用默认 Contains 的重载；不能改为 flags 相等。reflection modifiers 与原始 DEX accessFlags 分域。", "- 多字符串列表要求全部模式满足；每条保留 Equals/Contains 和大小写语义。addInvoke 是覆盖匹配的 Contains 集合，当前不同目标条件是合取；任意重叠谓词的多重性不在本轮证明范围。", "- 输入 codePaths 去重后最多 8 个；raw matches 加已物化方法超过 32、invoke 超过 128、类或关联类超过 32 都保留原失败状态。raw cap 在最终去重/业务接受之前，不是合法候选非唯一或无匹配的证明。", "- Class 结果固定为 SPONSOR_CONTAINER_SCOPE、SEARCH_HOME_STATE、HOME_CHROME_SEMANTICS；其余仍可能需要唯一 owner、唯一 owner 方法组或条件角色集。", "- 唯一性必须在相同 host profile 后判断；旧 API 丢弃绑定失败候选的行为不能被解释为已验证来源或全域唯一。新的 rich outcome 到旧界面的降级属于后续独立任务。", "", "## 与工程计划摘要相比需要补充的细节", "", "当前源码与计划基线没有提交差异。以下是同一基线下摘要不足，已写入本清单，未修改 BIL 行为：", "", "1. Sponsor 三项最终完整 resolve 读取 BizType.UGC 静态枚举字段，并读取 kotlin.Unit.INSTANCE；可能触发类初始化，不是纯结构反射。", "2. Follow current profile 的可选 moduleKinds 会取得 ModuleEnum.enumConstants，并对每个常量调用 viewType()。该映射失败会得到 null，不能把它误写成所有 Follow 发现的必需门禁。", "3. PlayerSpeed 除 option/item 样本构造和字段读取，还会读取静态默认倍速 List；factory 关联类转换阶段已可能调用 verifyOptionModel。", "4. HOME_CHROME_SEMANTICS discovery 读取 canonical static key 并调用 key.toString；setter 在后续 describe 调用，两个阶段分别记录。", "5. HOME_CHROME_TOP_CONTENT/BOTTOM_CONTENT 的实例 capture 值检查发生在 Hook 调用准入，不能当作 DEX 发现阶段已验证。", "", "## 逐项映射", "", "| enum | 静态输出 | 最终接受意图 | 源码证据 |", "|---|---|---|---|"]
    for rule in manifest["rules"]:
        refs = ", ".join(reference(ref) for ref in rule["source_refs"])
        lines.append(f"| `{rule['id']}` | {rule['static_output']} | {rule['result_intent']} | {refs} |")
    lines.extend(["", "每条精确筛选、全部 runtime 接受条件、能力及副作用见 JSON；上表用于索引，不另造第二份可漂移规则。", "", "## 上游 DSL 核实", "", "固定上游提交 `c9cd12a14b75409bebd2f73e4dfc5ff575df3eb8`，通过 GitHub connector 读取 MethodMatcher、MethodsMatcher 和 native matcher；文件 blob ID 与行段登记在 manifest.dsl_semantics.upstream_sources。原始 web fetch 出现 cache miss，随后 connector 成功；没有用失败网页内容作为证据。", "", "## 复现与验收范围", "", "```powershell", "python tools/verify_bil_manifest.py --root . --write-evidence", "```", "", "脚本只读 BIL，检查 33 个 enum 的顺序和集合严格相等、find 分支集合完整、每条字段和引用完整、源文件与 pinned HEAD 一致、文件/行段哈希未变、前后 HEAD/status/hash 稳定。`--seal` 仅用于首次建立冻结身份，已封存文件拒绝重新 seal，避免自动接受源码漂移。", "", "P0-02 的源码冻结验收通过；真实 APK 的完整规则正反例、角色配对、基数、未完成和运行时副作用对照属于后续 P2-04/P2-09 等门禁。本轮未运行 BIL 构建、测试或设备操作。", ""])
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--seal", action="store_true")
    parser.add_argument("--write-evidence", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    manifest_path = root / "integrations/bil/rules/manifest.v1.json"
    manifest, report = audit(manifest_path, args.seal)
    if args.seal:
        write_report(manifest, root / "integrations/bil/docs/semantic-parity.md")
    if args.write_evidence:
        target = root / "docs/evidence/bil-rules-freeze.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        report["command"] = "python tools/verify_bil_manifest.py --root ." + (" --seal" if args.seal else "") + " --write-evidence"
        report["workdir"] = str(root)
        target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"P0_02_source_freeze_acceptance": report["P0_02_source_freeze_acceptance"], "rules": report["rule_count"], "source_files": report["source_file_count"], "references": report["source_reference_count"], "checks_passed": len(report["checks"]), "runtime_effect_rules": report["runtime_effect_rules"], "device_or_build_executed": False}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, OSError) as error:
        print(json.dumps({"passed": False, "error": str(error)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(1)

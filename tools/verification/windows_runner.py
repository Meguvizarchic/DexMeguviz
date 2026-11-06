"""Curated Windows verification. No fixture regeneration, cleanup or broad CTest run."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET

VERSION = 1
SOURCE_DIRS = ("src", "include", "cli", "adapters", "cmake", "third_party",
               "tests", "tools", "bindings/android/tests")
OMIT_DIRS = {"build", "work", "evidence", "__pycache__", ".git", ".gradle", "node_modules"}
SOURCE_SUFFIXES = {".c", ".cpp", ".h", ".hpp", ".inc", ".py", ".json", ".md",
                   ".txt", ".cmake", ".kt", ".java", ".dex", ".apk", ".zip"}
FORBIDDEN = ("fuzz", "q08-caller-relation-candidate", "final-build-debug")
CONFIGS = ("debug", "asan")


class Stop(RuntimeError):
    pass


def need(ok, message):
    if not ok:
        raise Stop(message)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def write_json(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as f:
        json.dump(value, f, ensure_ascii=True, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())


def read_json(path):
    need(Path(path).stat().st_size <= 16 * 1024 * 1024, "JSON receipt too large")
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def fresh(parent, prefix):
    p = parent / (prefix + "-" + str(time.time_ns()) + "-" + uuid.uuid4().hex[:8])
    p.mkdir()
    return p


def plain(path):
    """Do not traverse junctions/symlinks, including any existing ancestor."""
    p = Path(os.path.abspath(path))
    for part in [p, *p.parents]:
        if part.exists():
            s = part.lstat()
            need(not stat.S_ISLNK(s.st_mode) and not
                 (getattr(s, "st_file_attributes", 0) & 0x400), "reparse path rejected: " + str(part))
    return p


def inside(path, root):
    p, r = plain(path), plain(root)
    need(p == r or r in p.parents, "path outside owned root: " + str(p))
    return p


def forbidden(value):
    text = str(value).lower().replace("\\", "/")
    return any(word in text for word in FORBIDDEN)


def inputs(root):
    result = [root / "CMakeLists.txt"]
    for rel in SOURCE_DIRS:
        start = root / rel
        need(start.is_dir(), "missing source directory: " + rel)
        for current, dirs, files in os.walk(start, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in OMIT_DIRS)
            plain(current)
            for name in sorted(files):
                p = plain(Path(current) / name)
                if p.suffix.lower() in SOURCE_SUFFIXES or name == "LICENSE":
                    result.append(p)
    return sorted(set(result), key=lambda p: p.relative_to(root).as_posix())


def tree_identity(root):
    rows = [{"path": p.relative_to(root).as_posix(), "bytes": p.stat().st_size,
             "sha256": sha(p)} for p in inputs(root)]
    need(sum(x["bytes"] for x in rows) <= 64 * 1024 * 1024, "source snapshot exceeds 64 MiB")
    return rows


def verify_snapshot(session):
    source = Path(session["out"]) / "source"
    for row in session["source_files"]:
        p = inside(source / row["path"], source)
        need(p.is_file() and p.stat().st_size == row["bytes"] and sha(p) == row["sha256"],
             "snapshot drift: " + row["path"])


def tools_identity(cmake):
    paths = {"runner": Path(__file__).resolve(), "cmake": cmake,
             "ctest": cmake.with_name("ctest.exe"), "python": Path(sys.executable).resolve()}
    for name, path in paths.items():
        need(plain(path).is_file() and not forbidden(path), "invalid tool: " + name)
    return {name: {"path": str(path), "sha256": sha(path)} for name, path in paths.items()}


def verify_tools(session, cmake):
    need(tools_identity(cmake) == session["tools"], "runner/CMake/CTest/Python changed")


def policy_check(policy, root):
    need(policy.get("schema_version") == VERSION, "review policy version")
    for rel, digest in policy.get("common_reviewed_sources", {}).items():
        p = inside(root / rel, root)
        need(p.is_file() and sha(p) == digest, "reviewed registration changed: " + rel)
    tests = policy.get("tests", {})
    need(isinstance(tests, dict) and len(tests) <= 256, "review policy test count")
    for name, item in tests.items():
        need(re.fullmatch(r"[a-z0-9_]+", name) and not forbidden(name), "forbidden test name")
        need(item["cleanup"] in ("none", "own-temporary-directory"), "cleanup review required")
        for target in item["targets"]:
            need(re.fullmatch(r"[A-Za-z0-9_]+", target) and not forbidden(target), "forbidden build target")
        need(item["command"][0] in ("native", "python"), "unsupported reviewed command")
        for rel, digest in item["reviewed_sources"].items():
            p = inside(root / rel, root)
            need(p.is_file() and sha(p) == digest, "review input changed: " + rel)
        need(not forbidden(json.dumps(item["command"])), "forbidden command")
    return tests


def environment(temp, compiler_dirs=()):
    env = os.environ.copy()
    env.update(TEMP=str(temp), TMP=str(temp), TMPDIR=str(temp), PYTHONDONTWRITEBYTECODE="1")
    env.pop("PYTHONOPTIMIZE", None)
    env["PATH"] = os.pathsep.join([*(str(p) for p in compiler_dirs), env.get("PATH", "")])
    # Values are deliberately not persisted: they may contain private environment data.
    keys = ("PATH", "INCLUDE", "LIB", "LIBPATH", "VSINSTALLDIR", "VCToolsInstallDir",
            "WindowsSdkDir", "CL", "_CL_", "LINK", "CMAKE_GENERATOR", "CMAKE_TOOLCHAIN_FILE")
    identity = hashlib.sha256(canonical({k: env.get(k) for k in keys})).hexdigest()
    return env, identity


def command(argv, cwd, folder, timeout, env, log_limit=64 * 1024 * 1024):
    """Exclusive logs; time/output failure is never a successful command."""
    need(all(x == "-DDMG_BUILD_FUZZERS=OFF" or not forbidden(x) for x in argv),
         "permanently excluded command")
    started = time.monotonic()
    record = {"argv": argv, "cwd": str(cwd), "timeout_seconds": timeout,
              "started_utc_ns": time.time_ns(), "exit_code": None, "failure": None}
    write_json(folder / "started.json", record)
    stdout, stderr = folder / "stdout.log", folder / "stderr.log"
    process = None
    try:
        with stdout.open("xb") as out, stderr.open("xb") as err:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=out, stderr=err,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
            while process.poll() is None:
                if time.monotonic() - started > timeout:
                    record["failure"] = "timeout"
                    break
                if stdout.stat().st_size + stderr.stat().st_size > log_limit:
                    record["failure"] = "output_limit"
                    break
                time.sleep(0.1)
            if record["failure"]:
                taskkill = Path(os.environ["SystemRoot"]) / "System32/taskkill.exe"
                killed = subprocess.run([str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
                (folder / "terminate.log").write_bytes(killed.stdout)
                record["terminate_exit_code"] = killed.returncode
            record["exit_code"] = process.wait(timeout=30)
    except BaseException as e:
        record["failure"] = type(e).__name__ + ": " + str(e)
        if process is not None and process.poll() is None:
            subprocess.run([str(Path(os.environ["SystemRoot"]) / "System32/taskkill.exe"),
                            "/PID", str(process.pid), "/T", "/F"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
            process.wait(timeout=30)
    record["elapsed_seconds"] = time.monotonic() - started
    record["logs"] = {p.name: {"bytes": p.stat().st_size, "sha256": sha(p)}
                      for p in (stdout, stderr) if p.is_file()}
    record["ok"] = record["exit_code"] == 0 and record["failure"] is None
    write_json(folder / "finished.json", record)
    return record


def make_plan(args, root, out, cmake):
    need(not out.exists(), "plan --out must be a new directory; never reuse old output")
    need(root not in out.parents and out not in root.parents and out != root,
         "output and formal source must be disjoint")
    policy_path = plain(args.review_policy)
    policy = read_json(policy_path)
    tests = policy_check(policy, root)
    rows = tree_identity(root)
    tool_ids = tools_identity(cmake)
    out.mkdir(parents=True)
    source = out / "source"
    source.mkdir()
    for row in rows:
        original, target = root / row["path"], source / row["path"]
        data = original.read_bytes()
        need(hashlib.sha256(data).hexdigest() == row["sha256"], "source changed during copy")
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as f:
            f.write(data)
        need(sha(target) == row["sha256"] and sha(original) == row["sha256"], "copy identity mismatch")
    write_json(out / "review-policy.json", policy)
    session = {"schema_version": VERSION, "root": str(root), "out": str(out),
               "created_utc_ns": time.time_ns(), "source_files": rows,
               "source_identity": hashlib.sha256(canonical(rows)).hexdigest(),
               "tools": tool_ids, "review_policy_sha256": sha(out / "review-policy.json"),
               "generator": args.generator, "configurations": CONFIGS,
               "permanent_exclusions": list(FORBIDDEN), "tested": False}
    write_json(out / "session.json", session)
    write_json(out / "plan.json", {"reviewed_test_names": list(tests),
               "selected": list(dict.fromkeys(args.test)), "source_bytes": sum(x["bytes"] for x in rows),
               "source_count": len(rows), "configurations": CONFIGS,
               "cleanup_permission": False, "action": "plan_only",
               "note": "No configure/build/test. Build/run require explicit reviewed test names; unreviewed CTest entries are not runnable."})
    return session


def load_session(args, root, out, cmake):
    need(out.is_dir(), "run plan with a new --out first")
    session = read_json(out / "session.json")
    need(session["schema_version"] == VERSION and session["root"] == str(root)
         and session["out"] == str(out), "session identity mismatch")
    verify_tools(session, cmake)
    need(sha(out / "review-policy.json") == session["review_policy_sha256"], "review policy changed")
    verify_snapshot(session)
    policy_check(read_json(out / "review-policy.json"), out / "source")
    return session


def compiler_tools(build):
    found = {}
    files = [build / "CMakeCache.txt", *build.glob("CMakeFiles/*/CMakeCXXCompiler.cmake"),
             *build.glob("CMakeFiles/*/CMakeCCompiler.cmake")]
    for file in files:
        if not file.is_file():
            continue
        text = file.read_text("utf-8", errors="replace")
        for value in re.findall(r'(?:CMAKE_(?:CXX_COMPILER|C_COMPILER|LINKER|MAKE_PROGRAM))(?::[^=\n]+)?=(.*)', text):
            p = Path(value.strip().strip('"'))
            if p.is_file(): found[str(plain(p))] = sha(p)
        for value in re.findall(r'set\(CMAKE_(?:CXX_COMPILER|C_COMPILER) "([^"]+)"', text):
            p = Path(value)
            if p.is_file(): found[str(plain(p))] = sha(p)
    need(found, "compiler/tool identity was not recorded")
    return found


def inventory(session, build, dest, env):
    rec = command([session["tools"]["ctest"]["path"], "--test-dir", str(build),
                   "-C", "Debug", "--show-only=json-v1"], build, dest, 120, env)
    need(rec["ok"], "CTest inventory failed")
    data = read_json(dest / "stdout.log")
    names = [x["name"] for x in data["tests"]]
    need(len(names) == len(set(names)), "duplicate CTest names")
    write_json(dest / "inventory.json", data)
    return data


def build_phase(args, session, tests):
    out, source = Path(session["out"]), Path(session["out"]) / "source"
    need(args.test, "build requires explicit --test names; no all-target build")
    selected = list(dict.fromkeys(args.test))
    need(all(x in tests and not forbidden(x) for x in selected), "build selection is unreviewed or forbidden")
    targets = list(dict.fromkeys(t for name in selected for t in tests[name]["targets"]))
    reports = []
    for config in args.config or CONFIGS:
        parent = out / "builds" / config
        parent.mkdir(parents=True, exist_ok=True)
        attempt = fresh(parent, "build")
        build, temp, logs = attempt / "tree", attempt / "temp", attempt / "logs"
        temp.mkdir(); logs.mkdir()
        env, env_id = environment(temp)
        argv = [session["tools"]["cmake"]["path"], "-S", str(source), "-B", str(build),
                "-DDMG_BUILD_TESTS=ON", "-DDMG_WITH_SQLITE=ON", "-DDMG_BUILD_SQLITE_PROTO_TESTS=ON",
                "-DDMG_ENABLE_ASAN=" + ("ON" if config == "asan" else "OFF"),
                "-DDMG_BUILD_FUZZERS=OFF", "-DCMAKE_BUILD_TYPE=Debug",
                "-DPython3_EXECUTABLE=" + session["tools"]["python"]["path"]]
        if session["generator"]:
            argv += ["-G", session["generator"]]
        # This literal OFF is the only fuzz-related argument; no user CMake flags are accepted.
        configure_dir = fresh(logs, "configure")
        record = {"config": config, "attempt": str(attempt), "tree": str(build),
                  "selected": selected, "targets": targets, "environment_sha256": env_id,
                  "source_identity": session["source_identity"], "status": "configure_failed"}
        result = command(argv, out, configure_dir, args.build_timeout, env)
        record["configure"] = str(configure_dir)
        if result["ok"]:
            tools = compiler_tools(build)
            record["compiler_tools"] = tools
            dirs = list(dict.fromkeys(Path(x).parent for x in tools))
            env, _ = environment(temp, dirs)
            build_dir = fresh(logs, "compile")
            result = command([session["tools"]["cmake"]["path"], "--build", str(build),
                              "--config", "Debug", "--parallel", str(args.parallel), "--target", *targets],
                             out, build_dir, args.build_timeout, env)
            record["build"] = str(build_dir)
            record["status"] = "build_failed"
            invdir = fresh(logs, "ctest-list")
            try:
                data = inventory(session, build, invdir, env)
                record["inventory"] = str(invdir / "inventory.json")
                record["inventory_sha256"] = sha(invdir / "inventory.json")
                record["registered_tests"] = len(data["tests"])
                if result["ok"]:
                    record["status"] = "built_not_tested"
            except Stop as e:
                record["inventory_failure"] = str(e)
            record["artifacts"] = {str(p.relative_to(build)): sha(p) for p in build.rglob("*")
                                   if p.is_file() and p.suffix.lower() in (".exe", ".dll", ".lib", ".pdb")}
        verify_snapshot(session)
        write_json(attempt / "receipt.json", record)
        reports.append(record)
    report = fresh(out, "build-report")
    write_json(report / "report.json", reports)
    return 0 if all(x["status"] == "built_not_tested" for x in reports) else 1


def bracket(value):
    marks = "="
    while "]" + marks + "]" in value:
        marks += "="
    return "[" + marks + "[" + value + "]" + marks + "]"


def check_test(entry, review, session, build):
    argv = entry.get("command", [])
    need(argv and all(not forbidden(x) for x in argv), "missing or forbidden CTest command")
    shape = review["command"]
    if shape[0] == "native":
        p = inside(argv[0], build)
        need(p.name.lower() == shape[1].lower() + ".exe", "CTest executable differs from review")
        expected = shape[2:]
    else:
        need(plain(argv[0]) == plain(session["tools"]["python"]["path"]), "CTest Python differs")
        expected = shape[1:]
    expanded = [x.replace("{source}", str(Path(session["out"]) / "source")) for x in expected]
    # Executable placeholders may point only to same-build products, never arbitrary legacy CLIs.
    actual = argv[1:]
    need(len(actual) == len(expanded), "CTest argument count differs from review")
    for got, wanted in zip(actual, expanded):
        if wanted.startswith("{target:") and wanted.endswith("}"):
            p = inside(got, build)
            need(p.name.lower() == wanted[8:-1].lower() + ".exe", "CTest tool target differs")
        else:
            need(got.replace("\\", "/") == wanted.replace("\\", "/"), "CTest argument differs from review")
    props = {x["name"]: x["value"] for x in entry.get("properties", [])}
    need(set(props) <= {"WORKING_DIRECTORY", "TIMEOUT"}, "unreviewed CTest properties/fixtures")
    return argv, props


def run_phase(args, session, tests):
    need(args.test, "run requires explicit --test names; no all-CTest option")
    out = Path(session["out"])
    selected = list(dict.fromkeys(args.test))
    report_dir = fresh(out, "run-report")
    rows = []
    for config in args.config or CONFIGS:
        receipts = sorted((out / "builds" / config).glob("build-*/receipt.json"))
        good = [read_json(p) for p in receipts if read_json(p).get("status") == "built_not_tested"]
        if not good:
            rows.extend({"config": config, "name": n, "status": "not_run", "reason": "no_successful_build"} for n in selected)
            continue
        built = good[-1]
        build = inside(built["tree"], out)
        need(sha(built["inventory"]) == built["inventory_sha256"], "CTest inventory drift")
        for rel, digest in built["artifacts"].items():
            need(sha(inside(build / rel, build)) == digest, "build artifact drift: " + rel)
        for path, digest in built["compiler_tools"].items():
            need(sha(path) == digest, "compiler/runtime tool drift")
        data = read_json(built["inventory"])
        registered = {x["name"]: x for x in data["tests"]}
        rows.extend({"config": config, "name": name, "status": "not_run", "reason": "not_selected"}
                    for name in registered if name not in selected)
        for name in selected:
            row = {"config": config, "name": name, "status": "not_run"}
            rows.append(row)
            if forbidden(name): row["reason"] = "permanently_excluded"; continue
            if name not in tests: row["reason"] = "not_reviewed"; continue
            if name not in registered: row["reason"] = "not_registered"; continue
            if name not in built["selected"]: row["reason"] = "not_built_in_selected_receipt"; continue
            review = tests[name]
            if review["cleanup"] != "none" and not args.allow_test_temp_cleanup:
                row["reason"] = "test_temporary_cleanup_not_authorized"; continue
            ledger = out / "tests" / config / name
            if ledger.exists() and any(ledger.glob("attempt-*/execution/started.json")):
                row["reason"] = "already_attempted_in_session"; continue
            ledger.mkdir(parents=True, exist_ok=True)
            attempt = fresh(ledger, "attempt")
            try:
                verify_snapshot(session)
                argv, props = check_test(registered[name], review, session, build)
                runtime_dirs = list(dict.fromkeys(Path(p).parent for p in built["compiler_tools"]))
                temp, execution = attempt / "temp", attempt / "execution"
                temp.mkdir(); execution.mkdir()
                env, env_id = environment(temp, runtime_dirs)
                row["environment_sha256"] = env_id
                row["original_ctest_entry"] = registered[name]
                row["cleanup"] = review["cleanup"]
                # A new one-test harness avoids CTest rotating/deleting earlier run logs or adding fixtures.
                text = "add_test(" + " ".join(bracket(x) for x in [name, *argv]) + ")\n"
                timeout = min(args.test_timeout, review["timeout_seconds"], int(props.get("TIMEOUT", args.test_timeout)))
                text += "set_tests_properties(" + bracket(name) + " PROPERTIES TIMEOUT " + str(timeout) + ")\n"
                with (attempt / "CTestTestfile.cmake").open("x", encoding="utf-8", newline="\n") as f:
                    f.write(text)
                write_json(attempt / "admission.json", row)
                result = command([session["tools"]["ctest"]["path"], "--test-dir", str(attempt),
                                  "-C", "Debug", "-R", "^" + re.escape(name) + "$", "-j", "1",
                                  "--no-tests=error", "--output-on-failure", "--output-junit", str(attempt / "junit.xml")],
                                 attempt, execution, timeout + 60, env)
                row["attempt"] = str(attempt)
                row["status"] = "failed"
                row["reason"] = result["failure"] or "ctest_or_junit_failure"
                junit = attempt / "junit.xml"
                if result["ok"] and junit.is_file():
                    cases = ET.parse(junit).getroot().findall(".//testcase")
                    if len(cases) == 1 and cases[0].get("name") == name and not any(
                            cases[0].find(x) is not None for x in ("failure", "error", "skipped")):
                        row["status"] = "passed"; row["reason"] = "ctest_exit_zero_and_one_successful_case"
                verify_snapshot(session)
            except (Stop, OSError, ValueError, ET.ParseError) as e:
                row["status"] = "failed" if (attempt / "execution/started.json").exists() else "not_run"
                row["reason"] = str(e)
            write_json(attempt / "result.json", row)
    write_json(report_dir / "report.json", {"source_identity": session["source_identity"], "rows": rows,
               "selected": selected, "duplicate_requests_removed": len(args.test) - len(selected),
               "allow_test_temp_cleanup": args.allow_test_temp_cleanup,
               "scope": "Only recorded selected tests; no full-suite/device/fuzz acceptance"})
    wanted = [x for x in rows if x["name"] in selected]
    return 0 if wanted and all(x["status"] == "passed" for x in wanted) else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--action", choices=("plan", "build", "run"), default="plan")
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--cmake", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--review-policy", type=Path, default=Path(__file__).with_name("windows-reviewed-tests.json"))
    p.add_argument("--generator", choices=("Visual Studio 17 2022", "Visual Studio 18 2026", "Ninja"))
    p.add_argument("--config", choices=CONFIGS, action="append")
    p.add_argument("--test", action="append", default=[])
    p.add_argument("--parallel", type=int, default=2)
    p.add_argument("--build-timeout", type=int, default=3600)
    p.add_argument("--test-timeout", type=int, default=300)
    p.add_argument("--allow-test-temp-cleanup", action="store_true")
    args = p.parse_args()
    need(os.name == "nt", "Windows runner only")
    need(1 <= args.parallel <= 8 and 1 <= args.build_timeout <= 14400 and
         1 <= args.test_timeout <= 3600, "invalid resource envelope")
    if args.config: args.config = list(dict.fromkeys(args.config))
    root, out, cmake = plain(args.root), plain(args.out), plain(args.cmake)
    if args.action == "plan":
        make_plan(args, root, out, cmake)
        print(json.dumps({"action": "plan", "out": str(out), "tests_run": 0}))
        return 0
    session = load_session(args, root, out, cmake)
    tests = read_json(out / "review-policy.json")["tests"]
    result = build_phase(args, session, tests) if args.action == "build" else run_phase(args, session, tests)
    print(json.dumps({"action": args.action, "out": str(out), "exit_code": result}))
    return result


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Stop, OSError, ValueError, KeyError) as error:
        print("STOP: " + str(error), file=sys.stderr)
        sys.exit(2)

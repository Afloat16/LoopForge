#!/usr/bin/env python3
"""Isolated, pinned-source checks; counterexamples must be executed assertions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import threading
import time
import traceback


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(root, *arguments, binary=False):
    value = subprocess.check_output(["git", "-C", str(root), *arguments])
    return value if binary else value.decode().strip()


def commit(root, ref):
    header = git(root, "cat-file", "-p", ref).split("\n\n", 1)[0].splitlines()
    return {"sha": git(root, "rev-parse", ref),
            "tree": next(line[5:] for line in header if line.startswith("tree ")),
            "parents": [line[7:] for line in header if line.startswith("parent ")]}


def hashes(root, paths):
    return {path: digest((root / path).read_bytes()) for path in paths}


def clean(root):
    status = git(root, "status", "--porcelain=v1", "--untracked-files=no")
    if status:
        raise AssertionError("Tracked source changed: " + status)
    git(root, "diff", "--exit-code", "HEAD", "--")
    return True


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def envelope(args, manifest, spec):
    assert os.environ.get("GITHUB_REPOSITORY") == manifest["repository"]
    assert os.environ.get("GITHUB_REF") == "refs/heads/" + manifest["validation_branch"]
    assert os.environ.get("GITHUB_EVENT_NAME") in {"push", "workflow_dispatch"}
    validation = commit(args.validation, "HEAD")
    assert validation["sha"] == os.environ["GITHUB_SHA"]
    assert validation["parents"] == [manifest["validation_parent"]]
    changed = git(args.validation, "diff", "--name-status", validation["parents"][0], "HEAD").splitlines()
    assert sorted(changed) == sorted("A\t" + path for path in manifest["validation_files"]), changed
    for path, expected in manifest["validation_hashes"].items():
        assert digest((args.validation / path).read_bytes()) == expected, path
    source = commit(args.source, "HEAD")
    assert source["sha"] == spec["source"]
    assert source["tree"] == spec["tree"]
    assert source["parents"] == [spec["old_head"], spec["base"]]
    assert commit(args.source, spec["base"])["tree"] == spec["base_tree"]
    observed = hashes(args.source, spec["source_hashes"])
    assert observed == spec["source_hashes"], "Frozen source file mismatch"
    assert re.search(r"^go " + re.escape(manifest["go_version"]) + r"$",
                     (args.source / "go.mod").read_text(), re.M)
    clean(args.source)
    clean(args.validation)
    result = {"validation": validation, "source": source,
              "base": commit(args.source, spec["base"]),
              "source_sha256": observed,
              "validation_sha256": hashes(args.validation, manifest["validation_files"]),
              "only_validation_files_added": True, "tracked_source_clean": True}
    save(args.results / "envelope.json", result)
    return result


def command(args, name, argv, timeout):
    log_path = args.results / (name + ".log")
    print("Starting " + name + ": " + " ".join(argv), flush=True)
    started = time.monotonic()
    timed_out = False
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(argv, cwd=args.source, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                   errors="replace", start_new_session=True)

        def collect():
            for line in process.stdout:
                log.write(line)
                log.flush()
                print(line, end="", flush=True)

        reader = threading.Thread(target=collect, daemon=True)
        reader.start()
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                code = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                code = process.wait()
        reader.join(timeout=10)
        assert not reader.is_alive(), "Output collection did not finish"
    return {"name": name, "command": argv, "exit_code": code, "timed_out": timed_out,
            "seconds": round(time.monotonic() - started, 3), "log": log_path.name,
            "log_sha256": digest(log_path.read_bytes())}


def go_results(args, phase):
    tests = {}
    packages = {}
    outputs = []
    ran = set()
    for line in (args.results / phase["log"]).read_text().splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        package, test, action = event.get("Package"), event.get("Test"), event.get("Action")
        if event.get("Output"):
            outputs.append(event["Output"])
        if test and action == "run":
            ran.add((package, test))
        if action in {"pass", "fail", "skip"}:
            if test:
                tests[(package, test)] = action
            elif package:
                packages[package] = action
    rows = [{"package": package, "test": test, "action": action}
            for (package, test), action in sorted(tests.items())]
    phase["test_results"] = rows
    phase["package_results"] = packages
    phase["counts"] = {
        action: sum(row["action"] == action for row in rows) for action in ("pass", "fail", "skip")}
    phase["top_level_counts"] = {
        action: sum(row["action"] == action and "/" not in row["test"] for row in rows)
        for action in ("pass", "fail", "skip")}
    assert not phase["timed_out"], "Timed-out runs are not test evidence"
    assert ran, "No actual test execution; setup/build failure is not a counterexample"
    assert all((row["package"], row["test"]) in ran for row in rows)
    return tests, packages, "".join(outputs)


def positive(args, phase, requirements):
    tests, packages, output = go_results(args, phase)
    assert phase["exit_code"] == 0, "Positive phase failed"
    assert "fail" not in tests.values() and "fail" not in packages.values()
    for item in requirements["required_passes"]:
        assert tests.get((item["package"], item["test"])) == "pass", item
    actual_skips = sorted({test for (package, test), action in tests.items() if action == "skip"})
    assert actual_skips == sorted(requirements.get("expected_skips", [])), actual_skips
    for fragment in requirements.get("skip_messages", []):
        assert fragment in output, fragment
    phase["required_behavior_verified"] = True


def negative(args, phase, expected):
    tests, packages, output = go_results(args, phase)
    assert phase["exit_code"] == 1, "Expected go test assertion-failure exit 1"
    observed_failures = sorted(test for (package, test), action in tests.items() if action == "fail")
    assert observed_failures == sorted(expected["failed_tests"]), observed_failures
    assert set(packages) == {expected["package"]} and packages[expected["package"]] == "fail"
    assert all(action == "fail" for action in tests.values()), tests
    for fragment in expected["assertion_fragments"]:
        assert fragment in output, fragment
    phase["expected_behavior_failures_verified"] = True


def run(args, manifest, spec):
    result = {"status": "running", "pr": args.pr, "phases": [], "negative_boundary": spec["negative_boundary"]}
    result_path = args.results / "result.json"
    saved = {}
    result["envelope"] = envelope(args, manifest, spec)
    before = hashes(args.source, spec["source_hashes"])
    save(result_path, result)
    try:
        versions = {"node": subprocess.check_output(["node", "--version"], text=True).strip(),
                    "npm": subprocess.check_output(["npm", "--version"], text=True).strip(),
                    "go": subprocess.check_output(["go", "version"], text=True).strip()}
        assert versions["node"] == "v" + manifest["node_version"]
        assert versions["go"].split()[2] == "go" + manifest["go_version"]
        assert os.environ.get("RUNNER_OS") == "Linux" and platform.machine() == "x86_64"
        assert os.environ.get("AGENTFLOW_TEST_AGENT_CLIS") != "1"
        environment = {"versions": versions, "platform": platform.platform(),
                       "os_release": Path("/etc/os-release").read_text(),
                       "runner_os": os.environ.get("RUNNER_OS"), "runner_arch": os.environ.get("RUNNER_ARCH"),
                       "go_env": subprocess.check_output(["go", "env", "GOOS", "GOARCH", "GOTOOLCHAIN", "GOMOD", "GOCACHE", "GOMODCACHE"], cwd=args.source, text=True),
                       "disk_before": shutil.disk_usage(args.source)._asdict()}
        save(args.results / "environment.json", environment)
        build = command(args, "frontend-build-and-tests", ["bash", "scripts/build-chatbot.sh"], 1200)
        result["phases"].append(build)
        save(result_path, result)
        assert build["exit_code"] == 0 and not build["timed_out"], "Frontend build/tests failed"
        build_text = re.sub(r"\x1b\[[0-9;]*m", "", (args.results / build["log"]).read_text())
        for label, expected in [("Test Files", 62), ("Tests", 535)]:
            match = re.search(label + r"\s+(\d+) passed\s+\((\d+)\)", build_text)
            assert match and int(match[1]) == expected and int(match[2]) == expected, (label, match)
        build["test_files_passed"] = 62
        build["tests_passed"] = 535
        for target in spec["positive_phases"]:
            phase = command(args, target["name"], target["command"], 2400)
            result["phases"].append(phase)
            positive(args, phase, target)
            save(result_path, result)
        baseline = {}
        for path, expected_hash in spec["negative_main_hashes"].items():
            saved[path] = (args.source / path).read_bytes()
            replacement = git(args.source, "show", spec["base"] + ":" + path, binary=True)
            assert digest(replacement) == expected_hash, path
            baseline[path] = {"candidate_sha256": digest(saved[path]), "main_sha256": digest(replacement)}
            (args.source / path).write_bytes(replacement)
        result["baseline_source_replacement"] = baseline
        try:
            phase = command(args, "exact-main-negative-control", spec["negative"]["command"], 2400)
            result["phases"].append(phase)
            negative(args, phase, spec["negative"])
        finally:
            for path, content in saved.items():
                (args.source / path).write_bytes(content)
            result["restored_negative_files"] = hashes(args.source, saved)
            assert all(result["restored_negative_files"][path] == digest(content) for path, content in saved.items())
            save(result_path, result)
        result["status"] = "passed"
    except Exception as error:
        result["status"] = "failed"
        result["error"] = str(error)
        (args.results / "harness-error.log").write_text(traceback.format_exc())
    finally:
        for path, content in saved.items():
            (args.source / path).write_bytes(content)
        result["source_sha256_before"] = before
        result["source_sha256_after"] = hashes(args.source, spec["source_hashes"])
        result["source_bytes_restored"] = result["source_sha256_after"] == before
        try:
            result["tracked_source_clean"] = clean(args.source)
            result["tracked_validation_clean"] = clean(args.validation)
            result["final_source_commit"] = commit(args.source, "HEAD")
            assert result["final_source_commit"] == result["envelope"]["source"]
            assert result["source_bytes_restored"]
        except Exception as error:
            result["status"] = "failed"
            result["restoration_error"] = str(error)
        result["disk_after"] = shutil.disk_usage(args.source)._asdict()
        save(result_path, result)
    return 0 if result["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["verify", "run"])
    parser.add_argument("--pr", required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--validation", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()
    args.source = args.source.resolve()
    args.validation = args.validation.resolve()
    args.results = args.results.resolve()
    args.results.mkdir(parents=True, exist_ok=True)
    manifest_path = Path(__file__).with_name("manifest.json")
    manifest = json.loads(manifest_path.read_text())
    (args.results / "manifest.json").write_bytes(manifest_path.read_bytes())
    spec = manifest["sources"][args.pr]
    if args.mode == "verify":
        envelope(args, manifest, spec)
        print("Pinned source and validation envelope verified", flush=True)
        return 0
    return run(args, manifest, spec)


if __name__ == "__main__":
    raise SystemExit(main())

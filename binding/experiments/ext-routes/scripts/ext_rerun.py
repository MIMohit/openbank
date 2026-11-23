"""Determinism reruns (oracle_spec §10) for ext-routes, adapted from W9 kill/scripts/rerun.py.

Every hit case of a topology is re-sent 3x, each on a freshly started topology
(down -> up --fresh-logs), with a fresh proof per send. Unlike W9's version this reads the
pre-generated ext cases.jsonl (which carries the v2 base ops and the custom fragment
primitives) and drives the matrix through ext_run_matrix.py so the v2 base ops are
registered for proof minting.

    cd binding/harness && orchestrator/.venv/bin/python \
        ../experiments/ext-routes/scripts/ext_rerun.py <topology-id> [--reps 3]

Writes experiments/ext-routes/reruns/<id>/rep<k>/ and reruns/<id>/rerun_outcome.jsonl:
one line per original hit, outcome confirmed (3/3) | flaky (1-2/3) | irreproducible (0/3).
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time

HARNESS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "harness"))
K = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS = os.path.dirname(os.path.abspath(__file__))
PY = os.path.join(HARNESS, "orchestrator", ".venv", "bin", "python")
ENV = {**os.environ, "BH_PROJECT_PREFIX": "w15r-bh-"}


def jl(p):
    return [json.loads(l) for l in open(p) if l.strip()] if os.path.exists(p) else []


def sh(cmd, log, cwd=HARNESS):
    with open(log, "a") as f:
        f.write("\n$ " + " ".join(str(c) for c in cmd) + "\n")
        return subprocess.run(cmd, cwd=cwd, stdout=f, stderr=subprocess.STDOUT, env=ENV).returncode


def clock_check(max_skew=5.0):
    """Abort if the Docker VM clock differs from the host clock (verifier IAT_WINDOW=60).
    Guards against the host-sleep clock skew W9 hit (G1_REPORT §5)."""
    out = subprocess.run(["docker", "run", "--rm", "python:3.12.16-slim-trixie", "date", "+%s"],
                         capture_output=True, text=True).stdout.strip()
    skew = abs(float(out) - time.time())
    if skew > max_skew:
        raise SystemExit(f"docker clock skew {skew:.0f}s > {max_skew}s; not running (fix clock first)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tid")
    ap.add_argument("--reps", type=int, default=3)
    a = ap.parse_args()
    tid = a.tid
    yml = os.path.join(K, "topologies", f"{tid}.yaml")
    import yaml
    t = yaml.safe_load(open(yml))
    fw, ov = t["framework"], str(t["override"])
    hits = jl(os.path.join(K, "runs", tid, "hits.jsonl"))
    if not hits:
        print(f"{tid}: no hits"); return
    want = {h["case_id"] for h in hits}
    allcases = jl(os.path.join(K, "cases.jsonl"))
    sel = [c for c in allcases if c["case_id"] in want or c.get("depth") == 0]
    missing = want - {c["case_id"] for c in sel}
    assert not missing, f"case ids not in cases.jsonl: {missing}"
    root = os.path.join(K, "reruns", tid)
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root, exist_ok=True)
    cfile = os.path.join(root, "cases.jsonl")
    with open(cfile, "w") as f:
        for c in sel:
            f.write(json.dumps(c) + "\n")
    rep_hits = []
    for k in range(1, a.reps + 1):
        d = os.path.join(root, f"rep{k}")
        os.makedirs(d)
        clock_check()
        log = os.path.join(d, "rerun.log")
        sh([PY, "-m", "orchestrator.down", yml], log)
        if sh([PY, "-m", "orchestrator.up", yml, "--stubs", "off", "--fresh-logs", "--timeout", "300"], log) != 0:
            sh([PY, "-m", "orchestrator.down", yml], log)
            print(f"{tid} rep{k}: UP FAILED"); rep_hits.append(None); continue
        sh([PY, os.path.join(SCRIPTS, "ext_run_matrix.py"), "--topology", yml,
            "--cases", cfile, "--out", f"logs/{tid}/runner.jsonl", "--minter", "w3"], log)
        sh([PY, "-m", "orchestrator.down", yml], log)
        for f in ("runner", "verifier", "executor"):
            src = os.path.join(HARNESS, "logs", tid, f"{f}.jsonl")
            if os.path.exists(src):
                shutil.copy(src, d)
        shutil.rmtree(os.path.join(HARNESS, "orchestrator", "generated", tid), ignore_errors=True)
        sh([PY, "-m", "oracle.correlate", "--log-dir", d, "--topology", yml,
            "--ground-truth", os.path.join(K, "groundtruth", f"{fw}-ov{ov}.jsonl")], log)
        rep_hits.append({h["case_id"]: h for h in jl(os.path.join(d, "hits.jsonl"))})
    with open(os.path.join(root, "rerun_outcome.jsonl"), "w") as f:
        for h in sorted(hits, key=lambda h: h["case_id"]):
            res = []
            for rh in rep_hits:
                r = (rh or {}).get(h["case_id"])
                res.append(bool(r and r["exec_op_id"] == h["exec_op_id"]
                                and r["exec_path_params"] == h["exec_path_params"]))
            n = sum(res)
            out = "confirmed" if n == a.reps else ("irreproducible" if n == 0 else "flaky")
            f.write(json.dumps({"topology": tid, "case_id": h["case_id"], "exec_op_id": h["exec_op_id"],
                                "primitive_ids": h["primitive_ids"], "reps": res, "outcome": out}) + "\n")
    conf = sum(1 for l in jl(os.path.join(root, "rerun_outcome.jsonl")) if l["outcome"] == "confirmed")
    print(f"{tid}: reran {len(hits)} hits x {a.reps}; confirmed {conf}/{len(hits)}")


if __name__ == "__main__":
    main()

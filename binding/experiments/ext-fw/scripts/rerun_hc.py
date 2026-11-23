"""Determinism reruns (oracle_spec §10): every hit case of a topology, 3x, each on a freshly
started topology (down -> up --fresh-logs), fresh proof per send.

    cd binding/harness && orchestrator/.venv/bin/python ../experiments/ext-fw/scripts/rerun.py <topology-id> [--reps 3]

Writes experiments/ext-fw/reruns/<id>/rep<k>/ (logs, hits.jsonl from oracle.correlate) and
experiments/ext-fw/reruns/<id>/rerun_outcome.jsonl: one line per original hit with
outcome confirmed (3/3) | flaky (1-2/3) | irreproducible (0/3).
"""
import argparse, json, os, shutil, subprocess, sys

HARNESS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "harness"))
K = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, HARNESS)
from mutator import compose  # noqa: E402

PY = os.path.join(HARNESS, "orchestrator", ".venv", "bin", "python")


def jl(p):
    return [json.loads(l) for l in open(p) if l.strip()] if os.path.exists(p) else []


def sh(cmd, log):
    with open(log, "a") as f:
        return subprocess.run(cmd, cwd=HARNESS, stdout=f, stderr=subprocess.STDOUT,
                              env={**os.environ, "BH_PROJECT_PREFIX": "w14-bh-"}).returncode


def clock_check(max_skew=5.0):
    """Abort if the Docker VM clock differs from the host clock (verifier IAT_WINDOW=60)."""
    import time
    out = subprocess.run(["docker", "run", "--rm", "python:3.12.16-slim-trixie", "date", "+%s"],
                         capture_output=True, text=True).stdout.strip()
    skew = abs(float(out) - time.time())
    if skew > max_skew:
        raise SystemExit(f"docker clock skew {skew:.0f}s > {max_skew}s; not running")


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("tid"); ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--redo-skewed", action="store_true",
                    help="keep existing reps; redo only reps whose verifier log has iat_skew denials "
                         "(oracle_spec §10 rerun_timing_deny; caused by the Docker VM clock lagging after host sleep)")
    ap.add_argument("--runs-dir", default="runs", help="dir under ext-fw/ to read hits.jsonl from")
    ap.add_argument("--reruns-dir", default="reruns", help="dir under ext-fw/ to write rerun reps to")
    a = ap.parse_args()
    tid = a.tid
    yml = os.path.join(K, "topologies", f"{tid}.yaml")
    t = {l.split(":")[0]: l.split(":", 1)[1].strip().strip("'") for l in open(yml) if ":" in l and not l.startswith(" ")}
    fw, ov = t["framework"], t["override"]
    hits = jl(os.path.join(K, a.runs_dir, tid, "hits.jsonl"))
    if not hits:
        print(f"{tid}: no hits"); return
    want = {h["case_id"] for h in hits}
    cases = [json.loads(c.to_json()) for c in compose.generate(depth=1)]
    sel = [c for c in cases if c["case_id"] in want or c.get("depth") == 0]
    missing = want - {c["case_id"] for c in sel}
    assert not missing, f"case ids not regenerated: {missing}"
    root = os.path.join(K, a.reruns_dir, tid)
    if not a.redo_skewed:
        shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root, exist_ok=True)
    cfile = os.path.join(root, "cases.jsonl")
    with open(cfile, "w") as f:
        for c in sel:
            f.write(json.dumps(c) + "\n")
    rep_hits = []
    for k in range(1, a.reps + 1):
        d = os.path.join(root, f"rep{k}")
        if a.redo_skewed and os.path.exists(os.path.join(d, "hits.jsonl")) and not any(
                v.get("reason") == "iat_skew" for v in jl(os.path.join(d, "verifier.jsonl"))):
            rep_hits.append({h["case_id"]: h for h in jl(os.path.join(d, "hits.jsonl"))}); continue
        if os.path.exists(d):
            old = d + ".iat_skew_discarded"; shutil.rmtree(old, ignore_errors=True); os.rename(d, old)
        os.makedirs(d)
        clock_check()
        log = os.path.join(d, "rerun.log")
        UPHC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "up_hostfix.py")
        # A rep is VALID only if the verifier actually engaged. On a cold start the gateway
        # (envoy ext_authz) can briefly fail OPEN before the verifier cluster is ready, so the
        # runner's requests reach the executor unverified (0 verifier records, all B0 bypass).
        # That is an infra-readiness failure, not a determinism result: discard and retry, the
        # same treatment oracle_spec §10 gives rerun_timing_deny. Up to 4 attempts.
        ok_rep = False
        for attempt in range(1, 5):
            sh([PY, "-m", "orchestrator.down", yml], log)
            if sh([PY, UPHC, yml, "--timeout", "300"], log) != 0:
                sh([PY, "-m", "orchestrator.down", yml], log)
                print(f"{tid} rep{k}: UP FAILED (attempt {attempt})"); continue
            import time as _t; _t.sleep(5)  # let ext_authz settle before the first case
            sh([PY, "-m", "runner.run_matrix", "--topology", yml, "--minter", "w3", "--cases", cfile], log)
            sh([PY, "-m", "orchestrator.down", yml], log)
            for f in ("runner", "verifier", "executor"):
                src = os.path.join(HARNESS, "logs", tid, f"{f}.jsonl")
                if os.path.exists(src):
                    shutil.copy(src, d)
            shutil.rmtree(os.path.join(HARNESS, "orchestrator", "generated", tid), ignore_errors=True)
            if len(jl(os.path.join(d, "verifier.jsonl"))) > 0:
                ok_rep = True; break
            print(f"{tid} rep{k}: INVALID (verifier never engaged / B0 bypass), retry (attempt {attempt})")
            for f in ("runner", "verifier", "executor"):
                try: os.remove(os.path.join(d, f"{f}.jsonl"))
                except OSError: pass
        if not ok_rep:
            print(f"{tid} rep{k}: GAVE UP after retries"); rep_hits.append(None); continue
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
                                "reps": res, "outcome": out}) + "\n")
    print(f"{tid}: reran {len(hits)} hits x {a.reps}")


if __name__ == "__main__":
    main()

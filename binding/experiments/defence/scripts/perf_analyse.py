"""Perf analysis: results/perf/raw/<cfg>-<fw>/<lvl>-r<k>.lat.npy -> analysis/perf_*.csv, perf_tables.md.
CIs: percentile bootstrap (analysis/stats.py bootstrap_ci, 2000 resamples) over the per-run percentile values
(captures run-to-run noise; n = runs). Tests: Mann-Whitney U (scipy, two-sided) and Cliff's delta
(analysis/stats.py) on per-request latencies, defence vs B-edge, same framework and load level
(Cliff's delta on a 5000-sample random subsample per side, seed 1).
Latency = k6 http_req_duration of EVERY request, failed ones included (failures are reported per cell)."""
import csv, glob, json, os, sys
import numpy as np
from scipy.stats import mannwhitneyu
D = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, "/Users/mimohit/openbank")
from analysis.stats import bootstrap_ci, cliffs_delta, cliffs_delta_magnitude  # noqa: E402
RAW = os.path.join(D, "results", "perf", "raw")
CFGS = ["bedge", "borigin", "da", "db"]; NAME = {"bedge": "B-edge", "borigin": "B-origin", "da": "D-A", "db": "D-B"}
LVLS = ["100", "500", "1000", "max"]

def load(cfg, fw, lvl):
    runs = []
    for f in sorted(glob.glob(os.path.join(RAW, f"{cfg}-{fw}", f"{lvl}-r*.lat.npy"))):
        m = json.load(open(f.replace(".lat.npy", ".meta.json")))
        sm = json.load(open(f.replace(".lat.npy", ".summary.json")))
        m["achieved_rps"] = sm["metrics"]["http_reqs"]["rate"]  # k6's own rate (CSV timestamps are 1 s resolution)
        runs.append((np.load(f).astype(np.float64), m))
    return runs

def main():
    rows, tests = [], []
    fws = sorted({os.path.basename(p).split("-", 1)[1] for p in glob.glob(os.path.join(RAW, "*-*"))})
    rng = np.random.default_rng(1)
    for fw in fws:
        for lvl in LVLS:
            pooled = {}
            for cfg in CFGS:
                runs = load(cfg, fw, lvl)
                if not runs: continue
                per = {q: np.array([np.percentile(x, q) for x, _ in runs]) for q in (50, 95, 99)}
                rps = np.array([m["achieved_rps"] or 0 for _, m in runs])
                fail = sum(m["checks_fail"] for _, m in runs); n = sum(m["n"] for _, m in runs)
                r = {"framework": fw, "level": lvl, "config": NAME[cfg], "runs": len(runs), "requests": n, "failed_checks": fail}
                for q in (50, 95, 99):
                    e, lo, hi = bootstrap_ci(per[q]); r.update({f"p{q}_ms": round(e, 3), f"p{q}_lo": round(lo, 3), f"p{q}_hi": round(hi, 3)})
                e, lo, hi = bootstrap_ci(rps); r.update({"rps": round(e, 1), "rps_lo": round(lo, 1), "rps_hi": round(hi, 1)})
                rows.append(r); pooled[cfg] = np.concatenate([x for x, _ in runs])
            if "bedge" in pooled:
                b = pooled["bedge"]
                for cfg in CFGS[1:]:
                    if cfg not in pooled: continue
                    x = pooled[cfg]; u, p = mannwhitneyu(x, b, alternative="two-sided")
                    xs = rng.choice(x, min(5000, len(x)), replace=False); bs = rng.choice(b, min(5000, len(b)), replace=False)
                    dlt = cliffs_delta(xs, bs)
                    tests.append({"framework": fw, "level": lvl, "config": NAME[cfg], "vs": "B-edge",
                                  "median_diff_ms": round(float(np.median(x) - np.median(b)), 3),
                                  "p99_diff_ms": round(float(np.percentile(x, 99) - np.percentile(b, 99)), 3),
                                  "mwu_U": float(u), "mwu_p": float(p), "cliffs_delta": round(dlt, 3),
                                  "magnitude": cliffs_delta_magnitude(dlt)})
    for name, data in (("perf_latency.csv", rows), ("perf_tests.csv", tests)):
        if data:
            with open(os.path.join(D, "analysis", name), "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(data[0])); w.writeheader(); w.writerows(data)
    L = ["| fw | load | config | p50 ms [95% CI] | p95 ms [95% CI] | p99 ms [95% CI] | achieved req/s [95% CI] | failed |",
         "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        L.append(f"| {r['framework']} | {r['level']} | {r['config']} | {r['p50_ms']:.2f} [{r['p50_lo']:.2f}, {r['p50_hi']:.2f}] | "
                 f"{r['p95_ms']:.2f} [{r['p95_lo']:.2f}, {r['p95_hi']:.2f}] | {r['p99_ms']:.2f} [{r['p99_lo']:.2f}, {r['p99_hi']:.2f}] | "
                 f"{r['rps']:.0f} [{r['rps_lo']:.0f}, {r['rps_hi']:.0f}] | {r['failed_checks']}/{r['requests']} |")
    L += ["", "| fw | load | config vs B-edge | Δmedian ms | Δp99 ms | MWU p | Cliff's δ |", "|---|---|---|---|---|---|---|"]
    for t in tests:
        L.append(f"| {t['framework']} | {t['level']} | {t['config']} | {t['median_diff_ms']:+.2f} | {t['p99_diff_ms']:+.2f} | {t['mwu_p']:.2g} | {t['cliffs_delta']:+.2f} ({t['magnitude']}) |")
    open(os.path.join(D, "analysis", "perf_tables.md"), "w").write("\n".join(L) + "\n")
    print("\n".join(L))

if __name__ == "__main__":
    main()

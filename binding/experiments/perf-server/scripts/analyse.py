"""Server perf analysis. Same method as experiments/defence/scripts/perf_analyse.py:
  * per-request latency = k6 http_req_duration of EVERY request (failed included);
  * CIs = percentile bootstrap (analysis/stats.py bootstrap_ci) over the 5 per-run percentiles;
  * Mann-Whitney U (scipy, two-sided) on pooled per-request latencies, defence vs B-edge, same fw + level;
  * Cliff's delta (analysis/stats.py) on a 5000-sample random subsample per side (seed 1).
Step 1 converts results/raw/<cfg>-<fw>/<lvl>-r<k>.csv.gz -> .lat.npy + .meta.json (logic of defence/scripts/perf_csv.py).
Step 2 writes analysis/{perf_latency.csv,perf_tests.csv,perf_tables.md,laptop_compare.md,cpu_throttle.md}.
Run: ../defence/build/.venv-stats/bin/python scripts/analyse.py   (from experiments/perf-server)"""
import csv, glob, gzip, json, os, sys
import numpy as np
from scipy.stats import mannwhitneyu
D = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, "/Users/mimohit/openbank")
from analysis.stats import bootstrap_ci, cliffs_delta, cliffs_delta_magnitude  # noqa: E402
RAW = os.path.join(D, "results", "raw"); OUT = os.path.join(D, "analysis")
LAPTOP = os.path.join(D, "..", "defence", "analysis", "perf_latency.csv")
CFGS = ["bedge", "borigin", "da", "db"]; NAME = {"bedge": "B-edge", "borigin": "B-origin", "da": "D-A", "db": "D-B"}
LVLS = ["50", "100"]


def convert(gz):
    base = gz[:-7]
    if os.path.exists(base + ".lat.npy") and os.path.getmtime(base + ".lat.npy") >= os.path.getmtime(gz):
        return
    lat, ok, fail, t = [], 0, 0, []
    with gzip.open(gz, "rt") as f:
        for row in csv.DictReader(f):
            m = row["metric_name"]
            if m == "http_req_duration":
                lat.append(float(row["metric_value"])); t.append(float(row["timestamp"]))
            elif m == "checks":
                if float(row["metric_value"]) == 1: ok += 1
                else: fail += 1
    np.save(base + ".lat.npy", np.asarray(lat, dtype=np.float32))
    dur = (max(t) - min(t)) if t else 0
    json.dump({"n": len(lat), "checks_ok": ok, "checks_fail": fail, "span_s": dur,
               "achieved_rps": (len(lat) / dur) if dur else None}, open(base + ".meta.json", "w"))


def load(cfg, fw, lvl):
    runs = []
    for f in sorted(glob.glob(os.path.join(RAW, f"{cfg}-{fw}", f"{lvl}-r*.lat.npy"))):
        m = json.load(open(f.replace(".lat.npy", ".meta.json")))
        sm = json.load(open(f.replace(".lat.npy", ".summary.json")))
        m["achieved_rps"] = sm["metrics"]["http_reqs"]["rate"]
        m["dropped"] = sm["metrics"].get("dropped_iterations", {}).get("count", 0)
        runs.append((np.load(f).astype(np.float64), m))
    return runs


def throttle():
    """cgroup cpu.stat deltas per run (throttled share of periods; usage in CPU-seconds)."""
    L = ["| topology | run | container | CPU-s used | periods | throttled periods | throttled % | throttled s | mem peak MiB |",
         "|---|---|---|---|---|---|---|---|---|"]
    rows = []
    for b in sorted(glob.glob(os.path.join(RAW, "*", "*.cpu_before.txt"))):
        a = b.replace("cpu_before", "cpu_after")
        if not os.path.exists(a): continue
        def parse(p):
            r = {}
            for line in open(p):
                parts = line.split(); n = parts[0]; kv = dict(zip(parts[1::2], parts[2::2]))
                peak = [x for x in parts if x.startswith("mem_peak=")]
                kv["mem_peak"] = peak[0].split("=")[1] if peak else ""
                r[n] = kv
            return r
        pb, pa = parse(b), parse(a); topo = os.path.basename(os.path.dirname(b)); tag = os.path.basename(b).split(".")[0]
        for n in sorted(pa):
            if n not in pb: continue
            d = {k: int(pa[n][k]) - int(pb[n][k]) for k in ("usage_usec", "nr_periods", "nr_throttled", "throttled_usec")}
            pct = 100 * d["nr_throttled"] / d["nr_periods"] if d["nr_periods"] else 0
            mp = int(pa[n]["mem_peak"]) / 2**20 if pa[n]["mem_peak"].isdigit() else float("nan")
            rows.append({"topology": topo, "run": tag, "container": n, **d, "throttled_pct": round(pct, 2), "mem_peak_mib": round(mp, 1)})
            L.append(f"| {topo} | {tag} | {n} | {d['usage_usec']/1e6:.1f} | {d['nr_periods']} | {d['nr_throttled']} | {pct:.1f} | "
                     f"{d['throttled_usec']/1e6:.2f} | {mp:.0f} |")
    return L, rows


def main():
    for gz in glob.glob(os.path.join(RAW, "*", "*-r*.csv.gz")):
        convert(gz)
    os.makedirs(OUT, exist_ok=True)
    rows, tests = [], []
    rng = np.random.default_rng(1)
    for fw in ("fastapi", "spring"):
        for lvl in LVLS:
            pooled = {}
            for cfg in CFGS:
                runs = load(cfg, fw, lvl)
                if not runs: continue
                per = {q: np.array([np.percentile(x, q) for x, _ in runs]) for q in (50, 95, 99)}
                rps = np.array([m["achieved_rps"] or 0 for _, m in runs])
                fail = sum(m["checks_fail"] for _, m in runs); n = sum(m["n"] for _, m in runs)
                r = {"framework": fw, "level": lvl, "config": NAME[cfg], "runs": len(runs), "requests": n, "failed_checks": fail,
                     "dropped_iterations": sum(m["dropped"] for _, m in runs)}
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
            with open(os.path.join(OUT, name), "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(data[0])); w.writeheader(); w.writerows(data)
    L = ["| fw | load | config | p50 ms [95% CI] | p95 ms [95% CI] | p99 ms [95% CI] | achieved req/s [95% CI] | failed | dropped |",
         "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        L.append(f"| {r['framework']} | {r['level']} | {r['config']} | {r['p50_ms']:.2f} [{r['p50_lo']:.2f}, {r['p50_hi']:.2f}] | "
                 f"{r['p95_ms']:.2f} [{r['p95_lo']:.2f}, {r['p95_hi']:.2f}] | {r['p99_ms']:.2f} [{r['p99_lo']:.2f}, {r['p99_hi']:.2f}] | "
                 f"{r['rps']:.1f} [{r['rps_lo']:.1f}, {r['rps_hi']:.1f}] | {r['failed_checks']}/{r['requests']} | {r['dropped_iterations']} |")
    L += ["", "| fw | load | config vs B-edge | Δmedian ms | Δp99 ms | MWU p | Cliff's δ |", "|---|---|---|---|---|---|---|"]
    for t in tests:
        L.append(f"| {t['framework']} | {t['level']} | {t['config']} | {t['median_diff_ms']:+.2f} | {t['p99_diff_ms']:+.2f} | {t['mwu_p']:.2g} | {t['cliffs_delta']:+.2f} ({t['magnitude']}) |")
    open(os.path.join(OUT, "perf_tables.md"), "w").write("\n".join(L) + "\n")
    print("\n".join(L))
    # laptop comparison at the shared level (100 req/s)
    lap = {(r["framework"], r["level"], r["config"]): r for r in csv.DictReader(open(LAPTOP))}
    C = ["| fw | config | laptop p50 ms [CI] | server p50 ms [CI] | laptop p99 ms [CI] | server p99 ms [CI] |", "|---|---|---|---|---|---|"]
    for r in rows:
        if r["level"] != "100": continue
        l = lap.get((r["framework"], "100", r["config"]))
        if not l: continue
        f = lambda e, lo, hi: f"{float(e):.2f} [{float(lo):.2f}, {float(hi):.2f}]"
        C.append(f"| {r['framework']} | {r['config']} | {f(l['p50_ms'], l['p50_lo'], l['p50_hi'])} | {f(r['p50_ms'], r['p50_lo'], r['p50_hi'])} | "
                 f"{f(l['p99_ms'], l['p99_lo'], l['p99_hi'])} | {f(r['p99_ms'], r['p99_lo'], r['p99_hi'])} |")
    open(os.path.join(OUT, "laptop_compare.md"), "w").write("\n".join(C) + "\n")
    print("\n".join(C))
    T, trows = throttle()
    open(os.path.join(OUT, "cpu_throttle.md"), "w").write("\n".join(T) + "\n")
    if trows:
        with open(os.path.join(OUT, "cpu_throttle.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(trows[0])); w.writeheader(); w.writerows(trows)


if __name__ == "__main__":
    main()

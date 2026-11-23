"""W18 A1 analysis: per variant x framework x override -> accepted, hits by class/mechanism/family, max
resolution, baseline false rejections, deny reasons. Run from experiments/ablation (after run_all.sh).
Outputs analysis/a1_per_topology.csv, a1_variant_summary.csv, a1_variant_mechanism.csv, a1_variant_family.csv,
a1_deny_reasons.csv, a1_hits_all.jsonl.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mech  # noqa: E402
from make_topologies import FWS, VARIANTS  # noqa: E402

A = Path(__file__).resolve().parents[1]
OUT = A / "analysis"
RUNS = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else A / "runs"
PFX = "a1" if RUNS.name == "runs" else "a1_" + RUNS.name


def rj(p):
    return [json.loads(l) for l in open(p)] if p.exists() else []


def main():
    summ = {}
    for r in csv.DictReader(open(RUNS / "summary.csv")):
        summ[r["topology"]] = r          # last row wins (re-runs append)
    per, allh, deny = [], [], []
    vm, vf = defaultdict(Counter), defaultdict(Counter)
    for v in VARIANTS:
        for fw in FWS:
            for ov in ("off", "on"):
                tid = f"w18-{v}-nginx-default-edge-{fw}-ov{ov}"
                d = RUNS / tid
                if not (d / "hits.jsonl").exists():
                    continue
                H = rj(d / "hits.jsonl")
                R = rj(d / "runner.jsonl")
                V = rj(d / "verifier.jsonl")
                G = rj(d / "digest_gate.jsonl")
                base = [r for r in R if r["depth"] == 0]
                fr = [r["base_op_id"] for r in base if r["status"] >= 400 or r["resp_op_id"] != r["base_op_id"]]
                dr = Counter(x["reason"] for x in V if x["decision"] == "deny")
                gr = Counter("gate:" + x["reason"] for x in G if x.get("decision") == "deny")
                for k, n in (dr + gr).items():
                    deny.append({"variant": v, "framework": fw, "override": ov, "reason": k, "n": n})
                c = Counter(mech.MECH_CLASS.get(mech.mechanism(h), "?") for h in H)
                for h in H:
                    h["variant"] = v
                    h["family"] = mech.hit_family(h)
                    h["mech"] = mech.mechanism(h)
                    vm[v][h["mech"]] += 1
                    vf[v][h["family"]] += 1
                    allh.append(h)
                s = summ.get(tid, {})
                per.append({"variant": v, "framework": fw, "override": ov, "cases": len(R),
                            "errors": sum(1 for r in R if r.get("error")),
                            "verifier_allow": sum(1 for x in V if x["decision"] == "allow"),
                            "gate_deny": sum(gr.values()),
                            "hits": len(H), "g1": c.get("G1", 0) + c.get("G1*", 0), "g2": c.get("G2", 0),
                            "other": sum(n for k, n in c.items() if k not in ("G1", "G1*", "G2")),
                            "S1": sum(1 for h in H if h["severity"] == "S1"),
                            "max_res_hat": s.get("max_res_hat", ""),
                            "baseline_false_reject": len(fr), "fr_ops": "|".join(fr)})
    f = list(per[0].keys())
    with open(OUT / f"{PFX}_per_topology.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=f); w.writeheader(); w.writerows(per)
    agg = []
    for v in VARIANTS:
        P = [p for p in per if p["variant"] == v]
        if not P:
            continue
        agg.append({"variant": v, "topologies": len(P), "cases": sum(p["cases"] for p in P),
                    "verifier_allow": sum(p["verifier_allow"] for p in P), "gate_deny": sum(p["gate_deny"] for p in P),
                    "hits": sum(p["hits"] for p in P), "g1": sum(p["g1"] for p in P), "g2": sum(p["g2"] for p in P),
                    "other": sum(p["other"] for p in P), "S1": sum(p["S1"] for p in P),
                    "max_res_hat": max(int(p["max_res_hat"] or 0) for p in P),
                    "mean_max_res_hat": round(sum(int(p["max_res_hat"] or 0) for p in P) / len(P), 2),
                    "baseline_false_reject": sum(p["baseline_false_reject"] for p in P),
                    "mechanisms": len(vm[v])})
    with open(OUT / f"{PFX}_variant_summary.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(agg[0].keys())); w.writeheader(); w.writerows(agg)
    for name, src in ((f"{PFX}_variant_mechanism.csv", vm), (f"{PFX}_variant_family.csv", vf)):
        keys = sorted({k for c in src.values() for k in c})
        with open(OUT / name, "w", newline="") as fh:
            w = csv.writer(fh); w.writerow(["key"] + list(VARIANTS))
            for k in keys:
                w.writerow([k] + [src[v].get(k, 0) for v in VARIANTS])
    with open(OUT / f"{PFX}_deny_reasons.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["variant", "framework", "override", "reason", "n"]); w.writeheader(); w.writerows(deny)
    with open(OUT / f"{PFX}_hits_all.jsonl", "w") as fh:
        for h in allh:
            fh.write(json.dumps(h, sort_keys=True) + "\n")
    for a in agg:
        print(a)


if __name__ == "__main__":
    main()

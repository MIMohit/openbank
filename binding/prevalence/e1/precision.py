#!/usr/bin/env python3
"""Precision of the E1 detectors from the seeded 100-operation hand validation.

Inputs: e1/out/validation_sample.csv (drawn by sample.py, seed 20261123) and
e1/validation_judgments.csv (one verdict per sample_id, judged by reading the spec text:
TP = the flagged (method, path) key carries >= 2 semantically different operations told apart only
by a query/header/body value; FP = the flagged value is data, a filter, an option or a polymorphic
body of one operation; UNCLEAR = the spec text does not settle it).
Outputs: e1/out/precision.csv and a markdown table on stdout.  Precision per stratum with Wilson 95%
CIs; overall precision re-weighted by stratum size (flagged ops in the chosen set).  UNCLEAR is
counted as FP (conservative) and, separately, excluded (optimistic).
"""
import csv
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "..")))
from analysis.stats import wilson_ci  # noqa: E402

OUT = os.path.join(HERE, "out")


def main():
    sample = {r["sample_id"]: r for r in csv.DictReader(open(os.path.join(OUT, "validation_sample.csv")))}
    judg = {r["sample_id"]: r for r in csv.DictReader(open(os.path.join(HERE, "validation_judgments.csv")))}
    missing = set(sample) - set(judg)
    extra = set(judg) - set(sample)
    assert not missing and not extra, (missing, extra)
    strata = {}
    for sid, s in sample.items():
        st = strata.setdefault(s["stratum"], dict(size=int(s["stratum_size"]), n=0, tp=0, fp=0, unclear=0))
        st["n"] += 1
        v = judg[sid]["verdict"]
        st[{"TP": "tp", "FP": "fp", "UNCLEAR": "unclear"}[v]] += 1
    rows = []
    tot_size = sum(st["size"] for st in strata.values())
    w_cons = w_opt = 0.0
    est_tp_cons = 0.0
    for m, st in sorted(strata.items()):
        p, lo, hi = wilson_ci(st["tp"], st["n"])
        n_opt = st["n"] - st["unclear"]
        p_opt = st["tp"] / n_opt if n_opt else float("nan")
        w_cons += p * st["size"] / tot_size
        w_opt += p_opt * st["size"] / tot_size
        est_tp_cons += p * st["size"]
        rows.append(dict(stratum=m, stratum_size=st["size"], sampled=st["n"], tp=st["tp"], fp=st["fp"], unclear=st["unclear"],
                         precision=round(p, 4), ci_lo=round(lo, 4), ci_hi=round(hi, 4),
                         precision_excl_unclear=round(p_opt, 4), est_true_flagged_ops=round(p * st["size"], 1)))
    k = sum(r["tp"] for r in rows)
    n = sum(r["sampled"] for r in rows)
    p, lo, hi = wilson_ci(k, n)
    rows.append(dict(stratum="ALL (unweighted sample)", stratum_size=tot_size, sampled=n, tp=k,
                     fp=sum(r["fp"] for r in rows), unclear=sum(r["unclear"] for r in rows), precision=round(p, 4),
                     ci_lo=round(lo, 4), ci_hi=round(hi, 4), precision_excl_unclear="", est_true_flagged_ops=""))
    rows.append(dict(stratum="ALL (stratum-weighted)", stratum_size=tot_size, sampled=n, tp="", fp="", unclear="",
                     precision=round(w_cons, 4), ci_lo="", ci_hi="", precision_excl_unclear=round(w_opt, 4),
                     est_true_flagged_ops=round(est_tp_cons, 1)))
    nonm1 = [r for r in rows[:-2] if r["stratum"] != "M1-query-in-path"]
    k2 = sum(r["tp"] for r in nonm1)
    n2 = sum(r["sampled"] for r in nonm1)
    p2, lo2, hi2 = wilson_ci(k2, n2)
    size2 = sum(r["stratum_size"] for r in nonm1)
    wp2 = sum(r["precision"] * r["stratum_size"] for r in nonm1) / size2
    rows.append(dict(stratum="non-M1 (M2+M4+M5) unweighted sample", stratum_size=size2, sampled=n2, tp=k2, fp="", unclear="",
                     precision=round(p2, 4), ci_lo=round(lo2, 4), ci_hi=round(hi2, 4), precision_excl_unclear="",
                     est_true_flagged_ops=""))
    rows.append(dict(stratum="non-M1 (M2+M4+M5) stratum-weighted", stratum_size=size2, sampled=n2, tp="", fp="", unclear="",
                     precision=round(wp2, 4), ci_lo="", ci_hi="", precision_excl_unclear="",
                     est_true_flagged_ops=round(sum(r["est_true_flagged_ops"] for r in nonm1), 1)))
    with open(os.path.join(OUT, "precision.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print("| " + " | ".join(rows[0].keys()) + " |")
    print("|" + "---|" * len(rows[0]))
    for r in rows:
        print("| " + " | ".join(str(v) for v in r.values()) + " |")


if __name__ == "__main__":
    main()


def finance_census():
    """Full census (not a sample) of every strong-tier flag in finance-category APIs."""
    rows = list(csv.DictReader(open(os.path.join(HERE, "finance_census_judgments.csv"))))
    tp = [r for r in rows if r["verdict"] == "TP"]
    print(f"\nfinance census: {len(tp)}/{len(rows)} flagged ops TP; APIs with >=1 TP: "
          f"{sorted({r['api_id'] for r in tp})} of {sorted({r['api_id'] for r in rows})} flagged")


if __name__ == "__main__":
    finance_census()

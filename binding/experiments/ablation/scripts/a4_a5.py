"""W18 A4 (primitive-family leave-one-out) and A5 (gateway profile) from EXISTING data, plus the new strict runs.
Inputs: ../{kill,ext-gw,ext-fw,ext-routes}/analysis/hits_all.jsonl, runs/summary.csv, topologies/*.yaml;
        ../e4/analysis/violations_all.csv + classes.json + runs/summary.csv; strict/runs*/ (new).
Outputs: analysis/a4_*.csv, analysis/a5_*.csv, analysis/a4_a5.json. Run from experiments/ablation.
"""
from __future__ import annotations

import csv
import glob
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mech  # noqa: E402

A = Path(__file__).resolve().parents[1]
X = A.parent
OUT = A / "analysis"
OUT.mkdir(exist_ok=True)
EXPS = ["kill", "ext-gw", "ext-fw", "ext-routes"]


def wcsv(name, rows, fields):
    with open(OUT / name, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def load_hits():
    H = []
    for d in EXPS:
        for l in open(X / d / "analysis" / "hits_all.jsonl"):
            h = json.loads(l)
            h["exp"] = d
            h["family"] = mech.hit_family(h)
            h["mech"] = mech.mechanism(h)
            H.append(h)
    return H


def a4(H):
    res = {}
    tot = len(H)
    mechs = sorted({h["mech"] for h in H})
    fams = sorted({h["family"] for h in H})
    fam_mech = defaultdict(Counter)
    for h in H:
        fam_mech[h["family"]][h["mech"]] += 1
    mech_fams = defaultdict(set)
    for f, c in fam_mech.items():
        for m in c:
            mech_fams[m].add(f)
    rows = []
    g2m = [m for m in mechs if mech.MECH_CLASS.get(m) == "G2"]
    g2_tot = sum(1 for h in H if h["mech"] in g2m)
    for f in fams:
        n = sum(fam_mech[f].values())
        n_g2 = sum(v for m, v in fam_mech[f].items() if m in g2m)
        lost = [m for m in mechs if mech_fams[m] == {f}]
        rows.append({"family": f, "group": next((mech.GROUP[p] for h in H if h["family"] == f
                                                  for p in h["primitive_ids"] if p in mech.GROUP), "G2"),
                     "hits": n, "hit_share": round(n / tot, 4), "g2_hits": n_g2,
                     "g2_hit_share": round(n_g2 / g2_tot, 4) if g2_tot else 0,
                     "mechanisms_reached": "|".join(sorted(fam_mech[f])),
                     "loo_hits_left": tot - n, "loo_hits_left_share": round((tot - n) / tot, 4),
                     "loo_mechs_left": len(mechs) - len(lost), "loo_mechs_lost": "|".join(lost),
                     "loo_g2_mechs_left": len(g2m) - len([m for m in lost if m in g2m])})
    rows.sort(key=lambda r: -r["hits"])
    wcsv("a4_binding_family_loo.csv", rows, list(rows[0].keys()))
    # per-experiment hit share by family
    per = []
    for d in EXPS:
        c = Counter(h["family"] for h in H if h["exp"] == d)
        n = sum(c.values())
        for f, v in c.most_common():
            per.append({"exp": d, "family": f, "hits": v, "share": round(v / n, 4)})
    wcsv("a4_binding_family_by_exp.csv", per, ["exp", "family", "hits", "share"])
    mrows = [{"mechanism": m, "name": mech.MECH_NAME.get(m, m), "class": mech.MECH_CLASS.get(m, "?"),
              "hits": sum(1 for h in H if h["mech"] == m), "families": "|".join(sorted(mech_fams[m])),
              "experiments": "|".join(sorted({h["exp"] for h in H if h["mech"] == m})),
              "gateways": "|".join(sorted({h["gateway"] for h in H if h["mech"] == m})),
              "frameworks": "|".join(sorted({h["framework"] for h in H if h["mech"] == m}))} for m in mechs]
    wcsv("a4_binding_mechanisms.csv", mrows, list(mrows[0].keys()))
    # group-level LOO (G1 vs G2 primitive groups)
    grp = Counter(next((mech.GROUP.get(p, "G2") for p in h["primitive_ids"]), "?") for h in H)
    res.update(total_hits=tot, mechanisms=len(mechs), g2_mechanisms=len(g2m), g2_hits=g2_tot,
               hits_by_primitive_group=dict(grp))
    return res, rows


def e4_a4(MERGE=False):
    rows = list(csv.DictReader(open(X / "e4" / "analysis" / "violations_all.csv")))
    classes = json.load(open(X / "e4" / "analysis" / "classes.json"))
    idx = {}
    for k, v in classes.items():
        for t in v["topologies"]:
            for vec in v["vectors"]:
                idx.setdefault((t, vec), []).append(k)
    for r in rows:
        r["fam"] = {"encdotseg": "dotseg"}.get(r["vector_id"].split("-")[0], r["vector_id"].split("-")[0]) \
            if MERGE else r["vector_id"].split("-")[0]
        ks = idx.get((r["topology"], r["vector_id"]), ["unmapped"])
        r["rc"] = ks[0] if len(ks) == 1 else "|".join(sorted(ks))
    tot = len(rows)
    rcs = sorted({r["rc"] for r in rows})
    fam_rc = defaultdict(Counter)
    for r in rows:
        fam_rc[r["fam"]][r["rc"]] += 1
    rc_f = defaultdict(set)
    for f, c in fam_rc.items():
        for k in c:
            rc_f[k].add(f)
    out = []
    for f in sorted(fam_rc, key=lambda f: -sum(fam_rc[f].values())):
        n = sum(fam_rc[f].values())
        lost = [k for k in rcs if rc_f[k] == {f}]
        out.append({"vector_family": f, "violations": n, "share": round(n / tot, 4),
                    "classes_reached": "|".join(sorted(fam_rc[f])), "loo_violations_left": tot - n,
                    "loo_classes_left": len(rcs) - len(lost), "loo_classes_lost": "|".join(lost)})
    wcsv("a4_e4_family_loo%s.csv" % ("_merged" if MERGE else ""), out, list(out[0].keys()))
    return {"e4_violations": tot, "e4_classes": len(rcs), "e4_class_keys": rcs}


def topo_meta(path):
    t = yaml.safe_load(open(path))
    return {k: t.get(k) for k in ("id", "gateway", "profile", "placement", "framework")} | {"override": str(t.get("override"))}


def a5_existing(H):
    rows = []
    hits_by_topo = defaultdict(list)
    for h in H:
        hits_by_topo[h["topology"]].append(h)
    agg = defaultdict(lambda: {"topologies": 0, "hits": 0, "g1": 0, "g2": 0, "g2_mechs": set(), "cases": 0})
    for d in EXPS:
        summ = {r["topology"]: r for r in csv.DictReader(open(X / d / "runs" / "summary.csv"))}
        for y in glob.glob(str(X / d / "topologies" / "*.yaml")):
            m = topo_meta(y)
            if m["placement"] != "edge" or m["id"] not in summ:
                continue
            key = (d, m["gateway"], m["profile"])
            a = agg[key]
            a["topologies"] += 1
            a["cases"] += int(summ[m["id"]]["cases"])
            for h in hits_by_topo.get(m["id"], []):
                a["hits"] += 1
                c = mech.MECH_CLASS.get(h["mech"], "?")
                if c == "G2":
                    a["g2"] += 1
                    a["g2_mechs"].add(h["mech"])
                else:
                    a["g1"] += 1
    for (d, gw, pr), a in sorted(agg.items()):
        rows.append({"exp": d, "gateway": gw, "profile": pr, "topologies": a["topologies"], "cases": a["cases"],
                     "hits": a["hits"], "g1_hits": a["g1"], "g2_hits": a["g2"],
                     "g2_mechanisms": "|".join(sorted(a["g2_mechs"]))})
    wcsv("a5_binding_profiles_existing.csv", rows, list(rows[0].keys()))
    return rows


def a5_e4_existing():
    summ = list(csv.DictReader(open(X / "e4" / "runs" / "summary.csv")))
    agg = defaultdict(lambda: [0, 0])
    viol = Counter(r["topology"] for r in csv.DictReader(open(X / "e4" / "analysis" / "violations_all.csv")))
    for r in summ:
        y = X / "e4" / "topologies" / f"{r['topology']}.yaml"
        if not y.exists():
            continue
        m = topo_meta(y)
        pol = r["topology"].split("-")[1]
        k = (pol, m["gateway"], m["framework"], m["profile"])
        agg[k][0] += 1
        agg[k][1] += viol.get(r["topology"], 0)
    rows = [{"policy": k[0], "gateway": k[1], "framework": k[2], "profile": k[3], "topologies": v[0], "violations": v[1]}
            for k, v in sorted(agg.items())]
    wcsv("a5_e4_profiles_existing.csv", rows, list(rows[0].keys()))
    return rows


def main():
    H = load_hits()
    r, _ = a4(H)
    r.update(e4_a4())
    e4_a4(MERGE=True)
    a5_existing(H)
    a5_e4_existing()
    json.dump(r, open(OUT / "a4_a5.json", "w"), indent=1)
    print(json.dumps(r, indent=1))


if __name__ == "__main__":
    main()


# ---------------------------------------------------------------- A5 new runs (strict + same-set controls)
def e4_class(v):
    fam = v["case_id"].split("-")[0]
    gw = v.get("gateway", "")
    fw = v.get("framework", "")
    if fam in ("dotseg", "encdotseg"):
        return "E4-RC2 gateway:kong:dot-segment" if gw == "kong" else f"E4-RC1 framework:{fw}:dot-segment"
    if fam == "dslash":
        return "gateway:kong:double-slash" if gw == "kong" else f"framework:{fw}:double-slash"
    return {"case": f"framework:{fw}:case-fold", "matrix": f"framework:{fw}:matrix-param"}.get(fam, fam)


def a5_new():
    rows, mrows = [], []
    sdir = A / "strict" / "runs"
    for y in sorted((A / "strict" / "topologies").glob("w18-g2-*.yaml")):
        m = topo_meta(y)
        d = sdir / m["id"]
        if not (d / "hits.jsonl").exists():
            continue
        H = [json.loads(l) for l in open(d / "hits.jsonl")]
        V = [json.loads(l) for l in open(d / "verifier.jsonl")] if (d / "verifier.jsonl").exists() else []
        R = [json.loads(l) for l in open(d / "runner.jsonl")]
        c = Counter(mech.mechanism(h) for h in H)
        st = Counter(r["status"] for r in R if r["depth"] > 0)
        rows.append({"gateway": m["gateway"], "framework": m["framework"], "profile": m["profile"], "cases": len(R),
                     "status_400": sum(1 for r in R if r["depth"] > 0 and r["status"] == 400)
                     ,
                     "verifier_allow": sum(1 for x in V if x["decision"] == "allow"),
                     "baseline_ok": sum(1 for r in R if r["depth"] == 0 and r["status"] < 400 and r["resp_op_id"] == r["base_op_id"]),
                     "hits": len(H), "g2_hits": sum(v for k, v in c.items() if mech.MECH_CLASS.get(k) == "G2"),
                     "mechs": "|".join(f"{k}:{v}" for k, v in sorted(c.items()))})
    if rows:
        wcsv("a5_g2_profiles_new.csv", rows, list(rows[0].keys()))
    e4 = []
    for y in sorted((A / "strict" / "topologies").glob("w18-e4-*.yaml")):
        m = topo_meta(y)
        d = A / "strict" / "runs_e4" / m["id"]
        if not (d / "status.txt").exists():
            continue
        V = [json.loads(l) for l in open(d / "violations.jsonl")] if (d / "violations.jsonl").exists() else []
        R = [json.loads(l) for l in open(d / "runner.jsonl")] if (d / "runner.jsonl").exists() else []
        cls = Counter(e4_class(dict(v, gateway=m["gateway"], framework=m["framework"])) for v in V)
        e4.append({"policy": m["id"].split("-")[2], "gateway": m["gateway"], "framework": m["framework"],
                   "profile": m["profile"], "cases": len(R), "violations": len(V),
                   "classes": "|".join(f"{k}:{v}" for k, v in sorted(cls.items()))})
    if e4:
        wcsv("a5_e4_strict_new.csv", e4, list(e4[0].keys()))
    return rows, e4


if __name__ == "__main__" and "--new" in sys.argv:
    a5_new()

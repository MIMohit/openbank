#!/usr/bin/env python3
"""Build the result figures of the paper from the recorded experiment outputs.

Inputs (read-only, all under binding/experiments/):
  kill/analysis/{hits_per_topology.csv,hits_all.jsonl,resolution.csv}         (W9)
  ext-gw/analysis/{hits_per_topology.csv,hits_all.jsonl,resolution.csv}       (W13)
  ext-fw/analysis/{hits_per_topology.csv,hits_all.jsonl,resolution.csv}       (W14)
  ext-routes/analysis/{hits_per_topology.csv,hits_all.jsonl,resolution.csv}   (W15)
  e4/runs/summary.csv                                                         (W12)

Outputs (in this directory):
  hits_heatmap.pdf    gateway x framework heatmap, v1 route space, edge placement
  aggregate.json      every aggregate the paper quotes from these files; numbers.tex
                      is checked against it by hand (each macro names this file)

Style: reuses /Users/mimohit/openbank/analysis/figstyle.py (rcParams, palette).
Run:   python make_figs.py   (needs matplotlib 3.9.2 + numpy, see requirements.txt)

Classification: the oracle labels a hit by the class of its primitive. A hit whose
primitive is G2 (g2-*, or W15's x-frag-*) but whose deviation kind is `dispatch`
and whose base op is accountAction.* is the "fragment lands in the query" effect
(kill RC7): the op change comes from the unbound query, so it is counted as G1
(kill/ROOT_CAUSES.md RC7; ext-gw/REPORT.md section 7; ext-fw/REPORT.md section 6).
W15's x-frag-statements* hits are also labelled `dispatch` but change the ROUTE
(getAccount -> getStatements), so they stay G2 (ext-routes/REPORT.md X1).
"""
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
BINDING = HERE.parent.parent
EXP = BINDING / "experiments"
sys.path.insert(0, str(BINDING.parent / "analysis"))

import figstyle  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402

LEAK_EXPS = ["kill", "ext-gw", "ext-fw", "ext-routes"]
GATEWAYS = ["nginx", "traefik", "envoy", "kong", "apisix", "haproxy"]
GW_LABEL = {"nginx": "NGINX", "traefik": "Traefik", "envoy": "Envoy",
            "kong": "Kong", "apisix": "APISIX", "haproxy": "HAProxy"}
FRAMEWORKS = ["fastapi", "express", "django", "go-chi", "spring", "aspnet",
              "rails", "laravel"]
FW_LABEL = {"fastapi": "FastAPI", "express": "Express", "django": "Django",
            "go-chi": "chi", "spring": "Spring", "aspnet": "ASP.NET",
            "rails": "Rails", "laravel": "Laravel"}


def read_csv(p):
    with open(p, newline="") as f:
        return list(csv.DictReader(f))


def read_jsonl(p):
    with open(p) as f:
        return [json.loads(line) for line in f if line.strip()]


def mech_class(h):
    """Return 'g1' or 'g2' by mechanism (see module docstring)."""
    cl = h["class"][0]
    if cl == "g1":
        return "g1"
    if cl == "g3":
        return "g3"
    if "dispatch" in h["deviation_kinds"] and h["base_op_id"].startswith("accountAction"):
        return "g1"  # RC7: '#' lands in the unbound query
    return "g2"


def placement(row):
    return row.get("placement") or "edge"


def main():
    agg = {"leak": {}, "e4": {}}
    tot = Counter()
    res_all = Counter()
    # (gw, fw) -> Counter over 4 topologies (2 profiles x 2 override), v1 routes, edge
    cell_g1 = defaultdict(int)
    cell_g2 = defaultdict(int)
    cell_n = defaultdict(int)
    for exp in LEAK_EXPS:
        a = EXP / exp / "analysis"
        topo = read_csv(a / "hits_per_topology.csv")
        hits = read_jsonl(a / "hits_all.jsonl")
        res = Counter(int(r["res_hat"]) for r in read_csv(a / "resolution.csv"))
        mc = Counter(mech_class(h) for h in hits)
        oc = Counter(h["class"][0] for h in hits)
        sev = Counter(h["severity"] for h in hits)
        e = {
            "topologies": len(topo),
            "hits": len(hits),
            "hits_csv": sum(int(r["hits"]) for r in topo),
            "oracle_class": dict(oc),
            "mech_class": dict(mc),
            "severity": dict(sev),
            "res_hat": {str(k): v for k, v in sorted(res.items())},
            "placements": dict(Counter(placement(r) for r in topo)),
        }
        assert e["hits"] == e["hits_csv"], exp
        agg["leak"][exp] = e
        tot["topologies"] += e["topologies"]
        tot["hits"] += e["hits"]
        for k, v in mc.items():
            tot["mech_" + k] += v
        for k, v in oc.items():
            tot["oracle_" + k] += v
        for k, v in sev.items():
            tot[k] += v
        res_all.update(res)
        if exp == "ext-routes":
            continue  # v2 route space: not part of the v1 heatmap
        for r in topo:
            if placement(r) != "edge":
                continue
            cell_n[(r["gateway"], r["framework"])] += 1
        for h in hits:
            if h.get("placement", "edge") != "edge":
                continue
            k = (h["gateway"], h["framework"])
            if mech_class(h) == "g1":
                cell_g1[k] += 1
            elif mech_class(h) == "g2":
                cell_g2[k] += 1
    agg["leak_total"] = dict(tot)
    agg["leak_res_hat_total"] = {str(k): v for k, v in sorted(res_all.items())}

    e4 = read_csv(EXP / "e4" / "runs" / "summary.csv")
    agg["e4"] = {
        "topologies": len(e4),
        "requests": sum(int(r["cases"]) for r in e4),
        "violations": sum(int(r["violations"]) for r in e4),
        "topologies_with_violations": sum(1 for r in e4 if int(r["violations"]) > 0),
        "admin": sum(int(r["admin"]) for r in e4),
        "bob": sum(int(r["bob"]) for r in e4),
    }

    grid_counts = {f"{g}/{f}": cell_n[(g, f)] for g in GATEWAYS for f in FRAMEWORKS}
    agg["heatmap_topologies_per_cell"] = grid_counts
    agg["heatmap_cells_full"] = sum(1 for v in grid_counts.values() if v == 4)
    agg["heatmap_g1"] = {f"{g}/{f}": cell_g1[(g, f)] for g in GATEWAYS for f in FRAMEWORKS}
    agg["heatmap_g2"] = {f"{g}/{f}": cell_g2[(g, f)] for g in GATEWAYS for f in FRAMEWORKS}
    agg["heatmap_g2_total"] = sum(cell_g2.values())
    agg["heatmap_g1_total"] = sum(cell_g1.values())

    (HERE / "aggregate.json").write_text(json.dumps(agg, indent=2, sort_keys=True) + "\n")

    # ---------------------------------------------------------------- figure
    figstyle.apply_style()
    G1 = np.array([[cell_g1[(g, f)] for f in FRAMEWORKS] for g in GATEWAYS])
    G2 = np.array([[cell_g2[(g, f)] for f in FRAMEWORKS] for g in GATEWAYS])
    fig, axes = plt.subplots(1, 2, figsize=(figstyle.COL2 * 0.98, 1.3),
                             gridspec_kw={"wspace": 0.08})
    cm_g1 = LinearSegmentedColormap.from_list("g1", ["#FFFFFF", figstyle.C_B1, figstyle.C_P])
    cm_g2 = LinearSegmentedColormap.from_list("g2", ["#FFFFFF", "#E7B7A3", figstyle.C_ACCENT])
    panels = [(axes[0], G1, cm_g1, "(a) G1 hits (query, body, override)"),
              (axes[1], G2, cm_g2, "(b) G2 hits (interpretation differential)")]
    for ax, M, cmap, title in panels:
        vmax = max(1, M.max())
        ax.imshow(M, cmap=cmap, vmin=0, vmax=vmax, aspect="auto")
        for i in range(M.shape[0]):
            for j in range(M.shape[1]):
                v = M[i, j]
                ax.text(j, i, str(v) if v else "0", ha="center", va="center",
                        fontsize=6.3,
                        color="white" if v > 0.6 * vmax else ("#9A9A9A" if v == 0 else "black"))
        ax.set_xticks(range(len(FRAMEWORKS)))
        ax.set_xticklabels([FW_LABEL[f] for f in FRAMEWORKS], rotation=35, ha="right")
        ax.set_yticks(range(len(GATEWAYS)))
        ax.set_yticklabels([GW_LABEL[g] for g in GATEWAYS])
        ax.set_title(title, loc="left", pad=3)
        ax.tick_params(length=0)
        for s in ax.spines.values():
            s.set_visible(False)
        ax.set_xticks(np.arange(-.5, len(FRAMEWORKS), 1), minor=True)
        ax.set_yticks(np.arange(-.5, len(GATEWAYS), 1), minor=True)
        ax.grid(which="minor", color="white", linewidth=0.8)
        ax.tick_params(which="minor", length=0)
    axes[1].set_yticklabels([])
    out = HERE / "hits_heatmap.pdf"
    fig.savefig(out)
    plt.close(fig)
    print(f"[OK] {out.name}")
    print(json.dumps({k: agg[k] for k in ("leak_total", "leak_res_hat_total", "e4",
                                          "heatmap_cells_full", "heatmap_g1_total",
                                          "heatmap_g2_total")}, indent=1))


if __name__ == "__main__":
    main()

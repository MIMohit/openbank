#!/usr/bin/env python3
"""Build the six result figures agreed in CONTRACT §13 (final paper wave, W26).

Every number is read from a committed experiment output; nothing is typed in by hand
except axis labels. Sources (all read-only):

  fig_hits_heatmap.pdf  paper/figs/aggregate.json [heatmap_g1, heatmap_g2,
                        heatmap_topologies_per_cell]  (written by make_figs.py)
  fig_resolution.pdf    paper/figs/aggregate.json [leak.<campaign>.res_hat,
                        leak_res_hat_total]; cross-checked against
                        experiments/{kill,ext-gw,ext-fw,ext-routes}/analysis/resolution.csv
  fig_class.pdf         aggregate.json [leak.<campaign>.mech_class];
                        experiments/<campaign>/analysis/hits_all.jsonl (primitive family)
                        mapped through harness/mutator/primitives/{g1,g2,g3}.yaml
  fig_ablation_a1.pdf   experiments/ablation/analysis/a1_variant_summary.csv (mutation set)
                        experiments/ablation/analysis/a1_runs_swap_variant_summary.csv (swap set)
  fig_defence.pdf       experiments/defence/analysis/e7_aleak_long.csv (residual hits by class)
                        experiments/defence/analysis/frr_summary.json (FRR, Wilson 95% CI;
                        recomputed here from the counts and asserted equal)
  fig_latency.pdf       experiments/defence/analysis/perf_latency.csv (level == 100 only)

Style: figures4papers house style (scientific-figure-making skill): sans-serif, top/right
spines off, frameless legends, black bar edges, blue = primary class, red = contrast,
hatch encodings so every figure stays readable in greyscale. Fonts are embedded as
TrueType (pdf.fonttype 42). No titles inside figures; captions live in the paper.

Run:  /usr/bin/python3 make_figs2.py        (matplotlib >= 3.9, numpy; see requirements.txt)
"""
import csv
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

HERE = Path(__file__).resolve().parent
BINDING = HERE.parent.parent
EXP = BINDING / "experiments"
PRIM = BINDING / "harness" / "mutator" / "primitives"

COL1 = 3.33   # ACM sigconf column width, inches
COL2 = 7.00   # full text width, inches

PALETTE = {
    "blue_main": "#0F4D92", "blue_secondary": "#3775BA",
    "green_1": "#DDF3DE", "green_2": "#AADCA9", "green_3": "#8BCF8B",
    "red_1": "#F6CFCB", "red_2": "#E9A6A1", "red_strong": "#B64342",
    "neutral": "#CFCECE", "grey_dark": "#4D4D4D", "highlight": "#FFD700",
    "teal": "#42949E", "violet": "#9A4D8E",
}
EDGE = "black"
EDGE_LW = 0.5

GATEWAYS = ["nginx", "traefik", "envoy", "kong", "apisix", "haproxy"]
GW_LABEL = {"nginx": "NGINX", "traefik": "Traefik", "envoy": "Envoy",
            "kong": "Kong", "apisix": "APISIX", "haproxy": "HAProxy"}
FRAMEWORKS = ["fastapi", "express", "django", "go-chi", "spring", "aspnet",
              "rails", "laravel"]
FW_LABEL = {"fastapi": "FastAPI", "express": "Express", "django": "Django",
            "go-chi": "chi", "spring": "Spring", "aspnet": "ASP.NET",
            "rails": "Rails", "laravel": "Laravel"}
CAMPAIGNS = ["kill", "ext-gw", "ext-fw", "ext-routes"]
CAMP_LABEL = {"kill": "kill", "ext-gw": "ext-gw", "ext-fw": "ext-fw",
              "ext-routes": "ext-routes\n(v2 routes)"}


def apply_style():
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.sans-serif": ["Arial", "Helvetica", "DejaVu Sans"],
        "font.size": 7.5,
        "axes.labelsize": 7.5,
        "axes.titlesize": 7.5,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "legend.fontsize": 6.8,
        "legend.frameon": False,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.linewidth": 0.7,
        "xtick.major.width": 0.7,
        "ytick.major.width": 0.7,
        "xtick.major.size": 2.5,
        "ytick.major.size": 2.5,
        "hatch.linewidth": 0.5,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "svg.fonttype": "none",
        "mathtext.fontset": "custom",
        "mathtext.rm": "Arial",
        "mathtext.it": "Arial:italic",
        "mathtext.bf": "Arial:bold",
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.02,
        "figure.dpi": 150,
    })


def read_csv(p):
    with open(p, newline="") as f:
        return list(csv.DictReader(f))


def save(fig, name):
    out = HERE / name
    fig.savefig(out, dpi=300)
    plt.close(fig)
    print(f"[OK] {name}")


def panel_label(ax, s, x=-0.02, y=1.02):
    ax.text(x, y, s, transform=ax.transAxes, ha="right", va="bottom",
            fontsize=8, fontweight="bold")


def wilson(k, n, z=1.959963984540054):
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return max(0.0, c - h), min(1.0, c + h)


# --------------------------------------------------------------------- 1 heatmap
def fig_hits_heatmap(agg):
    tpc = agg["heatmap_topologies_per_cell"]
    assert all(tpc[f"{g}/{f}"] == 4 for g in GATEWAYS for f in FRAMEWORKS)
    G1 = np.array([[agg["heatmap_g1"][f"{g}/{f}"] for f in FRAMEWORKS] for g in GATEWAYS])
    G2 = np.array([[agg["heatmap_g2"][f"{g}/{f}"] for f in FRAMEWORKS] for g in GATEWAYS])
    assert G1.sum() == agg["heatmap_g1_total"] and G2.sum() == agg["heatmap_g2_total"]

    fig, axes = plt.subplots(1, 2, figsize=(COL2, 1.95), gridspec_kw={"wspace": 0.06})
    cm1 = LinearSegmentedColormap.from_list("g1", ["#FFFFFF", PALETTE["blue_secondary"], PALETTE["blue_main"]])
    cm2 = LinearSegmentedColormap.from_list("g2", ["#FFFFFF", PALETTE["red_2"], PALETTE["red_strong"]])
    panels = [(axes[0], G1, cm1, "(a) G1: under-binding (query, body, override)", 0),
              (axes[1], G2, cm2, "(b) G2: interpretation differential", 0)]
    for ax, M, cmap, lab, vmin in panels:
        vmax = max(1, M.max())
        # pcolormesh (not imshow) so the cells are vector paths, not an embedded raster
        ax.pcolormesh(np.arange(M.shape[1] + 1) - 0.5, np.arange(M.shape[0] + 1) - 0.5, M,
                      cmap=cmap, vmin=vmin, vmax=vmax, edgecolors="white", linewidth=1.0)
        ax.set_xlim(-0.5, M.shape[1] - 0.5)
        ax.set_ylim(M.shape[0] - 0.5, -0.5)
        for i in range(M.shape[0]):
            for j in range(M.shape[1]):
                v = int(M[i, j])
                dark = v > 0.55 * vmax
                ax.text(j, i, str(v), ha="center", va="center", fontsize=6.5,
                        color="white" if dark else ("#8C8C8C" if v == 0 else "black"),
                        fontweight="bold" if v and not dark else "normal")
        ax.set_xticks(range(len(FRAMEWORKS)))
        ax.set_xticklabels([FW_LABEL[f] for f in FRAMEWORKS], rotation=35, ha="right",
                           rotation_mode="anchor")
        ax.set_yticks(range(len(GATEWAYS)))
        ax.set_yticklabels([GW_LABEL[g] for g in GATEWAYS])
        ax.tick_params(length=0)
        for s in ax.spines.values():
            s.set_visible(False)
        ax.set_xticks(np.arange(-.5, len(FRAMEWORKS), 1), minor=True)
        ax.set_yticks(np.arange(-.5, len(GATEWAYS), 1), minor=True)
        ax.grid(which="minor", color="white", linewidth=1.0)
        ax.tick_params(which="minor", length=0)
        ax.set_title(lab, loc="left", pad=3, fontsize=7.5)
    axes[1].set_yticklabels([])
    save(fig, "fig_hits_heatmap.pdf")


# ------------------------------------------------------------------ 2 resolution
def fig_resolution(agg):
    # Cross-check aggregate.json against the raw resolution.csv files.
    per = {}
    for c in CAMPAIGNS:
        cnt = Counter(int(r["res_hat"]) for r in read_csv(EXP / c / "analysis" / "resolution.csv"))
        per[c] = cnt
        assert {str(k): v for k, v in cnt.items()} == agg["leak"][c]["res_hat"], c
    tot = Counter()
    for c in CAMPAIGNS:
        tot.update(per[c])
    assert {str(k): v for k, v in tot.items()} == agg["leak_res_hat_total"]
    ks = list(range(1, max(tot) + 1))
    v1 = np.array([sum(per[c][k] for c in CAMPAIGNS if c != "ext-routes") for k in ks])
    v2 = np.array([per["ext-routes"][k] for k in ks])
    n = int(sum(tot.values()))

    fig, ax = plt.subplots(figsize=(COL1, 1.85))
    x = np.arange(len(ks))
    w = 0.38
    b1 = ax.bar(x - w / 2, v1, w, color=PALETTE["blue_main"], edgecolor=EDGE, linewidth=EDGE_LW,
                label="v1 route space (kill, ext-gw, ext-fw)")
    b2 = ax.bar(x + w / 2, v2, w, color=PALETTE["red_2"], edgecolor=EDGE, linewidth=EDGE_LW,
                hatch="////", label="v2 route space (ext-routes)")
    ax.set_yscale("log")
    ax.set_ylim(0.7, 60000)
    for bars, vals in ((b1, v1), (b2, v2)):
        for r, v in zip(bars, vals):
            if v > 0:
                ax.text(r.get_x() + r.get_width() / 2, v * 1.15, f"{v}", ha="center", va="bottom",
                        fontsize=6)
            else:
                ax.text(r.get_x() + r.get_width() / 2, 0.8, "0", ha="center", va="bottom",
                        fontsize=6, color="#8C8C8C")
    ax.set_xticks(x)
    ax.set_xticklabels([str(k) for k in ks])
    ax.set_xlabel(r"binding resolution $\widehat{res}$ (distinct ops reached by one proof)")
    ax.set_ylabel("(topology, base op) pairs")
    ax.axvspan(0.5, len(ks) - 0.5, color=PALETTE["neutral"], alpha=0.25, lw=0, zorder=0)
    ax.text(len(ks) - 0.55, 38000, "unsound (res > 1)", ha="right", va="center", fontsize=6.3,
            color=PALETTE["grey_dark"])
    ax.legend(loc="upper right", bbox_to_anchor=(1.0, 0.93), handlelength=1.4)
    ax.text(0.0, 1.0, f"n = {n}", transform=ax.transAxes, fontsize=6.3, va="bottom",
            color=PALETTE["grey_dark"])
    save(fig, "fig_resolution.pdf")
    return {"res_v1": dict(zip(ks, v1.tolist())), "res_v2": dict(zip(ks, v2.tolist())), "n": n}


# ------------------------------------------------------------------------ 3 class
FAMILY_LABEL = {
    "query-dispatch-switch": "query dispatch",
    "graphql-operation-switch": "JSON-body dispatch",
    "method-override-body": "override: body _method",
    "method-override-header": "override: header",
    "method-override-query": "override: query _method",
    "content-type-switch": "Content-Type relabel",
    "fragment": "# fragment",
    "encoded-slash": "encoded slash %2f",
    "dot-segment": "dot segment",
}


def primitive_family():
    fam = {}
    for g in ("g1", "g2", "g3"):
        cur = None
        for line in (PRIM / f"{g}.yaml").read_text().splitlines():
            m = re.match(r"^- id: (\S+)", line)
            if m:
                cur = m.group(1)
                continue
            m = re.match(r"^  class: (\S+)", line)
            if m and cur:
                fam[cur] = m.group(1)
                cur = None
    return fam


def mech_class(h):
    # identical to make_figs.py::mech_class (RC7: '#' landing in the unbound query is G1)
    cl = h["class"][0]
    if cl in ("g1", "g3"):
        return cl
    if "dispatch" in h["deviation_kinds"] and h["base_op_id"].startswith("accountAction"):
        return "g1"
    return "g2"


def fig_class(agg):
    fam = primitive_family()
    by_fam = defaultdict(Counter)        # family -> Counter(mech class)
    by_camp = {}
    for c in CAMPAIGNS:
        mc = Counter()
        with open(EXP / c / "analysis" / "hits_all.jsonl") as f:
            for line in f:
                if not line.strip():
                    continue
                h = json.loads(line)
                prims = h.get("minimal_primitive_set") or h["primitive_ids"]
                assert len(prims) == 1, h["case_id"]
                p = prims[0]
                fm = fam.get(p, "fragment" if p.startswith("x-frag-") else None)
                assert fm is not None, p
                k = mech_class(h)
                mc[k] += 1
                by_fam[fm][k] += 1
        assert dict(mc) == agg["leak"][c]["mech_class"], c
        by_camp[c] = mc

    fig, (a, b) = plt.subplots(1, 2, figsize=(COL2, 2.05),
                               gridspec_kw={"width_ratios": [1, 1.55], "wspace": 0.55})
    # (a) per campaign, stacked G1 / G2 / G3
    x = np.arange(len(CAMPAIGNS))
    g1 = np.array([by_camp[c]["g1"] for c in CAMPAIGNS])
    g2 = np.array([by_camp[c]["g2"] for c in CAMPAIGNS])
    g3 = np.array([by_camp[c]["g3"] for c in CAMPAIGNS])
    assert g3.sum() == 0
    a.bar(x, g1, 0.62, color=PALETTE["blue_main"], edgecolor=EDGE, linewidth=EDGE_LW,
          label="G1 by design")
    a.bar(x, g2, 0.62, bottom=g1, color=PALETTE["red_strong"], edgecolor=EDGE,
          linewidth=EDGE_LW, hatch="////", label="G2 differential")
    for i in range(len(CAMPAIGNS)):
        a.text(x[i], g1[i] / 2, str(g1[i]), ha="center", va="center", fontsize=6, color="white")
        a.text(x[i], g1[i] + g2[i] + 18, f"+{g2[i]}", ha="center", va="bottom", fontsize=6,
               color=PALETTE["red_strong"])
    a.set_xticks(x)
    a.set_xticklabels([CAMP_LABEL[c] for c in CAMPAIGNS], fontsize=6.5)
    a.set_ylabel("binding hits")
    a.set_ylim(0, max(g1 + g2) * 1.45)
    a.legend(handles=[Patch(fc=PALETTE["blue_main"], ec=EDGE, lw=EDGE_LW, label="G1 by design"),
                      Patch(fc=PALETTE["red_strong"], ec=EDGE, lw=EDGE_LW, hatch="////",
                            label="G2 differential"),
                      Patch(fc="white", ec=EDGE, lw=EDGE_LW, label="G3 propagation (0 in all)")],
             loc="upper right", handlelength=1.3, bbox_to_anchor=(1.05, 1.04))
    panel_label(a, "(a)")

    # (b) by primitive family, all campaigns, stacked by mechanism class
    order = sorted(by_fam, key=lambda k: -sum(by_fam[k].values()))
    y = np.arange(len(order))[::-1]
    f1 = np.array([by_fam[k]["g1"] for k in order])
    f2 = np.array([by_fam[k]["g2"] for k in order])
    b.barh(y, f1, 0.66, color=PALETTE["blue_main"], edgecolor=EDGE, linewidth=EDGE_LW)
    b.barh(y, f2, 0.66, left=f1, color=PALETTE["red_strong"], edgecolor=EDGE,
           linewidth=EDGE_LW, hatch="////")
    for yi, v1_, v2_ in zip(y, f1, f2):
        b.text(v1_ + v2_ + 12, yi, f"{v1_ + v2_}" + (f"  ({v2_} G2)" if v1_ and v2_ else ""),
               va="center", fontsize=6)
    b.set_yticks(y)
    b.set_yticklabels([FAMILY_LABEL.get(k, k) for k in order], fontsize=6.6)
    b.set_xlabel("binding hits, all four campaigns")
    b.set_xlim(0, max(f1 + f2) * 1.25)
    b.tick_params(axis="y", length=0)
    panel_label(b, "(b)", x=-0.36)
    save(fig, "fig_class.pdf")
    return {k: dict(v) for k, v in by_fam.items()}


# --------------------------------------------------------------------- 4 ablation
A1_ORDER = ["full", "no-htm", "no-htu", "no-ath", "query", "digest-nogate", "digest", "query-digest"]
A1_LABEL = {"full": "full\n(RFC 9449)", "no-htm": "−htm", "no-htu": "−htu",
            "no-ath": "−ath", "query": "+query", "digest-nogate": "+digest\n(no gate)",
            "digest": "+digest", "query-digest": "+query\n+digest"}


def fig_ablation_a1():
    a1 = EXP / "ablation" / "analysis"
    mut = {r["variant"]: r for r in read_csv(a1 / "a1_variant_summary.csv")}
    swp = {r["variant"]: r for r in read_csv(a1 / "a1_runs_swap_variant_summary.csv")}
    for r in mut.values():
        assert int(r["g1"]) + int(r["g2"]) + int(r["other"]) == int(r["hits"])

    fig, (a, b) = plt.subplots(1, 2, figsize=(COL2, 2.1),
                               gridspec_kw={"width_ratios": [1.7, 1], "wspace": 0.22})
    x = np.arange(len(A1_ORDER))
    g1 = np.array([int(mut[v]["g1"]) for v in A1_ORDER])
    g2 = np.array([int(mut[v]["g2"]) for v in A1_ORDER])
    ot = np.array([int(mut[v]["other"]) for v in A1_ORDER])
    w = 0.64
    a.bar(x, g1, w, color=PALETTE["blue_main"], edgecolor=EDGE, linewidth=EDGE_LW,
          label="G1 (query/body/override)")
    a.bar(x, g2, w, bottom=g1, color=PALETTE["red_strong"], edgecolor=EDGE, linewidth=EDGE_LW,
          hatch="////", label="G2 (# path, dot segment)")
    a.bar(x, ot, w, bottom=g1 + g2, color=PALETTE["neutral"], edgecolor=EDGE, linewidth=EDGE_LW,
          hatch="....", label="path primitives htu normally rejects")
    tot = g1 + g2 + ot
    for i, t in enumerate(tot):
        a.text(x[i], t + 8, str(t), ha="center", va="bottom", fontsize=6.3,
               fontweight="bold" if A1_ORDER[i] in ("full", "query-digest") else "normal")
    g2_floor = int(mut["full"]["g2"])
    assert all(int(mut[v]["g2"]) == g2_floor for v in A1_ORDER if v != "no-htu")
    a.axhline(g2_floor, color=PALETTE["red_strong"], lw=0.7, ls=(0, (3, 2)), zorder=0)
    a.text(-0.45, 228,
           f"dashed: {g2_floor} G2 hits\nsurvive every\nbinding variant\n(−htu: {int(mut['no-htu']['g2'])})",
           ha="left", va="bottom", fontsize=6, color=PALETTE["red_strong"])
    full = int(mut["full"]["hits"])
    qd = int(mut["query-digest"]["hits"])
    a.annotate(f"−{full - qd}: query+body bound;\nleft: {int(mut['query-digest']['g1'])} header-carried G1",
               xy=(x[-1], qd + 22), xytext=(x[-1] - 1.0, 255), fontsize=6, ha="center",
               arrowprops=dict(arrowstyle="-|>", lw=0.6, color=PALETTE["grey_dark"],
                               mutation_scale=6))
    a.set_xticks(x)
    a.set_xticklabels([A1_LABEL[v] for v in A1_ORDER], fontsize=6.5)
    a.set_ylabel("residual binding hits\n(mutation set, 8 topologies)")
    a.set_ylim(0, max(tot) * 1.12)
    a.legend(loc="upper right", handlelength=1.3, bbox_to_anchor=(1.0, 1.04))
    panel_label(a, "(a)")

    # (b) swap set: cross-op / method-swap replay
    sv = ["full", "no-htm", "no-htu", "no-ath", "query", "digest"]
    xs = np.arange(len(sv))
    hs = np.array([int(swp[v]["hits"]) for v in sv])
    cols = [PALETTE["red_strong"] if h > 0 else PALETTE["blue_main"] for h in hs]
    b.bar(xs, hs, 0.62, color=cols, edgecolor=EDGE, linewidth=EDGE_LW,
          hatch=["////" if h > 0 else "" for h in hs])
    for i, h in enumerate(hs):
        b.text(xs[i], h + 12, str(h), ha="center", va="bottom", fontsize=6.3)
    b.set_xticks(xs)
    b.set_xticklabels([A1_LABEL[v].split("\n")[0] if v != "full" else "full" for v in sv],
                      fontsize=6.5, rotation=30, ha="right", rotation_mode="anchor")
    b.set_ylabel("replay hits (swap set)")
    b.set_ylim(0, max(hs) * 1.15)
    b.text(0.98, 0.97, "proof for op p replayed\non op q / other method",
           transform=b.transAxes, va="top", ha="right", fontsize=6, color=PALETTE["grey_dark"])
    panel_label(b, "(b)")
    save(fig, "fig_ablation_a1.pdf")


# ---------------------------------------------------------------------- 5 defence
DEF_CFG = [("bedge", "B-edge"), ("borigin", "B-origin"), ("bstrict", "B-strict"),
           ("da", "D-A"), ("db", "D-B"), ("dc", "D-C")]
DEF_CLASSES = [
    ("G1-query", ["G1-query", "G1-query(frag-in-query)"], PALETTE["blue_main"], ""),
    ("G1-body", ["G1-body"], PALETTE["blue_secondary"], "...."),
    ("G1-override", ["G1-override"], PALETTE["teal"], "xxxx"),
    ("G2-#", ["G2-#"], PALETTE["red_strong"], "////"),
    ("G2-%2f", ["G2-%2f"], PALETTE["red_2"], "\\\\\\\\"),
    ("G2-dot", ["G2-dot"], PALETTE["violet"], "----"),
]


def fig_defence():
    d = EXP / "defence" / "analysis"
    rows = read_csv(d / "e7_aleak_long.csv")
    hits = defaultdict(Counter)
    for r in rows:
        if r["hit"] == "True":
            hits[r["cfg"]][r["class"]] += 1
    cfg_codes = sorted({r["cfg"] for r in rows})
    frr = json.loads((d / "frr_summary.json").read_text())
    # recompute Wilson CI from counts, must agree with the recorded summary
    for code, _ in DEF_CFG:
        lo, hi = wilson(frr[code]["att"], frr[code]["att_n"])
        assert abs(lo - frr[code]["lo"]) < 1e-9 and abs(hi - frr[code]["hi"]) < 1e-9, code

    fig, (a, b) = plt.subplots(1, 2, figsize=(COL2, 2.15),
                               gridspec_kw={"width_ratios": [1.35, 1], "wspace": 0.28})
    x = np.arange(len(DEF_CFG))
    bottom = np.zeros(len(DEF_CFG))
    totals = {}
    for lab, keys, col, hatch in DEF_CLASSES:
        v = np.array([sum(hits[c][k] for k in keys) for c, _ in DEF_CFG])
        a.bar(x, v, 0.64, bottom=bottom, color=col, edgecolor=EDGE, linewidth=EDGE_LW,
              hatch=hatch, label=lab)
        bottom += v
    for i, (c, _) in enumerate(DEF_CFG):
        totals[c] = int(bottom[i])
        a.text(x[i], bottom[i] + 4, str(int(bottom[i])), ha="center", va="bottom", fontsize=6.3)
    a.set_xticks(x)
    a.set_xticklabels([n for _, n in DEF_CFG], rotation=30, ha="right", rotation_mode="anchor")
    a.set_ylabel("residual hits on 229 witnesses (E7)")
    a.set_ylim(0, 300)
    a.legend(ncol=3, loc="upper right", handlelength=1.3, columnspacing=0.8,
             bbox_to_anchor=(1.02, 1.05), fontsize=6.3)
    a.text(x[4], totals["db"] + 26, "override and\nall G2 removed", ha="center", va="bottom",
           fontsize=5.9, color=PALETTE["grey_dark"])
    panel_label(a, "(a)")

    # (b) attributable FRR with Wilson 95% CI
    p = np.array([100 * frr[c]["frr"] for c, _ in DEF_CFG])
    lo = np.array([100 * frr[c]["lo"] for c, _ in DEF_CFG])
    hi = np.array([100 * frr[c]["hi"] for c, _ in DEF_CFG])
    cols = [PALETTE["blue_main"] if c.startswith("b") else PALETTE["red_strong"] for c, _ in DEF_CFG]
    hat = ["" if c.startswith("b") else "////" for c, _ in DEF_CFG]
    b.bar(x, p, 0.62, color=cols, edgecolor=EDGE, linewidth=EDGE_LW, hatch=hat)
    b.errorbar(x, p, yerr=[np.clip(p - lo, 0, None), np.clip(hi - p, 0, None)], fmt="none", ecolor="black", elinewidth=0.7,
               capsize=2, capthick=0.7)
    for i, (c, _) in enumerate(DEF_CFG):
        b.text(x[i], hi[i] + 1.5, f"{p[i]:.1f}", ha="center", va="bottom", fontsize=6.2)
    b.set_xticks(x)
    b.set_xticklabels([n for _, n in DEF_CFG], rotation=30, ha="right", rotation_mode="anchor")
    b.set_ylabel("false rejection, rewriting\ntraffic (%, 95% Wilson CI)")
    b.set_ylim(0, 60)
    b.text(0.02, 0.98, f"n = {frr['bedge']['att_n']} legit requests\n(S0–S5, NGINX, 4 frameworks)",
           transform=b.transAxes, va="top", fontsize=6, color=PALETTE["grey_dark"])
    panel_label(b, "(b)")
    save(fig, "fig_defence.pdf")
    return totals, {c: (frr[c]["att"], frr[c]["att_n"]) for c, _ in DEF_CFG}, cfg_codes


# ---------------------------------------------------------------------- 6 latency
LAT_CFG = ["B-edge", "B-origin", "D-A", "D-B"]
LAT_COL = {"B-edge": PALETTE["blue_main"], "B-origin": PALETTE["neutral"],
           "D-A": PALETTE["teal"], "D-B": PALETTE["red_strong"]}
LAT_HATCH = {"B-edge": "", "B-origin": "....", "D-A": "xxxx", "D-B": "////"}


def fig_latency():
    rows = read_csv(EXP / "defence" / "analysis" / "perf_latency.csv")
    excluded = sorted({r["level"] for r in rows if r["level"] != "100"}, key=lambda s: (s == "max", int(s) if s.isdigit() else 0))
    sel = {(r["framework"], r["config"]): r for r in rows if r["level"] == "100"}
    fws = ["fastapi", "spring"]
    for fw in fws:
        for c in LAT_CFG:
            assert int(sel[(fw, c)]["failed_checks"]) == 0, (fw, c)
    fig, axes = plt.subplots(1, 2, figsize=(COL2, 1.95), sharey=True,
                             gridspec_kw={"wspace": 0.08})
    qs = [("p50", "p50"), ("p95", "p95"), ("p99", "p99")]
    w = 0.19
    for ax, fw in zip(axes, fws):
        xq = np.arange(len(qs))
        for j, c in enumerate(LAT_CFG):
            r = sel[(fw, c)]
            v = np.array([float(r[f"{q}_ms"]) for q, _ in qs])
            lo = np.array([float(r[f"{q}_lo"]) for q, _ in qs])
            hi = np.array([float(r[f"{q}_hi"]) for q, _ in qs])
            xx = xq + (j - 1.5) * w
            ax.bar(xx, v, w, color=LAT_COL[c], edgecolor=EDGE, linewidth=EDGE_LW,
                   hatch=LAT_HATCH[c], label=c)
            ax.errorbar(xx, v, yerr=[v - lo, hi - v], fmt="none", ecolor="black",
                        elinewidth=0.6, capsize=1.5, capthick=0.6)
            for xi, vi in zip(xx, v):
                if vi >= 100:
                    ax.text(xi, vi * 1.6, f"{vi:.0f}", ha="center", va="bottom", fontsize=5.6,
                            rotation=90)
        ax.set_yscale("log")
        ax.set_ylim(0.5, 1e4)
        ax.set_xticks(xq)
        ax.set_xticklabels([l for _, l in qs])
        ax.text(0.02, 0.97, {"fastapi": "FastAPI", "spring": "Spring"}[fw] + " @ 100 req/s",
                transform=ax.transAxes, va="top", fontsize=7, fontweight="bold")
    axes[0].set_ylabel("latency (ms, log)")
    axes[1].legend(loc="upper right", ncol=2, handlelength=1.3, columnspacing=0.8,
                   bbox_to_anchor=(1.0, 1.0))
    fig.text(0.5, -0.06,
             f"Rows at {', '.join(e if e == 'max' else e + ' req/s' for e in excluded)} omitted: "
             "nginx 502 saturation on the shared laptop, not defence latency (defence/REPORT.md §6).",
             ha="center", va="top", fontsize=6, color=PALETTE["grey_dark"])
    save(fig, "fig_latency.pdf")
    return excluded


def main():
    apply_style()
    agg = json.loads((HERE / "aggregate.json").read_text())
    fig_hits_heatmap(agg)
    res = fig_resolution(agg)
    fam = fig_class(agg)
    fig_ablation_a1()
    tot, frr, codes = fig_defence()
    exc = fig_latency()
    print(json.dumps({"resolution": res, "families": fam, "e7_totals": tot, "frr": frr,
                      "e7_cfg_codes": codes, "latency_excluded_levels": exc}, indent=1))


if __name__ == "__main__":
    main()

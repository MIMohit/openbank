"""FRR tables from runs/frr/<cfg>/w17-frr-<cfg>-<fw>/frr.jsonl.
raw FRR      = legit requests not executed as the intended op (status >= 400 or wrong op) / all
attributable = requests that B-edge (same framework, same request) executed correctly but the config did not,
               / requests B-edge executed correctly  (nets out framework behaviour, e.g. Starlette 404 on %2F)
95% CIs: Wilson (analysis/stats.py wilson_ci)."""
import collections, csv, glob, json, os, sys
sys.path.insert(0, "/Users/mimohit/openbank")
D = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
from analysis.stats import wilson_ci  # noqa: E402
CFG = ["bedge", "borigin", "bstrict", "da", "db", "dc"]
NAME = {"bedge": "B-edge", "borigin": "B-origin", "bstrict": "B-strict", "da": "D-A", "db": "D-B", "dc": "D-C"}
def grp(s): return "S4-pct-id" if s.startswith("S4") else s
def main():
    R = {}
    for cfg in CFG:
        for f in glob.glob(os.path.join(D, "runs", "frr", cfg, "*", "frr.jsonl")):
            fw = f.split("/")[-2].split("-")[-1]
            for i, l in enumerate(open(f)):
                x = json.loads(l); R[(cfg, fw, i)] = x
    fws = sorted({k[1] for k in R}); rows = []
    tot = collections.Counter(); bad = collections.Counter(); att = collections.Counter(); attn = collections.Counter()
    reasons = collections.Counter()
    for (cfg, fw, i), x in R.items():
        b = R.get(("bedge", fw, i))
        for g in (grp(x["scenario"]), "ALL"):
            tot[(cfg, g)] += 1; bad[(cfg, g)] += not x["ok"]
            if b and b["ok"]:
                attn[(cfg, g)] += 1; att[(cfg, g)] += not x["ok"]
        if b and b["ok"] and not x["ok"]:
            reasons[(cfg, grp(x["scenario"]), f"{x['status']} {x['reason'] if isinstance(x['reason'], str) else json.dumps(x['reason'])}".splitlines()[0][:90])] += 1
        rows.append({"cfg": cfg, "framework": fw, **x})
    with open(os.path.join(D, "analysis", "frr_long.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    G = ["S0-identity", "S1-strip-prefix", "S2-version-rewrite", "S3-trailing-slash", "S4-pct-id", "S5-h2-to-h1", "ALL"]
    cfgs = [c for c in CFG if tot[(c, "ALL")]]
    L = [f"Frameworks: {', '.join(fws)} (nginx gateway). Cell = attributable false rejects / requests B-edge executed correctly "
         "(raw failures in parentheses).", "",
         "| scenario | " + " | ".join(NAME[c] for c in cfgs) + " |", "|---|" + "---|" * len(cfgs)]
    summary = {}
    for g in G:
        cells = []
        for c in cfgs:
            cells.append(f"{att[(c, g)]}/{attn[(c, g)]} ({bad[(c, g)]}/{tot[(c, g)]})")
        L.append(f"| {g} | " + " | ".join(cells) + " |")
    L += ["", "| config | attributable FRR [95% Wilson CI] | raw FRR [95% CI] |", "|---|---|---|"]
    for c in cfgs:
        p, lo, hi = wilson_ci(att[(c, "ALL")], attn[(c, "ALL")]); q, qlo, qhi = wilson_ci(bad[(c, "ALL")], tot[(c, "ALL")])
        summary[c] = {"att": att[(c, "ALL")], "att_n": attn[(c, "ALL")], "frr": p, "lo": lo, "hi": hi, "raw": bad[(c, "ALL")], "raw_n": tot[(c, "ALL")], "raw_frr": q}
        L.append(f"| {NAME[c]} | {100*p:.1f}% [{100*lo:.1f}, {100*hi:.1f}] ({att[(c,'ALL')]}/{attn[(c,'ALL')]}) | {100*q:.1f}% [{100*qlo:.1f}, {100*qhi:.1f}] ({bad[(c,'ALL')]}/{tot[(c,'ALL')]}) |")
    L += ["", "Attributable false rejects by cause (status + body reason):", "", "| config | scenario | status/reason | n |", "|---|---|---|---|"]
    for (c, g, r), n in sorted(reasons.items()):
        L.append(f"| {NAME[c]} | {g} | `{r}` | {n} |")
    open(os.path.join(D, "analysis", "frr_tables.md"), "w").write("\n".join(L) + "\n")
    json.dump(summary, open(os.path.join(D, "analysis", "frr_summary.json"), "w"), indent=1)
    print("\n".join(L))
if __name__ == "__main__":
    main()

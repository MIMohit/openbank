"""Pick representative hits for ddmin: one per (variant, mechanism) among A1 residual/new classes
(query-digest residuals; no-htu new families), and one per (gateway, mechanism) among strict survivors.
Prints lines: <yaml> <runs-dir> <cases> <bind> <gate> <case-id>"""
import json, sys
from collections import OrderedDict
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import mech
A = Path(__file__).resolve().parents[1]
pick = OrderedDict()
for l in open(A / "analysis" / "a1_hits_all.jsonl"):
    h = json.loads(l)
    v = h["variant"]
    if v == "query-digest" or (v == "no-htu" and mech.mechanism(h).startswith(("other", "M8"))) or (v == "no-htu" and h["mech"] == "M9"):
        k = (v, mech.mechanism(h))
        if k not in pick:
            bind = {"query-digest": "query-digest"}.get(v, "full")
            pick[k] = (f"{A}/topologies/{h['topology']}.yaml", f"{A}/runs", f"{A}/cases.jsonl", bind,
                       "1" if v == "query-digest" else "0", h["case_id"])
for d in sorted((A / "strict" / "runs").glob("w18-g2-*-str")):
    for l in open(d / "hits.jsonl"):
        h = json.loads(l)
        k = ("strict", d.name.split("-")[2], mech.mechanism(h))
        if k not in pick:
            pick[k] = (f"{A}/strict/topologies/{d.name}.yaml", f"{A}/strict/runs", f"{A}/strict/cases_g2.jsonl", "full", "0", h["case_id"])
for k, v in pick.items():
    print(" ".join(v))

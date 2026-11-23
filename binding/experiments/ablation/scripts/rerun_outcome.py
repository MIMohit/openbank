"""Rerun outcomes: per original hit -> confirmed (3/3, same exec op + path params) | flaky | irreproducible.
Usage: rerun_outcome.py <runs-dir> <reruns-dir>  -> <reruns-dir>/rerun_outcome.jsonl + summary on stdout."""
import json
import sys
from collections import Counter
from pathlib import Path

runs, rr = Path(sys.argv[1]), Path(sys.argv[2])
out, c = [], Counter()
for hp in sorted(runs.glob("*/hits.jsonl")):
    tid = hp.parent.name
    H = [json.loads(l) for l in open(hp)]
    if not H:
        continue
    reps = []
    for k in (1, 2, 3):
        p = rr / f"rep{k}" / tid / "hits.jsonl"
        reps.append({(h["case_id"], h["exec_op_id"], json.dumps(h["exec_path_params"], sort_keys=True))
                     for h in map(json.loads, open(p))} if p.exists() else None)
    for h in H:
        key = (h["case_id"], h["exec_op_id"], json.dumps(h["exec_path_params"], sort_keys=True))
        n = sum(1 for r in reps if r is not None and key in r)
        miss = sum(1 for r in reps if r is None)
        o = "confirmed" if n == 3 else ("not_rerun" if miss == 3 else ("flaky" if n else "irreproducible"))
        c[o] += 1
        out.append({"topology": tid, "case_id": h["case_id"], "exec_op_id": h["exec_op_id"], "reps_hit": n, "outcome": o})
with open(rr / "rerun_outcome.jsonl", "w") as f:
    for r in out:
        f.write(json.dumps(r) + "\n")
print(dict(c))

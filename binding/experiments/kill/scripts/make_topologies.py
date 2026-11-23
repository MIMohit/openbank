"""Write the 48 kill-experiment topology YAMLs into experiments/kill/topologies/.

Uses W6's generator function orchestrator.make_matrix.topo() unchanged, then (only) renames
the id with a 'w9-' prefix and assigns W9-private host ports 28100+i so that runs cannot
collide with other workers' logs/<id>/ dirs, compose projects or ports.
Run from binding/harness:  orchestrator/.venv/bin/python ../experiments/kill/scripts/make_topologies.py
"""
import itertools, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "harness"))
from orchestrator.make_matrix import topo
from orchestrator.topology import dump

OUT = Path(__file__).resolve().parents[1] / "topologies"
GWS = ["nginx", "traefik", "envoy"]; PROFS = ["default", "recommended"]
FWS = ["fastapi", "express", "spring", "aspnet"]; OVS = ["off", "on"]
ids = []
for i, (gw, pr, fw, ov) in enumerate(itertools.product(GWS, PROFS, FWS, OVS)):
    t = topo(gw, pr, "edge", fw, ov, 28100 + i)
    t["id"] = "w9-" + t["id"]
    (OUT / f"{t['id']}.yaml").write_text(dump(t))
    ids.append(t["id"])
(OUT.parent / "topologies.txt").write_text("".join(i + "\n" for i in ids))
print(len(ids))

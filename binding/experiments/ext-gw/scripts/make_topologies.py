"""Write the 96 ext-gw (W13) topology YAMLs into experiments/ext-gw/topologies/.

W13 scope (CONTRACT §12): the 3 gateways not covered by the kill experiment
(kong, apisix, haproxy) x profiles {default, recommended} x placement edge x
all 8 frameworks x override {off, on} = 96 topologies.

Uses W6's generator orchestrator.make_matrix.topo() unchanged, then only
(a) prefixes the id with 'w13-' and (b) assigns W13-private host ports 29100+i
so runs cannot collide with other workers' logs/<id>/ dirs, compose projects
or ports (kill used 28100-28147/28200+; W12/W14/W15 use their own).

Run from binding/harness:
  orchestrator/.venv/bin/python ../experiments/ext-gw/scripts/make_topologies.py
"""
import itertools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "harness"))
from orchestrator.make_matrix import topo
from orchestrator.topology import dump

OUT = Path(__file__).resolve().parents[1] / "topologies"
OUT.mkdir(parents=True, exist_ok=True)
GWS = ["kong", "apisix", "haproxy"]
PROFS = ["default", "recommended"]
FWS = ["fastapi", "express", "django", "go-chi", "spring", "aspnet", "rails", "laravel"]
OVS = ["off", "on"]

ids = []
# Order: override=off for all frameworks first, then override=on (brief: if runtime
# is too long run off first). We still keep every (gw,prof,fw) pairing.
for i, (ov, gw, pr, fw) in enumerate(itertools.product(OVS, GWS, PROFS, FWS)):
    t = topo(gw, pr, "edge", fw, ov, 29100 + i)
    t["id"] = "w13-" + t["id"]
    (OUT / f"{t['id']}.yaml").write_text(dump(t))
    ids.append(t["id"])

(OUT.parent / "topologies.txt").write_text("".join(i + "\n" for i in ids))
print(len(ids))

"""Write the ext-fw (W14) topology YAMLs into experiments/ext-fw/topologies/.

Uses W6's generator orchestrator.make_matrix.topo() unchanged, then renames the id with a
'w14-' prefix and assigns W14-private host ports so runs cannot collide with other workers'
logs/<id>/ dirs, compose projects or ports.

Part (a): nginx,traefik,envoy x default,recommended x edge x django,go-chi,rails,laravel x off,on = 48.
Part (b): nginx,envoy x default x {origin,both} x all 8 frameworks x override on = 32 (A3 ablation).

Run from binding/harness:
  orchestrator/.venv/bin/python ../experiments/ext-fw/scripts/make_topologies.py
"""
import itertools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "harness"))
from orchestrator.make_matrix import topo
from orchestrator.topology import dump

OUT = Path(__file__).resolve().parents[1] / "topologies"
OUT.mkdir(parents=True, exist_ok=True)

ids_a, ids_b = [], []

# ---- Part (a): remaining frameworks, edge ----
GWS = ["nginx", "traefik", "envoy"]
PROFS = ["default", "recommended"]
FWS_A = ["django", "go-chi", "rails", "laravel"]
OVS = ["off", "on"]
port = 34100
for gw, pr, fw, ov in itertools.product(GWS, PROFS, FWS_A, OVS):
    t = topo(gw, pr, "edge", fw, ov, port)
    t["id"] = "w14-" + t["id"]
    (OUT / f"{t['id']}.yaml").write_text(dump(t))
    ids_a.append(t["id"])
    port += 1

# ---- Part (b): A3 origin-placement ablation ----
GWS_B = ["nginx", "envoy"]
PLACEMENTS_B = ["origin", "both"]
FWS_B = ["fastapi", "express", "django", "go-chi", "spring", "aspnet", "rails", "laravel"]
port = 34200
for gw, pl, fw in itertools.product(GWS_B, PLACEMENTS_B, FWS_B):
    t = topo(gw, "default", pl, fw, "on", port)
    t["id"] = "w14-" + t["id"]
    (OUT / f"{t['id']}.yaml").write_text(dump(t))
    ids_b.append(t["id"])
    port += 1

(OUT.parent / "topologies_a.txt").write_text("".join(i + "\n" for i in ids_a))
(OUT.parent / "topologies_b.txt").write_text("".join(i + "\n" for i in ids_b))
(OUT.parent / "topologies.txt").write_text("".join(i + "\n" for i in ids_a + ids_b))
print(f"part(a) edge: {len(ids_a)}   part(b) A3 origin/both: {len(ids_b)}   total: {len(ids_a)+len(ids_b)}")

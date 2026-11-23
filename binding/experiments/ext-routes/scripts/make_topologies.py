"""Write the 32 ext-routes topology YAMLs (nginx+envoy, default profile, 8 frameworks,
override off/on), all edge, all using the bh-exec-<fw>:v2 images (ROUTES=v2 baked in).

W15-private ids (w15r- prefix) and host ports 29100+i so runs cannot collide with other
workers. Run from binding/harness:
    orchestrator/.venv/bin/python ../experiments/ext-routes/scripts/make_topologies.py
"""
import itertools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "harness"))
from orchestrator.make_matrix import topo       # noqa: E402
from orchestrator.topology import dump           # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "topologies"
OUT.mkdir(parents=True, exist_ok=True)
GWS = ["nginx", "envoy"]
PROFS = ["default"]
FWS = ["fastapi", "express", "django", "go-chi", "spring", "aspnet", "rails", "laravel"]
OVS = ["off", "on"]

ids = []
for i, (gw, pr, fw, ov) in enumerate(itertools.product(GWS, PROFS, FWS, OVS)):
    t = topo(gw, pr, "edge", fw, ov, 29100 + i)
    t["id"] = "w15r-" + t["id"]
    t["executor_image"] = f"bh-exec-{fw}:v2"   # ROUTES=v2 baked into the :v2 image
    (OUT / f"{t['id']}.yaml").write_text(dump(t))
    ids.append(t["id"])

(OUT.parent / "topologies.txt").write_text("".join(i + "\n" for i in ids))
print(len(ids), "topologies written to", OUT)

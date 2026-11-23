"""Write E4 topology YAMLs into experiments/e4/topologies/.

Uses W6's generator (orchestrator.make_matrix.topo) unchanged, then overrides the verifier
image with a PDP variant (bh-pdp-<policy>:latest) so the orchestrator runs the PDP in the
verifier slot (it exposes the same adapters). IDs are w12-prefixed and host ports are
W12-private (28500+) so they cannot collide with other workers' logs/ports/projects.

Policy is encoded in the image (POLICY/POLICY_NORMALIZE baked as ENV), because the
orchestrator only forwards the standard verifier env — we do NOT edit orchestrator/.

Sets (write all; the runner script picks which to run):
  allow : 6 gw x 6 fw x {default}         policy=allowlist   (dot-segment traversal leads)
  block : 6 gw x 4 fw x {default}         policy=blocklist   (case/matrix/slash/.json leads)
  rec   : confirmed-lead combos x recommended profile (both policies)

Run from binding/harness:
  python ../experiments/e4/scripts/make_topologies.py
"""
import itertools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "harness"))
from orchestrator.make_matrix import topo
from orchestrator.topology import dump

OUT = Path(__file__).resolve().parents[1] / "topologies"
OUT.mkdir(parents=True, exist_ok=True)

GWS = ["nginx", "traefik", "envoy", "kong", "apisix", "haproxy"]
GW_ABBR = {"nginx": "ngx", "traefik": "trf", "envoy": "env", "kong": "kng",
           "apisix": "apx", "haproxy": "hap"}
FW_ALL = ["aspnet", "rails", "spring", "express", "laravel", "fastapi"]
FW_LOOSE = ["aspnet", "rails", "spring", "express"]   # loose routers for block vectors
POLICY_IMAGE = {"allow": "bh-pdp-allow:latest", "block": "bh-pdp-block:latest",
                "allow-n": "bh-pdp-allow-n:latest", "block-n": "bh-pdp-block-n:latest"}


def mk(pol_tag, gw, fw, profile, port):
    tid = f"w12-{pol_tag}-{GW_ABBR[gw]}-{fw}-{profile[:3]}"
    t = topo(gw, profile, "edge", fw, "off", port, tid=tid,
             verifier_image=POLICY_IMAGE[pol_tag])
    return t


def main():
    ids = {"allow": [], "block": [], "rec": []}
    port = 28500
    # allow set: full 6x6, default
    for gw, fw in itertools.product(GWS, FW_ALL):
        t = mk("allow", gw, fw, "default", port); port += 1
        (OUT / f"{t['id']}.yaml").write_text(dump(t))
        ids["allow"].append(t["id"])
    # block set: 6 gw x loose fw, default
    for gw, fw in itertools.product(GWS, FW_LOOSE):
        t = mk("block", gw, fw, "default", port); port += 1
        (OUT / f"{t['id']}.yaml").write_text(dump(t))
        ids["block"].append(t["id"])
    # recommended set: lead frameworks x all gw x recommended, both policies
    for poltag in ("allow", "block"):
        for gw, fw in itertools.product(GWS, ["aspnet", "rails", "spring"]):
            t = mk(poltag, gw, fw, "recommended", port); port += 1
            (OUT / f"{t['id']}.yaml").write_text(dump(t))
            ids["rec"].append(t["id"])
    for name, lst in ids.items():
        (OUT.parent / f"set_{name}.txt").write_text("".join(i + "\n" for i in lst))
        print(f"{name}: {len(lst)} topologies")
    print(f"total: {sum(len(v) for v in ids.values())}  ports {28500}..{port-1}")


if __name__ == "__main__":
    main()

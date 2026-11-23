"""Write topology YAMLs.

    cd binding/harness && python -m orchestrator.make_matrix

  topologies/matrix/  6 gateways x 3 profiles x 3 placements x 8 frameworks x override off/on = 864
  topologies/pilot/   envoy/traefik/nginx x default x edge x fastapi/express/spring/aspnet x off/on = 24
  topologies/smoke/   6 gateways x 3 profiles, placement edge, stub verifier + stub executor = 18
  topologies/smokereal/ same 18, REAL verifier (bh-verifier:latest, W3) + stub executor

Host ports are deterministic: matrix index i -> 18000 + i (pilot reuses the matrix
port of the same id); smoke uses 19000+. Each list also goes to <set>.txt.
"""
import itertools
from pathlib import Path

from gateways.common import GATEWAYS, IMAGES, PLACEMENTS, PROFILES
from orchestrator.topology import FRAMEWORKS, STUB, dump

TOPO = Path(__file__).resolve().parent / "topologies"
PILOT = dict(gateways=["envoy", "traefik", "nginx"], profiles=["default"], placements=["edge"],
             frameworks=["fastapi", "express", "spring", "aspnet"])


def topo(gw, pr, pl, fw, ov, port, tid=None, verifier_image=None):
    return {
        "id": tid or f"{gw}-{pr}-{pl}-{fw}-ov{ov}",
        "gateway": gw, "gateway_image": IMAGES[gw], "profile": pr, "placement": pl,
        "framework": fw, "executor_image": STUB if fw == STUB else f"bh-exec-{fw}:latest",
        "override": ov,
        "verifier": {"image": verifier_image or (STUB if fw == STUB else "bh-verifier:latest"), "canon": "rfc3986", "view_mac": "off"},
        "host_port": port,
    }


def write_set(name, topos):
    d = TOPO / name
    d.mkdir(parents=True, exist_ok=True)
    for old in d.glob("*.yaml"):
        old.unlink()
    for t in topos:
        (d / f"{t['id']}.yaml").write_text(dump(t))
    (TOPO / f"{name}.txt").write_text("".join(f"{name}/{t['id']}.yaml\n" for t in topos))
    print(f"{name}: {len(topos)} topologies")


def main():
    matrix = [topo(gw, pr, pl, fw, ov, 18000 + i) for i, (gw, pr, pl, fw, ov) in enumerate(
        itertools.product(GATEWAYS, PROFILES, PLACEMENTS, FRAMEWORKS, ["off", "on"]))]
    write_set("matrix", matrix)
    write_set("pilot", [t for t in matrix if t["gateway"] in PILOT["gateways"]
                        and t["profile"] in PILOT["profiles"] and t["placement"] in PILOT["placements"]
                        and t["framework"] in PILOT["frameworks"]])
    write_set("smoke", [topo(gw, pr, "edge", STUB, "off", 19000 + i, f"smoke-{gw}-{pr}-edge")
                        for i, (gw, pr) in enumerate(itertools.product(GATEWAYS, PROFILES))])
    write_set("smokereal", [topo(gw, pr, "edge", STUB, "off", 19100 + i, f"smokereal-{gw}-{pr}-edge",
                                 verifier_image="bh-verifier:latest")
                            for i, (gw, pr) in enumerate(itertools.product(GATEWAYS, PROFILES))])


if __name__ == "__main__":
    main()

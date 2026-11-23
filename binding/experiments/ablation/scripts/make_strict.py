"""W18 A5 strict-profile topologies (copied pattern from e4/scripts/make_topologies.py).
  g2 set : {nginx,envoy,traefik,kong,apisix} x {fastapi,aspnet,spring} (:v2) x {strict, + default/recommended
           controls on the same case set}, override off, bh-verifier:latest. Cases = confirmed binding-G2 families.
  e4 set : {nginx,envoy,traefik,kong,apisix,haproxy} x {aspnet,spring} x strict x policy {allow,block}
           (bh-pdp-allow/block:latest), E4 battery (RC1 = aspnet /../, RC2 = kong /../ upstream normalisation).
Run from experiments/ablation: ../../harness/orchestrator/.venv/bin/python scripts/make_strict.py
"""
import itertools
import json
import sys
from pathlib import Path

A = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(A.parents[1] / "harness"))
from orchestrator.make_matrix import topo  # noqa: E402
from orchestrator.topology import dump  # noqa: E402

AB = {"nginx": "ngx", "traefik": "trf", "envoy": "env", "kong": "kng", "apisix": "apx", "haproxy": "hap"}
G2_FAMILIES_PRIMS = None


def main():
    out = A / "strict" / "topologies"
    out.mkdir(parents=True, exist_ok=True)
    g2, e4 = [], []
    for pr in ("strict", "default", "recommended"):
        for gw, fw in itertools.product(["nginx", "envoy", "traefik", "kong", "apisix"], ["fastapi", "aspnet", "spring"]):
            t = topo(gw, pr, "edge", fw, "off", 29882, tid=f"w18-g2-{AB[gw]}-{fw}-{pr[:3]}")
            t["executor_image"] = f"bh-exec-{fw}:v2"
            (out / f"{t['id']}.yaml").write_text(dump(t))
            g2.append(t["id"])
    for pol in ("allow", "block"):
        for gw, fw in itertools.product(AB, ["aspnet", "spring"]):
            t = topo(gw, "strict", "edge", fw, "off", 29883, tid=f"w18-e4-{pol}-{AB[gw]}-{fw}-str",
                     verifier_image=f"bh-pdp-{pol}:latest")
            (out / f"{t['id']}.yaml").write_text(dump(t))
            e4.append(t["id"])
    (A / "strict" / "g2_topologies.txt").write_text("\n".join(g2) + "\n")
    (A / "strict" / "e4_topologies.txt").write_text("\n".join(e4) + "\n")
    # G2 case set: baselines + every case whose primitive belongs to a family with confirmed binding-G2 hits
    from mutator.catalogue import load_catalogue
    fam = {p.id: p.cls for p in load_catalogue()}
    keep = {"fragment", "encoded-slash", "dot-segment"}
    n = 0
    with open(A / "strict" / "cases_g2.jsonl", "w") as f:
        for l in open(A / "cases.jsonl"):
            c = json.loads(l)
            ps = c["primitive_ids"]
            if not ps or any(p.startswith("x-frag") or fam.get(p) in keep for p in ps):
                f.write(l); n += 1
    print(len(g2), "g2 topologies,", len(e4), "e4 topologies,", n, "g2 cases")


if __name__ == "__main__":
    main()

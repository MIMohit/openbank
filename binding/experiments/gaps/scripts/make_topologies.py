"""W18 A1 topologies: nginx default edge x {fastapi,spring,rails,laravel} (:v2) x override x variant.
Variant -> verifier image tag; 'gate' variants additionally get the digest_gate hop (run_one.sh).
Usage (from experiments/ablation): python3 scripts/make_topologies.py
"""
from pathlib import Path

VARIANTS = {  # name -> (verifier tag, bind label for the minter, gate?)
    "full": ("ablate-full", "full", False),
    "no-htm": ("ablate-no-htm", "full", False),
    "no-htu": ("ablate-no-htu", "full", False),
    "no-ath": ("ablate-no-ath", "full", False),
    "query": ("ablate-query", "query", False),
    "digest-nogate": ("ablate-digest", "digest", False),
    "digest": ("ablate-digest", "digest", True),
    "query-digest": ("ablate-query-digest", "query-digest", True),
}
FWS = ["fastapi", "spring", "rails", "laravel"]
A = Path(__file__).resolve().parents[1]


def main():
    d = A / "topologies"
    d.mkdir(exist_ok=True)
    ids = []
    for v, (tag, _, _) in VARIANTS.items():
        for fw in FWS:
            for ov in ("off", "on"):
                tid = f"w18-{v}-nginx-default-edge-{fw}-ov{ov}"
                (d / f"{tid}.yaml").write_text(
                    f"id: {tid}\ngateway: nginx\ngateway_image: nginx:1.30.7-alpine\nprofile: default\n"
                    f"placement: edge\nframework: {fw}\nexecutor_image: bh-exec-{fw}:v2\noverride: '{ov}'\n"
                    f"verifier: {{image: 'bh-verifier:{tag}', canon: rfc3986, view_mac: 'off'}}\n"
                    f"host_port: 29881\n")
                ids.append(tid)
    (A / "topologies.txt").write_text("\n".join(ids) + "\n")
    print(len(ids), "topologies")


if __name__ == "__main__":
    main()

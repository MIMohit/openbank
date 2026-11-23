"""Render every gateway x profile x placement into gateways/<gw>/rendered/<profile>-<placement>/
for review and for `validate.sh`. The orchestrator renders its own copy per topology.

    cd binding/harness && python -m gateways.render_all
"""
import importlib
import json
import shutil
from pathlib import Path

from gateways.common import GATEWAYS, PLACEMENTS, PROFILES

HERE = Path(__file__).resolve().parent


def main() -> None:
    for gw in GATEWAYS:
        mod = importlib.import_module(f"gateways.{gw}.render")
        root = HERE / gw / "rendered"
        shutil.rmtree(root, ignore_errors=True)
        for pr in PROFILES:
            for pl in PLACEMENTS:
                out = root / f"{pr}-{pl}"
                svc = mod.render(pr, pl, out)
                (out / "service.json").write_text(json.dumps(svc, indent=2) + "\n")
        print(f"{gw}: {len(PROFILES) * len(PLACEMENTS)} configs -> {root.relative_to(HERE.parent)}")


if __name__ == "__main__":
    main()

"""
Attack runner — executes A1–A6 against B0, B1, and P configurations.

Usage:
  python -m attacks.runner \
      --controller-b0 http://localhost:9000 \
      --controller-b1 http://localhost:9001 \
      --controller-p  http://localhost:9002 \
      --out-dir data/raw/attacks \
      --repetitions 30

In the docker-compose testbed a single ZT Controller is used; the config is
switched by restarting with different ZT_MODE env vars.  For the full
experiment matrix, the Makefile calls this runner once per mode.
"""
import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from attacks import (
    a1_network_replay, a2_token_theft_reuse, a3_device_resident,
    a4_ato_new_device, a5_bola_bfla, a6_velocity_abuse,
)
from attacks.base import AttackResult, write_attack_result
from client_sim.device import Device


async def setup_legit_session(controller_url: str, mode: str):
    """
    Obtain a synthetic token + device for the given config.
    In the testbed we mock a valid token since Keycloak DPoP requires a browser
    flow; integration tests use the real flow.
    """
    import uuid, time as _time
    from jose import jwt as _jwt
    from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
    from cryptography.hazmat.primitives import serialization

    device = Device(device_id=f"legit_{mode}", geo="AU", source_ip="10.0.0.1", seed=42)

    # For the standalone runner we create a self-signed JWT that mimics a real AT.
    # (The ZT Controller validates against Keycloak JWKS in integration; here we
    # use a mock token that passes the controller in test/bypass mode.)
    mock_at = f"MOCK_AT_{uuid.uuid4().hex}"
    return device, mock_at


async def run_all(
    controller_urls: dict,
    out_dir: str,
    repetitions: int = 30,
):
    """Run A1–A6 against each config and write results."""
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    summary = []

    for config, url in controller_urls.items():
        print(f"\n=== Running attacks against {config} ({url}) ===")
        device, mock_at = await setup_legit_session(url, config)
        attacker_device = Device(device_id="attacker", geo="RU", source_ip="1.2.3.4")

        # A1: network replay — capture valid headers then replay
        captured_headers = {
            "Authorization": f"Bearer {mock_at}",
            "DPoP": device.sign_dpop_proof("GET", f"{url}/accounts", mock_at),
        }
        captured_headers.update(device.context_headers())
        r = await a1_network_replay.run(url, config, captured_headers,
                                        num_attempts=repetitions, out_dir=out_dir)
        summary.append(r.to_dict())
        print(f"  A1: {r.successes}/{r.attempts} succeeded, detected={r.detected}")

        # A2: token theft
        r = await a2_token_theft_reuse.run(url, config, mock_at,
                                           num_attempts=repetitions, out_dir=out_dir)
        summary.append(r.to_dict())
        print(f"  A2: {r.successes}/{r.attempts} succeeded, detected={r.detected}")

        # A3: device-resident key abuse (burst)
        r = await a3_device_resident.run(url, config, mock_at, device,
                                         num_attempts=repetitions, out_dir=out_dir)
        summary.append(r.to_dict())
        print(f"  A3: {r.successes}/{r.attempts} succeeded, detected={r.detected}")

        # A4: ATO from new device
        r = await a4_ato_new_device.run(url, config, mock_at, attacker_device,
                                        num_attempts=repetitions, out_dir=out_dir)
        summary.append(r.to_dict())
        print(f"  A4: {r.successes}/{r.attempts} succeeded, detected={r.detected}")

        # A5: BOLA — use a placeholder victim account id
        r = await a5_bola_bfla.run(url, config, mock_at, device,
                                   victim_account_id="acct_other_user",
                                   victim_user_id="other_user",
                                   num_attempts=repetitions, out_dir=out_dir)
        summary.append(r.to_dict())
        print(f"  A5: {r.successes}/{r.attempts} succeeded, detected={r.detected}")

        # A6: velocity abuse
        r = await a6_velocity_abuse.run(url, config, mock_at, device,
                                        num_attempts=repetitions, out_dir=out_dir)
        summary.append(r.to_dict())
        print(f"  A6: {r.successes}/{r.attempts} succeeded, detected={r.detected}")

    # Write summary
    summary_file = Path(out_dir) / "summary.jsonl"
    with open(summary_file, "w") as f:
        for r in summary:
            f.write(json.dumps(r) + "\n")
    print(f"\nSummary written to {summary_file}")
    return summary


def main():
    parser = argparse.ArgumentParser(description="Attack suite runner")
    parser.add_argument("--controller-b0", default="http://localhost:9000")
    parser.add_argument("--controller-b1", default="http://localhost:9000")
    parser.add_argument("--controller-p", default="http://localhost:9000")
    parser.add_argument("--out-dir", default="data/raw/attacks")
    parser.add_argument("--repetitions", type=int, default=30)
    args = parser.parse_args()

    urls = {
        "B0": args.controller_b0,
        "B1": args.controller_b1,
        "P": args.controller_p,
    }
    asyncio.run(run_all(urls, args.out_dir, args.repetitions))


if __name__ == "__main__":
    main()

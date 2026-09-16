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
    Obtain a real, Keycloak-signed access token + device for the given config.

    B0 uses the openbanking-b0 realm's public client (ROPC, no DPoP) directly.
    B1/P use the openbanking-fapi2 realm's harness-only client (see
    keycloak/realm-fapi2.json: zt-harness-client) — a direct-grant twin of the
    real browser-flow client, used solely so this runner can obtain real
    cnf.jkt-bound tokens without simulating PAR+PKCE. The ZT Controller
    verifies these tokens exactly as it would any other.
    """
    from client_sim.flows import OAuthSession

    keycloak_url = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
    device = Device(device_id=f"legit_{mode}", geo="AU", source_ip="10.0.0.1", seed=42)

    if mode == "B0":
        session = OAuthSession(
            device=device,
            keycloak_url=keycloak_url,
            realm=os.getenv("KC_REALM_B0", "openbanking-b0"),
            client_id="zt-client-b0",
            client_secret="",
            username="testuser",
            password="testpass",
            use_dpop=False,
        )
    else:
        session = OAuthSession(
            device=device,
            keycloak_url=keycloak_url,
            realm=os.getenv("KC_REALM_FAPI2", "openbanking-fapi2"),
            client_id="zt-harness-client",
            client_secret="zt-harness-client-secret-local",
            username="testuser",
            password="testpass",
            use_dpop=True,
        )
    access_token = await session.authenticate()
    return device, access_token


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
        device, access_token = await setup_legit_session(url, config)
        attacker_device = Device(device_id="attacker", geo="RU", source_ip="1.2.3.4")

        # A1: network replay — capture valid headers then replay
        captured_headers = {
            "Authorization": f"Bearer {access_token}",
            "DPoP": device.sign_dpop_proof("GET", f"{url}/accounts", access_token),
        }
        captured_headers.update(device.context_headers())
        r = await a1_network_replay.run(url, config, captured_headers,
                                        num_attempts=repetitions, out_dir=out_dir)
        summary.append(r.to_dict())
        print(f"  A1: {r.successes}/{r.attempts} succeeded, detected={r.detected}")

        # A2: token theft
        r = await a2_token_theft_reuse.run(url, config, access_token,
                                           num_attempts=repetitions, out_dir=out_dir)
        summary.append(r.to_dict())
        print(f"  A2: {r.successes}/{r.attempts} succeeded, detected={r.detected}")

        # A3: device-resident key abuse (burst)
        r = await a3_device_resident.run(url, config, access_token, device,
                                         num_attempts=repetitions, out_dir=out_dir)
        summary.append(r.to_dict())
        print(f"  A3: {r.successes}/{r.attempts} succeeded, detected={r.detected}")

        # A4: ATO from new device
        r = await a4_ato_new_device.run(url, config, access_token, attacker_device,
                                        num_attempts=repetitions, out_dir=out_dir)
        summary.append(r.to_dict())
        print(f"  A4: {r.successes}/{r.attempts} succeeded, detected={r.detected}")

        # A5: BOLA — use a placeholder victim account id
        r = await a5_bola_bfla.run(url, config, access_token, device,
                                   victim_account_id="acct_other_user",
                                   victim_user_id="other_user",
                                   num_attempts=repetitions, out_dir=out_dir)
        summary.append(r.to_dict())
        print(f"  A5: {r.successes}/{r.attempts} succeeded, detected={r.detected}")

        # A6: velocity abuse
        r = await a6_velocity_abuse.run(url, config, access_token, device,
                                        num_attempts=repetitions, out_dir=out_dir)
        summary.append(r.to_dict())
        print(f"  A6: {r.successes}/{r.attempts} succeeded, detected={r.detected}")

    # Append to the shared summary (the Makefile invokes this once per mode,
    # restarting the ZT Controller with a different ZT_MODE between calls —
    # each mode's results must accumulate, not overwrite the prior mode's).
    summary_file = Path(out_dir) / "summary.jsonl"
    with open(summary_file, "a") as f:
        for r in summary:
            f.write(json.dumps(r) + "\n")
    print(f"\nSummary appended to {summary_file}")
    return summary


def main():
    parser = argparse.ArgumentParser(description="Attack suite runner")
    parser.add_argument("--controller-b0", default="http://localhost:9000")
    parser.add_argument("--controller-b1", default="http://localhost:9000")
    parser.add_argument("--controller-p", default="http://localhost:9000")
    parser.add_argument("--out-dir", default="data/raw/attacks")
    parser.add_argument("--repetitions", type=int, default=30)
    parser.add_argument(
        "--modes", default="B0,B1,P",
        help="Comma-separated subset of configs to run this invocation. The "
             "single ZT Controller instance in this testbed only runs one "
             "ZT_MODE at a time, so the Makefile calls this once per mode, "
             "restarting the controller in between; --modes lets each call "
             "target just that mode instead of re-testing the same running "
             "config three times under three different labels.",
    )
    args = parser.parse_args()

    all_urls = {
        "B0": args.controller_b0,
        "B1": args.controller_b1,
        "P": args.controller_p,
    }
    modes = [m.strip().upper() for m in args.modes.split(",") if m.strip()]
    urls = {m: all_urls[m] for m in modes}
    asyncio.run(run_all(urls, args.out_dir, args.repetitions))


if __name__ == "__main__":
    main()

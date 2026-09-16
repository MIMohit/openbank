"""
Attack runner — executes the attack suite against B0, B1, P and the ablation
cells.  `--only` selects a subset; the default is the six attacks of the
primary taxonomy (A1–A6).  A7, the adaptive-adversary follow-up, is opt-in.

Usage:
  python -m attacks.runner --modes P --label P-minus-velocity \
      --out-dir data/raw/attacks --repetitions 30

In the docker-compose testbed a single ZT Controller is used; the config is
switched by restarting it with different ZT_MODE / ablation env vars, so the
Makefile calls this runner once per cell.  `--modes` selects the harness-side
behaviour (B0 uses plain bearer tokens, B1/P use DPoP), `--label` names the
cell in the results so ablations that share ZT_MODE=P stay distinguishable.

Per-attack isolation.  Before each attack the runner resets the controller's
continuous-trust state and then replays a short legitimate warm-up from the
victim's enrolled device.  This matters for both directions of the
measurement: without the reset, A6's call-rate signal inherits A3's burst and
A4's device signal inherits A2's foreign key, so no per-attack number is
interpretable; without the warm-up, the subject has no established baseline and
the device/geo rules have nothing to be inconsistent with — a new-device
adversary would look exactly like a first-time legitimate user.

The oracle tag.  `--oracle-tag` makes every attack send `x-attack-context:
true`, which rule R7 scores at 0.90.  That is the adversary telling the
defender it is an adversary; it measures a detection *ceiling*, not detection.
It is off by default and off in every primary measurement (see attacks/base.py
and zt-controller/app/risk.py).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx

from attacks import (
    a1_network_replay, a2_token_theft_reuse, a3_device_resident,
    a4_ato_new_device, a5_bola_bfla, a6_velocity_abuse, a7_paced_ato,
)
from attacks.base import AttackResult, write_attack_result
from client_sim.device import Device
from client_sim.flows import OAuthSession

# Mirrors mock-adr-api/app/auth.py: the controller's internal service secret,
# which never leaves the Docker network.  Used only for the harness control
# plane (/admin/reset-state), never on attack traffic.
INTERNAL_SECRET = "zt-internal-only"

WARMUP_REQUESTS = 10


def _kc_client(mode: str) -> tuple:
    """(realm, client_id, client_secret, use_dpop) for the given config."""
    if mode == "B0":
        return (os.getenv("KC_REALM_B0", "openbanking-b0"),
                "zt-client-b0", "", False)
    return (os.getenv("KC_REALM_FAPI2", "openbanking-fapi2"),
            "zt-harness-client", "zt-harness-client-secret-local", True)


async def _authenticate(device: Device, mode: str) -> str:
    """
    Obtain a real, Keycloak-signed access token bound to `device`'s key.

    B0 uses the openbanking-b0 realm's public client (ROPC, no DPoP).  B1/P use
    the openbanking-fapi2 realm's harness-only client (see
    keycloak/realm-fapi2.json: zt-harness-client) — a direct-grant twin of the
    real browser-flow client, used solely so this runner can obtain real
    cnf.jkt-bound tokens without simulating PAR+PKCE.  The ZT Controller
    verifies these tokens exactly as it would any other.
    """
    keycloak_url = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
    realm, client_id, client_secret, use_dpop = _kc_client(mode)
    session = OAuthSession(
        device=device,
        keycloak_url=keycloak_url,
        realm=realm,
        client_id=client_id,
        client_secret=client_secret,
        username="testuser",
        password="testpass",
        use_dpop=use_dpop,
    )
    return await session.authenticate()


def legit_device(mode: str) -> Device:
    """The victim's enrolled device — deterministic key, stable AU context."""
    return Device(device_id=f"legit_{mode}", geo="AU", source_ip="10.0.0.1", seed=42)


def victim_object_ids(seed: int = None) -> tuple:
    """
    A real account id belonging to a *different* synthetic user, for A5.

    Deterministically reproduces `_stable_id("acct", seed, u_idx, a_idx)` from
    mock-adr-api/seed/synthetic_data.py.  The harness cannot discover another
    user's object ids through the API — that is precisely what BOLA would be —
    so it derives one from the documented generator seed.  Victim = synthetic
    user 1; the harness identity (`testuser`) maps to synthetic user 0.
    """
    if seed is None:
        seed = int(os.getenv("MOCK_ADR_SEED", "42"))
    ns = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
    victim_user = f"u_{uuid.uuid5(ns, f'{seed}_1')}"
    victim_account = f"acct_{uuid.uuid5(ns, f'{seed}_1_0')}"
    return victim_account, victim_user


async def reset_controller_state(url: str) -> None:
    """Drop the controller's continuous-trust state between attacks."""
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(f"{url}/admin/reset-state",
                                 headers={"x-zt-admin": INTERNAL_SECRET})
        resp.raise_for_status()


async def warm_up(url: str, device: Device, access_token: str, mode: str,
                  n: int = WARMUP_REQUESTS) -> str:
    """
    Establish the victim's baseline: n ordinary requests from the enrolled
    device, labelled `warmup` so the analysis excludes them from reported
    legitimate-traffic rates.

    Returns the victim's own first account id, read back from the last
    response. A3 needs it: driving abnormal traffic at an id that does not
    exist makes the resource server answer 404, which the attack scores as
    "not 200" and therefore as blocked, so half of A3's attempts used to be
    recorded as defensive successes that no defence produced.
    """
    own_account = ""
    async with httpx.AsyncClient(base_url=url, timeout=10) as client:
        for _ in range(n):
            headers = {"Authorization": f"Bearer {access_token}",
                       "x-context-profile": "warmup"}
            headers.update(device.context_headers())
            if mode != "B0":
                headers["DPoP"] = device.sign_dpop_proof(
                    method="GET", url=f"{url}/accounts", access_token=access_token)
            try:
                resp = await client.get("/accounts", headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", [])
                    if data:
                        own_account = data[0]["id"]
            except Exception:
                pass
            await asyncio.sleep(0.05)
    return own_account


async def _prepare(url: str, mode: str) -> tuple:
    """Reset controller state, re-authenticate the victim, replay the warm-up."""
    await reset_controller_state(url)
    device = legit_device(mode)
    access_token = await _authenticate(device, mode)
    own_account = await warm_up(url, device, access_token, mode)
    return device, access_token, own_account


ALL_ATTACKS = ["A1", "A2", "A3", "A4", "A5", "A6"]


async def run_all(
    controller_urls: dict,
    out_dir: str,
    repetitions: int = 30,
    label: str = "",
    oracle_tag: bool = False,
    only: list | None = None,
    pace_seconds: float = a7_paced_ato.PACE_SECONDS,
):
    """
    Run the selected attacks against each config and write results.

    `only` restricts the suite to a subset of attack ids. It defaults to the
    six attacks of the primary taxonomy, so the default behaviour of this
    runner — and therefore of `make attacks` — is unchanged. A7 (the adaptive
    adversary) is never part of the default set: it is a separate, additively
    reported measurement with its own output directory and run labels, so that
    adding it cannot perturb a primary number.
    """
    selected = set(only or ALL_ATTACKS)
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    summary = []
    victim_account, victim_user = victim_object_ids()

    for mode, url in controller_urls.items():
        cell = label or mode
        print(f"\n=== Running attacks against {cell} (mode={mode}, {url}) "
              f"oracle_tag={oracle_tag} selected={sorted(selected)} ===")

        # ── A1: network replay ───────────────────────────────────────────────
        if "A1" in selected:
            device, access_token, own_account = await _prepare(url, mode)
            captured_headers = {"Authorization": f"Bearer {access_token}"}
            captured_headers.update(device.context_headers())
            if mode != "B0":
                captured_headers["DPoP"] = device.sign_dpop_proof(
                    "GET", f"{url}/accounts", access_token)
            r = await a1_network_replay.run(url, cell, captured_headers,
                                            num_attempts=repetitions, out_dir=out_dir,
                                            oracle_tag=oracle_tag)
            summary.append(r.to_dict())
            print(f"  A1: {r.successes}/{r.attempts} succeeded, detected={r.detected}")

        # ── A2: token theft without the key ──────────────────────────────────
        if "A2" in selected:
            device, access_token, own_account = await _prepare(url, mode)
            r = await a2_token_theft_reuse.run(url, cell, access_token,
                                               num_attempts=repetitions, out_dir=out_dir,
                                               oracle_tag=oracle_tag)
            summary.append(r.to_dict())
            print(f"  A2: {r.successes}/{r.attempts} succeeded, detected={r.detected}")

        # ── A3: device-resident key abuse (burst on the victim's own key) ────
        if "A3" in selected:
            device, access_token, own_account = await _prepare(url, mode)
            r = await a3_device_resident.run(
                url, cell, access_token, device,
                target_paths=["/accounts", f"/transactions?account_id={own_account}"],
                num_attempts=repetitions, out_dir=out_dir, oracle_tag=oracle_tag)
            summary.append(r.to_dict())
            print(f"  A3: {r.successes}/{r.attempts} succeeded, detected={r.detected}")

        # ── A4: ATO from a new device ────────────────────────────────────────
        # The attacker runs the token flow themselves, so their token's cnf.jkt
        # is their own key's thumbprint and every B1 check passes.
        if "A4" in selected:
            device, access_token, own_account = await _prepare(url, mode)
            attacker_device = Device(device_id="attacker_a4", geo="RU", source_ip="5.6.7.8")
            attacker_token = await _authenticate(attacker_device, mode)
            r = await a4_ato_new_device.run(url, cell, attacker_token, attacker_device,
                                            num_attempts=repetitions, out_dir=out_dir,
                                            oracle_tag=oracle_tag)
            summary.append(r.to_dict())
            print(f"  A4: {r.successes}/{r.attempts} succeeded, detected={r.detected}")

        # ── A5: BOLA/BFLA against a real object owned by another user ────────
        if "A5" in selected:
            device, access_token, own_account = await _prepare(url, mode)
            r = await a5_bola_bfla.run(url, cell, access_token, device,
                                       victim_account_id=victim_account,
                                       victim_user_id=victim_user,
                                       num_attempts=repetitions, out_dir=out_dir,
                                       oracle_tag=oracle_tag)
            summary.append(r.to_dict())
            print(f"  A5: {r.successes}/{r.attempts} succeeded, detected={r.detected}")

        # ── A6: velocity abuse ───────────────────────────────────────────────
        if "A6" in selected:
            device, access_token, own_account = await _prepare(url, mode)
            r = await a6_velocity_abuse.run(url, cell, access_token, device,
                                            num_attempts=repetitions, out_dir=out_dir,
                                            oracle_tag=oracle_tag)
            summary.append(r.to_dict())
            print(f"  A6: {r.successes}/{r.attempts} succeeded, detected={r.detected}")

        # ── A7: paced ATO from a new device (adaptive adversary) ─────────────
        # A4 with the two transient signals removed: the adversary paces below
        # the call-rate rule and mimics the victim's self-reported context, so
        # the only evidence left is the one they cannot forge — a cnf.jkt this
        # subject has never used.  Not part of the default suite.
        if "A7" in selected:
            device, access_token, own_account = await _prepare(url, mode)
            attacker_device = Device(device_id="attacker_a7")
            attacker_token = await _authenticate(attacker_device, mode)
            r = await a7_paced_ato.run(
                url, cell, attacker_token, attacker_device,
                mimic_session_id=device.device_id,
                mimic_geo=device.geo,
                mimic_source_ip=device.source_ip,
                mimic_device_fp=device.device_fp,
                num_attempts=repetitions, out_dir=out_dir,
                oracle_tag=oracle_tag, pace_seconds=pace_seconds)
            summary.append(r.to_dict())
            print(f"  A7: {r.successes}/{r.attempts} succeeded, detected={r.detected}")

    # Append to the shared summary (the Makefile invokes this once per cell,
    # restarting the ZT Controller with different flags between calls — each
    # cell's results must accumulate, not overwrite the prior cell's).
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
             "configuration at a time, so the Makefile calls this once per "
             "cell, restarting the controller in between.",
    )
    parser.add_argument(
        "--label", default="",
        help="Name for this experiment cell in the results (defaults to the "
             "mode). Use it to distinguish ablations that share ZT_MODE=P, "
             "e.g. --modes P --label P-minus-velocity.",
    )
    parser.add_argument(
        "--only", default="",
        help="Comma-separated attack ids to run (default: A1-A6, the primary "
             "taxonomy). Use --only A7 for the adaptive-adversary measurement, "
             "which writes to its own output directory and run label.",
    )
    parser.add_argument(
        "--pace-seconds", type=float, default=a7_paced_ato.PACE_SECONDS,
        help="A7 only: seconds between the adaptive adversary's requests. The "
             "sliding call-rate window is shared with the warm-up that "
             "establishes the victim's baseline, so a pace just under the "
             "threshold still trips it transiently; this exposes the pace so "
             "that effect can be measured rather than assumed.",
    )
    parser.add_argument(
        "--oracle-tag", action="store_true",
        help="Send x-attack-context:true on every attack request, enabling "
             "risk rule R7. This is an ORACLE (the adversary declares itself) "
             "and measures a detection ceiling, not detection. Off by default; "
             "never used for the paper's primary numbers.",
    )
    args = parser.parse_args()

    all_urls = {
        "B0": args.controller_b0,
        "B1": args.controller_b1,
        "P": args.controller_p,
    }
    modes = [m.strip().upper() for m in args.modes.split(",") if m.strip()]
    urls = {m: all_urls[m] for m in modes}
    if args.label and len(modes) > 1:
        parser.error("--label applies to a single cell; pass one mode")
    only = [a.strip().upper() for a in args.only.split(",") if a.strip()] or None
    asyncio.run(run_all(urls, args.out_dir, args.repetitions,
                        label=args.label, oracle_tag=args.oracle_tag, only=only,
                        pace_seconds=args.pace_seconds))


if __name__ == "__main__":
    main()

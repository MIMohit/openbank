"""
A4 — ATO from a new device.
Attacker has valid credentials and enrolls a DIFFERENT device.
B1 issues a valid DPoP-bound token for the attacker's own key —
so B1 cannot stop authenticated misuse from a foreign device/geo/fingerprint.
Only P detects device/geo/velocity mismatch → CHALLENGE/DENY.

Expected:
  B0: vulnerable
  B1: vulnerable (new key is valid DPoP; B1 checks pass)
  P:  detected — device fp / geo mismatch → risk elevation → CHALLENGE/DENY
"""
import asyncio
import time

import httpx

from attacks.base import AttackResult, write_attack_result
from client_sim.device import Device

ATTACK_ID = "A4"


async def run(
    controller_url: str,
    config: str,
    attacker_access_token: str,
    attacker_device: Device,
    victim_geo: str = "AU",
    num_attempts: int = 30,
    out_dir: str = "data/raw/attacks",
) -> AttackResult:
    """
    Attacker has their own valid token (enrolled new device).
    Requests come from a different geo/IP/fingerprint than the legitimate user.
    """
    result = AttackResult(attack_id=ATTACK_ID, config=config)
    t_start = time.perf_counter()

    async with httpx.AsyncClient(base_url=controller_url, timeout=5) as client:
        for _ in range(num_attempts):
            result.attempts += 1
            path = "/accounts"
            full_url = f"{controller_url}{path}"

            headers = {
                "Authorization": f"Bearer {attacker_access_token}",
                "x-attack-id": ATTACK_ID,
                "x-attack-context": "true",
            }
            # Attacker device has different geo/IP/fingerprint
            ctx = attacker_device.context_headers(
                geo="RU",          # geographically inconsistent with enrolled history
                source_ip="5.6.7.8",
            )
            headers.update(ctx)
            headers["DPoP"] = attacker_device.sign_dpop_proof(
                method="GET",
                url=full_url,
                access_token=attacker_access_token,
            )

            try:
                resp = await client.get(path, headers=headers)
                if resp.status_code == 200:
                    result.successes += 1
                else:
                    if not result.detected:
                        result.detected = True
                        result.time_to_detect_ms = (time.perf_counter() - t_start) * 1000
                        result.blocked_at_stage = _infer_stage(resp)
                result.raw_responses.append({"status": resp.status_code})
            except Exception as exc:
                result.notes += f"error: {exc}; "

    write_attack_result(result, out_dir)
    return result


def _infer_stage(resp) -> str:
    body = resp.text.lower()
    if "step_up" in body or "challenge" in body:
        return "policy:CHALLENGE"
    if resp.status_code == 403:
        return "policy:DENY"
    if resp.status_code == 401:
        return "dpop_verify"
    return "unknown"

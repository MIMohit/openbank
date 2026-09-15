"""
A6 — High-velocity abuse / consent over-use.
Valid session issues abnormally high request volume.

Expected:
  B0/B1: vulnerable (no velocity rule)
  P:     throttled/denied (velocity rule in risk scorer + OPA)
"""
import asyncio
import time

import httpx

from attacks.base import AttackResult, write_attack_result
from client_sim.device import Device

ATTACK_ID = "A6"
BURST = 60  # requests fired in rapid succession


async def run(
    controller_url: str,
    config: str,
    access_token: str,
    device: Device,
    num_attempts: int = 60,
    out_dir: str = "data/raw/attacks",
) -> AttackResult:
    result = AttackResult(attack_id=ATTACK_ID, config=config)
    t_start = time.perf_counter()

    async with httpx.AsyncClient(base_url=controller_url, timeout=5) as client:
        for _ in range(num_attempts):
            result.attempts += 1
            path = "/accounts"
            full_url = f"{controller_url}{path}"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "x-attack-id": ATTACK_ID,
                "x-attack-context": "false",  # legitimate key — only rate is anomalous
            }
            headers.update(device.context_headers())
            headers["DPoP"] = device.sign_dpop_proof(
                method="GET",
                url=full_url,
                access_token=access_token,
            )

            try:
                resp = await client.get(path, headers=headers)
                if resp.status_code == 200:
                    result.successes += 1
                else:
                    if not result.detected:
                        result.detected = True
                        result.time_to_detect_ms = (time.perf_counter() - t_start) * 1000
                        result.blocked_at_stage = "policy:velocity"
                result.raw_responses.append({"status": resp.status_code})
            except Exception as exc:
                result.notes += f"error: {exc}; "
            # No sleep — deliberate burst

    write_attack_result(result, out_dir)
    return result

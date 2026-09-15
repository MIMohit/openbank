"""
A5 — BOLA / BFLA.
Authenticated user requests another user's account/transaction object.
Object-level ownership checks in the mock API (and controller) should block.

Expected: 403 across all configs (ownership enforced at resource server).
"""
import asyncio
import time

import httpx

from attacks.base import AttackResult, write_attack_result
from client_sim.device import Device

ATTACK_ID = "A5"


async def run(
    controller_url: str,
    config: str,
    attacker_token: str,
    attacker_device: Device,
    victim_account_id: str,
    victim_user_id: str,
    num_attempts: int = 30,
    out_dir: str = "data/raw/attacks",
) -> AttackResult:
    result = AttackResult(attack_id=ATTACK_ID, config=config)
    t_start = time.perf_counter()

    async with httpx.AsyncClient(base_url=controller_url, timeout=5) as client:
        for _ in range(num_attempts):
            result.attempts += 1
            # BOLA: request victim's account
            path = f"/accounts/{victim_account_id}"
            full_url = f"{controller_url}{path}"
            headers = {
                "Authorization": f"Bearer {attacker_token}",
                "x-attack-id": ATTACK_ID,
                "x-attack-context": "true",
            }
            headers.update(attacker_device.context_headers())
            headers["DPoP"] = attacker_device.sign_dpop_proof(
                method="GET",
                url=full_url,
                access_token=attacker_token,
            )

            try:
                resp = await client.get(path, headers=headers)
                if resp.status_code == 200:
                    result.successes += 1
                else:
                    if not result.detected:
                        result.detected = True
                        result.time_to_detect_ms = (time.perf_counter() - t_start) * 1000
                        result.blocked_at_stage = "resource_server:ownership"
                result.raw_responses.append({"status": resp.status_code})
            except Exception as exc:
                result.notes += f"error: {exc}; "

    write_attack_result(result, out_dir)
    return result

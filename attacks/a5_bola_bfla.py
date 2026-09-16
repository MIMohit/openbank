"""
A5 — BOLA / BFLA.

An authenticated user requests another user's objects.  Object-level ownership
checks at the resource server (and the controller's policy) should refuse.

The victim object must actually exist, or the measurement is vacuous: the
attack previously targeted the literal id "acct_other_user", which no synthetic
account carries, so every attempt returned 404 "Account not found" and was
scored as "blocked" without any ownership check ever running.  The runner now
derives a real account id belonging to a different synthetic user (see
`victim_object_ids` in attacks/runner.py) so a refusal is a 403 from the
ownership check.

Expected: refused across all configs (ownership enforced at the resource
server, independently of the enforcement layer under test).
"""
import asyncio
import time

import httpx

from attacks.base import AttackResult, attack_headers, write_attack_result
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
    oracle_tag: bool = False,
) -> AttackResult:
    result = AttackResult(attack_id=ATTACK_ID, config=config, oracle_tag=oracle_tag)
    t_start = time.perf_counter()

    # Alternate between the victim's account object and its transaction
    # collection — both are ownership-checked on a different code path.
    target_paths = [
        f"/accounts/{victim_account_id}",
        f"/transactions?account_id={victim_account_id}",
    ]

    async with httpx.AsyncClient(base_url=controller_url, timeout=5) as client:
        for idx in range(num_attempts):
            result.attempts += 1
            path = target_paths[idx % len(target_paths)]
            full_url = f"{controller_url}{path}"

            headers = {"Authorization": f"Bearer {attacker_token}"}
            headers.update(attack_headers(ATTACK_ID, oracle_tag))
            headers.update(attacker_device.context_headers())
            if config != "B0":
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
    if "access_denied" in body:
        return "policy:DENY"
    if resp.status_code == 403:
        return "resource_server:ownership"
    if resp.status_code == 404:
        # The object does not exist — the ownership check never ran.
        return "resource_server:not_found"
    if resp.status_code == 401:
        return "dpop_verify"
    return "unknown"

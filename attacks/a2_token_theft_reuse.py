"""
A2 — Token theft without key (browser-storage exfiltration).
Attacker has the access token but NOT the device private key.
Attempts to call the API without a valid DPoP proof (or with a fresh key
that doesn't match cnf.jkt).

Expected:
  B0: vulnerable (no DPoP)
  B1: blocked (cannot produce matching DPoP / cnf.jkt mismatch)
  P:  blocked (same + risk policy)
"""
import asyncio
import time

import httpx

from attacks.base import AttackResult, attack_headers, write_attack_result
from client_sim.device import Device

ATTACK_ID = "A2"


async def run(
    controller_url: str,
    config: str,
    stolen_access_token: str,
    target_path: str = "/accounts",
    num_attempts: int = 30,
    out_dir: str = "data/raw/attacks",
    oracle_tag: bool = False,
) -> AttackResult:
    """
    Attempt to use stolen_access_token from a fresh device (different keypair).
    In B0 mode the token has no cnf.jkt so no DPoP is needed.
    In B1/P mode, a new device's DPoP proof will fail cnf.jkt check.
    """
    result = AttackResult(attack_id=ATTACK_ID, config=config, oracle_tag=oracle_tag)
    attacker_device = Device(device_id="attacker_a2", geo="CN", source_ip="1.2.3.4")
    t_start = time.perf_counter()

    async with httpx.AsyncClient(base_url=controller_url, timeout=5) as client:
        for _ in range(num_attempts):
            result.attempts += 1
            headers = {"Authorization": f"Bearer {stolen_access_token}"}
            headers.update(attack_headers(ATTACK_ID, oracle_tag))
            headers.update(attacker_device.context_headers())

            # Attacker signs a fresh DPoP proof with THEIR key (won't match cnf.jkt)
            if config != "B0":
                dpop = attacker_device.sign_dpop_proof(
                    method="GET",
                    url=f"{controller_url}{target_path}",
                    access_token=stolen_access_token,
                )
                headers["DPoP"] = dpop

            try:
                resp = await client.get(target_path, headers=headers)
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
    if "jkt" in body or "binding" in body or "dpop" in body:
        return "dpop_verify"
    if resp.status_code == 401:
        return "token_verify"
    if resp.status_code == 403:
        return "policy"
    return "unknown"

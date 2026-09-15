"""
A3 — Device-resident key abuse / session-riding.
Attacker operates ON the legitimate device and CAN invoke the signing key,
but exhibits anomalous behavior: abnormal call-rate, endpoint mix, timing.

This is the CRUX ATTACK (H2).  DPoP proofs are cryptographically valid!

Expected:
  B0: vulnerable
  B1: vulnerable (valid DPoP passes all B1 checks)
  P:  detected/blocked via telemetry + velocity + risk → CHALLENGE/DENY
"""
from __future__ import annotations

import asyncio
import time

import httpx

from attacks.base import AttackResult, write_attack_result
from client_sim.device import Device

ATTACK_ID = "A3"

# Burst rate that should trigger velocity rule in P mode
BURST_REQUESTS = 50
BURST_INTERVAL_S = 2.0   # 50 requests in 2 seconds = 1500 req/min → triggers rule


async def run(
    controller_url: str,
    config: str,
    access_token: str,
    legitimate_device: Device,
    target_paths: list | None = None,
    num_attempts: int = 30,
    out_dir: str = "data/raw/attacks",
) -> AttackResult:
    """
    Simulates session-riding: attacker uses the legitimate device's key
    but drives abnormal call patterns (burst + mixed endpoint access).
    """
    result = AttackResult(attack_id=ATTACK_ID, config=config)
    if target_paths is None:
        target_paths = ["/accounts", "/transactions?account_id=acct_test"]
    t_start = time.perf_counter()

    async with httpx.AsyncClient(base_url=controller_url, timeout=5) as client:
        for attempt_idx in range(num_attempts):
            result.attempts += 1
            path = target_paths[attempt_idx % len(target_paths)]
            full_url = f"{controller_url}{path}"

            headers = {
                "Authorization": f"Bearer {access_token}",
                "x-attack-id": ATTACK_ID,
                "x-attack-context": "true",
            }
            # Legitimate device context (key is valid) — telemetry sees abnormal rate
            headers.update(legitimate_device.context_headers())
            headers["DPoP"] = legitimate_device.sign_dpop_proof(
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
                        result.blocked_at_stage = _infer_stage(resp)
                result.raw_responses.append({
                    "status": resp.status_code,
                    "decision": _extract_decision(resp),
                })
            except Exception as exc:
                result.notes += f"error: {exc}; "

            # No sleep — intentional burst to trigger velocity rule

    write_attack_result(result, out_dir)
    return result


def _infer_stage(resp) -> str:
    body = resp.text.lower()
    if "step_up" in body or "challenge" in body:
        return "policy:CHALLENGE"
    if "access_denied" in body or resp.status_code == 403:
        return "policy:DENY"
    if resp.status_code == 401:
        return "token_verify"
    return "unknown"


def _extract_decision(resp) -> str:
    try:
        return resp.json().get("error", "unknown")
    except Exception:
        return str(resp.status_code)

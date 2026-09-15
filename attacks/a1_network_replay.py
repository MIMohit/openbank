"""
A1 — Network token replay.
Captures a valid request (token + DPoP proof) and resends it verbatim.

Expected:
  B0: vulnerable (no replay protection)
  B1: blocked (jti replay cache + iat skew)
  P:  blocked (same as B1, plus risk flags)
"""
import asyncio
import time

import httpx

from attacks.base import AttackResult, write_attack_result

ATTACK_ID = "A1"


async def run(
    controller_url: str,
    config: str,
    captured_headers: dict,
    target_path: str = "/accounts",
    num_attempts: int = 30,
    out_dir: str = "data/raw/attacks",
) -> AttackResult:
    """
    Replay `captured_headers` (which include a valid Authorization + DPoP
    from a prior legitimate request) `num_attempts` times.
    """
    result = AttackResult(attack_id=ATTACK_ID, config=config)
    t_start = time.perf_counter()

    replay_headers = dict(captured_headers)
    replay_headers["x-attack-id"] = ATTACK_ID
    replay_headers["x-attack-context"] = "true"

    async with httpx.AsyncClient(base_url=controller_url, timeout=5) as client:
        for _ in range(num_attempts):
            result.attempts += 1
            try:
                resp = await client.get(target_path, headers=replay_headers)
                if resp.status_code == 200:
                    result.successes += 1
                else:
                    if not result.detected:
                        result.detected = True
                        result.time_to_detect_ms = (time.perf_counter() - t_start) * 1000
                        result.blocked_at_stage = _infer_stage(resp)
                result.raw_responses.append({
                    "status": resp.status_code,
                    "body": resp.text[:200],
                })
            except Exception as exc:
                result.notes += f"request_error: {exc}; "

    write_attack_result(result, out_dir)
    return result


def _infer_stage(resp) -> str:
    body = resp.text.lower()
    if "replay" in body or "jti" in body:
        return "dpop_verify"
    if "401" in str(resp.status_code):
        return "token_verify"
    if "403" in str(resp.status_code):
        return "policy"
    return "unknown"

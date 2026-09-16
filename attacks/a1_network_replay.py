"""
A1 — Network token replay.
Captures a valid request (token + DPoP proof) and resends it verbatim.

The captured request is one the victim actually made, so the proof's `jti` has
already been consumed by the time the adversary replays it: `run()` therefore
issues the original request once (uncounted) before replaying it.  Counting the
first replay as an attempt, as this used to, credited the adversary with one
"success" per run that is really just the victim's own legitimate call.

Expected:
  B0: vulnerable (no replay protection)
  B1: blocked (jti replay cache + iat skew)
  P:  blocked (same as B1)
"""
import asyncio
import time

import httpx

from attacks.base import AttackResult, attack_headers, write_attack_result

ATTACK_ID = "A1"


async def run(
    controller_url: str,
    config: str,
    captured_headers: dict,
    target_path: str = "/accounts",
    num_attempts: int = 30,
    out_dir: str = "data/raw/attacks",
    oracle_tag: bool = False,
) -> AttackResult:
    """
    Replay `captured_headers` (which include a valid Authorization + DPoP
    from a prior legitimate request) `num_attempts` times.
    """
    result = AttackResult(attack_id=ATTACK_ID, config=config, oracle_tag=oracle_tag)

    replay_headers = dict(captured_headers)
    replay_headers.update(attack_headers(ATTACK_ID, oracle_tag))

    async with httpx.AsyncClient(base_url=controller_url, timeout=5) as client:
        # The victim's own use of the captured request (not an attack attempt).
        original = dict(captured_headers)
        original["x-context-profile"] = "warmup"
        try:
            await client.get(target_path, headers=original)
        except Exception as exc:
            result.notes += f"capture_error: {exc}; "

        t_start = time.perf_counter()
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
    if resp.status_code == 401:
        return "token_verify"
    if resp.status_code == 403:
        return "policy"
    return "unknown"

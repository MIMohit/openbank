"""
A4 — Account takeover from a new device.

The adversary has the victim's credentials and enrols their OWN device: they
run the token flow themselves, so Keycloak issues them a genuine access token
whose `cnf.jkt` is the thumbprint of *their* key, and every DPoP proof they
sign matches it.  Nothing at the FAPI 2.0 layer is out of place — this is the
regime where sender-constraining is silent by construction.

This is the fix for a scenario bug: the attack previously reused the *victim's*
access token while signing with a different key, which is a `cnf.jkt` mismatch
and therefore just a second copy of A2.  It made B1 look like it stopped A4
(401 at DPoP verification) when the paper's own claim — and the reason the
attack exists — is that B1 cannot.

`attacker_access_token` must therefore be a token the attacker obtained in
their own right (see `setup_attacker_session` in attacks/runner.py), bound to
`attacker_device`'s key.

Expected:
  B0: vulnerable
  B1: vulnerable (the new key is a valid DPoP binding; every B1 check passes)
  P:  detected — the subject is presenting a device key it has never used,
      from a geo inconsistent with its history → risk elevation → CHALLENGE/DENY
"""
import asyncio
import time

import httpx

from attacks.base import AttackResult, attack_headers, write_attack_result
from client_sim.device import Device

ATTACK_ID = "A4"


async def run(
    controller_url: str,
    config: str,
    attacker_access_token: str,
    attacker_device: Device,
    attacker_geo: str = "RU",
    attacker_ip: str = "5.6.7.8",
    num_attempts: int = 30,
    out_dir: str = "data/raw/attacks",
    oracle_tag: bool = False,
) -> AttackResult:
    """
    Attacker holds their own valid, DPoP-bound token for the victim's account.
    Requests come from a different device key, IP and geo than the victim's
    enrolled device.
    """
    result = AttackResult(attack_id=ATTACK_ID, config=config, oracle_tag=oracle_tag)
    t_start = time.perf_counter()

    async with httpx.AsyncClient(base_url=controller_url, timeout=5) as client:
        for _ in range(num_attempts):
            result.attempts += 1
            path = "/accounts"
            full_url = f"{controller_url}{path}"

            headers = {"Authorization": f"Bearer {attacker_access_token}"}
            headers.update(attack_headers(ATTACK_ID, oracle_tag))
            headers.update(attacker_device.context_headers(
                geo=attacker_geo,
                source_ip=attacker_ip,
            ))
            if config != "B0":
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

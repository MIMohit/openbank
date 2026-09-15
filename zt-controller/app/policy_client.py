"""
Stage 5: Policy decision via OPA.

Sends the current risk score and context to OPA's zt.rego policy.
Returns ALLOW | CHALLENGE | DENY.

Falls back to a local threshold check if OPA is unreachable (fail-safe: DENY).
"""
import logging

import httpx

from app import config

logger = logging.getLogger(__name__)

OPA_POLICY_URL = f"{config.OPA_URL}/v1/data/zt/decision"


async def decide(risk: float, telemetry: dict, checks: dict) -> str:
    """
    Query OPA for ALLOW/CHALLENGE/DENY.
    Returns the decision string.
    """
    input_doc = {
        "input": {
            "risk": risk,
            "telemetry": telemetry,
            "checks": checks,
            "thresholds": {
                "allow": config.RISK_THRESHOLD_ALLOW,
                "deny": config.RISK_THRESHOLD_DENY,
            },
        }
    }
    try:
        async with httpx.AsyncClient(timeout=2) as client:
            resp = await client.post(OPA_POLICY_URL, json=input_doc)
            resp.raise_for_status()
            result = resp.json()
            decision = result.get("result", {}).get("action", "DENY")
            return decision.upper()
    except Exception as exc:
        logger.error({"event": "opa_unreachable", "error": str(exc)})
        # Fail-safe: deny when policy engine is unreachable
        return "DENY"


def decide_local(risk: float) -> str:
    """Local fallback: threshold-based decision (no OPA)."""
    if risk < config.RISK_THRESHOLD_ALLOW:
        return "ALLOW"
    if risk < config.RISK_THRESHOLD_DENY:
        return "CHALLENGE"
    return "DENY"

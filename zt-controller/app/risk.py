"""
Stage 4: Rule-based risk scoring.

Produces a belief value b_t ∈ [0,1] — probability the session is legitimate.
risk = 1 - b_t.

Design: deterministic, auditable rules.  No ML.  Each rule contributes a
penalty to the risk score.  Penalties are additive (capped at 1.0).

Rules:
  R1: DPoP fingerprint mismatch (device key ≠ cnf.jkt) — severe
  R2: Device fingerprint changed — high
  R3: Geo velocity > 500 km/h (physically impossible) — high
  R4: Call rate > threshold (velocity/abuse) — medium
  R5: Session continuity low — medium
  R6: DPoP failure rate elevated — medium
  R7: Known attack context (injected by attack suite) — severe
"""
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Penalty weights (tunable)
PENALTY = {
    "cnf_jkt_mismatch": 0.80,   # R1: key doesn't match — almost certainly adversarial
    "device_fp_changed": 0.35,  # R2: fingerprint change — possible device change
    "impossible_velocity": 0.60, # R3: physical impossibility
    "high_call_rate": 0.25,     # R4: velocity abuse
    "low_session_continuity": 0.20,  # R5: session discontinuity
    "dpop_failure_elevated": 0.20,   # R6: repeated DPoP failures
    "attack_context": 0.90,     # R7: attack simulator flag
}

# Thresholds for triggering rules
CALL_RATE_THRESHOLD = 30.0          # requests/minute
VELOCITY_THRESHOLD_KMH = 500.0      # km/h
MIN_SESSION_CONTINUITY = 0.50
DPOP_FAILURE_THRESHOLD = 0.10       # 10% of requests


def score(
    telemetry: dict,
    checks: dict,
    attack_context: bool = False,
) -> dict:
    """
    Compute risk score and return detailed components.

    Args:
        telemetry: output of telemetry.collect()
        checks: dict with token/dpop check outcomes
        attack_context: injected by attack suite to signal adversarial intent

    Returns:
        {"belief_b": float, "risk": float, "score_components": dict}
    """
    penalties = {}
    components = {}

    # R1: cnf.jkt mismatch (already rejected upstream in B1/P, but defensive scoring)
    if not checks.get("cnf_jkt_match", True):
        penalties["cnf_jkt_mismatch"] = PENALTY["cnf_jkt_mismatch"]
        components["cnf_jkt_mismatch"] = True

    # R2: device fingerprint unstable
    if not telemetry.get("device_fp_stable", True):
        penalties["device_fp_changed"] = PENALTY["device_fp_changed"]
        components["device_fp_changed"] = True

    # R3: impossible geo velocity
    geo_vel = telemetry.get("geo_velocity", 0.0)
    if geo_vel > VELOCITY_THRESHOLD_KMH:
        penalties["impossible_velocity"] = PENALTY["impossible_velocity"]
        components["impossible_velocity"] = round(geo_vel, 1)

    # R4: high call rate (velocity abuse)
    call_rate = telemetry.get("call_rate", 0.0)
    if call_rate > CALL_RATE_THRESHOLD:
        penalties["high_call_rate"] = PENALTY["high_call_rate"]
        components["high_call_rate"] = round(call_rate, 2)

    # R5: session continuity
    continuity = telemetry.get("session_continuity", 1.0)
    if continuity < MIN_SESSION_CONTINUITY:
        penalties["low_session_continuity"] = PENALTY["low_session_continuity"]
        components["low_session_continuity"] = round(continuity, 3)

    # R6: DPoP failure rate elevated
    dpop_fail_rate = telemetry.get("dpop_failure_rate", 0.0)
    if dpop_fail_rate > DPOP_FAILURE_THRESHOLD:
        penalties["dpop_failure_elevated"] = PENALTY["dpop_failure_elevated"]
        components["dpop_failure_elevated"] = round(dpop_fail_rate, 3)

    # R7: attack context
    if attack_context:
        penalties["attack_context"] = PENALTY["attack_context"]
        components["attack_context"] = True

    total_risk = min(1.0, sum(penalties.values()))
    belief_b = round(1.0 - total_risk, 4)
    risk = round(total_risk, 4)

    logger.debug({"event": "risk_score", "risk": risk, "components": components})
    return {
        "belief_b": belief_b,
        "risk": risk,
        "score_components": components,
    }

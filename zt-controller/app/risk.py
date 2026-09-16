"""
Stage 4: Rule-based risk scoring.

Produces a belief value b_t in [0,1] — the controller's belief that the session
is legitimate.  risk = 1 - b_t.

Design: deterministic, auditable rules.  No ML.  Each rule contributes a
penalty to the risk score.  Penalties are additive (capped at 1.0).

Rules, grouped by the enforcement component they belong to.  The grouping is
what makes the §7.4 ablation meaningful: each ablation flag removes exactly one
group, so an observed change in attack success or false-challenge rate is
attributable to that component.

  device-binding (ZT_CHECK_DEVICE_BINDING)
    R1: DPoP key does not match the token's cnf.jkt                  — severe
    R2: subject is using a device key / fingerprint it has not used  — high
  context / telemetry PIP (ZT_ENABLE_TELEMETRY)
    R3: geo velocity above a physically implausible threshold        — high
    R5: session continuity low                                       — medium
    R6: DPoP failure rate elevated                                   — medium
  velocity (ZT_ENABLE_VELOCITY, a sub-component of the telemetry PIP)
    R4: call rate above threshold                                    — medium

  R7 (oracle, NOT part of P): a request that self-declares as an attack via the
    `x-attack-context` header.  See ORACLE_ATTACK_CONTEXT below.

ORACLE_ATTACK_CONTEXT.  R7 exists only so the testbed can measure a detection
*ceiling*: what the enforcement pipeline would do if it were handed a perfect
oracle telling it which requests are adversarial.  It is not a detector — the
signal is supplied by the adversary itself — and it is therefore disabled by
default and never active in the primary measurement.  The attack suite does not
send the header unless explicitly run in oracle mode
(`attacks.runner --oracle-tag`), and the controller ignores it unless
ZT_ORACLE_ATTACK_CONTEXT=true.  Reporting P's blocking rate with R7 active as
though it were organic detection would make the paper's central claim an
artifact of the attack simulator, so the two measurements are kept separate and
labelled.
"""
import logging
from typing import Optional

from app import config

logger = logging.getLogger(__name__)

# Penalty weights (tunable)
PENALTY = {
    "cnf_jkt_mismatch": 0.80,   # R1: key doesn't match — almost certainly adversarial
    "device_fp_changed": 0.35,  # R2: unknown device key/fingerprint for this subject
    "impossible_velocity": 0.60, # R3: physical impossibility
    "high_call_rate": 0.25,     # R4: velocity abuse
    "low_session_continuity": 0.20,  # R5: session discontinuity
    "dpop_failure_elevated": 0.20,   # R6: repeated DPoP failures
    "attack_context": 0.90,     # R7: oracle only — see module docstring
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
    device_signals: Optional[dict] = None,
) -> dict:
    """
    Compute risk score and return detailed components.

    Args:
        telemetry: output of telemetry.collect()
        checks: dict with token/dpop check outcomes
        device_signals: output of device_registry.observe()
        attack_context: oracle flag; only honoured when
            config.ORACLE_ATTACK_CONTEXT is enabled (off by default)

    Returns:
        {"belief_b": float, "risk": float, "score_components": dict}
    """
    penalties = {}
    components = {}
    device_signals = device_signals or {}

    # ── device-binding group ────────────────────────────────────────────────
    if config.CHECK_DEVICE_BINDING:
        # R1: cnf.jkt mismatch (already rejected upstream in B1/P, but the
        # request still reaches here when binding enforcement is ablated)
        if not checks.get("cnf_jkt_match", True):
            penalties["cnf_jkt_mismatch"] = PENALTY["cnf_jkt_mismatch"]
            components["cnf_jkt_mismatch"] = True

        # R2: subject presenting a device key or fingerprint it has not used
        device_known = device_signals.get("device_known", True)
        fp_stable = telemetry.get("device_fp_stable", True)
        if not device_known or not fp_stable:
            penalties["device_fp_changed"] = PENALTY["device_fp_changed"]
            components["device_fp_changed"] = True
            components["device_known"] = device_known

    # ── context / telemetry group ───────────────────────────────────────────
    # R3: impossible geo velocity
    geo_vel = telemetry.get("geo_velocity", 0.0)
    if geo_vel > VELOCITY_THRESHOLD_KMH:
        penalties["impossible_velocity"] = PENALTY["impossible_velocity"]
        components["impossible_velocity"] = round(geo_vel, 1)

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

    # ── velocity group ──────────────────────────────────────────────────────
    if config.ENABLE_VELOCITY:
        call_rate = telemetry.get("call_rate", 0.0)
        if call_rate > CALL_RATE_THRESHOLD:
            penalties["high_call_rate"] = PENALTY["high_call_rate"]
            components["high_call_rate"] = round(call_rate, 2)

    # ── R7: oracle (off by default; never active in the primary measurement) ─
    if attack_context and config.ORACLE_ATTACK_CONTEXT:
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

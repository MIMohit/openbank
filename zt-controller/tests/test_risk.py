"""
Unit tests for the rule-based risk scorer.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

import os
os.environ.setdefault("ZT_MODE", "P")

from app import risk


CLEAN_TELEMETRY = {
    "device_fp_stable": True,
    "geo": "AU",
    "geo_velocity": 0.0,
    "call_rate": 1.0,
    "session_continuity": 1.0,
    "dpop_failure_rate": 0.0,
}

CLEAN_CHECKS = {
    "token_valid": True,
    "dpop_valid": True,
    "jti_replayed": False,
    "cnf_jkt_match": True,
}


def test_clean_session_low_risk():
    r = risk.score(CLEAN_TELEMETRY, CLEAN_CHECKS)
    assert r["risk"] < 0.1
    assert r["belief_b"] > 0.9


def test_device_fp_change_elevates_risk():
    telemetry = {**CLEAN_TELEMETRY, "device_fp_stable": False}
    r = risk.score(telemetry, CLEAN_CHECKS)
    assert r["risk"] >= risk.PENALTY["device_fp_changed"]
    assert "device_fp_changed" in r["score_components"]


def test_impossible_velocity_elevates_risk():
    telemetry = {**CLEAN_TELEMETRY, "geo_velocity": 2000.0}
    r = risk.score(telemetry, CLEAN_CHECKS)
    assert r["risk"] >= risk.PENALTY["impossible_velocity"]
    assert "impossible_velocity" in r["score_components"]


def test_high_call_rate_elevates_risk():
    telemetry = {**CLEAN_TELEMETRY, "call_rate": 50.0}
    r = risk.score(telemetry, CLEAN_CHECKS)
    assert r["risk"] >= risk.PENALTY["high_call_rate"]


def test_cnf_jkt_mismatch_elevates_risk():
    checks = {**CLEAN_CHECKS, "cnf_jkt_match": False}
    r = risk.score(CLEAN_TELEMETRY, checks)
    assert r["risk"] >= risk.PENALTY["cnf_jkt_mismatch"]


def test_attack_context_high_risk():
    r = risk.score(CLEAN_TELEMETRY, CLEAN_CHECKS, attack_context=True)
    assert r["risk"] >= risk.PENALTY["attack_context"]


def test_risk_capped_at_one():
    # Multiple severe penalties should not exceed 1.0
    telemetry = {
        **CLEAN_TELEMETRY,
        "device_fp_stable": False,
        "geo_velocity": 5000.0,
        "call_rate": 100.0,
    }
    checks = {**CLEAN_CHECKS, "cnf_jkt_match": False}
    r = risk.score(telemetry, checks, attack_context=True)
    assert r["risk"] <= 1.0
    assert r["belief_b"] >= 0.0

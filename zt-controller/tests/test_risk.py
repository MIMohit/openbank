"""
Unit tests for the rule-based risk scorer.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

import os
os.environ.setdefault("ZT_MODE", "P")

from app import config, risk


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


def test_unknown_device_key_elevates_risk():
    r = risk.score(CLEAN_TELEMETRY, CLEAN_CHECKS,
                   device_signals={"device_known": False})
    assert r["risk"] >= risk.PENALTY["device_fp_changed"]
    assert r["score_components"]["device_known"] is False


def test_attack_context_is_ignored_unless_oracle_enabled():
    """
    R7 is an oracle, not a detector: the adversary supplies the signal. It must
    be inert by default so it can never leak into a primary measurement.
    """
    assert config.ORACLE_ATTACK_CONTEXT is False
    r = risk.score(CLEAN_TELEMETRY, CLEAN_CHECKS, attack_context=True)
    assert r["risk"] == 0.0
    assert "attack_context" not in r["score_components"]


def test_attack_context_fires_when_oracle_enabled(monkeypatch):
    monkeypatch.setattr(config, "ORACLE_ATTACK_CONTEXT", True)
    r = risk.score(CLEAN_TELEMETRY, CLEAN_CHECKS, attack_context=True)
    assert r["risk"] >= risk.PENALTY["attack_context"]


def test_device_binding_ablation_removes_device_rules(monkeypatch):
    monkeypatch.setattr(config, "CHECK_DEVICE_BINDING", False)
    telemetry = {**CLEAN_TELEMETRY, "device_fp_stable": False}
    checks = {**CLEAN_CHECKS, "cnf_jkt_match": False}
    r = risk.score(telemetry, checks, device_signals={"device_known": False})
    assert r["risk"] == 0.0


def test_velocity_ablation_removes_call_rate_rule(monkeypatch):
    monkeypatch.setattr(config, "ENABLE_VELOCITY", False)
    r = risk.score({**CLEAN_TELEMETRY, "call_rate": 500.0}, CLEAN_CHECKS)
    assert r["risk"] == 0.0


def test_risk_capped_at_one():
    # Multiple severe penalties should not exceed 1.0
    telemetry = {
        **CLEAN_TELEMETRY,
        "device_fp_stable": False,
        "geo_velocity": 5000.0,
        "call_rate": 100.0,
    }
    checks = {**CLEAN_CHECKS, "cnf_jkt_match": False}
    r = risk.score(telemetry, checks)
    assert r["risk"] <= 1.0
    assert r["belief_b"] >= 0.0

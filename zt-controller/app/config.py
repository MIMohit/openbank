"""
Feature-flag configuration for the ZT Controller.
Reads from environment variables so B0/B1/P and all ablations are
reachable purely by config — no code changes required.
"""
import os


def _bool(key: str, default: str = "true") -> bool:
    return os.getenv(key, default).lower() in ("1", "true", "yes")


def _float(key: str, default: float) -> float:
    try:
        return float(os.getenv(key, str(default)))
    except ValueError:
        return default


def _int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, str(default)))
    except ValueError:
        return default


# ─── Operational mode ────────────────────────────────────────────────────────
# ZT_MODE=B0|B1|P  sets all flags coherently; individual flags can override.
ZT_MODE = os.getenv("ZT_MODE", "P").upper()

_MODES = {
    "B0": dict(
        ENFORCE_DPOP=False,
        CHECK_DEVICE_BINDING=False,
        ENABLE_TELEMETRY=False,
        ENABLE_RISK_POLICY=False,
        ENABLE_VELOCITY=False,
        PROXY_PASSTHROUGH=True,
    ),
    "B1": dict(
        ENFORCE_DPOP=True,
        CHECK_DEVICE_BINDING=True,
        ENABLE_TELEMETRY=False,
        ENABLE_RISK_POLICY=False,
        ENABLE_VELOCITY=False,
        PROXY_PASSTHROUGH=False,
    ),
    "P": dict(
        ENFORCE_DPOP=True,
        CHECK_DEVICE_BINDING=True,
        ENABLE_TELEMETRY=True,
        ENABLE_RISK_POLICY=True,
        ENABLE_VELOCITY=True,
        PROXY_PASSTHROUGH=False,
    ),
}

_defaults = _MODES.get(ZT_MODE, _MODES["P"])

ENFORCE_DPOP: bool = _bool("ZT_ENFORCE_DPOP", str(_defaults["ENFORCE_DPOP"]))
CHECK_DEVICE_BINDING: bool = _bool("ZT_CHECK_DEVICE_BINDING", str(_defaults["CHECK_DEVICE_BINDING"]))
ENABLE_TELEMETRY: bool = _bool("ZT_ENABLE_TELEMETRY", str(_defaults["ENABLE_TELEMETRY"]))
ENABLE_RISK_POLICY: bool = _bool("ZT_ENABLE_RISK_POLICY", str(_defaults["ENABLE_RISK_POLICY"]))
ENABLE_VELOCITY: bool = _bool("ZT_ENABLE_VELOCITY", str(_defaults["ENABLE_VELOCITY"]))
PROXY_PASSTHROUGH: bool = _bool("ZT_PROXY_PASSTHROUGH", str(_defaults["PROXY_PASSTHROUGH"]))

# ─── Risk thresholds ─────────────────────────────────────────────────────────
# risk < ALLOW_THRESHOLD → ALLOW
# ALLOW_THRESHOLD ≤ risk < DENY_THRESHOLD → CHALLENGE
# risk ≥ DENY_THRESHOLD → DENY
RISK_THRESHOLD_ALLOW: float = _float("ZT_RISK_THRESHOLD_ALLOW", 0.4)
RISK_THRESHOLD_DENY: float = _float("ZT_RISK_THRESHOLD_DENY", 0.7)

# ─── Token / DPoP settings ───────────────────────────────────────────────────
KEYCLOAK_URL: str = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
KC_REALM_FAPI2: str = os.getenv("KC_REALM_FAPI2", "openbanking-fapi2")
KC_REALM_B0: str = os.getenv("KC_REALM_B0", "openbanking-b0")
DPOP_SKEW_SECONDS: int = _int("DPOP_SKEW_SECONDS", 60)
JTI_CACHE_TTL_SECONDS: int = _int("JTI_CACHE_TTL_SECONDS", 120)

# ─── Upstream services ───────────────────────────────────────────────────────
OPA_URL: str = os.getenv("OPA_URL", "http://opa:8181")
MOCK_ADR_URL: str = os.getenv("MOCK_ADR_URL", "http://mock-adr-api:8000")
INTERNAL_SECRET: str = "zt-internal-only"

# ─── Data output ─────────────────────────────────────────────────────────────
DATA_DIR: str = os.getenv("DATA_DIR", "/app/data/raw")

LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()


def as_dict() -> dict:
    """Return all active flags (for JSONL record embedding)."""
    return {
        "mode": ZT_MODE,
        "ENFORCE_DPOP": ENFORCE_DPOP,
        "CHECK_DEVICE_BINDING": CHECK_DEVICE_BINDING,
        "ENABLE_TELEMETRY": ENABLE_TELEMETRY,
        "ENABLE_RISK_POLICY": ENABLE_RISK_POLICY,
        "ENABLE_VELOCITY": ENABLE_VELOCITY,
        "PROXY_PASSTHROUGH": PROXY_PASSTHROUGH,
    }

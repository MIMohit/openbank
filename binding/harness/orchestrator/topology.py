"""Topology YAML loading and validation (CONTRACT section 5)."""
import re
from pathlib import Path

import yaml

from gateways.common import GATEWAYS, IMAGES, PLACEMENTS, PROFILES

HARNESS = Path(__file__).resolve().parent.parent
FRAMEWORKS = ["fastapi", "express", "django", "go-chi", "spring", "aspnet", "rails", "laravel"]
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
STUB = "stub"


def _onoff(v, default="off") -> str:
    # PyYAML (YAML 1.1) parses bare on/off as booleans.
    if v is None:
        return default
    if isinstance(v, bool):
        return "on" if v else "off"
    v = str(v).strip().lower()
    if v not in ("on", "off"):
        raise ValueError(f"expected on|off, got {v!r}")
    return v


def load(path) -> dict:
    t = yaml.safe_load(Path(path).read_text())
    for k in ("id", "gateway", "profile", "placement", "framework", "host_port"):
        if k not in t:
            raise ValueError(f"{path}: missing key {k!r}")
    if not ID_RE.match(t["id"]):
        raise ValueError(f"{path}: id {t['id']!r} must match {ID_RE.pattern}")
    if t["gateway"] not in GATEWAYS:
        raise ValueError(f"{path}: unknown gateway {t['gateway']!r}")
    if t["profile"] not in PROFILES or t["placement"] not in PLACEMENTS:
        raise ValueError(f"{path}: bad profile/placement")
    t.setdefault("gateway_image", IMAGES[t["gateway"]])
    t.setdefault("executor_image", f"bh-exec-{t['framework']}:latest")
    t["override"] = _onoff(t.get("override"))
    v = t.get("verifier") or {}
    t["verifier"] = {
        "image": v.get("image", "bh-verifier:latest"),
        "canon": v.get("canon", "rfc3986"),
        "view_mac": _onoff(v.get("view_mac")),
        "view_mac_key": v.get("view_mac_key", "bh-test-view-mac-key"),
        "jti_cache": _onoff(v.get("jti_cache"), "on"),
        "iat_window": int(v.get("iat_window", 60)),
    }
    # Executor VERIFY_MODE follows placement unless set explicitly (e.g. origin-routed for D-A).
    default_vm = "origin-raw" if t["placement"] in ("origin", "both") else "off"
    t["verify_mode"] = t.get("verify_mode", default_vm)
    if t["verify_mode"] not in ("off", "origin-raw", "origin-routed"):
        raise ValueError(f"{path}: bad verify_mode")
    t["host_port"] = int(t["host_port"])
    return t


def dump(t: dict) -> str:
    return yaml.safe_dump(t, sort_keys=False, default_flow_style=None)

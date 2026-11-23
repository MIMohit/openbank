"""Shared constants for gateway renderers (W6).

Every gateway listens on :8000, routes /api/ to executor:8080 keeping the path,
and in placement edge|both calls the verifier on verifier:9100 through the
adapter of CONTRACT section 4.
"""
from pathlib import Path

GATEWAYS = ["envoy", "traefik", "nginx", "kong", "apisix", "haproxy"]
PROFILES = ["default", "recommended", "strict"]
PLACEMENTS = ["edge", "origin", "both"]

# Pinned images (exact tags; digests recorded in gateways/README.md and IMAGES.lock).
IMAGES = {
    "envoy": "envoyproxy/envoy:v1.39.6",
    "traefik": "traefik:v3.7.19",
    "nginx": "nginx:1.30.7-alpine",
    "kong": "kong:3.9.5",
    "apisix": "apache/apisix:3.21.0-debian",
    "haproxy": "haproxy:3.2.27",
}

GW_PORT = 8000
EXECUTOR = ("executor", 8080)
VERIFIER = ("verifier", 9100)

# "strict" profile, harness-defined deny list for gateways WITHOUT a native toggle
# for a class (nginx, kong, apisix, haproxy). Case-insensitive regexes over the RAW
# request path (target before '?'). They mirror what Envoy strict
# (path_with_escaped_slashes_action=REJECT_REQUEST) and Traefik strict
# (encodedCharacters.* = false) reject natively, plus raw dot-segments and empty
# segments. Documented in README "strict profile".
STRICT_DENY_PATH_REGEX = r"(%2f|%5c|%00|%3b|%25|%3f|%23|%2e|;|\\|/\./|/\.\./|/\.$|/\.\.$|//)"


def edge(placement: str) -> bool:
    return placement in ("edge", "both")


def check(profile: str, placement: str) -> None:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}")
    if placement not in PLACEMENTS:
        raise ValueError(f"unknown placement {placement!r}")


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)

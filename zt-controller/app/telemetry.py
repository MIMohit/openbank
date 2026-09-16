"""
Stage 3: Telemetry collection (the Policy Information Point).

Synthesizes behavioral signals from request metadata supplied by the client
simulator.  In the testbed these come from HTTP request headers injected by the
simulator; no external geo-IP service is called.

Keying.  All continuous-trust history is keyed on the *subject* — the `sub`
claim of the access token verified in stage 1 — and not on the client-supplied
`x-device-id` header.  Continuous authorization is a property of the account
under evaluation, and an adversary picks their own `x-device-id`; keying history
on it means every adversary starts with a clean, empty history and no
behavioral rule can ever fire.  `subject` falls back to `device_id` only when no
verified subject exists (B0 pass-through, which does no risk scoring anyway).

Signals collected:
  - device_fp_stable: the presented device fingerprint matches one this subject
    has been seen with (corroborating, header-derived; the authoritative
    device signal is device_registry's cnf.jkt check)
  - geo: declared geographic region
  - geo_velocity: km/h implied by consecutive requests (synthetic)
  - call_rate: requests/minute in the current sliding window
  - session_continuity: fraction of recent requests from this session
  - dpop_failure_rate: rolling DPoP failures for this subject
"""
import logging
import time
from collections import defaultdict, deque
from typing import Optional

logger = logging.getLogger(__name__)

# Per-subject sliding windows (in-memory; fine for a single-node testbed)
_WINDOW_SECONDS = 60
_subject_history: dict = defaultdict(lambda: deque(maxlen=5000))
_subject_fps: dict = defaultdict(set)      # subject -> fingerprints seen
_subject_dpop_failures: dict = defaultdict(int)
_subject_dpop_total: dict = defaultdict(int)


def reset() -> None:
    """Drop all telemetry history (harness control plane only)."""
    _subject_history.clear()
    _subject_fps.clear()
    _subject_dpop_failures.clear()
    _subject_dpop_total.clear()


def collect(
    subject: str,
    device_id: str,
    session_id: str,
    source_ip: str,
    geo: str,
    device_fp: str,
    request_ts: float,
    dpop_failed: bool = False,
) -> dict:
    """
    Record a request event and return telemetry signals.
    Called per request *before* risk scoring.
    """
    key = subject or device_id
    history = _subject_history[key]
    now = request_ts

    # Prune old events outside the window
    while history and now - history[0]["ts"] > _WINDOW_SECONDS:
        history.popleft()

    # Device fingerprint stability — as with the key registry, the first
    # fingerprint seen for a subject establishes the baseline and later
    # unknown fingerprints are reported without being auto-enrolled.
    seen_fps = _subject_fps[key]
    if not seen_fps:
        seen_fps.add(device_fp)
        device_fp_stable = True
    else:
        device_fp_stable = device_fp in seen_fps

    # Call rate (requests/minute in sliding window)
    call_rate = len(history) / (_WINDOW_SECONDS / 60.0)

    # Geo velocity (synthetic: any region change between consecutive requests
    # implies a 1000 km hop over the elapsed interval)
    last_geo = history[-1]["geo"] if history else geo
    geo_changed = last_geo != geo
    geo_velocity = 0.0
    if geo_changed and history:
        elapsed_h = (now - history[-1]["ts"]) / 3600.0
        geo_velocity = 1000.0 / max(elapsed_h, 0.001)  # synthetic 1000 km distance

    # Session continuity: fraction of recent events with same session_id
    if history:
        same_session = sum(1 for e in history if e.get("session_id") == session_id)
        session_continuity = same_session / len(history)
    else:
        session_continuity = 1.0

    # DPoP failure rate
    _subject_dpop_total[key] += 1
    if dpop_failed:
        _subject_dpop_failures[key] += 1
    total = _subject_dpop_total[key]
    dpop_failure_rate = _subject_dpop_failures[key] / total if total > 0 else 0.0

    # Record this event
    history.append({
        "ts": now,
        "geo": geo,
        "session_id": session_id,
        "ip": source_ip,
        "device_id": device_id,
    })

    signals = {
        "device_fp_stable": device_fp_stable,
        "geo": geo,
        "geo_velocity": round(geo_velocity, 1),
        "call_rate": round(call_rate, 2),
        "session_continuity": round(session_continuity, 3),
        "dpop_failure_rate": round(dpop_failure_rate, 3),
    }
    logger.debug({"event": "telemetry", "subject": key, **signals})
    return signals

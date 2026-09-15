"""
Stage 3: Telemetry collection.

Synthesizes behavioral signals from request metadata supplied by the client
simulator.  In the testbed these come from HTTP request headers injected by
the simulator; no external geo-IP service is called.

Signals collected:
  - device_fp_stable: fingerprint token matches last seen for this device
  - geo: declared geographic region
  - geo_velocity: km/h between consecutive requests (synthetic)
  - call_rate: requests/minute in the current sliding window
  - session_continuity: fraction of recent requests from this session/device
  - dpop_failure_rate: rolling DPoP failures for this device
"""
import logging
import time
from collections import defaultdict, deque
from typing import Optional

logger = logging.getLogger(__name__)

# Per-device sliding windows (in-memory; fine for a single-node testbed)
_WINDOW_SECONDS = 60
_device_history: dict = defaultdict(lambda: deque(maxlen=1000))
_device_fp_map: dict = {}          # device_id -> last fingerprint token
_device_dpop_failures: dict = defaultdict(int)
_device_dpop_total: dict = defaultdict(int)


def collect(
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
    history = _device_history[device_id]
    now = request_ts

    # Prune old events outside the window
    while history and now - history[0]["ts"] > _WINDOW_SECONDS:
        history.popleft()

    # Device fingerprint stability
    last_fp = _device_fp_map.get(device_id)
    device_fp_stable = (last_fp == device_fp) if last_fp else True
    _device_fp_map[device_id] = device_fp

    # Call rate (requests/minute in sliding window)
    call_rate = len(history) / (_WINDOW_SECONDS / 60.0)

    # Geo velocity (synthetic: simple check if geo changed)
    last_geo = history[-1]["geo"] if history else geo
    geo_changed = last_geo != geo
    # For testbed: assign synthetic velocity (km/h) — 0 if same geo, high if changed
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
    _device_dpop_total[device_id] += 1
    if dpop_failed:
        _device_dpop_failures[device_id] += 1
    total = _device_dpop_total[device_id]
    dpop_failure_rate = _device_dpop_failures[device_id] / total if total > 0 else 0.0

    # Record this event
    history.append({
        "ts": now,
        "geo": geo,
        "session_id": session_id,
        "ip": source_ip,
    })

    signals = {
        "device_fp_stable": device_fp_stable,
        "geo": geo,
        "geo_velocity": round(geo_velocity, 1),
        "call_rate": round(call_rate, 2),
        "session_continuity": round(session_continuity, 3),
        "dpop_failure_rate": round(dpop_failure_rate, 3),
    }
    logger.debug({"event": "telemetry", "device_id": device_id, **signals})
    return signals

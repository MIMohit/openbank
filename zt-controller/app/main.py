"""
Zero Trust Controller — FastAPI PEP+PDP reverse proxy.

Per-request pipeline (§7 of spec):
  1. token_verify   — AT signature / issuer / scope / exp / cnf.jkt
  2. dpop_verify    — JWS verify, jti replay, iat skew, ath, cnf.jkt
  3. telemetry      — device fp, geo, velocity, call-rate, session continuity
  4. risk           — rule-based score → belief b_t
  5. policy_client  — OPA ALLOW / CHALLENGE / DENY
  6. proxy          — forward to mock ADR API (only on ALLOW)

All stages are instrumented; every request emits one JSONL record (§14).
Mode (B0/B1/P) and all ablation flags are set by environment variables (config.py).
"""
from __future__ import annotations

import logging
import os
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from app import config, token_verify, dpop_verify, telemetry, risk, policy_client, proxy, jsonl_logger

LOG_LEVEL = config.LOG_LEVEL
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":%(message)s}',
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="ZT Controller",
    description="Zero Trust PEP+PDP reverse proxy for Open Banking testbed.",
    version="1.0.0",
)

# Active run_id (set per experiment run; default = process UUID)
_RUN_ID = os.getenv("ZT_RUN_ID", str(uuid.uuid4())[:8])

# Realm selection by mode
_REALM = config.KC_REALM_B0 if config.ZT_MODE == "B0" else config.KC_REALM_FAPI2


@app.get("/health")
async def health():
    return {"status": "ok", "mode": config.ZT_MODE, "flags": config.as_dict()}


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
)
async def handle_request(request: Request, path: str):
    """
    Central request handler — implements the full ZT pipeline.
    """
    t_start = time.perf_counter()
    latency: dict = {
        "token_verify": 0.0, "dpop_verify": 0.0, "telemetry": 0.0,
        "risk": 0.0, "policy": 0.0, "proxy": 0.0, "total": 0.0,
    }
    checks: dict = {
        "token_valid": False, "dpop_valid": False,
        "jti_replayed": False, "cnf_jkt_match": False,
    }
    risk_result: dict = {"belief_b": 1.0, "risk": 0.0, "score_components": {}}
    decision = "DENY"
    user_id = ""
    telemetry_signals: dict = {}
    attack_info: dict | None = None

    # ── Extract common request metadata ──────────────────────────────────────
    authorization = request.headers.get("authorization", "")
    dpop_header = request.headers.get("dpop", "")
    source_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    device_id = request.headers.get("x-device-id", "unknown")
    session_id = request.headers.get("x-session-id", "unknown")
    geo = request.headers.get("x-geo", "AU")
    device_fp = request.headers.get("x-device-fp", "")
    request_url = str(request.url)

    # Attack instrumentation headers (injected by the attack suite only)
    attack_id = request.headers.get("x-attack-id", "")
    attack_context = request.headers.get("x-attack-context", "false").lower() == "true"
    if attack_id:
        attack_info = {"is_attack": True, "attack_id": attack_id, "succeeded": None}

    request_info = {
        "method": request.method,
        "path": "/" + path,
        "user_id": user_id,
        "device_id": device_id,
    }

    # ── B0 PASS-THROUGH (no auth/policy) ─────────────────────────────────────
    if config.PROXY_PASSTHROUGH:
        # B0: minimal header validation only; forward directly
        # We still need a user_id to forward — extract from token if present
        try:
            if authorization.lower().startswith("bearer "):
                from jose import jwt as _jwt
                raw = authorization[7:]
                claims = _jwt.get_unverified_claims(raw)
                user_id = claims.get("sub", "unknown")
        except Exception:
            user_id = "unknown"
        t_proxy = time.perf_counter()
        try:
            response = await proxy.forward(request, user_id)
        except Exception as exc:
            logger.error({"event": "proxy_error", "error": str(exc)})
            response = JSONResponse({"detail": "Upstream unavailable"}, status_code=502)
        latency["proxy"] = round((time.perf_counter() - t_proxy) * 1000, 3)
        latency["total"] = round((time.perf_counter() - t_start) * 1000, 3)
        request_info["user_id"] = user_id
        _emit(request_info, {}, checks, risk_result, "ALLOW", latency, attack_info)
        return response

    # ── STAGE 1: Access-token verification ───────────────────────────────────
    t0 = time.perf_counter()
    try:
        claims = await token_verify.verify_access_token(
            authorization=authorization,
            realm=_REALM,
            required_scopes=None,
        )
        user_id = claims.get("sub", "")
        checks["token_valid"] = True
        cnf_jkt = claims.get("cnf", {}).get("jkt", "")
        checks["cnf_jkt_match"] = bool(cnf_jkt)
    except Exception as exc:
        latency["token_verify"] = round((time.perf_counter() - t0) * 1000, 3)
        latency["total"] = round((time.perf_counter() - t_start) * 1000, 3)
        _emit(request_info, {}, checks, risk_result, "DENY", latency, attack_info)
        raise exc
    latency["token_verify"] = round((time.perf_counter() - t0) * 1000, 3)
    request_info["user_id"] = user_id

    # ── STAGE 2: DPoP verification ────────────────────────────────────────────
    if config.ENFORCE_DPOP:
        t0 = time.perf_counter()
        raw_at = authorization[7:]
        try:
            dpop_payload = dpop_verify.verify_dpop_proof(
                dpop_header=dpop_header,
                method=request.method,
                url=request_url,
                raw_access_token=raw_at,
                cnf_jkt=cnf_jkt,
            )
            checks["dpop_valid"] = True
            checks["jti_replayed"] = False
        except Exception as exc:
            checks["dpop_valid"] = False
            if "replay" in str(exc).lower():
                checks["jti_replayed"] = True
            latency["dpop_verify"] = round((time.perf_counter() - t0) * 1000, 3)
            latency["total"] = round((time.perf_counter() - t_start) * 1000, 3)
            _emit(request_info, {}, checks, risk_result, "DENY", latency, attack_info)
            raise exc
        latency["dpop_verify"] = round((time.perf_counter() - t0) * 1000, 3)

    # ── STAGE 3: Telemetry ────────────────────────────────────────────────────
    if config.ENABLE_TELEMETRY:
        t0 = time.perf_counter()
        telemetry_signals = telemetry.collect(
            device_id=device_id,
            session_id=session_id,
            source_ip=source_ip,
            geo=geo,
            device_fp=device_fp,
            request_ts=time.time(),
        )
        latency["telemetry"] = round((time.perf_counter() - t0) * 1000, 3)
    else:
        telemetry_signals = {
            "device_fp_stable": True, "geo": geo, "geo_velocity": 0.0,
            "call_rate": 0.0, "session_continuity": 1.0, "dpop_failure_rate": 0.0,
        }

    # ── STAGE 4: Risk scoring ─────────────────────────────────────────────────
    if config.ENABLE_RISK_POLICY:
        t0 = time.perf_counter()
        risk_result = risk.score(
            telemetry=telemetry_signals,
            checks=checks,
            attack_context=attack_context,
        )
        latency["risk"] = round((time.perf_counter() - t0) * 1000, 3)

    # ── STAGE 5: Policy decision ──────────────────────────────────────────────
    if config.ENABLE_RISK_POLICY:
        t0 = time.perf_counter()
        decision = await policy_client.decide(
            risk=risk_result["risk"],
            telemetry=telemetry_signals,
            checks=checks,
        )
        latency["policy"] = round((time.perf_counter() - t0) * 1000, 3)
    else:
        # B1 mode: token+DPoP passed → ALLOW
        decision = "ALLOW"

    # ── STAGE 6: Enforcement ──────────────────────────────────────────────────
    if decision == "ALLOW":
        t0 = time.perf_counter()
        if attack_info:
            attack_info["succeeded"] = True
        try:
            response = await proxy.forward(request, user_id)
        except Exception as exc:
            latency["proxy"] = round((time.perf_counter() - t0) * 1000, 3)
            latency["total"] = round((time.perf_counter() - t_start) * 1000, 3)
            _emit(request_info, telemetry_signals, checks, risk_result, decision, latency, attack_info)
            raise exc
        # `total` is measured after proxy.forward() returns — logging it
        # before the backend round-trip (as this used to) silently excluded
        # the proxy stage from every ALLOW record's latency, undercounting
        # B1/P's true end-to-end latency versus B0's separate pass-through
        # branch, which always measured total correctly.
        latency["proxy"] = round((time.perf_counter() - t0) * 1000, 3)
        latency["total"] = round((time.perf_counter() - t_start) * 1000, 3)
        _emit(request_info, telemetry_signals, checks, risk_result, decision, latency, attack_info)
        return response

    elif decision == "CHALLENGE":
        if attack_info:
            attack_info["succeeded"] = False
        latency["total"] = round((time.perf_counter() - t_start) * 1000, 3)
        _emit(request_info, telemetry_signals, checks, risk_result, decision, latency, attack_info)
        return JSONResponse(
            status_code=401,
            content={
                "error": "step_up_required",
                "detail": "Additional authentication required",
                "risk": risk_result["risk"],
            },
            headers={"WWW-Authenticate": 'Bearer error="insufficient_claims"'},
        )

    else:  # DENY
        if attack_info:
            attack_info["succeeded"] = False
        latency["total"] = round((time.perf_counter() - t_start) * 1000, 3)
        _emit(request_info, telemetry_signals, checks, risk_result, decision, latency, attack_info)
        return JSONResponse(
            status_code=403,
            content={"error": "access_denied", "detail": "Request denied by policy"},
        )


def _emit(request_info, telemetry_signals, checks, risk_result, decision, latency, attack_info):
    """Write the per-request JSONL record."""
    record = jsonl_logger.build_record(
        run_id=_RUN_ID,
        request_info=request_info,
        context=telemetry_signals,
        checks=checks,
        risk_result=risk_result,
        decision=decision,
        latency_ms=latency,
        attack_info=attack_info,
    )
    jsonl_logger.write_record(record)

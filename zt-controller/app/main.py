"""
Zero Trust Controller — FastAPI PEP+PDP reverse proxy.

Per-request pipeline (§7 of spec):
  1. token_verify    — AT signature / issuer / scope / exp / cnf.jkt
  2. dpop_verify     — JWS verify, jti replay, iat skew, ath, cnf.jkt binding
  3. telemetry       — geo/velocity, call-rate, session continuity, DPoP history
     device_registry — is this subject using a device key it has used before?
  4. risk            — rule-based score → belief b_t
  5. policy_client   — OPA ALLOW / CHALLENGE / DENY
  6. proxy           — forward to mock ADR API (only on ALLOW)

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

from app import (config, token_verify, dpop_verify, telemetry, device_registry,
                 risk, policy_client, proxy, jsonl_logger)

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

_NEUTRAL_TELEMETRY = {
    "device_fp_stable": True, "geo": "", "geo_velocity": 0.0,
    "call_rate": 0.0, "session_continuity": 1.0, "dpop_failure_rate": 0.0,
}


@app.get("/health")
async def health():
    return {"status": "ok", "mode": config.ZT_MODE, "run_label": config.RUN_LABEL,
            "flags": config.as_dict()}


@app.post("/admin/reset-state")
async def reset_state(request: Request):
    """
    Harness control plane — NOT part of the measured data path.

    Drops the controller's in-memory continuous-trust state (telemetry
    histories, per-subject enrolled device keys, DPoP jti replay cache) so that
    each attack in the suite is measured against a freshly established baseline
    rather than inheriting the preceding attack's history.  Without it, A6's
    call-rate signal would be contaminated by A3's burst, A4's device signal by
    A2's foreign key, and so on, and no per-attack number would be
    interpretable.  The alternative — restarting the container between attacks
    — is equivalent but an order of magnitude slower.

    Guarded by the internal service secret, which never leaves the Docker
    network; the endpoint is never exercised by the attack traffic itself.
    """
    if request.headers.get("x-zt-admin", "") != config.INTERNAL_SECRET:
        return JSONResponse({"detail": "forbidden"}, status_code=403)
    telemetry.reset()
    device_registry.reset()
    dpop_verify.reset()
    logger.info({"event": "state_reset"})
    return {"status": "reset"}


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
        "jti_replayed": False, "cnf_jkt_present": False, "cnf_jkt_match": False,
    }
    risk_result: dict = {"belief_b": 1.0, "risk": 0.0, "score_components": {}}
    decision = "DENY"
    user_id = ""
    cnf_jkt = ""
    telemetry_signals: dict = {}
    device_signals: dict = {}
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

    # Workload label for the legitimate-traffic experiments: "stable" (the
    # enrolled device's normal context), "drift" (network/geo change mid
    # session) or "warmup" (baseline-establishing requests, excluded from
    # reported rates).  Recorded so §7.2's false-challenge rate can be split
    # by context profile after the fact.
    context_profile = request.headers.get("x-context-profile", "")

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
        "context_profile": context_profile,
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
        if attack_info:
            attack_info["succeeded"] = response.status_code < 400
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
        checks["cnf_jkt_present"] = bool(cnf_jkt)
        # `cnf_jkt_match` means "the presented DPoP key's thumbprint was
        # verified equal to the token's cnf.jkt", which only stage 2 can
        # establish. Setting it from the claim's *presence* here (as this used
        # to) recorded True on requests whose binding had in fact mismatched —
        # A2's records read cnf_jkt_match=true while being refused precisely
        # for a jkt mismatch. It changes no reported quantity, because every
        # such request is already classified as credential-refused by
        # dpop_valid=false, but the field has to mean what it says. Where DPoP
        # is not enforced there is no binding to verify and no claim to
        # contradict, so the check is vacuously satisfied.
        checks["cnf_jkt_match"] = not config.ENFORCE_DPOP
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
            # Record whether the presented key actually matched the token's
            # confirmation claim.  With CHECK_DEVICE_BINDING on, a mismatch
            # never reaches here; with the binding ablated it does, and the
            # record must say so.
            checks["cnf_jkt_match"] = dpop_payload.get("_jkt", "") == cnf_jkt
        except Exception as exc:
            checks["dpop_valid"] = False
            if "replay" in str(exc).lower():
                checks["jti_replayed"] = True
            latency["dpop_verify"] = round((time.perf_counter() - t0) * 1000, 3)
            # A failed proof is itself a behavioural signal: feed it into the
            # subject's DPoP-failure history (rule R6) before denying.
            if config.ENABLE_TELEMETRY:
                telemetry_signals = telemetry.collect(
                    subject=user_id, device_id=device_id, session_id=session_id,
                    source_ip=source_ip, geo=geo, device_fp=device_fp,
                    request_ts=time.time(), dpop_failed=True,
                )
            latency["total"] = round((time.perf_counter() - t_start) * 1000, 3)
            _emit(request_info, telemetry_signals, checks, risk_result, "DENY",
                  latency, attack_info)
            raise exc
        latency["dpop_verify"] = round((time.perf_counter() - t0) * 1000, 3)

    # ── STAGE 3: Telemetry + device registry ──────────────────────────────────
    if config.ENABLE_TELEMETRY:
        t0 = time.perf_counter()
        telemetry_signals = telemetry.collect(
            subject=user_id,
            device_id=device_id,
            session_id=session_id,
            source_ip=source_ip,
            geo=geo,
            device_fp=device_fp,
            request_ts=time.time(),
        )
        latency["telemetry"] = round((time.perf_counter() - t0) * 1000, 3)
    else:
        telemetry_signals = dict(_NEUTRAL_TELEMETRY, geo=geo)

    if config.CHECK_DEVICE_BINDING:
        t0 = time.perf_counter()
        device_signals = device_registry.observe(user_id, cnf_jkt)
        latency["telemetry"] = round(
            latency["telemetry"] + (time.perf_counter() - t0) * 1000, 3)
        telemetry_signals = {**telemetry_signals, **device_signals}

    # ── STAGE 4: Risk scoring ─────────────────────────────────────────────────
    if config.ENABLE_RISK_POLICY:
        t0 = time.perf_counter()
        risk_result = risk.score(
            telemetry=telemetry_signals,
            checks=checks,
            attack_context=attack_context,
            device_signals=device_signals,
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
        try:
            response = await proxy.forward(request, user_id)
        except Exception as exc:
            latency["proxy"] = round((time.perf_counter() - t0) * 1000, 3)
            latency["total"] = round((time.perf_counter() - t_start) * 1000, 3)
            if attack_info:
                attack_info["succeeded"] = False
            _emit(request_info, telemetry_signals, checks, risk_result, decision, latency, attack_info)
            raise exc
        # `total` is measured after proxy.forward() returns — logging it
        # before the backend round-trip (as this used to) silently excluded
        # the proxy stage from every ALLOW record's latency, undercounting
        # B1/P's true end-to-end latency versus B0's separate pass-through
        # branch, which always measured total correctly.
        latency["proxy"] = round((time.perf_counter() - t0) * 1000, 3)
        latency["total"] = round((time.perf_counter() - t_start) * 1000, 3)
        # The controller allowed it, but the resource server still enforces
        # object-level ownership (A5); the adversary only succeeds if data
        # actually came back.
        if attack_info:
            attack_info["succeeded"] = response.status_code < 400
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

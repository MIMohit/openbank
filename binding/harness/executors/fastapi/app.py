"""Bench API executor: FastAPI / Starlette under uvicorn (CONTRACT section 3).

ASGI stack, outermost first:
  BenchLogMiddleware        records the raw method/target, writes the JSONL log line on completion
  HTTPMethodOverrideASGI    only when OVERRIDE=on (ASGI port of the Flask-documented pattern, see README)
  FastAPI app               routes; /api/v2 is a mounted FastAPI sub-application (prefix mount)
"""
from __future__ import annotations

import base64
import datetime as _dt
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

FRAMEWORK = os.environ.get("FRAMEWORK_TAG", "fastapi")
OVERRIDE = os.environ.get("OVERRIDE", "off").lower() == "on"
# ROUTES=v2 (default off) adds the richer v1 route space (W15 ext-routes): a POST sharing a path
# with GET/PUT/DELETE, a nested same-method route, a catch-all, and a nested DELETE. Off => :latest.
ROUTES = os.environ.get("ROUTES", "off").lower()
VERIFY_MODE = os.environ.get("VERIFY_MODE", "off").lower()
VERIFIER_URL = os.environ.get("VERIFIER_URL", "http://verifier:9100/authz/orig")
LOG_PATH = os.environ.get("LOG_PATH", "/logs/executor.jsonl")
TRUST_PREFIXES = ("x-forwarded-", "x-original-", "x-verified-", "x-client-cert",
                  "client-cert", "x-forwarded-client-cert", "x-auth-")
if VERIFY_MODE not in ("off", "origin-raw", "origin-routed"):
    sys.exit(f"bad VERIFY_MODE={VERIFY_MODE}")

_log_lock = threading.Lock()


# --------------------------------------------------------------------------- helpers
def jti_from_dpop(value: str | None):
    """base64url-decode the DPoP JWS payload WITHOUT verification; null on any failure."""
    if not value:
        return None
    try:
        parts = value.strip().split(".")
        if len(parts) != 3:
            return None
        seg = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(seg.encode("ascii")))
        jti = claims.get("jti") if isinstance(claims, dict) else None
        return jti if isinstance(jti, str) else None
    except Exception:
        return None


def canonical_path(template: str, params: dict) -> str:
    out = template
    for k, v in params.items():
        out = out.replace("{" + k + "}", quote(str(v), safe="-._~!$&'()*+,;=:@"))
    return out


def write_log(rec: dict) -> None:
    line = json.dumps(rec, separators=(",", ":"), ensure_ascii=False)
    with _log_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass


def call_verifier(method: str, uri: str, host: str, headers: list[tuple[str, str]]) -> bool:
    req = urllib.request.Request(VERIFIER_URL, method="GET")
    req.add_header("X-Original-Method", method)
    req.add_header("X-Original-URI", uri)
    req.add_header("X-Original-Host", host)
    for name, val in headers:
        if name in ("authorization", "dpop"):
            req.add_header(name, val)
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return 200 <= resp.status < 300
    except urllib.error.HTTPError:
        return False
    except Exception:
        return False  # verifier unreachable: fail closed


# --------------------------------------------------------------------------- middleware
class BenchLogMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        raw_path = scope.get("raw_path") or scope["path"].encode("utf-8")
        qs = scope.get("query_string", b"")
        raw_target = raw_path.decode("latin-1") + ("?" + qs.decode("latin-1") if qs else "")
        headers = [(k.decode("latin-1").lower(), v.decode("latin-1")) for k, v in scope["headers"]]
        trust: dict[str, str] = {}
        dpop = None
        for k, v in headers:
            if k.startswith(TRUST_PREFIXES):
                trust[k] = trust[k] + ", " + v if k in trust else v
            if k == "dpop" and dpop is None:
                dpop = v
        bh = {"op_id": "NOT_FOUND", "route_template": None, "path_params": {}, "denied": False,
              "raw_target": raw_target, "headers": headers, "raw_method": scope["method"]}
        scope["bh"] = bh
        raw_method = scope["method"]
        status = {"code": 500}

        async def send_wrapper(msg):
            if msg["type"] == "http.response.start":
                status["code"] = msg["status"]
            await send(msg)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            write_log({
                "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                "framework": FRAMEWORK,
                "jti": jti_from_dpop(dpop),
                "op_id": bh["op_id"],
                "route_template": bh["route_template"],
                "raw_method": raw_method,
                "effective_method": scope["method"],
                "raw_target": raw_target,
                "path_params": bh["path_params"],
                "query": qs.decode("latin-1"),
                "trust_headers": trust,
                "denied": bh["denied"],
                "status": status["code"],
            })


class HTTPMethodOverrideASGI:
    """Line-for-line ASGI transliteration of Flask's documented HTTPMethodOverrideMiddleware
    (https://flask.palletsprojects.com/patterns/methodoverrides/). Starlette/FastAPI ship no
    method-override mechanism and no maintained ASGI package exists on PyPI (see README)."""
    allowed_methods = frozenset(["GET", "HEAD", "POST", "DELETE", "PUT", "PATCH", "OPTIONS"])
    bodyless_methods = frozenset(["GET", "HEAD", "OPTIONS", "DELETE"])

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            method = ""
            for k, v in scope["headers"]:
                if k.lower() == b"x-http-method-override":
                    method = v.decode("latin-1").upper()
                    break
            if method in self.allowed_methods:
                scope["method"] = method  # mutate in place so the log middleware sees it
            if method in self.bodyless_methods:  # Flask: environ['CONTENT_LENGTH'] = '0'
                async def empty_receive():
                    return {"type": "http.request", "body": b"", "more_body": False}
                return await self.app(scope, empty_receive, send)
        return await self.app(scope, receive, send)


# --------------------------------------------------------------------------- handlers
def respond(request: Request, op_id: str, template: str, params: dict) -> JSONResponse:
    bh = request.scope["bh"]
    bh.update(op_id=op_id, route_template=template, path_params=params)
    method = request.scope["method"]
    if VERIFY_MODE != "off":
        if VERIFY_MODE == "origin-raw":
            vm, vu = bh["raw_method"], bh["raw_target"]
        else:
            vm, vu = method, canonical_path(template, params)
        host = request.headers.get("host", "")
        if not call_verifier(vm, vu, host, bh["headers"]):
            bh["denied"] = True
            return JSONResponse({"op_id": op_id, "framework": FRAMEWORK, "denied": True}, status_code=401)
    return JSONResponse({"op_id": op_id, "framework": FRAMEWORK, "method": method, "path_params": params})


async def not_found(request: Request, exc: Exception) -> JSONResponse:
    # 404 and 405 (method mismatch) both map to NOT_FOUND per CONTRACT section 3.
    return JSONResponse({"op_id": "NOT_FOUND", "framework": FRAMEWORK}, status_code=404)


async def _keep_http_exc(request: Request, exc: StarletteHTTPException):
    if exc.status_code in (404, 405):
        return await not_found(request, exc)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


def build_app() -> FastAPI:
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    app.add_exception_handler(StarletteHTTPException, _keep_http_exc)
    v1 = "/api/v1"

    @app.get(v1 + "/accounts")
    def list_accounts(request: Request):
        return respond(request, "listAccounts", "/api/v1/accounts", {})

    @app.get(v1 + "/accounts/{id}")
    def get_account(request: Request, id: str):
        return respond(request, "getAccount", "/api/v1/accounts/{id}", {"id": id})

    @app.put(v1 + "/accounts/{id}")
    def update_account(request: Request, id: str):
        return respond(request, "updateAccount", "/api/v1/accounts/{id}", {"id": id})

    @app.delete(v1 + "/accounts/{id}")
    def delete_account(request: Request, id: str):
        return respond(request, "deleteAccount", "/api/v1/accounts/{id}", {"id": id})

    @app.post(v1 + "/accounts/{id}/actions")
    def account_action(request: Request, id: str):
        op = request.query_params.get("op")  # Starlette: duplicate keys -> last value (README)
        sub = op if op in ("freeze", "close") else "unknown"
        return respond(request, "accountAction." + sub, "/api/v1/accounts/{id}/actions", {"id": id})

    @app.post(v1 + "/transfers")
    def create_transfer(request: Request):
        return respond(request, "createTransfer", "/api/v1/transfers", {})

    @app.post(v1 + "/graphql")
    async def graphql(request: Request):
        name = None
        try:
            body = json.loads(await request.body())
            if isinstance(body, dict):
                name = body.get("operationName")
        except Exception:
            name = None
        sub = {"getProfile": "getProfile", "deleteProfile": "deleteProfile"}.get(name, "unknown") \
            if isinstance(name, str) else "unknown"
        # respond() may block on the verifier; run it in the threadpool
        from starlette.concurrency import run_in_threadpool
        return await run_in_threadpool(respond, request, "graphql." + sub, "/api/v1/graphql", {})

    @app.get(v1 + "/me")
    def me(request: Request):
        return respond(request, "me", "/api/v1/me", {})

    @app.get(v1 + "/admin/users")
    def admin_list_users(request: Request):
        return respond(request, "adminListUsers", "/api/v1/admin/users", {})

    @app.delete(v1 + "/admin/users/{id}")
    def admin_delete_user(request: Request, id: str):
        return respond(request, "adminDeleteUser", "/api/v1/admin/users/{id}", {"id": id})

    @app.get(v1 + "/health")
    def health(request: Request):
        return respond(request, "health", "/api/v1/health", {})

    @app.get(v1 + "/public/{file}")
    def public_file(request: Request, file: str):
        return respond(request, "publicFile", "/api/v1/public/{file}", {"file": file})

    if ROUTES == "v2":
        # POST sharing the /accounts/{id} path with GET/PUT/DELETE: exercises POST-only override.
        @app.post(v1 + "/accounts/{id}")
        def post_account(request: Request, id: str):
            return respond(request, "postAccount", "/api/v1/accounts/{id}", {"id": id})

        # Nested same-method route under /accounts/{id}.
        @app.get(v1 + "/accounts/{id}/statements")
        def get_statements(request: Request, id: str):
            return respond(request, "getStatements", "/api/v1/accounts/{id}/statements", {"id": id})

        @app.delete(v1 + "/accounts/{id}/statements/{sid}")
        def delete_statement(request: Request, id: str, sid: str):
            return respond(request, "deleteStatement", "/api/v1/accounts/{id}/statements/{sid}",
                           {"id": id, "sid": sid})

        # Catch-all: Starlette path convertor binds the remainder (incl. '/') literally.
        @app.get(v1 + "/files/{path:path}")
        def catch_all_file(request: Request, path: str):
            return respond(request, "catchAllFile", "/api/v1/files/{path}", {"path": path})

    # Prefix mount: an independent FastAPI sub-application under /api/v2 (Starlette Mount).
    v2 = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    v2.add_exception_handler(StarletteHTTPException, _keep_http_exc)

    @v2.get("/accounts/{id}")
    def get_account_v2(request: Request, id: str):
        return respond(request, "getAccountV2", "/api/v2/accounts/{id}", {"id": id})

    app.mount("/api/v2", v2)
    return app


fastapi_app = build_app()
_inner = HTTPMethodOverrideASGI(fastapi_app) if OVERRIDE else fastapi_app
app = BenchLogMiddleware(_inner)

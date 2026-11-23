"""False-rejection measurement (task item 6). Legitimate requests generated from
experiments/ext-routes/bench-api.v2.openapi.yaml (every path x method; parameter values and bodies
from the registered base ops, which mirror the spec examples), sent through legitimate rewrite
scenarios. Each request carries a fresh, VALID proof whose htu is the public URL exactly as sent
(no query), htm = method. Run from binding/harness.

  frr_client.py --port P --out frr.jsonl [--h2]

Scenarios (gateway side injected by frr_nginx.py):
  S0 identity        /api/...                    -> /api/...         (control)
  S1 strip-prefix    /svc/api/...                -> /api/...         (nginx rewrite ^/svc(/.*)$ $1)
  S2 version-rewrite /api/latest/...             -> /api/v1/...
  S3 trailing-slash  /api/.../                   -> /api/...         (gateway strips the trailing '/')
  S4 pct-id          id percent-encoded: %2D, %2d, %20, UTF-8 %C3%A9, %2F    (no rewrite)
  S5 h2->h1          S0 over h2c prior knowledge (curl), gateway proxies HTTP/1.1
"""
import argparse, json, re, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ext_base  # noqa: E402
ext_base.register()
import yaml  # noqa: E402
from mutator.base_ops import BASE_OPS_BY_ID  # noqa: E402
from rawhttp.client import send  # noqa: E402
from runner.minter_adapter import get_minter  # noqa: E402

SPEC = Path(__file__).resolve().parents[2] / "ext-routes" / "bench-api.v2.openapi.yaml"
ORIGIN = "http://api.bench.test"
DISPATCH = {"accountAction": "accountAction.freeze", "graphql": "graphql.getProfile"}
ID_VARIANTS = {"pct-unreserved-upper": "acc%2Dalice%2D1", "pct-unreserved-lower": "acc%2dalice%2d1",
               "pct-space": "acc%20alice%201", "pct-utf8": "acc-%C3%A9-1", "pct-slash": "acc%2Falice%2F1"}

def spec_ops():
    spec = yaml.safe_load(SPEC.read_text())
    out = []
    for path, item in spec["paths"].items():
        for m, op in item.items():
            if m not in ("get", "post", "put", "delete", "patch"):
                continue
            oid = DISPATCH.get(op["operationId"], op["operationId"])
            b = BASE_OPS_BY_ID[oid]
            tmpl = "^" + re.sub(r"\{[^}]+\}", "[^?]+", path) + "$"
            assert b.method == m.upper() and re.match(tmpl, b.path), (oid, path, b.path)
            out.append((oid, path, b))
    return out

def requests():
    for oid, tmpl, b in spec_ops():
        p, q = b.path, b.query
        yield "S0-identity", oid, b, p, q, False
        yield "S1-strip-prefix", oid, b, "/svc" + p, q, False
        if p.startswith("/api/v1/"):
            yield "S2-version-rewrite", oid, b, "/api/latest/" + p[len("/api/v1/"):], q, False
        yield "S3-trailing-slash", oid, b, p + "/", q, False
        if "{id}" in tmpl:
            for name, v in ID_VARIANTS.items():
                yield "S4-" + name, oid, b, p.replace("acc-alice-1", v, 1), q, False
        yield "S5-h2-to-h1", oid, b, p, q, True

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--out", required=True); a = ap.parse_args()
    minter = get_minter(prefer="w3")
    n = 0
    with open(a.out, "w") as f:
        for scen, oid, b, path, q, h2 in requests():
            authz, proof, jti = minter.mint(client="alice", htm=b.method, htu=ORIGIN + path)
            target = path + ("?" + q if q else "")
            hdrs = [("Host", "api.bench.test"), ("Authorization", authz), ("DPoP", proof), ("Accept", "application/json")]
            if b.body:
                hdrs += [("Content-Type", b.content_type or "application/json"), ("Content-Length", str(len(b.body)))]
            if h2:
                cmd = ["curl", "-s", "--http2-prior-knowledge", "-o", "-", "-w", "\n%{http_code} %{http_version}",
                       "-X", b.method, f"http://127.0.0.1:{a.port}{target}", "--path-as-is", "--max-time", "10"]
                for k, v in hdrs:
                    if k not in ("Content-Length",):
                        cmd += ["-H", f"{k}: {v}"]
                if b.body:
                    cmd += ["--data-binary", b.body.decode()]
                r = subprocess.run(cmd, capture_output=True, text=True)
                body, _, tail = r.stdout.rpartition("\n")
                status, ver = (tail.split() + ["", ""])[:2]
                status = int(status or 0)
            else:
                raw = (f"{b.method} {target} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs)
                       + "Connection: close\r\n\r\n").encode() + (b.body or b"")
                resp = send("127.0.0.1", a.port, raw, timeout=10)
                status, body, ver = resp.status, resp.body.decode("utf-8", "replace"), resp.http_version
            try:
                js = json.loads(body); got = js.get("op_id"); reason = js.get("reason") or js.get("detail")
            except Exception:
                got, reason = None, body[:120]
            ok = status < 400 and got == oid
            f.write(json.dumps({"scenario": scen, "expected_op": oid, "method": b.method, "target": target,
                                "htu": ORIGIN + path, "jti": jti, "status": status, "op_id": got, "reason": reason,
                                "http_version": ver, "ok": ok}) + "\n")
            n += 1
    print(f"frr: {n} requests -> {a.out}", file=sys.stderr)

if __name__ == "__main__":
    main()

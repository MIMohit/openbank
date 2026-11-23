"""Smoke test: every gateway x profile with placement=edge, stub verifier + stub executor.

    cd binding/harness && BH_PROJECT_PREFIX=w6-bh- orchestrator/.venv/bin/python -m orchestrator.smoke [ids...]

For each topology in topologies/smoke/: up (fresh logs), mint a real token + DPoP
proof with W3's minter for GET http://api.bench.test/api/v1/accounts/acc-alice-1,
send it with `curl --path-as-is`, then check by jti that the verifier saw
(GET, /api/v1/accounts/acc-alice-1, api.bench.test) through the expected adapter
and that the executor matched getAccount on the same raw target; tear down.
One topology up at a time. Writes orchestrator/SMOKE.md and smoke_results.json.
"""
import datetime as dt
import json
import subprocess
import sys
import time
from pathlib import Path

from gateways.common import GATEWAYS, IMAGES, PROFILES
from orchestrator import down, up
from orchestrator.compose import LOGS
from orchestrator.topology import load

ORCH = Path(__file__).resolve().parent
ADAPTER = {"envoy": "envoy", "traefik": "fwd", "apisix": "fwd", "nginx": "orig", "kong": "orig", "haproxy": "orig"}
PATH = "/api/v1/accounts/acc-alice-1"
HTU = "http://api.bench.test" + PATH


def by_jti(f: Path, jti: str):
    if not f.exists():
        return []
    return [r for r in map(json.loads, f.read_text().splitlines()) if r.get("jti") == jti]


def digest(image: str) -> str:
    r = subprocess.run(["docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", image],
                       capture_output=True, text=True)
    return r.stdout.strip().split("@")[-1]


def run_one(path: Path) -> dict:
    from minter.dpop import decode_unverified, headers_for

    t = load(path)
    res = {"id": t["id"], "gateway": t["gateway"], "profile": t["profile"], "image": t["gateway_image"],
           "digest": digest(t["gateway_image"]), "ok": False}
    t0 = time.time()
    rc = up.main([str(path), "--fresh-logs", "--stubs", "auto"])
    res["stubs"] = json.loads((ORCH / "generated" / t["id"] / "meta.json").read_text())["stubs"]
    res["up_s"] = round(time.time() - t0, 1)
    if rc != 0:
        res["error"] = f"up failed rc={rc}"
        down.main([str(path)])
        return res
    try:
        h = headers_for("alice", "GET", HTU)
        jti = decode_unverified(h["DPoP"])[1]["jti"]
        res["jti"] = jti
        cmd = ["curl", "-sS", "--path-as-is", "-o", "-", "-w", "\n%{http_code}",
               "-H", "Host: api.bench.test", "-H", f"Authorization: {h['Authorization']}",
               "-H", f"DPoP: {h['DPoP']}", f"http://127.0.0.1:{t['host_port']}{PATH}"]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
        body, _, code = out.rpartition("\n")
        res["status"] = int(code or 0)
        res["body"] = body[:300]
        time.sleep(0.5)
        v = by_jti(LOGS / t["id"] / "verifier.jsonl", jti)
        e = by_jti(LOGS / t["id"] / "executor.jsonl", jti)
        res["verifier"] = v
        res["executor"] = e
        checks = {
            "http_200": res["status"] == 200,
            "verifier_once": len(v) == 1,
            "executor_once": len(e) == 1,
        }
        if v:
            checks.update({
                "adapter": v[0]["adapter"] == ADAPTER[t["gateway"]],
                "view_method": v[0]["view_method"] == "GET",
                "view_uri": v[0]["view_uri"] == PATH,
                "view_host": v[0]["view_host"] == "api.bench.test",
                # stub logs header presence; the real verifier can only allow if both arrived and verified
                "auth+dpop_to_verifier": bool(v[0].get("has_authorization") and v[0].get("has_dpop"))
                if v[0].get("stub") else v[0].get("decision") == "allow",
                "decision_allow": v[0].get("decision") == "allow",
            })
        if e:
            checks.update({"exec_op": e[0]["op_id"] == "getAccount",
                           "exec_target": e[0]["raw_target"] == PATH})
        res["checks"] = checks
        res["ok"] = all(checks.values())
    finally:
        down.main([str(path)])
    return res


def table(results) -> str:
    rows = ["| gateway | image (tag @ digest) | profile | up (s) | HTTP | adapter | verifier view (method, uri, host) | executor op_id / raw_target | Authz+DPoP at verifier | result |",
            "|---|---|---|---|---|---|---|---|---|---|"]
    for r in results:
        v = (r.get("verifier") or [{}])[0]
        e = (r.get("executor") or [{}])[0]
        failed = [k for k, ok in (r.get("checks") or {}).items() if not ok]
        rows.append("| {gw} | `{img}` @ `{dg}` | {pr} | {up} | {st} | {ad} | `{vm} {vu}` host=`{vh}` | {op} `{rt}` | {ad2} | {res} |".format(
            gw=r["gateway"], img=r["image"], dg=r["digest"][:19] + "…", pr=r["profile"], up=r.get("up_s"),
            st=r.get("status", "-"), ad=v.get("adapter", "-"), vm=v.get("view_method"), vu=v.get("view_uri"),
            vh=v.get("view_host"), op=e.get("op_id", "-"), rt=e.get("raw_target"),
            ad2=("yes" if v.get("has_authorization") and v.get("has_dpop") else "no") if v.get("stub")
            else f"{v.get('decision')} ({v.get('reason')})",
            res="PASS" if r["ok"] else "FAIL " + (r.get("error") or ",".join(failed))))
    return "\n".join(rows)


def _order(rid: str) -> tuple:
    for si, prefix in enumerate(("smoke-", "smokereal-")):
        for gi, g in enumerate(GATEWAYS):
            for pi, p in enumerate(PROFILES):
                if rid == f"{prefix}{g}-{p}-edge":
                    return (si, gi, pi)
    return (9, 0, 0)


def main(argv=None):
    """args: [--set smoke|smokereal|all] [topology ids...]"""
    argv = list(sys.argv[1:] if argv is None else argv)
    which = "all"
    if argv[:1] == ["--set"]:
        which, argv = argv[1], argv[2:]
    sets = ["smoke", "smokereal"] if which == "all" else [which]
    paths = [p for s_ in sets for p in (ORCH / "topologies" / s_).glob("*.yaml")]
    paths.sort(key=lambda p: _order(p.stem))
    if argv:
        paths = [p for p in paths if p.stem in argv]
    out_json = ORCH / "smoke_results.json"
    prev = {r["id"]: r for r in json.loads(out_json.read_text())} if out_json.exists() else {}
    for p in paths:
        r = run_one(p)
        print(f"== {r['id']}: {'PASS' if r['ok'] else 'FAIL'} {r.get('checks') or r.get('error')}", flush=True)
        prev[r["id"]] = r
        out_json.write_text(json.dumps(sorted(prev.values(), key=lambda r: _order(r["id"])), indent=2) + "\n")
    results = sorted(prev.values(), key=lambda r: _order(r["id"]))
    stub = [r for r in results if r["id"].startswith("smoke-")]
    real = [r for r in results if r["id"].startswith("smokereal-")]
    md = ORCH / "SMOKE.md"
    md.write_text(f"""# Smoke test: gateways x profiles, placement=edge

Generated by `orchestrator/smoke.py` (last write {dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}).
Raw per-run records, including the full verifier and executor log lines: `smoke_results.json`.
Command: `cd binding/harness && BH_PROJECT_PREFIX=w6-bh- orchestrator/.venv/bin/python -m orchestrator.smoke [--set smoke|smokereal]`.
One topology was up at a time, and each was torn down after its request.

**Request.** `curl --path-as-is` GET `{PATH}` with `Host: api.bench.test`. It carries a real ES256 access
token and a DPoP proof minted by W3's `minter.dpop.headers_for` for htu `{HTU}`. Requests are correlated by the proof `jti`.

**What this shows.** Each gateway profile config loads and routes `/api/` to the executor with the path
kept. It calls the verifier through its CONTRACT section 4 adapter (envoy -> `/authz/envoy`; traefik
and apisix -> `/authz/fwd`; nginx, kong and haproxy -> `/authz/orig`), and it passes `Authorization` and `DPoP`.
**What it does not show.** Anything about binding soundness: the executor is the W6 stub echo, which
uses regex routing and no framework.

**PASS requires:**
- HTTP 200;
- exactly one verifier line and one executor line for the jti;
- the expected adapter;
- view = (GET, `{PATH}`, `api.bench.test`);
- Authorization and DPoP reached the verifier: header presence for the stub, an `allow` decision for the real verifier;
- executor op_id `getAccount` with raw_target `{PATH}`.

## A. W6 stub verifier (always allows, logs the view) + W6 stub executor

{table(stub) if stub else "_not run_"}

Passed {sum(r['ok'] for r in stub)}/{len(stub)}.

## B. Real verifier `bh-verifier:latest` (W3; HTU_CANON=rfc3986, JTI_CACHE=on) + W6 stub executor

{table(real) if real else "_not run_"}

Passed {sum(r['ok'] for r in real)}/{len(real)}.
""")
    print(f"wrote {md}")
    return 0 if all(r["ok"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())

"""Bring an ORIGIN/BOTH topology up like orchestrator.up, but first make the gateway
preserve the client's public Host (api.bench.test) when it proxies to the executor.

WHY (A3 ablation correctness, documented as a §12 work-around; orchestrator/ and
gateways/ are W6-owned and must not be edited):

  In placement=origin / both the executor runs VERIFY_MODE=origin-raw and itself calls
  the verifier with X-Original-Host = the Host it received (CONTRACT §3). But NGINX's
  `default` profile template (gateways/nginx/render.py: PROXY_PROFILE["default"] == "")
  emits a bare `proxy_pass http://executor:8080;` with NO `proxy_set_header Host`, so
  NGINX rewrites Host to the upstream name `executor:8080`. The executor then forwards
  X-Original-Host: executor:8080, the verifier reconstructs the view URL as
  http://executor:8080/... and every request (even the sound baseline) is denied with
  reason `htu_mismatch` against the proof's htu http://api.bench.test/.... That makes the
  A3 ablation degenerate (fail-closed everywhere, 0 hits) and measures the NGINX default
  Host-rewrite, not origin verification. The `recommended` profile already sets
  `proxy_set_header Host $host;` (PROXY_PROFILE["recommended"]); envoy preserves :authority
  by default. This script restores that one header for the nginx default profile so the
  sound path is accepted and the A3 question (does app-side RAW-TARGET verification keep or
  drop the G1/G2 differentials?) can actually be measured. Nothing else changes.

  It ALSO disables the executor's inherited image healthcheck (same reason as up_hcfix.py:
  the Laravel FrankenPHP/Caddy healthcheck flaps under load and gates `--wait`).

    cd binding/harness && orchestrator/.venv/bin/python \
        ../experiments/ext-fw/scripts/up_hostfix.py <topology.yaml> [--timeout 300]
Prints the host port on the last stdout line, exactly like orchestrator.up.
"""
import argparse
import os
import socket
import subprocess
import sys
import time

import yaml

HARNESS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "harness"))
if HARNESS not in sys.path:
    sys.path.insert(0, HARNESS)

from orchestrator.compose import LOGS, generate, project_name
from orchestrator.topology import load

HOSTLINE = "            proxy_set_header Host $host;\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("topology")
    ap.add_argument("--timeout", type=int, default=300)
    a = ap.parse_args(argv)

    t = load(a.topology)
    for f in (LOGS / t["id"]).glob("*.jsonl"):   # --fresh-logs behaviour
        f.unlink()
    path, meta = generate(t, "off")
    for role, s in meta["stubs"].items():
        if s:
            print(f"WARNING: {role} is the W6 STUB", file=sys.stderr)

    # --- work-around 1: disable the executor's inherited image healthcheck (Laravel) ---
    d = yaml.safe_load(path.read_text())
    d["services"]["executor"]["healthcheck"] = {"disable": True}
    path.write_text("# healthcheck-disabled on executor by ext-fw/up_hostfix.py\n"
                    + yaml.safe_dump(d, sort_keys=False))

    # --- work-around 2: preserve the public Host on the nginx default profile so the
    #     origin/both executor's X-Original-Host matches the proof htu authority ---
    if t["gateway"] == "nginx" and t["placement"] in ("origin", "both"):
        conf = path.parent / "gateway" / "nginx.conf"
        text = conf.read_text()
        if "proxy_set_header Host" not in text:
            text = text.replace("            proxy_pass http://executor:8080;\n",
                                HOSTLINE + "            proxy_pass http://executor:8080;\n")
            conf.write_text(text)
            print("hostfix: added 'proxy_set_header Host $host;' to nginx default origin/both",
                  file=sys.stderr)

    proj = project_name(t["id"])
    cmd = ["docker", "compose", "-p", proj, "-f", str(path), "up", "-d", "--wait",
           "--wait-timeout", str(a.timeout)]
    r = subprocess.run(cmd)
    if r.returncode != 0:
        subprocess.run(["docker", "compose", "-p", proj, "-f", str(path), "ps", "-a"])
        subprocess.run(["docker", "compose", "-p", proj, "-f", str(path), "logs", "--tail", "40"])
        print(f"up failed for {t['id']}", file=sys.stderr)
        return r.returncode or 1
    deadline = time.time() + 30
    while True:
        try:
            socket.create_connection(("127.0.0.1", t["host_port"]), timeout=2).close()
            break
        except OSError:
            if time.time() > deadline:
                print("host port not reachable", file=sys.stderr)
                return 1
            time.sleep(0.5)
    print(t["host_port"])
    return 0


if __name__ == "__main__":
    sys.exit(main())

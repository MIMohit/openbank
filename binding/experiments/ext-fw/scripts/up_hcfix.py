"""Bring a topology up like orchestrator.up, but DISABLE the executor container's
image-inherited healthcheck first.

Why: the W5 Laravel image inherits FrankenPHP/Caddy's HEALTHCHECK (curl :2019/metrics,
default 30s interval x3 retries). Under concurrent CPU load that healthcheck flaps and
`docker compose up --wait` gates on it, so `orchestrator.up` reports "up failed" even
though the executor app on :8080 serves fine (the probe sidecar confirms readiness
gateway->executor). CONTRACT §11/§12 forbids editing orchestrator/, so this is a local
work-around: generate the compose with the unmodified W6 code, then set
`healthcheck.disable: true` on the executor service before `up`. Nothing else changes.

    cd binding/harness && orchestrator/.venv/bin/python \
        ../experiments/ext-fw/scripts/up_hcfix.py <topology.yaml> [--timeout 300]
Prints the host port on the last stdout line, exactly like orchestrator.up.
"""
import argparse
import os
import socket
import subprocess
import sys
import time

import yaml

# Running this as a file (not `python -m`) does not put the harness dir on sys.path,
# so `import orchestrator` fails. Insert it explicitly (harness is three levels up).
HARNESS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "harness"))
if HARNESS not in sys.path:
    sys.path.insert(0, HARNESS)

from orchestrator.compose import LOGS, generate, project_name
from orchestrator.topology import load


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

    # --- local work-around: disable the executor's inherited image healthcheck ---
    d = yaml.safe_load(path.read_text())
    d["services"]["executor"].setdefault("healthcheck", {})
    d["services"]["executor"]["healthcheck"] = {"disable": True}
    path.write_text("# healthcheck-disabled on executor by ext-fw/up_hcfix.py\n"
                    + yaml.safe_dump(d, sort_keys=False))

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

"""Bring a topology up.

    cd binding/harness && python -m orchestrator.up topologies/x.yaml [--stubs auto|on|off] [--fresh-logs]

Writes orchestrator/generated/<id>/docker-compose.yml, starts it as project
bh-<id> (prefix overridable with BH_PROJECT_PREFIX), waits until the probe
sidecar is healthy, and prints the host port on the last stdout line.
"""
import argparse
import socket
import subprocess
import sys
import time

from orchestrator.compose import LOGS, generate, project_name
from orchestrator.topology import load


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("topology")
    ap.add_argument("--stubs", choices=["auto", "on", "off"], default="auto")
    ap.add_argument("--fresh-logs", action="store_true", help="truncate logs/<id>/*.jsonl first")
    ap.add_argument("--timeout", type=int, default=240)
    a = ap.parse_args(argv)

    t = load(a.topology)
    if a.fresh_logs:
        for f in (LOGS / t["id"]).glob("*.jsonl"):
            f.unlink()
    path, meta = generate(t, a.stubs)
    for role, s in meta["stubs"].items():
        if s:
            print(f"WARNING: {role} is the W6 STUB (not a measurement component)", file=sys.stderr)
    proj = project_name(t["id"])
    cmd = ["docker", "compose", "-p", proj, "-f", str(path), "up", "-d", "--wait",
           "--wait-timeout", str(a.timeout)]
    r = subprocess.run(cmd)
    if r.returncode != 0:
        subprocess.run(["docker", "compose", "-p", proj, "-f", str(path), "ps", "-a"])
        subprocess.run(["docker", "compose", "-p", proj, "-f", str(path), "logs", "--tail", "40"])
        print(f"up failed for {t['id']} (left running for inspection; run orchestrator.down)", file=sys.stderr)
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

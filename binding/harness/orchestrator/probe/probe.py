"""Health probe run as the compose healthcheck of the `probe` sidecar (W6).

Healthy when: verifier GET /health answers 2xx, the executor answers ANY HTTP
status < 500 on GET /api/v1/health (in origin modes it may legitimately answer
401), and the gateway accepts TCP on :8000. Exit 0 = healthy.
"""
import os
import socket
import sys
import urllib.error
import urllib.request


def http_status(url: str) -> int:
    try:
        with urllib.request.urlopen(url, timeout=2) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def main() -> int:
    try:
        if os.environ.get("PROBE_VERIFIER", "1") == "1":
            s = http_status("http://verifier:9100/health")
            if not 200 <= s < 300:
                print(f"verifier {s}"); return 1
        s = http_status("http://executor:8080/api/v1/health")
        if s >= 500:
            print(f"executor {s}"); return 1
        socket.create_connection(("gateway", 8000), timeout=2).close()
    except Exception as exc:
        print(f"not ready: {exc}"); return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

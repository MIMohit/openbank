import socket, time, sys

HOST, PORT = "127.0.0.1", 18021
targets = [
    ("control",   "/api/v1/accounts/acc-alice-1"),
    ("pct2f_low", "/api/v1/accounts/%2facc-alice-1"),
    ("pct2F_up",  "/api/v1/accounts/%2Facc-alice-1"),
    ("pct252f",   "/api/v1/accounts/%252facc-alice-1"),
    ("pct5c",     "/api/v1/accounts/%5cacc-alice-1"),
    ("pct2e",     "/api/v1/accounts/%2eacc-alice-1"),
    ("dotdot_pct2f", "/api/v1/accounts/..%2facc-alice-1"),
    ("pct2f_midseg", "/api/v1/accounts/acc%2falice-1"),
    ("double_slash", "/api/v1/accounts//acc-alice-1"),
    ("dot_seg",   "/api/v1/accounts/./acc-alice-1"),
]
extra = sys.argv[1:]  # allow ad-hoc targets: name=target
for a in extra:
    n,_,t = a.partition("=")
    targets.append((n,t))
for name, tgt in targets:
    req = (f"DELETE {tgt} HTTP/1.1\r\nHost: api.bench.test\r\nX-Probe: {name}\r\n"
           f"Authorization: DPoP testtoken\r\nDPoP: testproof\r\n"
           f"Accept: application/json\r\nConnection: close\r\n\r\n")
    s = socket.create_connection((HOST, PORT), timeout=5)
    s.settimeout(3)
    s.sendall(req.encode("latin-1"))
    try:
        data = s.recv(4096)
    except socket.timeout:
        data = b"<timeout>"
    s.close()
    status = data.split(b"\r\n",1)[0].decode("latin-1","replace")
    print(f"[{name}] {tgt}  ->  {status}")
    time.sleep(0.15)

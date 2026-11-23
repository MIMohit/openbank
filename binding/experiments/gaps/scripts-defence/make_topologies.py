"""E7/E8 topologies: every hit-source stack x defence/baseline config. Writes topologies/<cfg>/<id>.yaml
and worklists. All real images (run with orchestrator.up --stubs off). Ids are prefixed w17-.

configs (A_leak sources):
  bedge    B-edge    status quo: edge verifier (rfc3986), gateway default profile, executor :v2
  da       D-A       placement origin, executor VERIFY_MODE=origin-routed (gateway does not verify)
  db       D-B       edge verifier VIEW_MAC=on + executor bh-exec-<fw>:defence (DEFENCE=db)
  dc       D-C       verifier HTU_CANON=strict + gateway strict profile
  borigin  B-origin  placement origin, executor VERIFY_MODE=origin-raw
  bstrict  B-strict  gateway strict profile, verifier rfc3986
  bopt     B-optional edge verifier with htm/htu checks disabled (bh-verifier:w17-optional)
E4 (A_client, PDP in the verifier slot) uses the same configs except bopt (an A_client proof always
matches the request, so disabling htm/htu changes nothing)."""
import json, os, yaml
D = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
E4 = os.path.join(D, "..", "e4", "topologies")
CFGS = ["bedge", "da", "db", "dc", "borigin", "bstrict", "bopt"]
GW_SHORT = {"ngx": "nginx", "kng": "kong"}

def topo(tid, gw, fw, ov, cfg, port, vimage="bh-verifier:latest"):
    t = {"id": tid, "gateway": gw, "profile": "default", "placement": "edge", "framework": fw,
         "executor_image": f"bh-exec-{fw}:v2", "override": ov,
         "verifier": {"image": vimage, "canon": "rfc3986", "view_mac": "off"}, "host_port": port}
    if cfg in ("da", "borigin"):
        t["placement"] = "origin"; t["verify_mode"] = "origin-routed" if cfg == "da" else "origin-raw"
        # nginx/kong DEFAULT profiles rewrite Host to executor:8080 upstream, so app-side verification
        # denies every request on the htu authority (the ext-fw A3.2 artefact). Their `recommended`
        # profiles differ only by Host preservation (+ X-Forwarded-*, keep-alive; nginx's other
        # recommended directives equal nginx defaults; kong: preserve_host=true only).
        if gw in ("nginx", "kong"):
            t["profile"] = "recommended"
    elif cfg == "db":
        if fw not in ("fastapi", "express", "spring", "aspnet"):
            return None
        t["executor_image"] = f"bh-exec-{fw}:defence"; t["verifier"]["view_mac"] = "on"
    elif cfg == "dc":
        t["profile"] = "strict"; t["verifier"]["canon"] = "strict"
    elif cfg == "bstrict":
        t["profile"] = "strict"
    elif cfg == "bopt":
        if vimage != "bh-verifier:latest":
            return None
        t["verifier"]["image"] = "bh-verifier:w17-optional"
    return t

def main():
    src = json.load(open(os.path.join(D, "cases", "sources.json")))
    work = {}
    port = 28800
    for cfg in CFGS:
        os.makedirs(os.path.join(D, "topologies", cfg), exist_ok=True)
        for s, m in src.items():
            port += 1
            tid = f"w17-{cfg}-{s}"
            t = topo(tid, m["gateway"], m["framework"], m["override"], cfg, port)
            if t is None: continue
            yaml.safe_dump(t, open(os.path.join(D, "topologies", cfg, tid + ".yaml"), "w"), sort_keys=False)
            work.setdefault("aleak", []).append(f"{cfg} {s} {tid}")
    # E4: one representative topology per root-cause class (e4 REPORT §7), same configs minus bopt
    reps = {"RC1": "w12-allow-ngx-aspnet-def", "RC2": "w12-allow-kng-fastapi-def", "RC3": "w12-block-ngx-aspnet-def",
            "RC4": "w12-block-ngx-express-def", "RC5": "w12-block-ngx-spring-def", "RC6": "w12-block-ngx-rails-def",
            "RC7": "w12-block-kng-spring-def"}
    for cfg in CFGS[:-1]:
        for rc, e4id in reps.items():
            port += 1
            o = yaml.safe_load(open(os.path.join(E4, e4id + ".yaml")))
            tid = f"w17-{cfg}-e4{rc.lower()}-{o['framework']}"
            t = topo(tid, o["gateway"], o["framework"], o["override"], cfg, port, o["verifier"]["image"])
            if t is None: continue
            yaml.safe_dump(t, open(os.path.join(D, "topologies", cfg, tid + ".yaml"), "w"), sort_keys=False)
            work.setdefault("e4", []).append(f"{cfg} {rc} {tid}")
    for k, v in work.items():
        open(os.path.join(D, f"worklist_{k}.txt"), "w").write("\n".join(v) + "\n")
        print(k, len(v))

if __name__ == "__main__":
    main()

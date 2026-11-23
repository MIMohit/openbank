"""W23: write one path-map topology YAML. cfg in {dapm, dbpm, da, db}. nginx only.
  dbpm  D-B + path map  edge, executor :pathmap (DEFENCE=db via VERIFY_MODE=off), verifier VIEW_MAC=on
  dapm  D-A + path map  origin, VERIFY_MODE=origin-routed, executor :pathmap (DEFENCE=off), recommended profile
  db/da  controls using the shipped :defence / :v2 images (no path map) for the before/after contrast
Usage: make_pm_topo.py <cfg> <fw> <id> <port>"""
import sys, yaml

cfg, fw, tid, port = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
t = {"id": tid, "gateway": "nginx", "profile": "default", "placement": "edge", "framework": fw,
     "executor_image": f"bh-exec-{fw}:v2", "override": "off",
     "verifier": {"image": "bh-verifier:latest", "canon": "rfc3986", "view_mac": "off"}, "host_port": port}
if cfg == "dbpm":
    t["executor_image"] = f"bh-exec-{fw}:pathmap"; t["verifier"]["view_mac"] = "on"
elif cfg == "db":
    t["executor_image"] = f"bh-exec-{fw}:defence"; t["verifier"]["view_mac"] = "on"
elif cfg == "dapm":
    t["executor_image"] = f"bh-exec-{fw}:pathmap"; t["placement"] = "origin"
    t["verify_mode"] = "origin-routed"; t["profile"] = "recommended"
elif cfg == "da":
    t["placement"] = "origin"; t["verify_mode"] = "origin-routed"; t["profile"] = "recommended"
yaml.safe_dump(t, sys.stdout, sort_keys=False)

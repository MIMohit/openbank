"""k6 CSV -> <tag>.lat.npy (float32 ms, http_req_duration per request) + <tag>.meta.json (counts)."""
import csv, json, sys, numpy as np
p = sys.argv[1]; lat, ok, fail, t = [], 0, 0, []
with open(p) as f:
    r = csv.DictReader(f)
    for row in r:
        m = row["metric_name"]
        if m == "http_req_duration":
            lat.append(float(row["metric_value"])); t.append(float(row["timestamp"]))
        elif m == "checks":
            if float(row["metric_value"]) == 1: ok += 1
            else: fail += 1
base = p[:-4]
np.save(base + ".lat.npy", np.asarray(lat, dtype=np.float32))
dur = (max(t) - min(t)) if t else 0
json.dump({"n": len(lat), "checks_ok": ok, "checks_fail": fail, "span_s": dur,
           "achieved_rps": (len(lat) / dur) if dur else None}, open(base + ".meta.json", "w"))

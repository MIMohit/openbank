"""A2: leave-one-out over the D-B executor-side canonicalisation steps.

D-B accepts iff  UPPER(view_method) == UPPER(exec_method)  and
                 canon(view_uri) == canon(substitute(route_template, decoded_params))  and no param in {., ..}
(the MAC is a deterministic function of exactly these strings plus jti/jkt, which are identical on both
sides in our runs). We therefore replay the check OFFLINE over the B-edge logs (verifier view + executor
route/params/method for the same jti), using W11's own viewmac.canon_path/substitute, and validate the
model against the LIVE D-B runs (same case set, same images modulo the patch). Each ablation removes one step:

  full        D-B as shipped
  -pct        decoded params inserted without the D-A/D-B percent-encoder (no re-encoding)
  -dot        no dot-segment parameter guard and no remove_dot_segments on the executor side
  -case       case-insensitive comparison (both sides lower-cased)
  -slash      '//' merged on both sides before comparison
  -prefix     mount-prefix map dropped: executor uses the route template WITHOUT its /api/vN mount prefix,
              and both sides compare after stripping a leading /api/vN (lenient version-agnostic map)
  -method     method not bound (path-only MAC)  [reference, not a canonicalisation step]
  -pct-slash  pair: -pct and -slash together (the %2f witnesses need both)
Witnesses: E7 A_leak hits (B-edge) and E4 A_client violations (B-edge, PDP)."""
import collections, csv, glob, importlib.util, json, os, re
D = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
spec = importlib.util.spec_from_file_location("vm", os.path.join(D, "..", "..", "harness", "defence", "fastapi", "viewmac.py"))
import sys; vm = importlib.util.module_from_spec(spec); sys.modules["vm"] = vm; spec.loader.exec_module(vm)
from urllib.parse import quote  # noqa: E402

def jl(p): return [json.loads(l) for l in open(p) if l.strip()] if os.path.exists(p) else []
PFX = re.compile(r"^/api/v\d+(?=/|$)")
def canon_nodot(u):
    path = re.split(r"[?#]", u, maxsplit=1)[0]
    return vm.normalise_pct(path) or "/"

def accept(abl, vmeth, vuri, xmeth, tmpl, params):
    if abl != "-method" and vmeth.upper() != xmeth.upper(): return False
    if abl != "-dot" and any(str(v) in (".", "..") for v in params.values()): return False
    if abl in ("-pct", "-pct-slash"):
        ex = tmpl
        for k, v in params.items(): ex = ex.replace("{" + k + "}", str(v))
    else:
        ex = vm.substitute(tmpl, params)
    if abl == "-prefix": ex = PFX.sub("", ex)
    a = vm.canon_path(vuri)
    b = canon_nodot(ex) if abl == "-dot" else vm.canon_path(ex)
    if abl == "-case": a, b = a.lower(), b.lower()
    if abl in ("-slash", "-pct-slash"): a, b = re.sub("/+", "/", a), re.sub("/+", "/", b)
    if abl == "-prefix": a = PFX.sub("", a)
    return a == b

ABL = ["full", "-pct", "-dot", "-case", "-slash", "-prefix", "-method", "-pct-slash"]

def records():
    """(set, source/rc, class, case_id, kind, view_method, view_uri, exec_method, template, params)"""
    meta = {}
    for f in glob.glob(os.path.join(D, "cases", "*.meta.jsonl")):
        s = os.path.basename(f)[:-11]
        for m in jl(f): meta[(s, m["case_id"])] = m
    for d in sorted(glob.glob(os.path.join(D, "runs", "bedge", "w17-bedge-*"))):
        s = os.path.basename(d)[len("w17-bedge-"):]
        V = {v["jti"]: v for v in jl(f"{d}/verifier.jsonl") if v.get("decision") == "allow"}
        X = {x["jti"]: x for x in jl(f"{d}/executor.jsonl") if x.get("jti")}
        if s.startswith("e4"):
            viol = {v["case_id"] for v in jl(f"{d}/violations.jsonl")}
            for r in jl(f"{d}/runner.jsonl"):
                j = r.get("jti")
                if j in V and j in X and X[j].get("route_template"):
                    kind = "witness" if r["case_id"] in viol else ("legit" if (r.get("vector_id") or "").startswith("legit-") else "other")
                    yield ("E4", s.split("-")[0].upper(), "E4-" + (r.get("vector_id") or "?").split("-")[0], r["case_id"], kind,
                           V[j]["view_method"], V[j]["view_uri"], X[j]["effective_method"], X[j]["route_template"], X[j]["path_params"] or {})
        else:
            H = {h["case_id"] for h in jl(f"{d}/hits.jsonl")}
            for r in jl(f"{d}/runner.jsonl"):
                j = r.get("jti"); m = meta.get((s, r["case_id"]))
                if m and j in V and j in X and X[j].get("route_template"):
                    kind = "witness" if r["case_id"] in H else ("legit" if m["kind"] == "baseline" else "other")
                    yield ("E7", s, m["class"] or "baseline", r["case_id"], kind,
                           V[j]["view_method"], V[j]["view_uri"], X[j]["effective_method"], X[j]["route_template"], X[j]["path_params"] or {})

def frr_records():
    """Legit FRR traffic under B-edge (no defence): would D-B (+ablation) accept it?"""
    for d in sorted(glob.glob(os.path.join(D, "runs", "frr", "bedge", "w17-frr-bedge-*"))):
        fw = d.rsplit("-", 1)[1]
        V = {v["jti"]: v for v in jl(f"{d}/verifier.jsonl") if v.get("decision") == "allow"}
        X = {x["jti"]: x for x in jl(f"{d}/executor.jsonl") if x.get("jti")}
        for r in jl(f"{d}/frr.jsonl"):
            j = r["jti"]
            if r["ok"] and j in V and j in X and X[j].get("route_template"):
                g = "S4-pct-id" if r["scenario"].startswith("S4") else r["scenario"]
                yield ("FRR", fw, "FRR-" + g, r["target"], "legit", V[j]["view_method"], V[j]["view_uri"],
                       X[j]["effective_method"], X[j]["route_template"], X[j]["path_params"] or {})


def live_db():
    """case -> accepted by the executor under live D-B (not denied, executed)."""
    out = {}
    for d in glob.glob(os.path.join(D, "runs", "db", "w17-db-*")):
        s = os.path.basename(d)[len("w17-db-"):]
        V = {v["jti"] for v in jl(f"{d}/verifier.jsonl") if v.get("decision") == "allow"}
        X = {x["jti"]: x for x in jl(f"{d}/executor.jsonl") if x.get("jti")}
        for r in jl(f"{d}/runner.jsonl"):
            j = r.get("jti")
            if j in V and j in X and X[j].get("route_template"):
                out[(s, r["case_id"])] = not X[j].get("denied")
    return out

def main():
    recs = list(records()) + list(frr_records()); live = live_db()
    # validation of the offline model against the live D-B runs
    agree = dis = 0; dis_ex = []
    for st, s, c, cid, kind, *args in recs:
        key = (s.lower() if st == "E4" else s, cid)
        if st == "E4":
            key = next((k for k in live if k[0].startswith(s.lower() + "-") and k[1] == cid), None)
        if key in live:
            if live[key] == accept("full", *args): agree += 1
            else: dis += 1; dis_ex.append((s, cid, live[key]))
    rows, tab = [], collections.Counter()
    tot = collections.Counter()
    for st, s, c, cid, kind, *args in recs:
        res = {a: accept(a, *args) for a in ABL}
        rows.append({"set": st, "source": s, "class": c, "case_id": cid, "kind": kind,
                     "view": f"{args[0]} {args[1]}", "exec": f"{args[2]} {args[3]} {json.dumps(args[4])}", **res})
        if kind in ("witness", "legit"):
            grp = (st, kind, c if (kind == "witness" or st == "FRR") else "legit")
            tot[grp] += 1
            for a in ABL: tab[(grp, a)] += res[a]
    with open(os.path.join(D, "analysis", "a2_long.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    L = [f"Offline D-B model vs live D-B runs: {agree} agree, {dis} disagree" + (f" (e.g. {dis_ex[:3]})" if dis else ""), "",
         "Cells: witnesses that D-B-with-ablation would ACCEPT (= hit comes back); for legit/FRR rows: legit requests accepted (higher = fewer false rejects; FRR rows count only requests B-edge served correctly).", "",
         "| set | group (n) | " + " | ".join(ABL) + " |", "|---|---|" + "---|" * len(ABL)]
    for grp in sorted(tot):
        L.append(f"| {grp[0]} | {grp[2]} {'witness' if grp[1]=='witness' else ''} ({tot[grp]}) | " + " | ".join(str(tab[(grp, a)]) for a in ABL) + " |")
    open(os.path.join(D, "analysis", "a2_tables.md"), "w").write("\n".join(L) + "\n")
    print("\n".join(L))

if __name__ == "__main__":
    main()

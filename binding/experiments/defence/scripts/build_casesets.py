"""E7 A_leak case sets: the CONFIRMED (3/3) hit cases of earlier experiments + every depth-0 baseline,
taken verbatim from <exp>/reruns/<topology>/cases.jsonl, merged per source stack.
Writes cases/<source>.jsonl (runner input) and cases/<source>.meta.jsonl (case_id -> class, provenance)."""
import json, os, collections
E = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(E, "defence", "cases")

def cls(prim_ids, gw, base, exe):
    """Class by mechanism AND observed effect (a `_method` form body sent to /graphql changes the
    operation through body dispatch, not through an override)."""
    p = "|".join(prim_ids)
    if base.startswith("graphql.") and (exe or "").startswith("graphql."): return "G1-body"
    if base.startswith("accountAction.") and (exe or "").startswith("accountAction."):
        return "G1-query(frag-in-query)" if "frag" in p else "G1-query"
    if "pct2f" in p: return "G2-%2f"
    if "frag" in p: return "G1-query(frag-in-query)" if gw == "apisix" else "G2-#"
    if "dot" in p: return "G2-dot"
    if any(x in p for x in ("hdr-xhmo", "fmethod", "qmethod")): return "G1-override"
    if "g1-op" in p: return "G1-query"
    if any(x in p for x in ("gql", "g1-ct")): return "G1-body"
    return "other:" + p

SOURCES = {}
for fw in ("fastapi", "express", "spring", "aspnet"):
    for ov in ("off", "on"):
        SOURCES[f"ngx-{fw}-ov{ov}"] = ("nginx", fw, ov, [("kill", f"w9-nginx-default-edge-{fw}-ov{ov}"),
                                                         ("ext-routes", f"w15r-nginx-default-edge-{fw}-ov{ov}")])
SOURCES["apisix-express-ovoff"] = ("apisix", "express", "off", [("ext-gw", "w13-apisix-default-edge-express-ovoff")])
SOURCES["apisix-aspnet-ovoff"] = ("apisix", "aspnet", "off", [("ext-gw", "w13-apisix-default-edge-aspnet-ovoff")])
SOURCES["kong-fastapi-ovoff"] = ("kong", "fastapi", "off", [("ext-gw", "w13-kong-default-edge-fastapi-ovoff")])

def main():
    os.makedirs(OUT, exist_ok=True)
    summary = {}
    for src, (gw, fw, ov, origins) in SOURCES.items():
        cases, meta, seen = [], [], set()
        for exp, tid in origins:
            d = os.path.join(E, exp, "reruns", tid)
            if os.path.exists(os.path.join(d, "rerun_outcome.jsonl")):
                outc = {json.loads(l)["case_id"]: json.loads(l) for l in open(os.path.join(d, "rerun_outcome.jsonl"))}
                cfile = os.path.join(d, "cases.jsonl")
            else:  # no hits in that topology: still take the experiment's depth-0 baselines
                outc, cfile = {}, os.path.join(E, exp, "cases.jsonl")
            for l in open(cfile):
                c = json.loads(l)
                base = c.get("depth") == 0 or not c["primitive_ids"]
                o = outc.get(c["case_id"])
                if not base and not (o and o["outcome"] == "confirmed"):
                    continue
                key = c["raw_request_b64"]
                if key in seen:
                    continue
                seen.add(key); cases.append(c)
                meta.append({"case_id": c["case_id"], "source_exp": exp, "source_topology": tid,
                             "kind": "baseline" if base else "hit",
                             "class": None if base else cls(c["primitive_ids"], gw, c["base_op_id"], o["exec_op_id"]),
                             "orig_exec_op_id": o["exec_op_id"] if o else None,
                             "base_op_id": c["base_op_id"], "primitive_ids": c["primitive_ids"]})
        with open(os.path.join(OUT, f"{src}.jsonl"), "w") as f:
            for c in cases: f.write(json.dumps(c) + "\n")
        with open(os.path.join(OUT, f"{src}.meta.jsonl"), "w") as f:
            for m in meta: f.write(json.dumps(m) + "\n")
        summary[src] = {"gateway": gw, "framework": fw, "override": ov,
                        "n_cases": len(cases), "classes": dict(collections.Counter(m["class"] or "baseline" for m in meta))}
    json.dump(summary, open(os.path.join(OUT, "sources.json"), "w"), indent=1)
    for k, v in summary.items(): print(k, v["n_cases"], v["classes"])

if __name__ == "__main__":
    main()

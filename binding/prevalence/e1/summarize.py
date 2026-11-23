#!/usr/bin/env python3
"""Aggregate e1/out/*.csv into the tables used in E1_results.md.

Unit of analysis
  * spec file  = one API version in the directory (all parsed files)
  * API        = one APIs.guru API id (provider[:service]); we use the version APIs.guru marks
                 `preferred` in https://api.apis.guru/v2/list.json (snapshot in data/), falling back
                 to the lexicographically last version directory if the API is not in the list.
Writes e1/out/e1_tables.md and e1/out/e1_by_category.csv, e1/out/e1_api_level.csv
"""
import csv
import json
import os
import re
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "..")))  # repo root, for analysis/stats.py
from analysis.stats import wilson_ci  # noqa: E402

OUT = os.path.join(HERE, "out")
LIST = os.path.join(HERE, "..", "data", "apisguru_list.json")
HEALTH = re.compile(r"\b(health|healthcare|medical|medicine|fhir|patient|clinical|hospital|pharma\w*|drug|ehr|hl7)\b", re.I)
STRONG_MECHS = ["M1-query-in-path", "M2-dispatch-param", "M3-header-dispatch", "M4-body-discriminator", "M5-rpc-endpoint"]


def pct(k, n):
    if n == 0:
        return "n/a"
    p, lo, hi = wilson_ci(k, n)
    return f"{100*p:.1f}% [{100*lo:.1f}, {100*hi:.1f}]"


def load():
    specs = list(csv.DictReader(open(os.path.join(OUT, "e1_specs.csv"))))
    flags = list(csv.DictReader(open(os.path.join(OUT, "e1_flags.csv"))))
    errs = list(csv.DictReader(open(os.path.join(OUT, "e1_parse_errors.csv"))))
    return specs, flags, errs


def preferred_files():
    d = json.load(open(LIST))
    pref = {}
    for api, v in d.items():
        ver = v["versions"].get(v["preferred"], {})
        url = ver.get("swaggerYamlUrl") or ver.get("swaggerUrl") or ""
        m = re.search(r"/v2/specs/(.+)$", url)
        if m:
            pref[api] = m.group(1).replace(".json", ".yaml")
    return pref, len(d)


def main():
    specs, flags, errs = load()
    for r in specs:
        for k in ("n_ops", "n_state", "n_keys", "n_flag_strong", "n_keys_collided", "n_keys_collided_state",
                  "n_ops_in_collided_keys", "n_state_ops_in_collided_keys"):
            r[k] = int(r[k])
    by_file = {r["file"]: r for r in specs}
    pref, n_list = preferred_files()
    err_files = {e["file"] for e in errs}

    # choose one spec per API
    by_api = defaultdict(list)
    for r in specs:
        by_api[r["api_id"]].append(r)
    all_api_ids = {r["api_id"] for r in specs} | {
        (lambda p: p[0] + (":" + p[1] if len(p) == 4 else ""))(e["file"].split("/")) for e in errs}
    chosen, how = {}, Counter()
    for api, rows in by_api.items():
        f = pref.get(api)
        if f and f in by_file:
            chosen[api] = by_file[f]
            how["preferred (list.json)"] += 1
        elif f and f in err_files:
            # preferred version failed to parse: fall back to newest parsed version
            chosen[api] = sorted(rows, key=lambda r: r["version"])[-1]
            how["preferred unparseable -> last parsed version"] += 1
        else:
            chosen[api] = sorted(rows, key=lambda r: r["version"])[-1]
            how["not in list.json -> last version dir"] += 1
    apis = list(chosen.values())
    chosen_files = {r["file"] for r in apis}

    sflags = [f for f in flags if f["tier"] == "strong" and f["file"] in chosen_files]
    wflags = [f for f in flags if f["tier"] == "weak" and f["file"] in chosen_files]

    def domain(r):
        cats = set(r["categories"].split("|"))
        out = set(cats)
        if cats & {"financial", "payment"}:
            out.add("FINANCE (financial|payment)")
        if HEALTH.search(r["title"] + " " + r["api_id"]):
            out.add("HEALTH (title/id keyword)")
        return out

    L = []
    w = L.append
    w("## T1 Corpus\n")
    w(f"- spec files found: {len(specs) + len(errs)}; parsed: {len(specs)}; failed: {len(errs)}; "
      f"parsed only after tab/C1-control-char repair: {sum(1 for r in specs if r.get('parse_recovered_tabs') == 'True')}")
    w(f"- distinct API ids (incl. failed files): {len(all_api_ids)}; APIs with >=1 parsed version: {len(apis)}; "
      f"entries in list.json snapshot: {n_list}")
    w(f"- version selection: {dict(how)}")
    w(f"- spec versions (chosen set): {dict(Counter(('OpenAPI 3.x' if r['spec_version'].startswith('3') else 'Swagger 2.0') for r in apis))}\n")

    def headline(rows, label):
        n = len(rows)
        ops = sum(r["n_ops"] for r in rows)
        st = sum(r["n_state"] for r in rows)
        a_any = sum(1 for r in rows if r["n_keys_collided"] > 0)
        a_state = sum(1 for r in rows if r["n_keys_collided_state"] > 0)
        o_coll = sum(r["n_ops_in_collided_keys"] for r in rows)
        s_coll = sum(r["n_state_ops_in_collided_keys"] for r in rows)
        has_state = sum(1 for r in rows if r["n_state"] > 0)
        return (f"| {label} | {n} | {ops} | {st} | {a_any} ({pct(a_any, n)}) | {a_state} ({pct(a_state, has_state)} of {has_state} APIs with state ops) "
                f"| {o_coll} ({pct(o_coll, ops)}) | {s_coll} ({pct(s_coll, st)}) |")

    w("## T2 Headline (one preferred version per API; strong-tier flags; 95% Wilson CIs)\n")
    w("| subset | APIs | operations | state-changing ops | APIs with >=1 collided key | APIs with >=1 state-changing collided key | ops in collided keys | state-changing ops in collided keys |")
    w("|---|---|---|---|---|---|---|---|")
    w(headline(apis, "all"))
    noaws = [r for r in apis if r["provider"] != "amazonaws.com"]
    w(headline(noaws, "excluding amazonaws.com"))
    nobig = [r for r in apis if r["provider"] not in ("amazonaws.com", "azure.com", "googleapis.com", "microsoft.com")]
    w(headline(nobig, "excluding amazonaws/azure/googleapis/microsoft"))
    fin = [r for r in apis if "FINANCE (financial|payment)" in domain(r)]
    w(headline(fin, "finance (financial|payment)"))
    hl = [r for r in apis if "HEALTH (title/id keyword)" in domain(r)]
    w(headline(hl, "health (keyword)"))
    w("")

    # per-mechanism
    w("## T3 Per mechanism (chosen set, strong tier)\n")
    w("| mechanism | APIs | collided keys (method,path) | state-changing keys | flagged spec operations | APIs excl. AWS |")
    w("|---|---|---|---|---|---|")
    mech_rows = []
    for m in STRONG_MECHS:
        fl = [f for f in sflags if f["mech"] == m]
        a = {f["api_id"] for f in fl}
        keys = {(f["file"], f["method"], f["norm_path"]) for f in fl}
        skeys = {(f["file"], f["method"], f["norm_path"]) for f in fl if f["state"] == "True"}
        a2 = {x for x in a if not x.startswith("amazonaws.com")}
        w(f"| {m} | {len(a)} | {len(keys)} | {len(skeys)} | {len(fl)} | {len(a2)} |")
        mech_rows.append((m, len(fl)))
    w("")
    w("Sub-types (strong tier):\n")
    w("| mechanism | sub-type | flagged ops | APIs |")
    w("|---|---|---|---|")
    sub = Counter()
    suba = defaultdict(set)
    for f in sflags:
        s = f["sub"]
        if f["mech"] == "M2-dispatch-param":
            s = s.split(":")[0] + ":" + s.split(":", 1)[1].lower()
        elif f["mech"] == "M4-body-discriminator" and s.startswith("prop:"):
            s = "prop:" + s[5:].lower()
        sub[(f["mech"], s)] += 1
        suba[(f["mech"], s)].add(f["api_id"])
    for (m, s), c in sorted(sub.items(), key=lambda x: (x[0][0], -x[1])):
        w(f"| {m} | {s} | {c} | {len(suba[(m, s)])} |")
    w("")
    w(f"Weak-tier flags (NOT counted above): {len(wflags)} ops in {len({f['api_id'] for f in wflags})} APIs; "
      f"by mechanism {dict(Counter(f['mech'] for f in wflags))}\n")

    # by category
    cat_rows = []
    cats = Counter()
    for r in apis:
        for c in domain(r):
            cats[c] += 1
    for c, n in sorted(cats.items(), key=lambda x: -x[1]):
        rows = [r for r in apis if c in domain(r)]
        a_any = sum(1 for r in rows if r["n_keys_collided"] > 0)
        a_state = sum(1 for r in rows if r["n_keys_collided_state"] > 0)
        st = sum(r["n_state"] for r in rows)
        s_coll = sum(r["n_state_ops_in_collided_keys"] for r in rows)
        ov = sum(1 for r in rows if r["override_documented"] == "True")
        cat_rows.append(dict(category=c, apis=n, apis_collided=a_any, apis_collided_state=a_state,
                             ops=sum(r["n_ops"] for r in rows), state_ops=st, state_ops_in_collided_keys=s_coll,
                             apis_override_documented=ov))
    with open(os.path.join(OUT, "e1_by_category.csv"), "w", newline="") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(cat_rows[0].keys()))
        wr.writeheader()
        wr.writerows(cat_rows)
    w("## T4 By domain (APIs.guru x-apisguru-categories; an API can carry several; FINANCE/HEALTH are derived)\n")
    w("| category | APIs | APIs w/ collided key | APIs w/ state-changing collided key | state ops | state ops in collided keys | override documented |")
    w("|---|---|---|---|---|---|---|")
    for c in cat_rows:
        if c["apis"] < 10 and not c["category"].startswith(("FINANCE", "HEALTH")):
            continue
        w(f"| {c['category']} | {c['apis']} | {c['apis_collided']} ({pct(c['apis_collided'], c['apis'])}) | {c['apis_collided_state']} "
          f"| {c['state_ops']} | {c['state_ops_in_collided_keys']} ({pct(c['state_ops_in_collided_keys'], c['state_ops'])}) | {c['apis_override_documented']} |")
    w("\n(categories with < 10 APIs omitted from this table; all are in e1_by_category.csv)\n")

    # override documented
    ov = [r for r in apis if r["override_documented"] == "True"]
    w(f"## T5 Method override documented in the spec: {len(ov)} of {len(apis)} APIs ({pct(len(ov), len(apis))})\n")
    w("| API | evidence |")
    w("|---|---|")
    for r in sorted(ov, key=lambda r: r["api_id"]):
        w(f"| {r['api_id']} | {r['override_evidence'][:160]} |")
    w("")

    # rpc endpoints
    rpc = [f for f in sflags if f["mech"] == "M5-rpc-endpoint"]
    w(f"## T6 GraphQL / JSON-RPC single endpoints (strong tier): {len({f['api_id'] for f in rpc})} APIs\n")
    w("| API | method | path | signal |")
    w("|---|---|---|---|")
    for f in sorted(rpc, key=lambda f: (f["api_id"], f["norm_path"])):
        w(f"| {f['api_id']} | {f['method']} | `{f['norm_path']}` | {f['sub']} |")
    w("")

    # top APIs by collided state-changing keys (non-AWS)
    w("## T7 Largest non-AWS APIs by state-changing operations inside collided keys\n")
    w("| API | categories | state ops | state ops in collided keys | mechanisms |")
    w("|---|---|---|---|---|")
    for r in sorted(noaws, key=lambda r: -r["n_state_ops_in_collided_keys"])[:25]:
        if r["n_state_ops_in_collided_keys"] == 0:
            break
        w(f"| {r['api_id']} | {r['categories']} | {r['n_state']} | {r['n_state_ops_in_collided_keys']} | {r['mechs']} |")
    w("")

    # all-files variant (sensitivity)
    w("## T8 Sensitivity: all parsed spec files (every version counted)\n")
    w("| subset | spec files | operations | state-changing ops | files with >=1 collided key | files with >=1 state-changing collided key | ops in collided keys | state-changing ops in collided keys |")
    w("|---|---|---|---|---|---|---|---|")
    w(headline(specs, "all files"))
    w(headline([r for r in specs if r["provider"] != "amazonaws.com"], "all files excl. AWS"))

    open(os.path.join(OUT, "e1_tables.md"), "w").write("\n".join(L) + "\n")
    with open(os.path.join(OUT, "e1_api_level.csv"), "w", newline="") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(apis[0].keys()))
        wr.writeheader()
        wr.writerows(sorted(apis, key=lambda r: r["api_id"]))
    print("\n".join(L))


if __name__ == "__main__":
    main()

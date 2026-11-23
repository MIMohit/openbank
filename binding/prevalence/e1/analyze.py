#!/usr/bin/env python3
"""E1: G1 (under-binding by design) prevalence over the APIs.guru openapi-directory.

For every spec file (OpenAPI 2.0 / 3.x) we compute, per spec:
  * operations (method x path-template entries; methods get/put/post/delete/options/head/patch/trace)
  * state-changing operations (POST/PUT/PATCH/DELETE)
  * "binding collisions": a DPoP-style view key K = (METHOD, path template without query/fragment)
    that the spec maps to >= 2 semantically different operations, distinguished only by
    something outside K.  Detected mechanisms (see README / E1_results.md for exact rules):
      M1 query-in-path   several operations whose OpenAPI path keys differ only after '?' or '#'
                         (AWS-style '/?Action=X', '/#X-Amz-Target=Y'); grouped by normalised key
      M2 dispatch-param  one operation with a query/form/header parameter whose NAME is a
                         dispatcher name (action, op, cmd, ...) and whose schema has an enum of >= 2
                         values (strong tier) or no enum (weak tier, reported separately, not counted)
      M3 header-dispatch header parameter X-Amz-Target / SOAPAction / X-Goog-*Method etc.
      M4 body-discriminator request body schema (JSON/form) that is a oneOf/anyOf with >= 2
                         branches carrying a discriminator, or has a top-level property named like a
                         dispatcher (action, op, operation, command, method, type*) with enum >= 2
      M5 rpc-endpoint    GraphQL / JSON-RPC single endpoints (path heuristics or body schema with
                         jsonrpc+method, or query+variables/operationName)
  * documented method-override (X-HTTP-Method-Override & friends as header params, `_method`
    param, or mention in description text)

Outputs (to --out):
  e1_specs.csv        one row per spec file
  e1_flags.csv        one row per flagged (spec, method, normalised path, mechanism)
  e1_parse_errors.csv files that failed to parse
Usage:  python -I e1/analyze.py --root data/openapi-directory/APIs --out e1/out --procs 4
"""
import argparse
import csv
import json
import os
import re
import sys
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
from concurrent.futures.process import BrokenProcessPool

import yaml

_Base = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


class Loader(_Base):
    """SafeLoader that keeps timestamps as strings and tolerates the YAML '=' (value) tag;
    both otherwise abort parsing of otherwise valid OpenAPI documents in this corpus."""


Loader.add_constructor("tag:yaml.org,2002:timestamp", lambda l, n: l.construct_scalar(n))
Loader.add_constructor("tag:yaml.org,2002:value", lambda l, n: l.construct_scalar(n))
C1 = re.compile(rb"\xc2[\x80-\x9f]")

METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
STATE = {"post", "put", "patch", "delete"}

# Dispatcher parameter names (case-insensitive, exact after stripping leading '_' / '$').
DISPATCH_NAMES = {
    "action", "op", "operation", "operationname", "method", "cmd", "command", "func",
    "function", "do", "task", "verb", "call", "rpc", "request", "actiontype", "action_type",
}
# Names we treat as *not* a dispatcher even though they contain the word (common false friends)
HEADER_DISPATCH = re.compile(r"^(x-amz-target|soapaction|x-goog-.*method.*|x-target|x-action|x-operation)$", re.I)
OVERRIDE_HEADER = re.compile(r"^x-(http-)?method(-override)?$|^x-http-method-override$|^x-method-override$", re.I)
OVERRIDE_PARAM = re.compile(r"^_?method$|^_?http_method$|^x-http-method-override$", re.I)
OVERRIDE_TEXT = re.compile(r"x-http-method-override|x-method-override|x-http-method\b|method[- ]override|\b_method=", re.I)
GRAPHQL_PATH = re.compile(r"(^|/)(graphql|gql)(/|$|\.)", re.I)
JSONRPC_PATH = re.compile(r"(^|/)(json-?rpc|rpc|xmlrpc|xml-rpc)(/|$|\.)", re.I)
BODY_DISPATCH_PROP = re.compile(r"^_?(action|op|operation|operationname|command|cmd|method|function|task|verb|action_?type)$", re.I)


def norm_path(p):
    """Strip query / fragment parts that some specs put in the path key."""
    cut = len(p)
    for ch in ("?", "#"):
        i = p.find(ch)
        if i != -1:
            cut = min(cut, i)
    q = p[cut:]
    base = p[:cut] or "/"
    return base, q


class Resolver:
    def __init__(self, doc):
        self.doc = doc

    def get(self, node, depth=0):
        seen = 0
        while isinstance(node, dict) and "$ref" in node and isinstance(node["$ref"], str) and seen < 20:
            ref = node["$ref"]
            if not ref.startswith("#/"):
                return {}
            cur = self.doc
            try:
                for part in ref[2:].split("/"):
                    part = part.replace("~1", "/").replace("~0", "~")
                    cur = cur[part]
            except (KeyError, TypeError, IndexError):
                return {}
            node = cur
            seen += 1
        return node if isinstance(node, (dict, list)) else {}


def enum_values(schema, R):
    schema = R.get(schema)
    if not isinstance(schema, dict):
        return None
    if isinstance(schema.get("enum"), list):
        return schema["enum"]
    if schema.get("const") is not None:
        return [schema["const"]]
    items = schema.get("items")
    if items is not None and schema.get("type") == "array":
        return None  # array of enums is a multi-select filter, not a dispatcher
    for k in ("oneOf", "anyOf"):
        if isinstance(schema.get(k), list):
            vals = []
            for s in schema[k]:
                v = enum_values(s, R)
                if v:
                    vals.extend(v)
            if vals:
                return vals
    return None


def param_list(path_item, op, R):
    out = {}
    for src in (path_item.get("parameters", []), op.get("parameters", [])):
        if not isinstance(src, list):
            continue
        for p in src:
            p = R.get(p)
            if not isinstance(p, dict) or "name" not in p:
                continue
            out[(str(p.get("in")), str(p["name"]))] = p
    return list(out.values())


def param_enum(p, R):
    if "schema" in p:
        return enum_values(p["schema"], R)
    if isinstance(p.get("enum"), list):  # swagger 2 non-body param
        return p["enum"]
    return None


def body_schemas(op, params, R, is_v3):
    """Yield (media_type, schema) for request bodies."""
    if is_v3:
        rb = R.get(op.get("requestBody", {}))
        content = rb.get("content", {}) if isinstance(rb, dict) else {}
        if isinstance(content, dict):
            for mt, m in content.items():
                m = R.get(m) if isinstance(m, dict) else {}
                if isinstance(m, dict) and "schema" in m:
                    yield str(mt), R.get(m["schema"])
    else:
        for p in params:
            if p.get("in") == "body" and "schema" in p:
                yield "application/json", R.get(p["schema"])


def schema_props(schema, R, depth=0):
    """Top-level properties of a schema, merging allOf."""
    schema = R.get(schema)
    props = {}
    if not isinstance(schema, dict) or depth > 4:
        return props
    if isinstance(schema.get("properties"), dict):
        props.update(schema["properties"])
    for s in schema.get("allOf", []) or []:
        props.update(schema_props(s, R, depth + 1))
    return props


def text_of(*objs):
    parts = []
    for o in objs:
        if isinstance(o, dict):
            for k in ("summary", "description"):
                v = o.get(k)
                if isinstance(v, str):
                    parts.append(v)
    return "\n".join(parts)


def analyse(path_rel_root):
    path, root = path_rel_root
    rel = os.path.relpath(path, root)
    recovered = False
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
        if path.endswith(".json"):
            doc = json.loads(raw)
        else:
            try:
                doc = yaml.load(raw, Loader=Loader)
            except yaml.YAMLError:
                # Common corpus defect: TAB characters inside block scalars. Retry once with
                # tabs expanded; the result is flagged as 'recovered' in e1_specs.csv.
                doc = yaml.load(C1.sub(b" ", raw.replace(b"\t", b"    ")), Loader=Loader)
                recovered = True
        if not isinstance(doc, dict):
            raise ValueError("top-level is not a mapping")
    except Exception as e:  # tolerate & count
        return {"error": f"{type(e).__name__}: {str(e)[:200]}", "file": rel}

    try:
        res = _analyse_doc(doc, rel)
        res["row"]["parse_recovered_tabs"] = recovered
        return res
    except Exception as e:
        return {"error": f"analysis {type(e).__name__}: {str(e)[:200]} {traceback.format_exc()[-300:]}", "file": rel}


def _analyse_doc(doc, rel):
    R = Resolver(doc)
    is_v3 = str(doc.get("openapi", "")).startswith("3")
    ver = str(doc.get("openapi") or doc.get("swagger") or "?")
    info = doc.get("info", {}) if isinstance(doc.get("info"), dict) else {}
    cats = info.get("x-apisguru-categories") or []
    if not isinstance(cats, list):
        cats = [str(cats)]
    origin = info.get("x-origin")
    parts = rel.split(os.sep)
    provider = parts[0]
    # APIs/<provider>/[<service>/]<version>/<file>
    if len(parts) == 4:
        service, version = parts[1], parts[2]
    else:
        service, version = "", parts[1] if len(parts) > 2 else ""
    api_id = provider + (":" + service if service else "")

    paths = doc.get("paths") or {}
    if not isinstance(paths, dict):
        paths = {}

    ops = []  # (method, rawpath, normpath, query_part, op, path_item)
    for rawp, item in paths.items():
        item = R.get(item)
        if not isinstance(item, dict):
            continue
        base, q = norm_path(str(rawp))
        for m in METHODS:
            if m in item and isinstance(item[m], dict):
                ops.append((m, str(rawp), base, q, item[m], item))

    n_ops = len(ops)
    n_state = sum(1 for o in ops if o[0] in STATE)
    flags = []

    # ---- M1: several path keys collapsing to one (method, normalised path) ----
    groups = {}
    for o in ops:
        groups.setdefault((o[0], o[2]), []).append(o)
    m1_ops = set()
    for (m, base), lst in groups.items():
        if len(lst) >= 2:
            qs = sorted(set(o[3] for o in lst))
            # dispatch component: query (?), fragment (#)
            for o in lst:
                suf = o[3]
                if re.search(r"x-amz-target", suf, re.I):
                    kind = "header(X-Amz-Target, encoded as #fragment)"
                elif suf.startswith("#"):
                    kind = "query(encoded as #fragment)"
                elif suf.startswith("?"):
                    kind = "query"
                else:
                    kind = "base op of a query-variant group (no suffix)"
                m1_ops.add((o[0], o[1]))
                flags.append(dict(mech="M1-query-in-path", sub=kind, method=m.upper(), norm_path=base,
                                  raw_path=o[1], opid=str(o[4].get("operationId", "")),
                                  evidence=f"{len(lst)} ops share key; this one: {o[1][:160]}",
                                  n_variants=len(lst), state=m in STATE, tier="strong"))

    override_doc = False
    override_evidence = []
    for (m, rawp, base, q, op, item) in ops:
        params = param_list(item, op, R)
        # ---- method override documented ----
        for p in params:
            nm = str(p.get("name", ""))
            loc = str(p.get("in", ""))
            # an override only makes sense on a request whose method can be rewritten (POST in every
            # framework we surveyed); a filter parameter called http_method on a GET is not an override
            if m == "post" and ((loc == "header" and OVERRIDE_HEADER.match(nm)) or
                                (loc in ("query", "formData") and OVERRIDE_PARAM.match(nm) and nm.lower() != "method")):
                override_doc = True
                override_evidence.append(f"{m.upper()} {rawp} param {loc}:{nm}")
        t = text_of(op, item)
        if OVERRIDE_TEXT.search(t):
            override_doc = True
            override_evidence.append(f"{m.upper()} {rawp} text")

        if (m, rawp) in m1_ops:
            continue  # already counted; avoid double counting the same op

        # ---- M2 dispatch parameter ----
        flagged_here = False
        for p in params:
            nm = str(p.get("name", ""))
            loc = str(p.get("in", ""))
            if loc not in ("query", "formData", "header"):
                continue
            key = nm.lower().lstrip("_$")
            if loc == "header" and HEADER_DISPATCH.match(nm):
                ev = param_enum(p, R)
                flags.append(dict(mech="M3-header-dispatch", sub=nm, method=m.upper(), norm_path=base,
                                  raw_path=rawp, opid=str(op.get("operationId", "")),
                                  evidence=f"header {nm} enum={json.dumps(ev)[:200] if ev else None} required={p.get('required')}",
                                  n_variants=len(set(map(str, ev))) if ev else 0, state=m in STATE,
                                  tier="strong" if ev and len(set(map(str, ev))) >= 2 else "weak"))
                flagged_here = True
                continue
            if key in DISPATCH_NAMES and not OVERRIDE_PARAM.match(nm) or (key == "method" and loc != "header"):
                ev = param_enum(p, R)
                nv = len(set(map(str, ev))) if ev else 0
                flags.append(dict(mech="M2-dispatch-param", sub=f"{loc}:{nm}", method=m.upper(), norm_path=base,
                                  raw_path=rawp, opid=str(op.get("operationId", "")),
                                  evidence=f"{loc} param '{nm}' enum={json.dumps(ev, default=str)[:200] if ev else None} required={p.get('required')}",
                                  n_variants=nv, state=m in STATE, tier="strong" if nv >= 2 else "weak"))
                flagged_here = True

        # ---- M4 body discriminator / M5 rpc body ----
        bodies = list(body_schemas(op, params, R, is_v3))
        rpc = None
        for mt, sch in bodies:
            if not isinstance(sch, dict):
                continue
            props = schema_props(sch, R)
            lprops = {str(k).lower(): k for k in props}
            if "jsonrpc" in lprops and "method" in lprops:
                rpc = ("jsonrpc-body", f"body props jsonrpc+method; method enum={json.dumps(enum_values(props[lprops['method']], R), default=str)[:150]}")
            elif "query" in lprops and ("variables" in lprops or "operationname" in lprops):
                rpc = ("graphql-body", "body props query+variables/operationName")
            alts = None
            for k in ("oneOf", "anyOf"):
                if isinstance(sch.get(k), list) and len(sch[k]) >= 2:
                    alts = (k, len(sch[k]), sch.get("discriminator"))
            if alts and alts[2]:
                flags.append(dict(mech="M4-body-discriminator", sub=f"{alts[0]}+discriminator", method=m.upper(),
                                  norm_path=base, raw_path=rawp, opid=str(op.get("operationId", "")),
                                  evidence=f"{mt} {alts[0]} with {alts[1]} branches, discriminator={json.dumps(alts[2], default=str)[:150]}",
                                  n_variants=alts[1], state=m in STATE, tier="strong"))
                flagged_here = True
            elif alts:
                flags.append(dict(mech="M4-body-discriminator", sub=f"{alts[0]}-no-discriminator", method=m.upper(),
                                  norm_path=base, raw_path=rawp, opid=str(op.get("operationId", "")),
                                  evidence=f"{mt} {alts[0]} with {alts[1]} branches, no discriminator",
                                  n_variants=alts[1], state=m in STATE, tier="weak"))
            for lk, k in lprops.items():
                if BODY_DISPATCH_PROP.match(lk) and not rpc:
                    ev = enum_values(props[k], R)
                    nv = len(set(map(str, ev))) if ev else 0
                    if nv >= 2:
                        flags.append(dict(mech="M4-body-discriminator", sub=f"prop:{k}", method=m.upper(),
                                          norm_path=base, raw_path=rawp, opid=str(op.get("operationId", "")),
                                          evidence=f"{mt} body property '{k}' enum={json.dumps(ev, default=str)[:200]}",
                                          n_variants=nv, state=m in STATE, tier="strong"))
                        flagged_here = True
        if rpc is None:
            if GRAPHQL_PATH.search(base):
                rpc = ("graphql-path", f"path {base}")
            elif JSONRPC_PATH.search(base):
                rpc = ("jsonrpc-path", f"path {base}")
        if rpc:
            flags.append(dict(mech="M5-rpc-endpoint", sub=rpc[0], method=m.upper(), norm_path=base, raw_path=rawp,
                              opid=str(op.get("operationId", "")), evidence=rpc[1], n_variants=0,
                              state=m in STATE, tier="strong" if rpc[0].endswith("body") or m == "post" else "weak"))

    # Global text mention of override (info.description)
    if OVERRIDE_TEXT.search(text_of(info)):
        override_doc = True
        override_evidence.append("info.description text")

    # de-duplicate (same op flagged once per media type)
    seen, dd = set(), []
    for f in flags:
        k = (f["method"], f["raw_path"], f["mech"], f["sub"])
        if k not in seen:
            seen.add(k)
            dd.append(f)
    flags = dd
    strong = [f for f in flags if f["tier"] == "strong"]
    keys_strong = {(f["method"], f["norm_path"]) for f in strong}
    keys_strong_state = {(f["method"], f["norm_path"]) for f in strong if f["state"]}
    distinct_keys = {(o[0], o[2]) for o in ops}
    title = str(info.get("title", ""))[:120].replace("\n", " ")
    row = dict(file=rel, api_id=api_id, provider=provider, service=service, version=version, title=title,
               spec_version=ver, categories="|".join(map(str, cats)) or "uncategorized",
               origin_format=(origin[0].get("format") if isinstance(origin, list) and origin and isinstance(origin[0], dict) else ""),
               n_ops=n_ops, n_state=n_state, n_keys=len(distinct_keys),
               n_flag_strong=len(strong), n_keys_collided=len(keys_strong), n_keys_collided_state=len(keys_strong_state),
               n_ops_in_collided_keys=sum(1 for o in ops if (o[0].upper(), o[2]) in keys_strong),
               n_state_ops_in_collided_keys=sum(1 for o in ops if o[0] in STATE and (o[0].upper(), o[2]) in keys_strong),
               mechs="|".join(sorted({f["mech"] for f in strong})),
               override_documented=override_doc, override_evidence="; ".join(override_evidence[:5]))
    for f in flags:
        f["file"] = rel
        f["api_id"] = api_id
        f["categories"] = row["categories"]
    return {"row": row, "flags": flags}


def find_specs(root):
    for d, _, files in os.walk(root):
        for f in files:
            if f in ("openapi.yaml", "swagger.yaml", "openapi.json", "swagger.json"):
                yield os.path.join(d, f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--procs", type=int, default=4)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    files = sorted(find_specs(a.root))
    if a.limit:
        files = files[: a.limit]
    print(f"spec files: {len(files)}", file=sys.stderr)
    rows, flags, errs = [], [], []

    def collect(res):
        if "error" in res:
            errs.append(res)
        else:
            rows.append(res["row"])
            flags.extend(res["flags"])

    BIG = 15 * 1024 * 1024  # files above this are parsed one at a time (memory: the corpus has a 58 MB YAML)
    small = [f for f in files if os.path.getsize(f) <= BIG]
    big = [f for f in files if os.path.getsize(f) > BIG]
    done = 0
    with ProcessPoolExecutor(a.procs) as ex:
        futs = {ex.submit(analyse, (f, a.root)): f for f in small}
        for fut in as_completed(futs):
            try:
                collect(fut.result())
            except BrokenProcessPool:
                raise SystemExit("worker pool died (likely memory pressure); re-run with fewer --procs")
            done += 1
            if done % 500 == 0:
                print(f"  {done}/{len(files)}", file=sys.stderr)
    for f in big:
        print(f"  big file (sequential, own process): {os.path.relpath(f, a.root)}", file=sys.stderr)
        try:
            with ProcessPoolExecutor(1) as ex:
                collect(ex.submit(analyse, (f, a.root)).result())
        except BrokenProcessPool:
            errs.append({"file": os.path.relpath(f, a.root), "error": "worker process killed while parsing (memory)"})
    rows.sort(key=lambda r: r["file"])
    flags.sort(key=lambda r: (r["file"], r["method"], r["raw_path"], r["mech"]))
    errs.sort(key=lambda r: r["file"])

    def dump(name, data, fields=None):
        with open(os.path.join(a.out, name), "w", newline="") as fh:
            if not data:
                fh.write("")
                return
            w = csv.DictWriter(fh, fieldnames=fields or list(data[0].keys()))
            w.writeheader()
            w.writerows(data)

    dump("e1_specs.csv", rows)
    dump("e1_flags.csv", flags, ["file", "api_id", "categories", "mech", "sub", "tier", "method", "norm_path",
                                 "raw_path", "opid", "state", "n_variants", "evidence"])
    dump("e1_parse_errors.csv", errs, ["file", "error"])
    print(f"parsed {len(rows)} specs, {len(errs)} errors, {len(flags)} flags", file=sys.stderr)


if __name__ == "__main__":
    main()

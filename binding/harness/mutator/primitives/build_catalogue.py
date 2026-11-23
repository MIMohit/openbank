"""Generate the primitive catalogue YAML files (g1.yaml, g2.yaml, g3.yaml).

The YAML files are the committed source of truth that `compose.py` loads (CONTRACT §6).
This script is the authoring tool: it encodes the structured primitive data once and dumps
readable YAML, so the ~80 entries stay consistent (ids, citations, transform specs). Re-run
after editing: `python build_catalogue.py`.

Primitive schema (per CONTRACT §6):
  id          unique string
  class       short category
  description human-readable
  source      paper / advisory / RFC citation
  transform   ordered list of {fn, args}  (see mutator/transforms.py)
  applies_to  optional compatibility selector:
                omitted           -> every base op
                requires_tags: [] -> base op must have ALL these tags
                op_ids: []        -> only these base op ids
"""
from __future__ import annotations

import os
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))

# Citation shorthands reused below.
SRC_OVERRIDE = ("Framework method-override middleware: Rails Rack::MethodOverride, "
                "Symfony HttpMethodParameterOverride/_method, Laravel @method, "
                "Spring HiddenHttpMethodFilter; method confusion in HDHunter (USENIX Sec 2025).")
SRC_WAFFLED = ("WAFFLED: Exploiting Parsing Discrepancies to Bypass WAFs "
               "(Akhavani et al., arXiv:2503.10846) — security layer vs. framework "
               "content-type parsing differential.")
SRC_DISPATCH = "G1 query/body dispatch (CONTRACT §3): proof covers method+URI, not the dispatch key."
SRC_TREQS = ("T-Reqs: HTTP Request Smuggling with Differential Fuzzing "
             "(Jabiyev et al., ACM CCS 2021, DOI 10.1145/3460120.3485384).")
SRC_GUDIFU = ("Gudifu: Guided Differential Fuzzing for HTTP Request Parsing Discrepancies "
              "(Jabiyev et al., RAID 2024, DOI 10.1145/3678890.3678904).")
SRC_HDHUNTER = ("HDHunter / 'The Silent Danger in HTTP' (Mu et al., USENIX Security 2025).")
SRC_RFC3986 = "RFC 3986 §3.3/§6 path and percent-encoding normalisation (dot-segments, %2e, %2f)."
SRC_RFC7230 = "RFC 7230 §5.3–5.4 request-target forms and Host handling (absolute-form, duplicate Host)."
SRC_ISTIO = ("Istio/Envoy CVE-2021-31920: ext_authz path-confusion authorization bypass "
             "(path mismatch between Envoy and backend).")
SRC_TRAEFIK = ("Traefik gateway path/authorization CVEs: CVE-2026-40912, CVE-2026-88009, "
               "CVE-2026-39858 (gateway vs. backend path interpretation).")
SRC_OPA = ("opa-envoy CVE-2026-26205: OPA-Envoy ext_authz path evaluated differently "
           "from the backend route.")
SRC_XFCC = ("Envoy XFCC / Istio CVE-2021-31920 and RFC 9440 (Client-Cert/Client-Cert-Chain): "
            "spoofable client-identity headers when not stripped at the trust boundary.")
SRC_HEADER_SMUGGLE = ("D. Thatcher, 'Practical HTTP Header Smuggling' (Black Hat EU 2021) — "
                      "duplicate/underscore/case header variants bypass gateway checks.")
SRC_REWRITE = ("X-Original-URL / X-Rewrite-URL / X-Forwarded-Prefix rewrite headers "
               "(framework & reverse-proxy routing overrides; header-smuggling bypass class).")

TARGET_METHODS = ["PUT", "DELETE", "POST", "PATCH", "GET"]
OVERRIDE_HEADERS = [
    ("X-HTTP-Method-Override", "xhmo"),
    ("X-Method-Override", "xmo"),
    ("X-HTTP-Method", "xhm"),
]

# Attacker-controlled example material.
SPOOF_XFCC = ('By=spiffe://cluster.local/ns/default/sa/admin;'
              'Hash=0000;Subject="CN=admin,O=bank";URI=spiffe://cluster.local/ns/default/sa/admin')
SPOOF_PEM = "MIIB...SPOOFED-CERT...IDAQAB"
SPOOF_JKT = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"  # example RFC 7638 thumbprint
SPOOF_VIEW = "v1;c3Bvb2ZlZC1tYWMtZG9lcy1ub3QtdmVyaWZ5"     # forged X-Verified-View (D-B)


def g1():
    prims = []
    # 1. Override headers x target methods
    for hname, hslug in OVERRIDE_HEADERS:
        for m in TARGET_METHODS:
            prims.append({
                "id": f"g1-hdr-{hslug}-{m.lower()}",
                "class": "method-override-header",
                "description": f"Inject {hname}: {m} to flip the effective verb while the "
                               f"proof binds the on-the-wire method.",
                "source": SRC_OVERRIDE,
                "transform": [{"fn": "add_header", "args": {"name": hname, "value": m}}],
            })
    # 2. _method query param x methods
    for m in TARGET_METHODS:
        prims.append({
            "id": f"g1-qmethod-{m.lower()}",
            "class": "method-override-query",
            "description": f"Add ?_method={m} query override (Rails/Laravel/Symfony style).",
            "source": SRC_OVERRIDE,
            "transform": [{"fn": "add_query_param", "args": {"key": "_method", "value": m}}],
        })
    # 3. _method form body x methods
    for m in TARGET_METHODS:
        prims.append({
            "id": f"g1-fmethod-{m.lower()}",
            "class": "method-override-body",
            "description": f"Replace body with a urlencoded form carrying _method={m}.",
            "source": SRC_OVERRIDE,
            "transform": [{"fn": "set_form_body", "args": {"fields": {"_method": m}}}],
        })
    # 4. content-type switches (WAFFLED)
    prims += [
        {"id": "g1-ct-urlencoded", "class": "content-type-switch",
         "description": "Keep a JSON body but relabel Content-Type as "
                        "application/x-www-form-urlencoded (WAFFLED CT differential).",
         "source": SRC_WAFFLED,
         "applies_to": {"requires_tags": ["with_body"]},
         "transform": [{"fn": "set_content_type",
                        "args": {"value": "application/x-www-form-urlencoded"}}]},
        {"id": "g1-ct-textplain", "class": "content-type-switch",
         "description": "Relabel the body Content-Type as text/plain so the WAF/verifier "
                        "skips body parsing but the framework still parses it.",
         "source": SRC_WAFFLED,
         "applies_to": {"requires_tags": ["with_body"]},
         "transform": [{"fn": "set_content_type", "args": {"value": "text/plain"}}]},
        {"id": "g1-ct-charset-confuse", "class": "content-type-switch",
         "description": "Append a bogus charset/boundary to Content-Type to trigger "
                        "parser disagreement.",
         "source": SRC_WAFFLED,
         "applies_to": {"requires_tags": ["with_body"]},
         "transform": [{"fn": "set_content_type",
                        "args": {"value": "application/json; charset=utf-7;boundary=x"}}]},
    ]
    # 5. query op switch (actions)
    action_req = {"requires_tags": ["action"]}
    prims += [
        {"id": "g1-op-freeze-to-close", "class": "query-dispatch-switch",
         "description": "Switch ?op=freeze to op=close: proof binds the path /actions, "
                        "not the destructive op selector.",
         "source": SRC_DISPATCH, "applies_to": action_req,
         "transform": [{"fn": "set_query_param", "args": {"key": "op", "value": "close"}}]},
        {"id": "g1-op-freeze-to-unknown", "class": "query-dispatch-switch",
         "description": "Switch ?op=freeze to an unknown op value.",
         "source": SRC_DISPATCH, "applies_to": action_req,
         "transform": [{"fn": "set_query_param", "args": {"key": "op", "value": "wipe"}}]},
        {"id": "g1-op-remove", "class": "query-dispatch-switch",
         "description": "Remove the ?op selector entirely.",
         "source": SRC_DISPATCH, "applies_to": action_req,
         "transform": [{"fn": "remove_query_param", "args": {"key": "op"}}]},
        {"id": "g1-op-dup-close", "class": "query-dispatch-switch",
         "description": "Add a second op=close so op=freeze&op=close — last-wins parser "
                        "differential selects the destructive op.",
         "source": SRC_DISPATCH, "applies_to": action_req,
         "transform": [{"fn": "add_query_param", "args": {"key": "op", "value": "close"}}]},
        {"id": "g1-op-case-close", "class": "query-dispatch-switch",
         "description": "Case-variant op=CLOSE to probe case-insensitive dispatch.",
         "source": SRC_DISPATCH, "applies_to": action_req,
         "transform": [{"fn": "set_query_param", "args": {"key": "op", "value": "CLOSE"}}]},
    ]
    # 6. graphql operationName swaps
    gql_req = {"requires_tags": ["graphql"]}
    prims += [
        {"id": "g1-gql-to-deleteProfile", "class": "graphql-operation-switch",
         "description": "Swap operationName getProfile -> deleteProfile; proof binds "
                        "POST /graphql, not the operation.",
         "source": SRC_DISPATCH, "applies_to": gql_req,
         "transform": [{"fn": "set_json_field",
                        "args": {"field": "operationName", "value": "deleteProfile"}}]},
        {"id": "g1-gql-to-unknown", "class": "graphql-operation-switch",
         "description": "Swap operationName to an unknown operation.",
         "source": SRC_DISPATCH, "applies_to": gql_req,
         "transform": [{"fn": "set_json_field",
                        "args": {"field": "operationName", "value": "wipeEverything"}}]},
        {"id": "g1-gql-null", "class": "graphql-operation-switch",
         "description": "Set operationName to null to force default/first-operation "
                        "selection in the executor.",
         "source": SRC_DISPATCH, "applies_to": gql_req,
         "transform": [{"fn": "set_json_field",
                        "args": {"field": "operationName", "value": None}}]},
        {"id": "g1-gql-dup-deleteProfile", "class": "graphql-operation-switch",
         "description": "Inject a duplicate operationName=deleteProfile JSON key "
                        "(duplicate-key last/first-wins differential).",
         "source": SRC_DISPATCH, "applies_to": gql_req,
         "transform": [{"fn": "inject_duplicate_json_field",
                        "args": {"field": "operationName", "value": "deleteProfile"}}]},
    ]
    return prims


def g2():
    prims = []

    def p(pid, cls, desc, src, transform, applies_to=None):
        d = {"id": pid, "class": cls, "description": desc, "source": src,
             "transform": transform}
        if applies_to:
            d["applies_to"] = applies_to
        return d

    # dot-segment family
    for pid, token, label in [
        ("g2-dotdot-literal", "../", "literal ../"),
        ("g2-dot-literal", "./", "literal ./"),
        ("g2-dotdot-enc", "%2e%2e/", "percent-encoded %2e%2e/"),
        ("g2-dot-enc", "%2e/", "percent-encoded %2e/"),
        ("g2-dotdot-mixed", "..%2f", "mixed ..%2f"),
        ("g2-dotdot-encslash", "%2e%2e%2f", "fully encoded %2e%2e%2f"),
    ]:
        prims.append(p(pid, "dot-segment",
                       f"Insert a {label} dot-segment before the last path segment; "
                       f"verifier and router normalise it differently.",
                       SRC_RFC3986,
                       [{"fn": "insert_before_last_segment", "args": {"token": token}}]))
    # encoded slash
    prims.append(p("g2-encslash-all", "encoded-slash",
                   "Percent-encode every path slash as %2F.", SRC_RFC3986,
                   [{"fn": "encode_char_in_path", "args": {"char": "/", "encoding": "%2F"}}]))
    prims.append(p("g2-pct2f-before-last", "encoded-slash",
                   "Insert an encoded slash (%2f) before the last path segment.", SRC_RFC3986,
                   [{"fn": "insert_before_last_segment", "args": {"token": "%2f"}}]))
    # double slash
    prims.append(p("g2-double-slash-leading", "double-slash",
                   "Double the leading slash (//api/...).", SRC_GUDIFU,
                   [{"fn": "double_leading_slash", "args": {}}]))
    prims.append(p("g2-double-slash-mid", "double-slash",
                   "Double an interior slash (/api//...).", SRC_GUDIFU,
                   [{"fn": "replace_in_path", "args": {"find": "/api/", "replace": "/api//"}}]))
    # matrix params
    prims.append(p("g2-matrix-param", "matrix-param",
                   "Append a ;matrix parameter to the final segment.", SRC_RFC3986,
                   [{"fn": "append_to_path", "args": {"suffix": ";v=1"}}]))
    prims.append(p("g2-matrix-jsessionid", "matrix-param",
                   "Append a ;jsessionid matrix parameter (servlet path-param stripping).",
                   SRC_RFC3986,
                   [{"fn": "append_to_path", "args": {"suffix": ";jsessionid=abc"}}]))
    # trailing slash
    prims.append(p("g2-trailing-slash", "trailing-slash",
                   "Append a trailing slash to the path.", SRC_GUDIFU,
                   [{"fn": "add_trailing_slash", "args": {}}]))
    # case
    prims.append(p("g2-uppercase-path", "case-variant",
                   "Uppercase the whole path.", SRC_HDHUNTER,
                   [{"fn": "uppercase_path", "args": {}}]))
    prims.append(p("g2-swapcase-path", "case-variant",
                   "Swap the case of every path character.", SRC_HDHUNTER,
                   [{"fn": "swapcase_path", "args": {}}]))
    # absolute form
    prims.append(p("g2-abs-form-same", "absolute-form",
                   "Rewrite the request target to absolute-form with the same authority.",
                   SRC_RFC7230,
                   [{"fn": "to_absolute_form", "args": {}}]))
    prims.append(p("g2-abs-form-diff-authority", "absolute-form",
                   "Absolute-form target with a different authority than the Host header "
                   "(Host vs absolute-form conflict).", SRC_RFC7230,
                   [{"fn": "to_absolute_form", "args": {"authority": "internal.svc.local"}}]))
    prims.append(p("g2-abs-form-diff-path", "absolute-form",
                   "Absolute-form target whose path is rewritten (v1->v2) while Host stays, "
                   "so layers keying on different target forms diverge.", SRC_TRAEFIK,
                   [{"fn": "to_absolute_form", "args": {}},
                    {"fn": "replace_in_path", "args": {"find": "/api/v1", "replace": "/api/v2"}}]))
    # backslash
    prims.append(p("g2-backslash", "backslash",
                   "Insert a backslash dot-segment (..\\) before the last segment; "
                   "some stacks treat \\ as /.", SRC_GUDIFU,
                   [{"fn": "insert_before_last_segment", "args": {"token": "..\\"}}]))
    # fragment
    prims.append(p("g2-fragment", "fragment",
                   "Append a #fragment to the request target (should be client-only; "
                   "some proxies forward it).", SRC_RFC3986,
                   [{"fn": "set_fragment", "args": {"value": "frag"}}]))
    # null byte
    prims.append(p("g2-null-byte", "null-byte",
                   "Append a %00 null byte to the path (truncation differential).",
                   SRC_GUDIFU,
                   [{"fn": "append_to_path", "args": {"suffix": "%00"}}]))
    prims.append(p("g2-null-byte-ext", "null-byte",
                   "Insert %00 before the last segment with a decoy extension.", SRC_GUDIFU,
                   [{"fn": "insert_before_last_segment", "args": {"token": "%00"}}]))
    # overlong / unicode
    prims.append(p("g2-overlong-utf8-slash", "overlong-encoding",
                   "Overlong UTF-8 encoding of '/' (%c0%af).", SRC_HDHUNTER,
                   [{"fn": "encode_char_in_path", "args": {"char": "/", "encoding": "%c0%af"}}]))
    prims.append(p("g2-unicode-fullwidth", "unicode-normalisation",
                   "Replace 'api' with fullwidth Unicode codepoints to probe NFKC folding.",
                   SRC_HDHUNTER,
                   [{"fn": "replace_in_path", "args": {"find": "api", "replace": "ａｐｉ"}}]))
    # prefix rewrite
    prims.append(p("g2-prefix-v1-to-v2", "prefix-rewrite",
                   "Rewrite the /api/v1 prefix to /api/v2 (prefix-mount confusion).",
                   SRC_TRAEFIK,
                   [{"fn": "replace_in_path", "args": {"find": "/api/v1", "replace": "/api/v2"}}],
                   applies_to={"requires_tags": ["v1"]}))
    prims.append(p("g2-prefix-v2-to-v1", "prefix-rewrite",
                   "Rewrite the /api/v2 prefix to /api/v1.", SRC_TRAEFIK,
                   [{"fn": "replace_in_path", "args": {"find": "/api/v2", "replace": "/api/v1"}}],
                   applies_to={"requires_tags": ["v2"]}))
    # request-line whitespace
    prims.append(p("g2-ws-tab-reqline", "request-line-ws",
                   "Use a TAB instead of SP between request-line tokens.", SRC_TREQS,
                   [{"fn": "set_line_sep", "args": {"value": "\t"}}]))
    prims.append(p("g2-ws-double-reqline", "request-line-ws",
                   "Use a double space between request-line tokens.", SRC_TREQS,
                   [{"fn": "set_line_sep", "args": {"value": "  "}}]))
    # duplicate Host
    prims.append(p("g2-dup-host", "duplicate-host",
                   "Send two Host headers with different authorities.", SRC_RFC7230,
                   [{"fn": "duplicate_header",
                     "args": {"name": "Host", "value": "api.bench.test",
                              "second": "internal.svc.local"}}]))
    # rewrite headers
    prims.append(p("g2-xforwarded-prefix", "rewrite-header",
                   "Inject X-Forwarded-Prefix to shift the perceived path prefix.",
                   SRC_REWRITE,
                   [{"fn": "add_header", "args": {"name": "X-Forwarded-Prefix", "value": "/api/v1"}}]))
    prims.append(p("g2-x-original-url", "rewrite-header",
                   "Inject X-Original-URL pointing at an admin route "
                   "(reverse-proxy routing override).", SRC_OPA,
                   [{"fn": "add_header",
                     "args": {"name": "X-Original-URL", "value": "/api/v1/admin/users"}}]))
    prims.append(p("g2-x-rewrite-url", "rewrite-header",
                   "Inject X-Rewrite-URL pointing at an admin route.", SRC_REWRITE,
                   [{"fn": "add_header",
                     "args": {"name": "X-Rewrite-URL", "value": "/api/v1/admin/users"}}]))
    return prims


def g3():
    prims = []

    def p(pid, cls, desc, src, transform):
        return {"id": pid, "class": cls, "description": desc, "source": src,
                "transform": transform}

    prims += [
        p("g3-xverified-sub-alice", "trust-header-inject",
          "Inject X-Verified-Sub: alice to forge the verifier's identity assertion.",
          SRC_HEADER_SMUGGLE,
          [{"fn": "add_header", "args": {"name": "X-Verified-Sub", "value": "alice"}}]),
        p("g3-xverified-sub-bob", "trust-header-inject",
          "Inject X-Verified-Sub: bob to impersonate another subject.",
          SRC_HEADER_SMUGGLE,
          [{"fn": "add_header", "args": {"name": "X-Verified-Sub", "value": "bob"}}]),
        p("g3-xverified-sub-case", "trust-header-case",
          "Inject lowercase x-verified-sub to bypass case-sensitive stripping.",
          SRC_HEADER_SMUGGLE,
          [{"fn": "add_header", "args": {"name": "x-verified-sub", "value": "bob"}}]),
        p("g3-xverified-sub-underscore", "trust-header-underscore",
          "Inject X_Verified_Sub (underscore) which some stacks fold to the dash form.",
          SRC_HEADER_SMUGGLE,
          [{"fn": "add_header", "args": {"name": "X_Verified_Sub", "value": "bob"}}]),
        p("g3-xverified-sub-dup", "trust-header-dup",
          "Send a duplicate X-Verified-Sub (verifier value plus a spoofed one).",
          SRC_HEADER_SMUGGLE,
          [{"fn": "duplicate_header",
            "args": {"name": "X-Verified-Sub", "value": "alice", "second": "bob"}}]),
        p("g3-xverified-jkt", "trust-header-inject",
          "Inject X-Verified-Jkt with an attacker thumbprint.", SRC_HEADER_SMUGGLE,
          [{"fn": "add_header", "args": {"name": "X-Verified-Jkt", "value": SPOOF_JKT}}]),
        p("g3-xverified-view", "defence-db-spoof",
          "Inject a forged X-Verified-View MAC (D-B) that the executor may trust "
          "without verifying.", SRC_HEADER_SMUGGLE,
          [{"fn": "add_header", "args": {"name": "X-Verified-View", "value": SPOOF_VIEW}}]),
        p("g3-xfcc-inject", "trust-header-inject",
          "Inject X-Forwarded-Client-Cert (XFCC) to spoof an mTLS client identity.",
          SRC_XFCC,
          [{"fn": "add_header",
            "args": {"name": "X-Forwarded-Client-Cert", "value": SPOOF_XFCC}}]),
        p("g3-xfcc-case", "trust-header-case",
          "Inject lowercase x-forwarded-client-cert.", SRC_XFCC,
          [{"fn": "add_header",
            "args": {"name": "x-forwarded-client-cert", "value": SPOOF_XFCC}}]),
        p("g3-xfcc-underscore", "trust-header-underscore",
          "Inject X_Forwarded_Client_Cert (underscore variant).", SRC_XFCC,
          [{"fn": "add_header",
            "args": {"name": "X_Forwarded_Client_Cert", "value": SPOOF_XFCC}}]),
        p("g3-xfcc-dup", "trust-header-dup",
          "Send a duplicate XFCC header (append a spoofed one after a benign one).",
          SRC_XFCC,
          [{"fn": "duplicate_header",
            "args": {"name": "X-Forwarded-Client-Cert",
                     "value": "By=spiffe://cluster.local/ns/default/sa/web;Hash=1111",
                     "second": SPOOF_XFCC}}]),
        p("g3-client-cert", "trust-header-inject",
          "Inject RFC 9440 Client-Cert header with a spoofed certificate.", SRC_XFCC,
          [{"fn": "add_header", "args": {"name": "Client-Cert", "value": SPOOF_PEM}}]),
        p("g3-x-client-cert", "trust-header-inject",
          "Inject X-Client-Cert with a spoofed certificate.", SRC_XFCC,
          [{"fn": "add_header", "args": {"name": "X-Client-Cert", "value": SPOOF_PEM}}]),
        p("g3-x-client-cert-case", "trust-header-case",
          "Inject lowercase x-client-cert.", SRC_XFCC,
          [{"fn": "add_header", "args": {"name": "x-client-cert", "value": SPOOF_PEM}}]),
        p("g3-x-client-cert-underscore", "trust-header-underscore",
          "Inject X_Client_Cert (underscore variant).", SRC_XFCC,
          [{"fn": "add_header", "args": {"name": "X_Client_Cert", "value": SPOOF_PEM}}]),
    ]
    return prims


def dump(group_name, description, prims, filename):
    doc = {
        "class_group": group_name,
        "description": description,
        "count": len(prims),
        "primitives": prims,
    }
    path = os.path.join(HERE, filename)
    with open(path, "w") as f:
        f.write(f"# {group_name}: {description}\n")
        f.write("# Auto-generated by build_catalogue.py. Edit the generator, not this file.\n")
        yaml.safe_dump(doc, f, sort_keys=False, default_flow_style=False, allow_unicode=True,
                       width=100)
    print(f"wrote {path}: {len(prims)} primitives")
    return len(prims)


def main():
    n1 = dump("G1", "Under-binding by design: method/verb and op-dispatch not covered by the proof.",
              g1(), "g1.yaml")
    n2 = dump("G2", "Interpretation differentials: verifier and router parse method/URI differently.",
              g2(), "g2.yaml")
    n3 = dump("G3", "Binding propagation: spoofable trust headers across the boundary.",
              g3(), "g3.yaml")
    print(f"TOTAL base primitives: {n1 + n2 + n3}")


if __name__ == "__main__":
    main()

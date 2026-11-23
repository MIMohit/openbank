"""W18 unified root-cause (mechanism) classifier for binding hits, shared by A1 and A4.

Families = the W7 catalogue `class` of the hit's primitive (W15 custom x-frag-* -> 'fragment').
Mechanisms follow binding/experiments/GATE_DECISION.md (one row per resolving component x differential):
  G1  M1 query-dispatch       query `op` not covered by htu                  (kill RC1)
  G1  M2 body-dispatch        JSON operationName not covered                  (kill RC2)
  G1  M3 content-type-switch  relabelled body not parsed -> unknown           (kill RC3)
  G1  M4 form-body-replace    `_method` form body replaces the JSON body      (kill RC4)
  G1  M5a override-any-method header override honoured on a non-POST method   (kill RC5 / ext-routes X5)
  G1  M5b override-post       POST-only override reaches a shared-path sibling (ext-routes X4)
  G2  M6 fragment-in-path     '#' kept in the path by the server; verifier drops it (kill RC6, X1/X2, W13-B)
  G1* M7 fragment-in-query    '#' kept inside the query value (G2 vehicle, G1 effect; kill RC7)
  G2  M8 decoded-view-split   APISIX forward-auth decoded view vs raw %2f upstream (W13-A)
  G2  M9 dot-segment-catchall verifier removes ./ ; catch-all captures it raw   (ext-routes X3)
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "harness"))
from mutator.catalogue import load_catalogue  # noqa: E402

FAM = {p.id: p.cls for p in load_catalogue()}
GROUP = {p.id: p.group for p in load_catalogue()}
MECH_CLASS = {"M1": "G1", "M2": "G1", "M3": "G1", "M4": "G1", "M5a": "G1", "M5b": "G1",
              "M6": "G2", "M7": "G1*", "M8": "G2", "M9": "G2",
              "R-swap-op": "replay", "R-swap-method": "replay"}
MECH_NAME = {"M1": "query-dispatch", "M2": "body-dispatch", "M3": "content-type-switch",
             "M4": "form-body-replace", "M5a": "override-any-method", "M5b": "override-post",
             "M6": "fragment-in-path", "M7": "fragment-in-query", "M8": "decoded-view-split",
             "M9": "dot-segment-catchall"}


def family(pid: str) -> str:
    if pid.startswith("x-frag"):
        return "fragment"
    if pid.startswith("swap-op-"):
        return "swap-op"
    if pid.startswith("swap-method-"):
        return "swap-method"
    return FAM.get(pid, "unknown:" + pid)


def hit_family(h: dict) -> str:
    ps = h.get("primitive_ids") or []
    return "+".join(sorted({family(p) for p in ps})) or "baseline"


def mechanism(h: dict) -> str:
    fam = hit_family(h)
    raw_m, eff_m = h.get("raw_method"), h.get("effective_method")
    t = h.get("raw_target") or ""
    if fam == "query-dispatch-switch":
        return "M1"
    if fam == "graphql-operation-switch":
        return "M2"
    if fam == "content-type-switch":
        return "M3"
    if fam.startswith("method-override"):
        if eff_m and raw_m and eff_m != raw_m:
            return "M5b" if raw_m == "POST" else "M5a"
        return "M4"
    if fam == "fragment":
        q, hsh = t.find("?"), t.find("#")
        return "M7" if (q != -1 and hsh > q) else "M6"
    if fam == "encoded-slash":
        return "M8"
    if fam == "dot-segment":
        return "M9"
    if fam in ("swap-op", "swap-method"):
        return "R-" + fam      # cross-op / cross-method replay of a leaked proof (A1 swap set)
    return "other:" + fam

#!/usr/bin/env python3
"""Named-spec analysis: HL7 FHIR.

Inputs (fetched by e1/fetch_named.sh into data/named/):
  hapi_r4_metadata.json  CapabilityStatement of the public HAPI FHIR R4 test server
  fhir_r5_http.txt       text of https://hl7.org/fhir/R5/http.html
Prints the counts used in E1_results.md section "FHIR" and writes e1/out/fhir_capability.csv.
"""
import csv
import json
import os
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.path.join(HERE, "..", "data", "named")
OUT = os.path.join(HERE, "out")


def main():
    cap = json.load(open(os.path.join(D, "hapi_r4_metadata.json")))
    fetched = open(os.path.join(D, "hapi_r4_metadata.fetched_at")).read().strip()
    rest = cap["rest"][0]
    res = rest["resource"]
    n = len(res)
    print(f"server: {cap.get('implementation', {}).get('url')} software={cap.get('software')} fhirVersion={cap.get('fhirVersion')} fetched={fetched}")
    print(f"resource types: {n}")
    for k in ("conditionalCreate", "conditionalUpdate", "conditionalDelete", "conditionalPatch"):
        print(f"  {k}: {dict(Counter(str(x.get(k)) for x in res))}")
    sys_int = [i["code"] for i in rest.get("interaction", [])]
    print(f"system interactions: {sys_int}")
    inter = Counter()
    for x in res:
        for i in x.get("interaction", []):
            inter[i["code"]] += 1
    print(f"type-level interactions (count of resource types supporting each): {dict(inter)}")
    print(f"system-level operations: {len(rest.get('operation', []))}; type/instance operation declarations: {sum(len(x.get('operation', [])) for x in res)}")
    rows = [dict(type=x["type"], conditionalCreate=x.get("conditionalCreate"), conditionalUpdate=x.get("conditionalUpdate"),
                 conditionalDelete=x.get("conditionalDelete"), interactions="|".join(i["code"] for i in x.get("interaction", [])),
                 operations="|".join(o["name"] for o in x.get("operation", []))) for x in res]
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "fhir_capability.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    # spec text anchors (line numbers in the extracted text, for traceability)
    txt = open(os.path.join(D, "fhir_r5_http.txt")).read().splitlines()
    anchors = ["PUT [base]/[type]?[search parameters]", "DELETE [base]/[type]?[search parameters]",
               "conditional PATCH", "If-None-Exist: [search parameters]",
               "POST [base] {?_format=[mime-type]}", "POST [base]/[type]/_search", "X-HTTP-Method-Override"]
    for a in anchors:
        hits = [i + 1 for i, l in enumerate(txt) if a in l]
        print(f"  R5 http.html text contains {a!r}: lines {hits[:5]}")


if __name__ == "__main__":
    main()

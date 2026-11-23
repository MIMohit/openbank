#!/usr/bin/env python3
"""Lower bound: APIs with at least one HAND-CONFIRMED collision (TP), from the 100-op sample,
the finance census and the non-AWS M1 API-level census.  Prints counts against the chosen-set
denominators (all APIs; APIs excluding amazonaws.com)."""
import csv
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")


def main():
    api_of = {r["file"]: r["api_id"] for r in csv.DictReader(open(os.path.join(OUT, "e1_api_level.csv")))}
    sample = {r["sample_id"]: r for r in csv.DictReader(open(os.path.join(OUT, "validation_sample.csv")))}
    tp = set()
    for r in csv.DictReader(open(os.path.join(HERE, "validation_judgments.csv"))):
        if r["verdict"] == "TP":
            tp.add(api_of[sample[r["sample_id"]]["file"]])
    for fn in ("finance_census_judgments.csv", "nonaws_m1_census_judgments.csv"):
        for r in csv.DictReader(open(os.path.join(HERE, fn))):
            if r["verdict"] == "TP":
                tp.add(r["api_id"])
    n_all = len(api_of)
    n_nonaws = sum(1 for a in api_of.values() if not a.startswith("amazonaws.com"))
    nonaws = sorted(a for a in tp if not a.startswith("amazonaws.com"))
    aws = sorted(a for a in tp if a.startswith("amazonaws.com"))
    print(f"hand-confirmed APIs: {len(tp)} of {n_all}; AWS {len(aws)}; non-AWS {len(nonaws)} of {n_nonaws}")
    print("non-AWS:", ", ".join(nonaws))
    with open(os.path.join(OUT, "confirmed_apis.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["api_id", "aws"])
        for a in sorted(tp):
            w.writerow([a, a.startswith("amazonaws.com")])


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""E2: turn the raw code-search / npm counts into rough enablement ratios.
Reads e2/out/code_search.csv (run 2) and e2/out/code_search_run3.csv (run 3); writes
e2/out/E2_enablement.csv.  Every ratio is numerator_count / denominator_count of GitHub legacy
code-search total_count estimates (files, not repositories) or npm monthly downloads.  These are
ROUGH INDICATORS ONLY (see E2_results.md, Limitations)."""
import csv
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")

RATIOS = [
    # (framework, what, numerator query/package, denominator query/package)
    ("spring", "application.properties that set the override to true / application.properties naming an app",
     '"spring.mvc.hiddenmethod.filter.enabled=true" filename:application.properties',
     '"spring.application.name" filename:application.properties'),
    ("spring", "share of application.properties hiddenmethod settings that are '=true'",
     '"spring.mvc.hiddenmethod.filter.enabled=true" filename:application.properties',
     '"hiddenmethod.filter.enabled" filename:application.properties'),
    ("aspnetcore", "C# files calling UseHttpMethodOverride / C# files calling UseRouting",
     '"UseHttpMethodOverride" language:C#', '"UseRouting" language:C#'),
    ("express", "package.json depending on method-override / package.json mentioning express",
     '"method-override" filename:package.json', '"express" filename:package.json'),
    ("express", "JS files with app.use(methodOverride / package.json mentioning express",
     '"app.use(methodOverride" language:JavaScript', '"express" filename:package.json'),
    ("express", "query getter _method among methodOverride( calls: methodOverride('_method') / (that + methodOverride())",
     '"methodOverride(\'_method\')" language:JavaScript', None),
    ("express", "npm monthly downloads method-override / express", "method-override", "express"),
    ("go-gorilla", "Go files calling HTTPMethodOverrideHandler / Go files importing gorilla/handlers",
     '"HTTPMethodOverrideHandler" language:Go', '"github.com/gorilla/handlers" language:Go'),
    ("rails", "application.rb with api_only=true (override REMOVED) / application.rb defining a Rails app",
     '"config.api_only = true" filename:application.rb', '"Rails::Application" filename:application.rb'),
    ("symfony", "yaml enabling http_method_override / (enabling + disabling)",
     '"http_method_override: true" extension:yaml', None),
]


def main():
    counts = {}
    for fn in ("code_search.csv", "code_search_run3.csv"):
        for r in csv.DictReader(open(os.path.join(OUT, fn))):
            if r["total_count"]:
                counts[r["query"]] = (int(r["total_count"]), r["ts"], r["first_page_exact"])
    rows = []
    for fw, what, num, den in RATIOS:
        n = counts[num][0]
        if den is None and fw == "express":
            d = n + counts['"methodOverride()" language:JavaScript'][0]
            den_label = "methodOverride('_method') + methodOverride()"
        elif den is None and fw == "symfony":
            d = n + counts['"http_method_override: false" extension:yaml'][0]
            den_label = "http_method_override: true + false"
        else:
            d = counts[den][0]
            den_label = den
        rows.append(dict(framework=fw, ratio=what, numerator_query=num, numerator=n, denominator_query=den_label,
                         denominator=d, ratio_value=round(n / d, 5), numerator_ts=counts[num][1],
                         numerator_first_page_exact=counts[num][2]))
    with open(os.path.join(OUT, "E2_enablement.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    for r in rows:
        print(f"{r['framework']:11} {r['numerator']:>9} / {r['denominator']:>9} = {100*r['ratio_value']:.2f}%  {r['ratio']}")


if __name__ == "__main__":
    main()

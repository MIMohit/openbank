#!/usr/bin/env python3
"""E2: GitHub code-search estimates of how often projects enable method override.

Uses the authenticated GitHub REST endpoint GET /search/code through the `gh` CLI
(legacy code-search engine: default branches only, files < 384 KB, forks excluded unless
they have more stars than the parent, total_count is an estimate).  Rate limit: 10 req/min,
we sleep 7 s between requests.  Every raw response summary is appended to
e2/out/code_search_raw.jsonl with a UTC timestamp, and e2/out/code_search.csv is rewritten.

Also queries package-registry download counters (npm) as a second, independent popularity signal.
Usage: python -I e2/code_search.py
"""
import base64
import csv
import re
import datetime as dt
import json
import os
import subprocess
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")

# (framework, what it measures, query)
QUERIES = [
    # Spring Boot: off by default since Boot 2.2; enabling is a property
    ("spring", "enable via properties", '"spring.mvc.hiddenmethod.filter.enabled=true"'),
    ("spring", "enable via YAML/properties (any value, incl. false)", '"hiddenmethod.filter.enabled"'),
    ("spring", "WebFlux enable via properties", '"spring.webflux.hiddenmethod.filter.enabled=true"'),
    ("spring", "explicit filter bean / registration (Java)", '"new HiddenHttpMethodFilter" language:Java'),
    ("spring", "explicit filter (Kotlin)", '"HiddenHttpMethodFilter" language:Kotlin'),
    ("spring", "any reference (Java)", '"HiddenHttpMethodFilter" language:Java'),
    # ASP.NET Core: opt-in middleware
    ("aspnetcore", "middleware enabled", '"UseHttpMethodOverride" language:C#'),
    ("aspnetcore", "form-field variant", '"HttpMethodOverrideOptions" language:C#'),
    # Express: method-override package
    ("express", "package.json dependency", '"method-override" filename:package.json'),
    ("express", "require/import (JS)", '"require(\'method-override\')" language:JavaScript'),
    ("express", "query-string getter _method (JS)", '"methodOverride(\'_method\')" language:JavaScript'),
    ("express", "default header getter (JS)", '"methodOverride()" language:JavaScript'),
    ("express", "TypeScript import", '"method-override" language:TypeScript'),
    # Go
    ("go-gorilla", "gorilla/handlers override wrapper", '"HTTPMethodOverrideHandler" language:Go'),
    ("go", "X-HTTP-Method-Override in Go code", '"X-HTTP-Method-Override" language:Go'),
    # Rails: Rack::MethodOverride on by default; api_only removes it
    ("rails", "API-only apps (override middleware absent)", '"config.api_only = true" filename:application.rb'),
    ("rails", "all Rails application.rb (denominator)", '"Rails::Application" filename:application.rb'),
    ("rails", "explicit removal", '"delete Rack::MethodOverride"'),
    ("rails", "explicit re-add in API mode", '"use Rack::MethodOverride"'),
    # Laravel / Symfony
    ("laravel", "Blade @method spoofing (DELETE)", '"@method(\'DELETE\')" extension:php'),
    ("laravel", "Blade @method spoofing (PUT)", '"@method(\'PUT\')" extension:php'),
    ("laravel", "method_field helper", '"method_field(" extension:php'),
    ("symfony", "explicit enable of _method", '"http_method_override: true" extension:yaml'),
    ("symfony", "explicit disable of _method", '"http_method_override: false" extension:yaml'),
    ("symfony", "restrict override list (7.4+)", '"allowed_http_method_override" extension:yaml'),
    # Python
    ("django", "third-party override middleware", '"MethodOverrideMiddleware" language:Python'),
    ("python", "X-HTTP-Method-Override in Python code", '"X-HTTP-Method-Override" language:Python'),
    # Others / middleware
    ("hono", "hono method-override middleware", '"hono/method-override"'),
    ("jersey", "Jersey HttpMethodOverrideFilter", '"HttpMethodOverrideFilter" language:Java'),
    ("php", "X-HTTP-Method-Override in PHP code", '"X-HTTP-Method-Override" language:PHP'),
    ("csharp", "X-HTTP-Method-Override in C# code", '"X-HTTP-Method-Override" language:C#'),
    ("js", "X-HTTP-Method-Override in JS code", '"X-HTTP-Method-Override" language:JavaScript'),
]

# Run 3 (2026-11-23): file-scoped queries that target real configuration files rather than docs,
# plus rough per-ecosystem denominators.  Selected with --run3; written to code_search_run3.csv.
QUERIES_RUN3 = [
    ("spring", "enable in application.properties", '"spring.mvc.hiddenmethod.filter.enabled=true" filename:application.properties'),
    ("spring", "any hiddenmethod setting in application.properties", '"hiddenmethod.filter.enabled" filename:application.properties'),
    ("spring", "any hiddenmethod setting in application.yml", '"hiddenmethod" filename:application.yml'),
    ("spring", "denominator: application.properties naming an app", '"spring.application.name" filename:application.properties'),
    ("aspnetcore", "denominator: C# files calling UseRouting", '"UseRouting" language:C#'),
    ("express", "app.use(methodOverride (JS)", '"app.use(methodOverride" language:JavaScript'),
    ("express", "denominator: package.json depending on express", '"express" filename:package.json'),
    ("go-gorilla", "denominator: gorilla/handlers imports", '"github.com/gorilla/handlers" language:Go'),
    ("laravel", "denominator: Laravel composer.json", '"laravel/framework" filename:composer.json'),
]

NPM = ["method-override", "express", "koa-override", "fastify-method-override"]


def gh_search(q):
    p = subprocess.run(["gh", "api", "-X", "GET", "search/code", "-f", f"q={q}", "-f", "per_page=10"],
                       capture_output=True, text=True)
    if p.returncode != 0:
        return {"error": (p.stderr or p.stdout)[:300]}
    d = json.loads(p.stdout)
    return {"total_count": d.get("total_count"), "incomplete_results": d.get("incomplete_results"),
            "sample": [f'{i["repository"]["full_name"]}/{i["path"]}' for i in d.get("items", [])][:10],
            "item_urls": [i["url"] for i in d.get("items", [])][:10]}


def literal_of(q):
    m = re.search(r'"((?:[^"\\]|\\.)*)"', q)
    return m.group(1).replace('\\"', '"') if m else q


def exact_hits(urls, literal):
    """Fetch each first-page hit and test whether the exact literal occurs (case-sensitive).
    The legacy engine tokenises quoted phrases, so total_count over-counts; this gives the
    first-page exact-match rate as a quality indicator."""
    ok = 0
    n = 0
    for u in urls:
        p = subprocess.run(["gh", "api", u, "--jq", ".content"], capture_output=True, text=True)
        if p.returncode != 0:
            continue
        try:
            txt = base64.b64decode(p.stdout.strip()).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            continue
        n += 1
        ok += literal in txt
    return ok, n


def npm_downloads(pkg):
    url = f"https://api.npmjs.org/downloads/point/last-month/{pkg}"
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            return json.loads(r.read())
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


def main():
    import sys
    run3 = "--run3" in sys.argv
    os.makedirs(OUT, exist_ok=True)
    rows = []
    raw = open(os.path.join(OUT, "code_search_raw.jsonl"), "a")
    for fw, what, q in (QUERIES_RUN3 if run3 else QUERIES):
        ts = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        for attempt in range(3):
            res = gh_search(q)
            if "error" in res and ("rate limit" in res["error"].lower() or "403" in res["error"]):
                time.sleep(61)
                continue
            break
        lit = literal_of(q)
        ex_ok, ex_n = exact_hits(res.get("item_urls", []), lit)
        res["first_page_exact"] = f"{ex_ok}/{ex_n}"
        rec = dict(ts=ts, run="run3" if run3 else "run2", source="github-rest-search-code", framework=fw, measures=what, query=q, literal=lit, **res)
        raw.write(json.dumps(rec) + "\n")
        raw.flush()
        rows.append(dict(ts=ts, framework=fw, measures=what, query=q, total_count=res.get("total_count"),
                         incomplete_results=res.get("incomplete_results"), first_page_exact=res.get("first_page_exact", ""),
                         error=res.get("error", ""),
                         sample_hits=" ; ".join(res.get("sample", [])[:3])))
        print(fw, what, q, "->", res.get("total_count"), res.get("error", ""), flush=True)
        time.sleep(7)
    for pkg in ([] if run3 else NPM):
        ts = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        d = npm_downloads(pkg)
        raw.write(json.dumps(dict(ts=ts, source="npm-downloads-last-month", query_package=pkg, response=d)) + "\n")
        rows.append(dict(ts=ts, framework="npm", measures=f"npm downloads last month {d.get('start')}..{d.get('end')}",
                         query=pkg, total_count=d.get("downloads"), incomplete_results="", first_page_exact="", error=d.get("error", ""),
                         sample_hits=""))
        print("npm", pkg, d.get("downloads"), d.get("error", ""))
    with open(os.path.join(OUT, "code_search_run3.csv" if run3 else "code_search.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    main()

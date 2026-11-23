#!/usr/bin/env python3
"""Fetch each official documentation page cited in E2_results.md and check that it contains the
phrase the claim relies on.  Writes e2/out/doc_checks.csv (url, phrase, http status, found, fetched_at)."""
import csv
import datetime as dt
import os
import re
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DOCS = [
    ("spring", "https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/filter/HiddenHttpMethodFilter.html", "_method"),
    ("spring", "https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-2.2-Release-Notes", "hiddenmethod.filter.enabled"),
    ("spring", "https://docs.spring.io/spring-boot/appendix/application-properties/index.html", "spring.mvc.hiddenmethod.filter.enabled"),
    ("aspnetcore", "https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.builder.httpmethodoverrideextensions.usehttpmethodoverride", "X-HTTP-Method-Override"),
    ("aspnetcore", "https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.builder.httpmethodoverrideoptions.formfieldname", "FormFieldName"),
    ("express", "https://expressjs.com/en/resources/middleware/method-override.html", "X-HTTP-Method-Override"),
    ("rails", "https://guides.rubyonrails.org/rails_on_rack.html", "Rack::MethodOverride"),
    ("rails", "https://guides.rubyonrails.org/api_app.html", "Rack::MethodOverride"),
    ("rails", "https://guides.rubyonrails.org/form_helpers.html", "_method"),
    ("laravel", "https://laravel.com/docs/routing", "_method"),
    ("symfony", "https://symfony.com/doc/current/reference/configuration/framework.html", "http_method_override"),
    ("go-gorilla", "https://pkg.go.dev/github.com/gorilla/handlers", "HTTPMethodOverrideHandler"),
    ("go-chi", "https://pkg.go.dev/github.com/go-chi/chi/v5/middleware", "RealIP"),
    ("starlette", "https://www.starlette.dev/middleware/", "TrustedHostMiddleware"),
    ("django", "https://docs.djangoproject.com/en/stable/ref/middleware/", "CommonMiddleware"),
    ("go-nethttp", "https://pkg.go.dev/net/http", "matches both GET and HEAD"),
    ("go-chi", "https://pkg.go.dev/github.com/go-chi/chi/v5/middleware", "GetHead"),
    ("hono", "https://hono.dev/docs/middleware/builtin/method-override", "_method"),
    ("jersey", "https://eclipse-ee4j.github.io/jersey.github.io/apidocs/latest/jersey/org/glassfish/jersey/server/filter/HttpMethodOverrideFilter.html", "X-HTTP-Method-Override"),
]


def main():
    rows = []
    for fw, url, phrase in DOCS:
        ts = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "prevalence-doc-check/1.0"})
            with urllib.request.urlopen(req, timeout=40) as r:
                body = r.read().decode("utf-8", "replace")
                status = r.status
        except Exception as e:  # noqa: BLE001
            body, status = "", f"ERR {type(e).__name__}: {e}"[:120]
        found = phrase in body or phrase in re.sub(r"<[^>]+>", "", body)
        rows.append(dict(framework=fw, url=url, phrase=phrase, status=status, found=found, fetched_at=ts))
        print(fw, status, found, url)
    os.makedirs(os.path.join(HERE, "out"), exist_ok=True)
    with open(os.path.join(HERE, "out", "doc_checks.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    main()

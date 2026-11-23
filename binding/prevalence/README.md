# binding/prevalence (W8): E1 corpus prevalence + E2 framework method-override survey

**Status: complete** (2026-11-23). Results are in **`E1_results.md`** and **`E2_results.md`**. Every number in them comes from a script in this directory (outputs in `e1/out/` and `e2/out/`) or from a cited, pinned source.

## What it is
- **E1:** how often an API description maps one DPoP view key (METHOD, path without query) to ≥2 semantically different operations (G1). It covers the APIs.guru openapi-directory (2,652 APIs, 127,642 operations), a seeded 100-operation hand validation, and two named specs: HL7 FHIR and MCP.
- **E2:** method-override and dispatch features of Spring, ASP.NET Core, Express, FastAPI/Starlette, Django, Go (net/http, chi, gorilla), Rails, Laravel/Symfony, plus Jersey and Hono. Each feature is checked against official docs and against source lines pinned at release tags, then sized with GitHub code-search enablement estimates.

## Layout
- `data/`: gitignored downloads.
  - APIs.guru clone at commit f04b8d0b (2026-04-20) and the list.json snapshot
  - Pinned framework sources (`e2_sources/`) and release tarballs (`e2_trees/`)
  - FHIR and MCP spec text (`named/`)
  - Spring Boot wiki
- `e1/`
  - Inputs and analysis: `fetch_named.sh`, `analyze.py` (detectors M1–M5 plus override), `summarize.py` (tables T1–T8)
  - Validation: `sample.py` (seed 20261123), `validation_judgments.csv` (100 hand verdicts), `finance_census_judgments.csv`, `nonaws_m1_census_judgments.csv`
  - Results: `precision.py` (T9), `confirmed.py` (hand-confirmed lower bound), `named_fhir.py`
- `e2/`
  - Pinned sources: `pins.tsv` and `verify_pins.sh`
  - Negative-result greps: `fetch_trees.sh` and `grep_trees.sh`
  - Checks and counts: `check_docs.py`, `code_search.py` (run 2, plus `--run3`), `summarize_e2.py`
  - Feature matrix: `out/E2_framework_features.csv`

## How to run / test
See §8 of `E1_results.md` and §6 of `E2_results.md`. Setup: `python3.12 -m venv .venv && .venv/bin/pip install pyyaml numpy scipy`. Always run scripts with `-I`, because the downloaded data is untrusted. The checks that act as tests:
- `precision.py` asserts that every sampled id has exactly one judgment.
- `verify_pins.sh` must print 20 × IDENTICAL.
- `check_docs.py` must report every phrase found.

## Headline numbers (details and CIs in the results files)
- **E1:**
  - Corpus-wide, 11.4% of state-changing operations sit on a collided (method, path) key. That is 7,577 of 66,184, almost all AWS query/RPC protocols, with M1 precision 30/30.
  - Excluding AWS, 2.9% of APIs are flagged. 19 of 2,298 non-AWS APIs (0.8%) have a hand-confirmed collision.
  - Precision is M2 0.40 and M4 0.30. In finance, 4 of 9 flags are true (Stripe, Zuora).
  - FHIR makes query-selected conditional update and delete, plus `POST [base]` transactions, standard behaviour. MCP puts every tool call on one POST endpoint.
- **E2:**
  - Override is on by default in Rails (≈86% of apps keep it) and in Laravel (always, header and `_method` from body or query). It is opt-in in Spring, ASP.NET Core and Express, and absent in FastAPI, Django and Go.
  - Projects with an opt-in mechanism enable it at roughly 1–2% (Spring 0.99%, Express 1.1–1.9%, gorilla 1.15%; ASP.NET Core 0.06%).
  - Query-string override (invisible to `htu`) is reachable in Spring, Express (`methodOverride('_method')`, about half of uses), gorilla, Laravel/Symfony and Jersey.

## Known limitations
These are summarised here; the full lists are in each results file.
- Specs describe APIs, not deployments.
- The APIs.guru corpus is dominated by cloud vendors.
- One judge did the hand validation, so no inter-rater agreement is reported, and recall is not measured.
- One known M1 detector artefact: `#` inside templated paths (mastercard masterpassqr).
- Code-search totals are engine estimates over files, so the ratios are rough orders of magnitude.

## Contract interpretations
- The validation sample is stratified by mechanism rather than uniform, because M1 (AWS) is about 98% of flags. Overall precision is also reported stratum-weighted.
- The unit of analysis is one APIs.guru-preferred version per API. All-files results are reported as a sensitivity check (T8).
- "Collision" means ≥2 semantically different operations on one (METHOD, path-without-query) key, matching the DPoP `htm`/`htu` coverage in CONTRACT §1. Filters, data attributes, options and polymorphic bodies of a single operation are judged FP.
- E2 covers the CONTRACT's 8 frameworks plus Symfony (Laravel's HTTP layer), gorilla/handlers, Jersey and Hono, because they are the common override middleware.

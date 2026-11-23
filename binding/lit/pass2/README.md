# binding/lit/pass2: targeted literature pass 2 (W20)

## What this is
This is a second, targeted literature pass, done as read-only web research on 2026-11-24. It covers three things pass 1 missed:
- **practitioner work** on path normalisation and parser-differential access-control bypass: Orange Tsai, PortSwigger, xvnpw, Acunetix and Assetnote, and the Envoy, Istio, Traefik, Kong, APISIX, Spring, Heimdall and Oathkeeper CVE families;
- **academic papers** on normalisation and routing/authentication differentials, searched in dblp by hand through SPARQL;
- a **recency check** of the CCS'26, S&P'26/'27, USENIX'26/'27, NDSS'26/'27, EuroS&P'26, ACSAC'26 and AsiaCCS'26 lists, and of arXiv cs.CR 2026.

No system was tested and nothing was run against any hosted service. The only traffic was page and API fetches of public documents.

| File | Content |
|---|---|
| `NOVELTY_UPDATE.md` | **Main deliverable.** Per-claim verdicts (C1 binding soundness, C2 G1, C3 G2 under A_leak, C4 E4, C5 A1, C6 D-A/D-B), the positioning sentences to use, the must-cite list, residual risks and the recency table (§R) |
| `screening.csv` | 84 screened items, in the same columns as `../screening.csv` (`id,title,authors,venue,year,url,stage,decision,reason`): 28 include, 30 background, 26 exclude. Stages: FT 11, MD 30, TA 42, SPEC 1. Each `reason` field carries `[claims: C1..C6]` and `[found via: ...]` |
| `refs_pass2.bib` | 40 BibTeX entries with `p2:` keys. Each note gives the evidence level (FT/ABS/TITLE). Unconfirmed fields are marked `UNVERIFIED` |
| `SEARCH_LOG.md` | Every query actually run: dblp SPARQL terms, web search strings, arXiv queries, venue URLs and their status, and the primary-source code checks |
| `search_log/` | `dblp.jsonl` (all SPARQL rows), `dblp_run{1,2}.txt`, `arxiv2026.jsonl`, `arxiv2026_run.txt`, `urls_to_verify.txt`, `url_verification.tsv` |
| `tools/` | `dblp_sparql.py`, `arxiv_q.py`, `verify_urls.py`, `build_screening.py` (builds `screening.csv`) |

## How to run / reproduce
```sh
cd /Users/mimohit/openbank/binding/lit/pass2
python3 -I tools/build_screening.py                 # -> screened=84 {'include': 28, 'background': 30, 'exclude': 26}
python3 -I tools/dblp_sparql.py "parser differential" 2014   # one dblp title query (appends to search_log/dblp.jsonl)
python3 -I tools/arxiv_q.py 'all:"sender-constrained"'      # one arXiv 2026 query
python3 -I tools/verify_urls.py search_log/urls_to_verify.txt > /tmp/check.tsv   # re-verify all bib URLs/DOIs
```
Live sources drift. The logs in `search_log/` are the record that was actually screened.

## How it was verified
- `tools/verify_urls.py` checked **61 targets: all returned HTTP 200 or resolved through Crossref** (`search_log/url_verification.tsv`). The datatracker URL for the signed-request draft was checked separately (200).
  - NVD pages render client-side and return a generic title. Their content was confirmed through the OSV, GitLab, Istio or Red Hat mirrors named in each bib note.
- **Full texts read (FT):**
  - Tsai BH18 slides; Doyhenard 2024 white paper; Kettle 2025 white paper (grepped);
  - all 7 xvnpw posts (Kong/F5, APISIX, Traefik/HAProxy, Emissary, ingress-nginx, tips, hunting);
  - UABScan CCS'25 (author PDF);
  - draft-ietf-oauth-signed-http-request-03.
- **Source code read:**
  - APISIX `apisix/init.lua` at tags 3.20.0 and 3.21.0 (`uri_normalized_by_nginx`, lines 643–662 in 3.21.0);
  - `apisix/plugins/forward-auth.lua` at 3.21.0, line 254;
  - PR #14035 metadata via `gh api` (merged 2026-10-26).
- Every `p2:` key cited in `NOVELTY_UPDATE.md` exists in `refs_pass2.bib`. The check is in the command list in the worker_done report.

## Contract interpretations
- **"dblp and Google Scholar by hand".** The dblp web, API and mirrors returned an anti-bot challenge, so dblp was searched through its public SPARQL endpoint (title substrings only). Google Scholar returned 403 and was not usable. Semantic Scholar, Crossref and venue pages were used instead. This is recorded as a threat to validity.
- **"Same format as pass 1"** was taken to mean the same CSV columns and decision vocabulary. IDs are `P2-NNN` so they cannot collide with the positional `S0xx` IDs of pass 1.
- **Bib keys** are prefixed `p2:`, so `refs_pass2.bib` can be added next to `../refs.bib` without clashes. `p2:golinelli2026post` supersedes the arXiv entry `golinelli2026post` in `../refs.bib`, because the paper is now accepted at ACSAC 2026.
- No file outside `binding/lit/pass2/` was edited (CONTRACT §15).

## Known limitations
- There was one reviewer and no inter-rater check.
- Abstract-only, with no full text:
  - NginxBuster (CCS'26): ACM DL returned 403. **It must be read before submission.**
  - Audience Injection (S&P'26): closed access.
  - SPCA, H3Act, and the arXiv items.
- Title-only: PathFault (ICISC) and ProxyShell; Tiurin 2018 was seen at landing-page level.
- NDSS 2027, S&P 2027 and USENIX Security 2027 lists were not available on 2026-11-24. The EuroS&P 2026 accepted page returned 403, so the program page was used.
- CVE-2026-2880 (fastify/middie) and CVE-2026-39852 (Quarkus) rest on single secondary sources and are marked UNVERIFIED.
- The dblp SPARQL search matches titles only. Papers whose relevance shows only in the abstract can be missed; venue lists and web search partly compensate.

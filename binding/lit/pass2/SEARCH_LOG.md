# Pass-2 search log (W20, 2026-11-24)

Every query below was actually run. Raw machine output is in `search_log/`. Downloaded PDFs and pages were kept in the session scratchpad, not in the repo; they were read with `pdftotext` or an HTML-to-text strip.

## 1. dblp (by hand, through the public SPARQL endpoint)
The dblp search API, the dblp web UI and both mirrors (`dblp.uni-trier.de`, `dblp.dagstuhl.de`) returned an anti-bot challenge page ("Making sure you're not a bot!") to every scripted request on 2026-11-24. That is the same block pass 1 hit. `https://sparql.dblp.org/sparql` was **not** blocked, so dblp was searched through it with `tools/dblp_sparql.py`.

The query semantics are: every listed substring must appear, case-insensitively, in the title, and the year must be ≥ `min_year`. Results are in `search_log/dblp.jsonl` (one JSON line per query, all rows kept) and in the human-readable `search_log/dblp_run1.txt` and `search_log/dblp_run2.txt`.

**Run 1 (min_year 2015):**
- `path confusion`; `normaliz|url`; `normalis|url`; `normaliz|path`
- `parsing discrepanc`; `parsing differen`; `semantic gap|http`
- `request smuggling`; `desync`; `reverse proxy`; `api gateway`
- `access control bypass`; `authorization bypass`; `url pars`; `uri pars`
- `proof-of-possession|token`; `dpop`; `sender-constrain`
- `web cache deception`; `differential|http`; `inconsisten|http`; `http|discrepanc`
- `access control|web|differen`; `path traversal`; `service mesh`; `broken access control`
- `authorization|microservice`; `web application firewall|bypass`; `waf|bypass`
- `method override`; `graphql|authoriz`; `request|interpretation`

**Run 2 (min_year 2023):**
- `url|parser`; `confusion|http`; `confusion|web`; `access control|proxy`; `authoriz|gateway`
- `canonicali`; `parsing|inconsisten`; `differential fuzz`; `oauth`
- `proof of possession`; `message signature`; `token binding`; `sender`
- `semantic gap`; `parser|discrepanc`; `smuggling`; `cache deception`; `cache poison`
- `access control|fuzz`; `authoriz|bypass`; `access control|bypass`; `authenticat|bypass`
- `path|confus`; `url|confus`; `reverse prox`; `middlebox|http`; `ext_authz`
- `zero trust|proxy`; `policy enforcement point`; `authorization|api`; `rest api|security`
- `graphql|security`; `http method`; `jwt`; `dpop`

The `dpop` query returns mostly homonyms (DPOP constraint optimisation, FedPop). The only real hits are RFC 9449 and RFC 7800/8747.

## 2. Google Scholar
`curl https://scholar.google.com/scholar?q=path+normalization+access+control+bypass` returned **HTTP 403**. Google Scholar could not be used, the same as in pass 1. This is a threat to validity. Scholar's forward-citation coverage was partly replaced by:
- Semantic Scholar (`api.semanticscholar.org/graph/v1`): paper lookups by DOI or title for UABScan, NginxBuster, Audience Injection, PathFault, SPCA and TBSG;
- Crossref `/works/{doi}` and `query.bibliographic`;
- the arXiv export API (§4).

## 3. Web searches (WebSearch tool, exact strings)
**Practitioner track:**
1. `Orange Tsai "Breaking Parser Logic" Black Hat 2018 path normalization`
2. `xvnpw path traversal in authorization context Kong F5 NGINX`
3. `PortSwigger research path confusion URL parser discrepancies access control bypass Kettle`
4. `Martin Doyhenard "Gotta cache 'em all" web cache deception path confusion Black Hat 2024`
5. `Orange Tsai "Confusion Attacks" Apache HTTP Server Black Hat USA 2024 ACL bypass`
6. `Orange Tsai ProxyShell "path confusion" Exchange frontend backend explicit logon URL normalization Black Hat 2021`
7. `Assetnote research path normalization access control bypass reverse proxy backend "path confusion"`
8. `Acunetix "path normalization" reverse proxy backend discrepancy "..;/" tomcat nginx research`
9. `Aleksei Tiurin "Reverse proxies & Inconsistency" talk 2018 path ACL bypass`
10. `Detectify research path normalization reverse proxy access control bypass "path normalization"`
11. `DEF CON OR "OWASP AppSec" talk proxy backend URL parsing discrepancy access control bypass "middleware" 2023 2024 2025`

**CVE families:**
12. `Istio CVE-2021-39156 fragment "#" path authorization policy bypass Envoy CVE-2021-32779`
13. `Envoy CVE-2021-29492 escaped slash %2F authorization bypass path_with_escaped_slashes_action`
14. `Traefik CVE path normalization authorization bypass ForwardAuth advisory GHSA 2025 2026`
15. `Apache APISIX CVE path traversal plugin bypass uri normalization CVE-2021-45232 CVE-2022 forward-auth`
16. `envoy-security-announce "Double URL Decoding Mismatch Between Edge and Origin Envoy"`
17. `Traefik CVE-2026-88009 GHSA-f52w-8j3h-j724 opaque request-target forwardAuth bypass`
18. `Spring Security CVE-2016-5007 path matching inconsistency Spring MVC authorization bypass; CVE-2023-34034 CVE-2024-38821 mvcRequestMatcher`
19. `"CVE-2016-5007" Spring Security Spring MVC path matching inconsistency`
20. `Kong gateway CVE path normalization authorization bypass CVE-2021-27306 jwt plugin route`
21. `Kong Gateway 2026 CVE path normalization route authorization bypass advisory`
22. `ASP.NET Core Kestrel path normalization dot segment authorization bypass reverse proxy advisory CVE`
23. `oauth2-proxy CVE-2025-64484 header underscore normalization bypass X-Forwarded headers; fabio CVE-2025-48865`
24. `Heimdall CVE-2026-42274 raw path access rule bypass; Ory Oathkeeper path normalization authorization bypass 2026 advisory`
25. `Next.js CVE-2025-29927 x-middleware-subrequest middleware authorization bypass`

**Academic track:**
26. `paper "path normalization" OR "URL normalization" inconsistencies reverse proxy backend access control bypass USENIX Security OR NDSS OR CCS 2025 2026` (extended)
27. `"403 Forbidden? Ethically Evaluating Broken Access Control in the Wild" IEEE S&P 2025`
28. `"yoU aRe a Liar" unified framework cross-testing URL parsers LangSec 2022`
29. `URL-based authentication bypass routing authentication inconsistency 2026 paper gateway framework multi-language follow-up UABScan` (extended)
30. `arXiv 2026 path confusion authorization bypass API gateway backend inconsistency differential testing` (extended)
31. `"Breaking the Gate" "Authentication Slip-Through" NGINX reverse proxy CCS 2026` (extended)

## 4. arXiv (export API, `tools/arxiv_q.py`, submissions ≥ 2026-01-01, sorted by date, max 100 per query)
The queries are listed below. Results are in `search_log/arxiv2026.jsonl` and `search_log/arxiv2026_run.txt`.
- `all:DPoP`; `all:"proof-of-possession"`; `all:"sender-constrained"`
- `all:"parser differential"`; `all:"parsing differential"`
- `abs:"path normalization"`; `abs:"URL normalization"`
- `cat:cs.CR AND abs:"API gateway"`; `cat:cs.CR AND abs:"reverse proxy"`; `cat:cs.CR AND abs:"request smuggling"`
- `cat:cs.CR AND abs:"access control" AND abs:"parsing"`; `cat:cs.CR AND abs:"authorization" AND abs:"gateway"`
- `cat:cs.CR AND abs:"method override"`; `cat:cs.CR AND abs:"HTTP message signatures"`; `cat:cs.CR AND abs:"discrepanc" AND abs:HTTP`
- `cat:cs.CR AND abs:"broken access control"`; `cat:cs.CR AND abs:"path confusion"`; `cat:cs.CR AND abs:normalization AND abs:bypass`

A follow-up `id_list=` call returned empty bodies, which looks like rate-limiting. The six candidate abstracts were therefore read from `arxiv.org/abs/<id>` `citation_*` meta tags instead.

## 5. Accepted-paper lists (fetched 2026-11-24, then grepped for the topic keyword set in `NOVELTY_UPDATE.md` §R)
| Venue | URL fetched | Status |
|---|---|---|
| CCS 2026 | sigsac.org/ccs/CCS2026/program/accepted-papers.html (+ schedule.html) | **full list available**; screened |
| NDSS 2027 | ndss-symposium.org/ndss2027/accepted-papers/ | **not available**: redirects to the *2017* list. Not screenable. |
| NDSS 2026 | ndss-symposium.org/ndss2026/accepted-papers/ | screened |
| USENIX Security 2026 | usenix.org/conference/usenixsecurity26/technical-sessions | screened (full program) |
| USENIX Security 2027 | usenixsecurity27/cycle1-accepted-papers | placeholder page, no papers listed |
| IEEE S&P 2026 | sp2026.ieee-security.org/accepted-papers.html | screened |
| IEEE S&P 2027 | sp2027.ieee-security.org/accepted-papers.html | page exists, **no papers listed yet** |
| EuroS&P 2026 | eurosp2026.ieee-security.org/accepted-papers.html | **HTTP 403**; program.html screened instead |
| ACSAC 2026 | acsac.org/2026/program/papers/ | screened |
| AsiaCCS 2026 | asiaccs2026.cse.iitkgp.ac.in/cycle-1-papers/, cycle-2-papers/ | screened (accepted-papers/ is a 404; the cycle pages work) |

## 6. Primary-source checks (code and advisories)
- APISIX: `apisix/init.lua` at tags 3.20.0 and 3.21.0 (raw.githubusercontent.com) contains `uri_normalized_by_nginx`, lines 643–662 in 3.21.0. `apisix/plugins/forward-auth.lua` at 3.21.0 line 254 is `["X-Forwarded-Uri"] = ctx.var.request_uri`. PR #14035 was merged 2026-10-26 (via `gh api`).
- IETF: `draft-ietf-oauth-signed-http-request-03` (archive copy) read in full.
- URL and DOI verification of every bib entry: `tools/verify_urls.py` → `search_log/url_verification.tsv` (61 targets, all HTTP 200 or Crossref-resolved). NVD pages render client-side, so their titles are generic. Where an NVD URL is cited, the content was confirmed through the GitLab, OSV, Istio or Red Hat mirror named in the bib note.

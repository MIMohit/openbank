# Systematic literature review protocol (Phase 1, W1)

Project: *Proof ≠ Execution: binding soundness of sender-constrained API requests in layered deployments.*
Protocol fixed and executed on 2026-11-23, following Kitchenham-style SLR steps scaled to a novelty gate. The execution record is in `screening.csv`, `extraction.csv`, `search_log/`, `killreads.md` and `README.md` (§ "How it was verified" and § "Resume pass").

## 1. Review questions

The plan (`research/ASIACCS2027_research_directions.md`) names the RQ-L topics but does not word them. The coordinator's plan artifact could not be opened (artifact not found). The wording below was derived from the plan's §2, §8 and §10 week-1 kill criteria; see the README section "Contract interpretations".

- **RQ-L1 (oracle novelty).** Has any prior work used *acceptance of a sender-constraint proof or request signature* (DPoP, mTLS-bound tokens, HTTP message signatures, FAPI message signing) as the oracle for testing layered deployments? That is, has anyone measured whether a request accepted under proof π executes an operation other than op(π)?
- **RQ-L2 (formal coverage).** Do formal analyses of DPoP/FAPI/OAuth model an intermediary between the verifier and the executor, or any URI normalisation, method override or propagation of verification results? Which resource-server checks do they assume, and does their attacker model include leaked resource requests?
- **RQ-L3 (differentials and defences).** Which request-interpretation-differential primitives (path, method, host, header, body framing) are documented for proxy→backend chains? Do the proposed defences (Request Synchronization, cryptographic hop binding, normalisers, header whitelisting) bind the client's proof to the executed operation?
- **RQ-L4 (deployment and standards state).** What is known empirically about RS-side sender-constraint enforcement (testing tools, conformance suites, measurements) and about under-binding by design (query, body, method override, single-endpoint dispatch)? What is the current standards discussion (OAuth WG, FAPI, MCP)?

## 2. Sources (databases)

| Source | Access method | Role |
|---|---|---|
| arXiv | export.arxiv.org API (`tools/arx.py`) | primary (preprints 2024–26) |
| Crossref | REST API `query.bibliographic`, from 2016 (`tools/cr.py`) | primary (peer-reviewed venues incl. ACM/IEEE/USENIX DOIs) |
| Semantic Scholar | Graph API `/paper/search` (`tools/s2.py`) | secondary (rate-limited; see README) |
| dblp | search API | planned; **blocked** by an anti-bot challenge (HTTP 202 with challenge page); replaced by Crossref and venue pages |
| Google Scholar | — | not used (no programmatic access, ToS); replaced by a general web search engine |
| General web search | WebSearch tool | grey literature, venue pages, advisories, new preprints |
| IACR ePrint | landing pages + Wayback PDF copies | formal analyses |
| Venue pages | NDSS 2026 papers, USENIX Sec'25, CCS 2026 accepted list (search) | venue confirmation |
| Standards/WG | IETF datatracker, OAuth WG mail archive, OIDF specs, MCP GitHub | RQ-L4 |
| Advisories | NVD, GitHub Security Advisories, Istio bulletins | G2/G3 provenance |

## 3. Search strings

**Block A: binding mechanism.**
`DPoP OR "demonstrating proof of possession" OR "proof-of-possession" OR "sender-constrained" OR "certificate-bound" OR "mutual TLS" token OR "HTTP message signatures" OR "request signing"`

**Block B: interpretation differential.**
`"request smuggling" OR "parsing discrepanc*" OR "parser differential" OR "path confusion" OR "host confusion" OR "semantic gap" OR "differential fuzzing" AND HTTP OR desync`

**Block C: placement / intermediary.**
`"API gateway" OR "reverse proxy" OR "service mesh" OR ext_authz OR "external authorization" OR "forward auth" OR auth_request OR "verifier placement" OR "X-Forwarded" OR "trust header"`

**Block D: execution semantics / oracle.**
`"method override" OR "HTTP method" security OR "method interchangeability" OR GraphQL authorization OR "authorization bypass" OR "access control bypass" OR "executed operation"`

**Combinations executed:**
- A, B, C, D alone. Per-concept queries were needed because arXiv/Crossref ranking with long ORs is poor; see `search_log/arxq.json`, `s2q.json`.
- A∧B, A∧C, A∧D, B∧C∧D, C∧D (`search_log/arxq2.json`).

**Targeted 2025–26 recency queries (web):**
- "DPoP" + CCS 2026 / NDSS 2027 / USENIX Sec 2026;
- "proof-of-possession" OR "sender-constrained" + reverse proxy/gateway bypass;
- "verifier placement" / authorization placement;
- "ext_authz bypass" path normalisation;
- DPoP htu normalisation behind a reverse proxy.

The arXiv field syntax used was `all:"..."`; the exact strings are in the JSON files.

## 4. Inclusion and exclusion criteria

**Include if all of the following hold:**
- **I1.** The item is a peer-reviewed paper, a preprint (arXiv/ePrint/author site) or a standards/WG/advisory artefact. Window: 2016–2026 for searches; seeds and lineage works may be older.
- **I2.** It addresses at least one of:
  - (a) sender-constraint, PoP or request-signature binding semantics or their verification;
  - (b) request-interpretation differentials between HTTP components;
  - (c) security-check placement across intermediaries (gateway, PDP, WAF, cache) relative to the executor;
  - (d) execution semantics that decouple the checked request view from the executed operation (method override or interchangeability, single-endpoint dispatch).
- **I3.** It contributes a model, measurement, tool, attack, defence or normative requirement.

Decision **background** = cited for context or standards but not extracted.

**Exclude:**
- **E1.** Off-topic or homonym (e.g. DPOP = distributed constraint optimisation; DPO = preference optimisation).
- **E2.** No accessible metadata.
- **E3.** Tutorial, marketing, position piece or case study without a technical method.
- **E4.** Duplicate or version of an included item.
- **E5.** In-domain keyword but none of I2 (a)–(d), e.g. OAuth client flows, IoT token schemes, revocation.
- **E6.** Primitive source superseded by included works with no new oracle (used sparingly; the reason is logged).

## 5. Screening procedure

1. Title/abstract screening (stage `TA`) of the following:
   - all arXiv API hits;
   - the top 15 Crossref hits per query;
   - the top 20 Semantic Scholar hits per returned query;
   - web-search hits.
2. Metadata check (stage `MD`): venue, DOI or URL confirmed on the publisher/venue page or via Crossref.
3. Full-text read (stage `FT`) for all priority kill-reads and for any hit judged a potential kill (an oracle, layer or binding match).
4. One reviewer (W1). Decisions and reasons are logged per item in `screening.csv`. The decision table is code (`tools/build_csv.py`), so the logs are reproducible.

## 6. Snowballing seeds

Backward and forward snowballing was done from:
- T-Reqs (CCS'21);
- Gudifu (RAID'24);
- HDHunter (USENIX Sec'25);
- WAFFLED (arXiv 2503.10846 / ACSAC'25);
- HTTP Request Synchronization (arXiv 2510.09952);
- Hosseyni/Küsters/Würtele FAPI 2.0 (ePrint 2024/1540 = ACM TOPS; ePrint 2024/078 = CSF'24);
- JWTeemo / Token Time Bomb (NDSS'26);
- OAuch (RAID'22).

Snowballing used each paper's related-work section and references (for the full texts read). Forward snowballing used web search, plus the OIDF announcement pages for the FAPI work. Snowball finds:
- the OIDF 2022 FAPI 2.0 technical report (from the openid.net announcement);
- H2Fuzz (RAID'25, from the Gudifu/HDHunter neighbourhood via Crossref);
- CREHMA (CODASPY'20);
- Golinelli et al. 2026 (Trento, from the same group network as Innocenti/Golinelli/Kirda);
- Mancinas 2026 (it cites Hosseyni et al.).

## 7. Data extraction

The `extraction.csv` fields, one row per included item:
- `id`, `venue_year`;
- `layer` (where the studied disagreement sits);
- `oracle` (what counts as a finding);
- `binding_involved` (DPoP/mTLS/signature, or none);
- `placement_modelled` (is the checker separate from the executor?);
- `primitives`;
- `targets_versions`;
- `threat_model`;
- `artefact` (public code?);
- `closest_rq`;
- `kill_risk` (none/low/medium/high for our core claim);
- `notes`.

## 8. Novelty gate G0

**FAIL** if any included work does any of the following:
- (i) measures acceptance of a sender-constraint proof or request signature against the operation actually executed, across a verifier/executor split;
- (ii) formally models an intermediary between the DPoP/mTLS verifier and the executor and proves or refutes binding of the executed operation;
- (iii) already evaluates a canonical-request or view-binding defence against G1–G3.

Otherwise the verdict is **PASS**, together with a must-cite/differentiate list. The verdict and reasons are in `novelty_memo.md`.

## 9. Threats to validity of the review

- A single reviewer.
- dblp and Google Scholar were not usable programmatically, and the Semantic Scholar API was mostly rate-limited. This was mitigated with Crossref plus the web search engine plus venue pages.
- arXiv API ranking is shallow for long OR-queries, so block queries were run separately.
- Only 2 of the advisory sources were read at primary pages (NVD/Istio); the advisory details come from secondary aggregators.
- HDHunter, T-Reqs, Host of Troubles and Cached and Confused were checked at metadata level only.

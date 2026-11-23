# binding/lit: systematic literature review and novelty gate G0 (W1)

## What this is
This directory holds Phase 1 of the "Proof ≠ Execution" project: a protocol-driven literature review, full-text kill-reads, and the G0 novelty verdict. It also feeds the paper's related-work section.

| File | Content |
|---|---|
| `protocol.md` | RQ-L1..RQ-L4, sources, search blocks A–D and their combinations, inclusion/exclusion criteria, snowballing seeds, extraction fields, G0 criteria, threats to validity |
| `screening.csv` | Every screened item: `id,title,authors,venue,year,url,stage,decision,reason` (385 items: 28 include, 21 background, 336 exclude) |
| `extraction.csv` | One row per included item, with the 13 fields required by the task |
| `related_matrix.csv` | Papers × (oracle, layer, binding, placement, artefact), plus a planned row for this work |
| `killreads.md` | Full-text evidence for the priority kill-reads, with page and section references (K1–K12) |
| `novelty_memo.md` | Answers to RQ-L1..L4, **G0 verdict: PASS**, and the must-cite/differentiate table |
| `refs.bib` | BibTeX for every cited work; unverifiable fields are flagged `UNVERIFIED` in comments |
| `search_log/` | Raw API dumps and query files: arXiv, Crossref, Semantic Scholar, plus the DOI metadata used for the bib |
| `tools/` | `arx.py`, `cr.py`, `s2.py`, `doi.py` (search clients), `pg.py` (page-wise PDF grep), `build_csv.py` (builds the three CSVs from the logs and the curated decisions) |
| `../paper/sections/related.tex` | About one page of related work (ACM sigconf), cites `refs.bib` and three `w2:` keys from `../paper/extra.bib` |

## How to run / reproduce
```sh
cd /Users/mimohit/openbank
python3 -I binding/lit/tools/build_csv.py   # regenerates screening/extraction/related_matrix CSVs
# prints: screened=385 include=28 background=21 exclude=336
```
The search clients (`tools/arx.py` and the others) re-query live APIs. Their results will drift over time; the dumps in `search_log/` are the record actually screened. Downloaded PDFs were kept out of the repo and read with `pdftotext`.

## How it was verified
- `build_csv.py` runs cleanly and reproduces the CSV counts above. Every included or background record has a URL or DOI. DOI metadata comes from Crossref (`search_log/dois.json`).
- Cite-key check: every `\cite` key in `related.tex` (45 keys) resolves in `refs.bib` or `../paper/extra.bib`. Zero keys are missing.
- Compile check: `tectonic -X compile main.tex --outdir <scratch>` in `binding/paper/` returned rc=0.
  - There were no undefined citations or references, and zero `??` / `[?]` in the PDF.
  - BibTeX gave 25 cosmetic warnings (empty `address`, missing pages for USENIX/NDSS entries).
  - The related-work section renders at about one page.
  - The build output went to the scratchpad, not to W2's `paper/build/`.

## Resume pass (2026-11-23)
A previous attempt was cut off by a usage limit after it wrote the protocol, the CSVs, the search logs and `killreads.md`. That work was kept. This pass added:
- `novelty_memo.md`, `refs.bib`, `related.tex` and this README;
- a read of the OAuth WG thread "DPoP tokens vs downstream resource servers" (msg24959/msg24995), previously marked unread;
- one new close hit, grpc-gateway CVE-2026-37236 (method override bypasses upstream method-based controls), from repeated recency searches;
- a project devlog, screened out (E3).

Both were added through `build_csv.py`. Because the screening IDs (`S0xx`) are positional, they shift when records are added; extraction uses stable keys.

## Contract interpretations
- **RQ-L1..L4 wording.** The plan names the topics but does not word the questions, and the coordinator's plan artifact could not be opened. The wording is derived from the plan's §2, §8 and §10 kill criteria (`protocol.md` §1).
- **"Search dblp/Scholar".** dblp returned an anti-bot challenge, and Google Scholar has no usable programmatic access. Both were replaced by Crossref, arXiv, Semantic Scholar (heavily rate-limited), web search and venue pages. This is recorded as a threat to validity.
- **ePrint PDFs.** IACR ePrint returned Cloudflare 403. The full texts were read from Wayback Machine copies whose page counts and titles match the ePrint landing pages.
- **Bib keys.** W2's `extra.bib` already defines `w2:rfc9449`, `w2:rfc9421` and `w2:fapi2am`. `related.tex` cites those keys so the bibliography does not list the same work twice. `refs.bib` still carries standalone entries (`rfc9449`, `rfc9421`, `fapiam2025`, ...) for other users.
  - **Duplicate to resolve (W2/coordinator):** `w2:hosseyni2024fapi2` (ePrint 2024/078 as `@misc`) is the same work as `hosseyni2024csf` (the CSF'24 DOI, with the ePrint in `note`). Both appear in the bibliography now that intro.tex and related.tex cite them. Recommendation: switch intro/model to `hosseyni2024csf`.
- **Venue-less items.** Preprints (Mancinas 2026, HTTP Garden) are cited as `@misc` with the URL actually seen. Any first name expanded from initials is flagged UNVERIFIED in a comment.

## Known limitations
- One reviewer; no inter-rater agreement.
- Not read in full: HDHunter, T-Reqs, Host of Troubles, Cached and Confused, FRAMESHIFTER. They are primitive sources, not kill candidates, and are cited only for metadata-level claims.
- CCS 2026 and NDSS 2027 accepted-paper lists were not enumerated completely. **Re-run the recency searches before submission** (`novelty_memo.md`, residual risk 2).
- Advisory details (Traefik, OPA-Envoy, Envoy) partly come from secondary aggregators. Only the NVD/OSV/Istio pages were seen directly.
- The arXiv 2510.09952 artefact was unavailable (404) on 2026-11-23. E8 must re-implement it or argue analytically.

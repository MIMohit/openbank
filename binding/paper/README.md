# Paper: "Proof ≠ Execution"

**What it is.** The LaTeX sources for the ASIA CCS 2027 submission. It uses ACM `acmart`,
`\documentclass[sigconf,anonymous,review]{acmart}`. Owner: W2. The exception is
`sections/related.tex`, which W1 owns and which `main.tex` only `\input`s.

```
main.tex            includes macros, numbers, sections, appendices
macros.tex          notation (\htm, \Aleak, \GA, ...) and \TBD{}/\todo{}
numbers.tex         EVERY quantitative claim is a macro here, all TBD for now
extra.bib           W2's citations (keys prefixed "w2:" to avoid clashing with ../lit/refs.bib)
sections/
  intro.tex         outline draft; numbers only via numbers.tex macros
  background.tex    DPoP (RFC 9449), RFC 8705/9440, RFC 9421, ext_authz/ForwardAuth/auth_request
  model.tex         system model, binding soundness/resolution, authorization soundness,
                    G1/G2/G3, A_leak/A_client, excluded adversaries, H1-H5 table, scope
  prevalence.tex harness.tex defence.tex discussion.tex conclusion.tex   TODO stubs
  related.tex       (W1; a stub section is printed while it is absent)
appendix/
  hypotheses.tex    H1-H5 with tests, falsifiers, and ablations A1-A5
  oracle.tex        paper-facing summary of ../harness/oracle/oracle_spec.md
  primitives.tex    TODO: to be generated from the W7 primitive catalogue
```

## How to build

- `make pdf` uses `tectonic` (0.17.0 at `/opt/homebrew/bin/tectonic`, user-level). It downloads
  `acmart` and its fonts on the first run. No system-wide TeX was installed.
- `make docker` is the alternative, using the locally present `texlive/texlive:latest-medium` image
  (container name `w2-latex`, removed after the run). Not exercised in this session.
- If `../lit/refs.bib` is absent, only `extra.bib` is used (`\IfFileExists` in `main.tex`).

## How to test

On 2026-11-23, `tectonic -X compile main.tex --outdir <scratch> --keep-logs` gave:
- exit code 0, a 5-page PDF;
- no undefined references or citations (checked with
  `grep -E "undefined|Overfull" main.log`);
- 0 BibTeX warnings;
- remaining overfull boxes come only from the red `[TBD:...]` placeholders in TODO
  paragraphs, plus a few lines up to about 10 pt over. They disappear once numbers are filled in.

## Rules for editing

- Never put a number in prose. Add a macro to `numbers.tex` and fill it from a recorded output
  (`harness/logs/*/summary.csv`, `prevalence/*`), with the producing script named in a comment.
- Quotations in `background.tex` and `model.tex` were checked against the RFC texts fetched from
  rfc-editor.org (9449, 8705, 9440, 9421, 9530 header), the FAPI 2.0 Attacker Model (final,
  published 22 Feb 2025) and the vendor docs (Envoy ext_authz v3 API, Traefik ForwardAuth, NGINX
  auth_request), all fetched on 2026-11-23. Re-check them if you edit a quotation.

## Contract interpretations

1. **Ablations A1–A5** (reconciled with the plan by W10, 2026-11-23): A1 binding claims (drop htm / htu / ath,
   add query binding, add body digest; this is E9); A2 D-B canonicalisation steps, leave one out (percent-decode,
   dot-segment removal, case, slash merge, prefix map); A3 verifier placement (edge / origin / both); A4 primitive
   classes, leave one out (G1 / G2 / G3); A5 gateway profiles (default / recommended / strict).
2. **Hypothesis-to-experiment mapping.** H1 → E1, E2, E3 (G1 primitives), E6, E9/A1; H2 → E3, E6, E8, A1 (drop htu),
   A3, A5; H3 → E4, E5, A3, A4; H4 → E7, E8, A2, A3; H5 → E10.
3. **Executed-operation identity** is `x̂(r) = (op_id, path_params)`, not just `op_id`. Without the
   path parameters, the contract's S1 rule "a different `{id}` / owner" can never fire. The oracle
   spec therefore adds a *resource substitution* disjunct to the hit definition. **W7 should
   implement this**; it needs `path_params` in the ground truth.
4. **Ground truth** is measured, not read from the contract §3 table. The canonical request is sent
   directly to the executor with `VERIFY_MODE=off` and the topology's `OVERRIDE` value. A mismatch
   with §3 marks the executor `nonconformant`, and its cases are excluded.
5. **The runner must log the case's `jti`**, or derive it from `raw_request_b64`. It is needed for the join.
6. **G3 without an operation change** (spoofed identity or certificate headers that reach the
   executor) is reported by a separate *propagation* predicate. It is not counted as a §6 binding
   hit.
7. **Verifier bypass** (executor ran, no verifier record in edge placement) is reported as class B0
   and is never counted as a binding hit.
8. **A_leak and replay state.** The runner sends only the mutated request for each fresh proof.
   This models deployments where the jti check does not reject it: no shared cache across replicas,
   or a cache keyed per target URI (RFC 9449 §11.1: "In the context of the target URI"). The paper
   states this and reports results with `JTI_CACHE` on and off.
9. **TLS scope.** The model states why TLS is out of the harness's scope, as contract §1 asks. Any
   HTTP/2 front-end behaviour can only be exercised through cleartext h2c. This is flagged as a
   limitation for E7's "H2→H1" false-rejection cases.

## Known limitations / open items

- Wave 2 (W10, 2026-11-23): `sections/prevalence.tex` is written from `../prevalence/E1_results.md` and
  `E2_results.md`; every number is a macro in `numbers.tex` whose comment names the source line.
  `sections/harness.tex` has the methodology (architecture, oracle, validation, matrix) from the harness READMEs;
  its Results subsection is `\todo{}` until W9's kill experiment and the campaign produce outputs.
  Fig. 1 (`model.tex`, views) and Fig. 2 (`harness.tex`, harness) are TikZ.
- Bibliography: works held by `../lit/refs.bib` are cited by its keys (rfc9449, rfc8705, rfc9440, rfc9421,
  fapiam2025, hosseyni2024csf); their `w2:` duplicates were removed from `extra.bib`. The remaining BibTeX
  warnings ("empty address", missing pages) come from `../lit/refs.bib` entries (W1).
- Intro, defence, discussion, conclusion and the primitives appendix are still outlines or TODO stubs;
  campaign numbers stay `\TBD{}`.
- I could not read the published plan artifact (claude.ai/artifact/6rdXSAjgm5gNtGcJiBk8eW): access
  was denied. Hypotheses and experiments follow `research/ASIACCS2027_research_directions.md`.
- `extra.bib` keys duplicate references W1 may also hold, for example RFC 9449. Deduplicate at camera-ready.

## Wave 3 (W19, 2026-11-23): results integration

- `sections/harness.tex` §5.4–5.6: campaign table (Table 4), binding results under A_leak (totals,
  class split, B1–B3, G1, G3, resolution, A3), heatmap (Fig. 3), root-cause table (Table 5), and
  authorization soundness under A_client (E4). Sources: `../experiments/GATE_DECISION.md`,
  `kill/{G1_REPORT,ROOT_CAUSES}.md`, `ext-gw/REPORT.md`, `ext-fw/REPORT.md`, `ext-routes/REPORT.md`,
  `e4/{REPORT,ROOT_CAUSES}.md`. Every number is a macro in `numbers.tex` naming its source.
- `sections/model.tex`: paragraph "Which property a finding violates" (E4 = authorization soundness
  with the DPoP check passing; binding soundness = leaked proof). The JTI_CACHE on/off claim was
  removed (only cache-on with a fresh proof per case was run).
- Intro, discussion (recommendations, limitations, ethics/disclosure), conclusion and abstract are
  final apart from `\todo{}` hooks for W17 (defence, E7/E8/A2) and W18 (A1/A4/A5), and the
  Kong/APISIX novelty sentence, which stays `\todo{pending triage}` until W16 reports.
- **Figures.** `figs/make_figs.py` (matplotlib 3.9.2, style from `../../analysis/figstyle.py`) reads the
  experiment CSV/JSONL files and writes `figs/hits_heatmap.pdf` (vector) and `figs/aggregate.json`
  (every recomputed total cited in `numbers.tex`). Run it with `python figs/make_figs.py` in an
  environment from `figs/requirements.txt`. Class rule: a G2-labelled hit whose ddmin witness is a
  byte in the unbound `?op=` (kill RC7) counts as G1 (36 hits).
- Build check (tectonic): 14 pages, references start on p. 12, so the body is about 11.4 pages.
  One overfull box (27 pt) remains; it comes from the `\TBD{FalseRejectionRate}` placeholder in
  `defence.tex` and disappears when W17 fills it.

## Integrity revision (W19, after W16 triage)

- APISIX RC-W13-A is now presented as a *measured observation whose mechanism is unconfirmed*:
  the published `forward-auth.lua` sets `X-Forwarded-Uri` from `ctx.var.request_uri` (expected
  raw), which conflicts with the decoded view the verifier logged (`ext-gw/runs/w13-apisix-*/verifier.jsonl`).
  It is marked B2† in Table 5, with a `\todo` to confirm the bytes locally (`disclosure/TRIAGE.md`).
- The abstract and intro now lead with the load-bearing G2 classes: E4 dot-segment allow-list bypass
  (RC1/RC2) and the ext-routes fragment nested-route substitution (X1).
- Kong RC2/RC7 is cited as documented/known (xvnpw 2021, CVE-2021-27306); `#` handling as known
  (uvicorn discussion #1222). New `extra.bib` keys: `w2:kongcve27306`, `w2:xvnpw2021kong`, `w2:uvicorn1222`.

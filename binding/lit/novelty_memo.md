# Novelty memo and gate G0 (W1, 2026-11-23)

Inputs: `protocol.md` (questions, strings, criteria), `screening.csv` (385 items screened: 28 include, 21 background, 336 exclude), `extraction.csv` (28 rows), `killreads.md` (full-text evidence with page numbers). Bracketed keys are BibTeX keys in `refs.bib`.

Evidence levels used below: **FT** = full text read; **MD** = metadata or landing page only; **SPEC** = standard, mailing-list or GitHub artefact read directly. A "not found" means not found in the logged searches, not "does not exist".

---

## RQ-L1: Has anyone used acceptance of a sender-constraint proof as the oracle against the executed operation?

**Answer: no, as far as the logged searches reach.**

The nearest works use the same *check-versus-execute* structure with a different check:
- **WAFFLED** [akhavani2025waffled] (ACSAC'25, FT): the WAF lets a request through while the framework parses and executes the payload. The check is a content signature (WAF rules), not a cryptographic binding. Their primitives are body parsing differentials; G1 and G3 involve no parsing bug.
- **When POST Becomes GET** [golinelli2026post] (arXiv Oct 2026, FT): method interchangeability. The oracle is response equivalence, plus CSRF tokens rejected for POST but accepted for GET (7 cases on 2 sites). It is single-application, with no proof binding, no gateway placement and no measurement of override middleware. **This is the closest G1 prior art and must be cited in G1 and in E2.**
- **Mancinas Fontalvo** [mancinas2026] (preprint, FT): DPoP replay through bounded jti caches (B1) and lossy XFCC propagation behind TLS termination (B2). The second is a G3-type propagation failure, but for mTLS. The paper explicitly says DPoP is unaffected because "its binding is at the application layer above any TLS termination point" (p7). Our G1/G2 claim contests this directly. It is not peer-reviewed.
- **Advisories** (MD): Traefik CVE-2026-40912 (ForwardAuth view differs from the executed path), Istio CVE-2021-31920, OPA-Envoy CVE-2026-26205, the Envoy 2019 advisory, and **grpc-gateway CVE-2026-37236**, where method override "allows bypassing method-based access controls enforced by upstream proxies or WAFs". These are single-product bugs with path or method ACLs as the check. They show that the class exists. None involves a cryptographic proof or a systematic cross-product.
- **Conceptual works** (FT): Gallo [gallo2026continuity] and Kim et al. [kim2026tbsg] argue in the abstract that an accepted token or signature can be insufficient. They contain no HTTP measurement.

## RQ-L2: Do formal analyses model an intermediary, URI normalisation or method override? Which RS checks are assumed? Are leaked requests in scope?

**No intermediary is modelled.** Hosseyni, Küsters and Würtele [hosseyni2022tr, hosseyni2024csf, hosseyni2024tops] (FT) model the RS as one atomic process:
- `reqUri := <URL, S, m.host, m.path, <>, ⊥>` and `resourceID := m.path`, both taken from the same message (2024/078 p39; 2024/1540 p72; TR Alg. 12 p25). The verified view *is* the executed request by construction.
- The only proxy mention is A7, *response* tampering by a compromised reverse proxy (2024/1540 p12).
- There is no URI normalisation, method override, or query or body semantics. A grep for proxy, intermediar, normaliz/normalis, canonical, reverse, gateway and rewrit in 2024/078 gave 0 hits.

**RS checks assumed:** signature with the `jwk` key; htm and htu; a server nonce, strictly one-time (stronger than RFC 9449); ath; cnf.jkt or x5t#S256.

**Property:** confidentiality of the resource (Def. 3, 2024/1540 p27). Integrity of the *executed operation* is not modelled.

**Leaked requests:** FAPI 2.0 AM [fapiam2025] (SPEC) A5 covers resource requests leaked *after* the RS has processed them (§7.7). The formal model was changed to match (2024/1540 §3.3, p15). Our A_leak therefore needs an explicit justification. Three cases qualify: jti tracking is optional (RFC 9449; SEP-1932 "NOT required"); the cache is bounded or per-replica (Mancinas B1); or the leak is pre-use. A_client (a malicious but legitimate client) needs no leak and should lead.

**Older lineage** [fett2016oauth, fett2019fapi] (MD) is background and precedes DPoP.

## RQ-L3: Which differential primitives are documented, and do the defences bind the proof to the executed operation?

**Primitive sources** (G2 provenance):
- T-Reqs [jabiyev2021treqs]: request line, headers, framing.
- Gudifu [jabiyev2024gudifu]: whole-request graybox fuzzing; artefact public.
- HDHunter [mu2025hdhunter]: artefact on Zenodo; full text not read.
- HTTP Garden [kallus2024garden]: gateway transformations; artefact public.
- FRAMESHIFTER [jabiyev2022frameshifter] and H2Fuzz [gavazzi2025h2fuzz]: HTTP/2 to HTTP/1 conversion.
- HDiff [shen2022hdiff]; Host of Troubles [chen2016host] (Host / absolute-URI).
- Cached and Confused [mirheidari2020cached]: path confusion (`%2F`, `;`, `%3F`).
- Equivocal URLs [reynolds2022equivocal]; CPDoS [nguyen2019cpdos].
- WAFFLED [akhavani2025waffled]: body content types.

**Defences.** None binds to the client's proof:
- **HTTP Request Synchronization** [topcuoglu2025sync] (FT) synchronises the full URL, Host and framing across hops.
  - It does not cover the effective method (override headers or `_method`), body dispatch or trust headers.
  - G1 query dispatch involves no hop disagreement, so synchronisation cannot catch it.
  - It dismisses message signatures as not "capable of providing systemic defense" (p5).
  - It requires a modified origin, and **the artefact is not public** (GitHub 404 and a user with 0 repos on 2026-11-23).
  - It is the baseline for E8 and must be re-implemented or argued analytically.
- **Header whitelisting** [buttner2021whitelisting] and **normalisers** (WAFFLED's HTTP-Normalizer) are view-agnostic.
- **CREHMA** [nguyen2020crehma] (TA) signs REST messages end to end for caches. It is the closest "sign the full request" precedent, but it does not tie a client PoP to a router decision.
- **draft-nygren-httpbis-http11-request-binding** [nygren2025binding] (MD) binds hops cryptographically against smuggling. It is hop-level, not tied to the client's proof.
- **RFC 9421** message signatures [rfc9421] (SPEC) make coverage a deployment choice, which is the same under-binding knob.
- **Our D-A (verify the routed view) and D-B (view-binding MAC) are not anticipated** by any of these.

## RQ-L4: What is known empirically about RS-side enforcement and under-binding, and where do the standards discussions stand?

**Measurement and tools** target the AS or the client side, or single-endpoint checks:
- OAuch [philippaerts2022oauch] (MD) tests AS compliance.
- JWTeemo [yang2026jwteemo] (NDSS'26, FT) works at the JWS/JWE library level: 0 PoP-related hits.
- MCP measurements [zhou2026mcp, padilla2026mcp] (FT) contain no PoP checks.
- MCP conformance issue #369 [mcpconf369] (SPEC) has negative tests for htm, htu, ath, iat and cnf on one endpoint. It does not test a proof for op A replayed as op B.

**Standards state:**
- RFC 9449 [rfc9449] binds only htm and htu without the query; jti tracking is "SHOULD"-level.
- The OAuth WG thread [allam2026thread] (29 Jun 2026, SPEC) proposes making htm and htu *optional* because proxies rewrite URIs. No replies were found.
- The earlier thread [madden2025thread] (Oct 2025, SPEC) discusses relaxing htu for downstream RSs. N. Madden states that backend trust in the token "fails to guarantee that the token relates to the backend API requests being made".
- MCP SEP-1932 [sep1932] (open) defers to RFC 9449 §4.3 and does not require jti tracking.
- RFC 9700 [rfc9700] and FAPI 2.0 SP [fapisp2025] require sender-constraining but say nothing about verifier placement (FAPI AM §8.4: internal architectures out of scope).

**Under-binding by design is acknowledged but unmeasured.** Golinelli et al. measure method interchangeability (not override, not proof-bound). No work quantifies how many state-changing operations are dispatched by query or body (our E1) or how often override is reachable with defaults (our E2).

---

## G0 verdict: **PASS**

The criteria come from `protocol.md` §8.
- **(i) A measurement of proof acceptance against the executed operation across a verifier/executor split: none found.**
  - The nearest works either have the structure without a cryptographic binding (WAFFLED, Golinelli, the advisories) or have the binding without operation-level oracles (Mancinas, MCP conformance).
- **(ii) A formal model of an intermediary between the verifier and the executor: none.**
  - The Hosseyni et al. RS is atomic, takes the verified view and the executed resource from the same message, and has a confidentiality-only property (FT, page evidence in `killreads.md` K1).
- **(iii) A canonical-request or view-binding defence evaluated against G1–G3: none.**
  - Request Synchronization covers the G2 path, host and framing parts only, and is not public.

**Residual risks (not gate failures):**
1. **The G1 method angle is partly pre-empted** by Golinelli et al. (Oct 2026) and CVE-2026-37236. The claim must be framed as *proof-bound* method mismatch across placements, not "method confusion is new".
2. **Concurrent work.** The Kirda/Onarlioglu group (T-Reqs → Gudifu → WAFFLED → Request Sync) and the Golinelli/Crispo group are active neighbours, and Mancinas could extend to DPoP. CCS 2026 and NDSS 2027 accepted lists could not be fully enumerated. **Re-run the recency searches before submission.**
3. **Review coverage.** There was a single reviewer, and dblp and Scholar were unavailable programmatically (`protocol.md` §9). HDHunter, T-Reqs, Host of Troubles and Cached and Confused were not read in full; they are primitive sources only, not kill candidates.
4. **The empirical kill experiment** (plan week 2–3) is a separate gate. G0 says only that the idea is unclaimed, not that the effect exists at scale.

## Must cite and differentiate

| Work | Differentiation line |
|---|---|
| Hosseyni et al. CSF'24 / TOPS'24 (+ TR'22) | Their RS is atomic; we generalise their RS check to deployments where the check and the execution are split, and replace resource confidentiality with operation integrity. |
| FAPI 2.0 AM | A5 leaks only after processing; we justify A_leak (optional jti, bounded caches) and lead with A_client. |
| HTTP Request Synchronization (arXiv 2510.09952) | Covers G2 path, host and framing between proxies; it does not cover G1 (no disagreement exists) or G3, and does not bind to the client's proof. Artefact unavailable; baseline E8. |
| WAFFLED (ACSAC'25) | Same check-versus-execute shape; our check is a cryptographic binding, and two of our three classes need no parsing bug. |
| When POST Becomes GET (arXiv 2610.37474) | Method interchangeability within one app; we study override middleware and dispatch under a proof-bound htm across gateway placements. |
| Mancinas Fontalvo 2026 | Their claim that "DPoP is unaffected by TLS-termination" holds for transport, but app-layer binding is still view-relative (G1/G2). Their XFCC result is a G3 sibling for mTLS. |
| T-Reqs, Gudifu, HDHunter, HTTP Garden, FRAMESHIFTER, H2Fuzz, Host of Troubles, Cached and Confused | Primitive provenance for G2. They are smuggling or desync oracles, not authorisation oracles. |
| Traefik CVE-2026-40912, Istio CVE-2021-31920, OPA-Envoy CVE-2026-26205, Envoy GHSA-xcx5-93pw-jw2w, grpc-gateway CVE-2026-37236 | Single-product instances of the edge-view ≠ executed-view class; we systematise it and add the proof. |
| JWTeemo (NDSS'26), OAuch (RAID'22), MCP measurements, MCP conformance #369 | Token- or AS-level testing; nobody tests op(π) against the executed op. |
| OAuth WG threads (Allam 2026; Zehavi/Madden 2025), SEP-1932 | Standards pressure to *weaken* htu/htm, and gateway-trust patterns, as motivation. |
| Gallo 2026; Kim et al. 2026 | Conceptual statements of "accepted but insufficient"; we give concrete HTTP semantics and measurement. |
| CREHMA; draft-nygren request binding; RFC 9421 | End-to-end or hop signatures as alternative defences. Coverage is a knob, so G1 persists unless the coverage includes the dispatch fields. |

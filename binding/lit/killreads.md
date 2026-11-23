# Priority full-text kill-reads (W1): evidence log

Date of all reads: 2026-11-23. "p" = PDF page number of the file that was read. Quotes are verbatim, except that symbolic-model notation has been flattened to ASCII. Page numbers were located with `tools/pg.py` (pdftotext, one page at a time). Any item not read in full text says so explicitly.

Where the PDFs came from:
- IACR ePrint returned HTTP 403 (a Cloudflare challenge) to both curl and the fetch tool. The ePrint PDFs were therefore read from Wayback Machine copies:
  - `https://web.archive.org/web/2025id_/https://eprint.iacr.org/2024/078.pdf`: 86 pp, PDF CreationDate 2024-01-17.
  - `https://web.archive.org/web/2025id_/https://eprint.iacr.org/2024/1540.pdf`: 186 pp, CreationDate 2024-10-02.
  The title, authors and page counts match the ePrint landing pages (both HTTP 200).
- The 2022 OIDF technical report was read from openid.net.
- arXiv and NDSS PDFs were fetched directly.
- Specs, mailing-list pages and GitHub pages were read through a web-fetch tool.

---

## K1. Hosseyni, Küsters, Würtele: ePrint 2024/078 (CSF 2024 full version) and ePrint 2024/1540 (ACM TOPS full version)

**Q1. Does the model contain an intermediary, proxy, gateway or URI normalisation between client and RS? No.**
- The resource server is "a Web server modeled as an atomic process":
  - 2024/078, RS section, around p39.
  - 2024/1540, App. C.12 "Resource Servers", p71.
- In both papers, the RS request handler (Algorithm 12 / App. C.12 "Processing HTTPS Requests") builds the comparison URI from the *same* message it serves:
  - `let reqUri := <URL, S, m.host, m.path, <>, ⊥>` (empty parameters, no fragment)
  - `if dpopClaims[htm] != m.method or dpopClaims[htu] != reqUri then stop`
  - Locations: 2024/078 text lines ~3080–3082 (p39); 2024/1540 lines ~5347–5349 (p72).
- The resource that is served is selected from the same field: `let resourceID := m.path` (2024/078 p39; 2024/1540 p72).
- **Consequence:** by construction, the view the verifier checks is the request that executes. There is no separate router, no override, and nothing between the check and the execution.
- A full-text search of both PDFs for `proxy|intermediar|normaliz|normalis|canonical|reverse|gateway|rewrit`:
  - 2024/078: 0 hits.
  - 2024/1540: exactly 1 hit, on p12. A7 says the attacker can modify resource responses, and "The specification mentions a compromised reverse proxy in front of the RS as a possible reason for this attacker ability." That concerns *response* tampering, not request rewriting.

**Q2. Which RS checks are assumed?** All in the same algorithm:
- signature with the `jwk` header key;
- htm == m.method;
- htu == (scheme S, host, path) of the received message;
- `nonce` ∈ server-issued nonces, removed after use (strict one-time);
- `ath == hash(accessToken)`;
- `cnf` equals jkt(verificationKey), or x5t#S256 for mTLS;
- AT signature.

The RS model also *requires* a server-provided DPoP nonce. That is stronger than RFC 9449, where nonces are optional. It is the fix the authors proposed for the DPoP proof replay attack (2024/1540 Sec. 3.3, pp14–15).

**Q3. Leaked resource requests?**
- A5 "Resource requests (Step 18) leak to the attacker in plain" (2024/1540 p12).
- The model leaks the request **after** the RS sent its response: "we adapted the model such that the resource request now leaks after the RS sent the corresponding resource response" (2024/1540, around p25, the modelling notes section).
- Sec. 3.3 (p15): "FAPI 2.0 AM was changed to clarify that resource requests leak after processing by the RS".

**Q4. Security property.** Definition 3, Authorization Property (simplified) (2024/1540 p27), and Def. 19 (p78). "whenever RS provides access to, i.e., emits, a resource r associated with id ... (iii) ... then the attacker cannot derive the resource r."
- This is a **confidentiality-of-resource** property.
- The model has one operation type per path (return a fresh resource nonce). Method-dependent or state-changing operations, query or body semantics, and dispatch are not modelled.
- 2024/078 Definition 2 (p14) is the same in substance.

**Verdict for H5 (formal angle).** The angle survives. The proofs hold for the RS's own view, and the model has no notion of "executed operation ≠ verified view". This must be cited as *support*: our property generalises their RS check to deployments where the check and the execution are split.

## K1b. OIDF technical report WP 1(b) (2022), same authors

URL: https://openid.net/wordpress-content/uploads/2022/12/Formal-Security-Analysis-of-FAPI-2.0_FINAL_2022-10.pdf (76 pp)

- Algorithm 12 "Relation of RS – Processing HTTPS Requests" (p25), lines 35–36: the same `reqUri` construction, and `resourceID := m.path` (line 14).
- Line 67–70: "Leak resource request. Note that we only leak the application-layer message".
- Sec. III (p6), "Resource Request Leak at Resource Server": "If one assumes that such a leak occurs before the resource server processes the (honest) client's request, an attacker could just replay the whole resource request".
- This is the earliest version. The model is unchanged in the later papers.

## K2. FAPI 2.0 Attacker Model (Final, 22 Feb 2025)

URL: https://openid.net/specs/fapi-attacker-model-2_0-final.html. Read via the fetch tool.

- §7.7, A5 "Read resource requests": "read requests sent to the resource server after they have been processed by the resource server, for example because the attacker can read TLS intercepting proxy logs on the resource server's side." So **leaked resource requests are in scope, but only post-processing**.
- §5.2, Authorization: "no attacker can access protected resources" other than their own.
- §6: TLS is assumed unbroken.
- §8.4: the profiles do not prescribe "security aspects of internal architectures". There is no mention of intermediaries between client and RS.
- **Implication for W2's threat model:**
  - An A_leak attacker who replays a *consumed* proof is defeated by a correct jti or nonce cache.
  - A_leak is still meaningful in three cases:
    - jti tracking is optional, as in RFC 9449 and SEP-1932 ("MCP servers are NOT required to track jti values");
    - the cache is bounded or per-replica (Mancinas 2026 class B1);
    - the leak is pre-use, which is outside the FAPI AM.
  - A_client (a legitimate but malicious client) needs no leak and should lead.

## K3. arXiv 2510.09952, HTTP Request Synchronization (Topcuoglu, Onarlioglu, Sprecher, Kirda; v1, 11 Oct 2025)

- **Scope:** "We implement our general design focusing on the specific request components targeted by known attacks. Namely, the full URL, the Host header value, and the request message framing" (p1). Design §4: "synchronization of request components that factor into path, host, and framing decisions".
- **Not synchronised:**
  - the effective method, including `X-HTTP-Method-Override` / `_method`;
  - body-level dispatch (GraphQL `operationName`);
  - trust headers.
  The full URL includes the query, so a hop that disagrees on the query would be caught. However, G1 query dispatch involves *no hop disagreement*: every hop sees the same query, and the proof simply does not cover it.
- **On signatures** (p5): "Message signatures neither aim to prevent discrepancy attacks, nor are they capable of providing systemic defense." DPoP is not mentioned anywhere in the paper; a grep of the full text for dpop/oauth/htu/9449/jwt found nothing relevant.
- **Threat model** (§4): the attacker controls the request; servers are honest; TLS is used; the body is immutable.
- **Artefact** (p15): "https://github.com/http-request-sync/defeats_discrepancy_attacks". On 2026-11-23 that URL returned 404, and the GitHub API lists 0 public repos for user `http-request-sync`. **The artefact is not publicly available.**
- **Would it cover DPoP htu/htm binding?**
  - Partially for G2 path/host differentials between *proxies that implement it*.
  - No for G1 or G3.
  - No binding to the client's proof.
  - It requires a modified origin.
  - It must be discussed as a baseline (E8); because the code is not public, it must be re-implemented or argued analytically.

## K4. arXiv 2503.10846, WAFFLED (v4, 13 Mar 2026), published at ACSAC 2025

- Venue: Crossref DOI 10.1109/ACSAC67867.2025.00062, pp. 689–702, "2025 IEEE Annual Computer Security Applications Conference (ACSAC)". **Venue verified.**
- Oracle: the WAF lets the request through while the framework parses and executes the payload. "This misinterpretation allows the payload to pass through, while the web application framework correctly parses and executes the attack" (p2).
- Targets:
  - WAFs: AWS, Azure, Cloud Armor, Cloudflare, ModSecurity.
  - Frameworks: Flask, Laravel, FastAPI, Gin, Express, Spring Boot.
  - Content types: multipart/form-data, application/xml, application/json.
- Token or signature content: none. The only "signature" hits concern WAF *signature-based detection* (p3).
- Artefact: https://github.com/sa-akhavani/waffled (HTTP 200); "Sensitive bypass requests will remain restricted" (p2).
- Defence: HTTP-Normalizer.

## K5. arXiv 2607.08906, Proof-of-Continuity (Gallo, v2, 8 Oct 2026) and arXiv 2611.07159 (Gallo, Nov 2026)

- **2607.08906** is a conceptual and formal model (PIC) with no experiments.
  - Sec. 4.1 (p5): "Sender-constrained and holder-bound tokens — for example DPoP and Token Binding — prove who may present or use an artifact by binding it to a key or transport channel. They do not, by themselves, prove that the a[uthority]…"
  - p20 limitations: the construction is abstract.
- **2611.07159** is a follow-up theory paper. It says DPoP "binds each proof to HTTP request properties as specified by its profile". It contains no measurement.

## K6. arXiv 2607.01711, Trust Boundary Semantic Gaps (Kim, Choi, Lee, v1, 2 Jul 2026)

- A design-time taxonomy (Identity, Spatial, Temporal, Interpretation) built from 75 incidents (2014–2025), with a SolarWinds case study.
- p1: "A TBSG is not an absent validation step, a parser bug, or a failed signature check."
- p6: Interpretation "subsumes … the parser differentials studied in language-theoretic security".
- It contains no HTTP or DPoP measurement.

## K7. JWTeemo, "Token Time Bomb" (NDSS 2026)

- PDF: https://www.ndss-symposium.org/wp-content/uploads/2026-f697-paper.pdf
- A full-text grep for `dpop|htu|proof-of-possession|sender|cnf|mtls` gives **0 hits** related to PoP. The work is at the JWS/JWE level only.
- Artefact: https://github.com/JWTeemo/JWTeemo (200; last push 2026-06-08).

## K8. OAuth WG thread, mail-archive msg26175

- The message was read.
- Thread index `thrd2.html`: the `[OAUTH-WG] rfc9449` thread contains only msg26175.
- An IETF mailarchive search for "htu" lists one message under that subject (2026-06-29) and **no replies**.
- msg26176 and msg26177 belong to an unrelated thread.
- No WG outcome was found as of 2026-11-23.
- The earlier thread "DPoP tokens vs downstream resource servers" was read in the resume pass (2026-11-23) at the message level: msg24959 (N. Madden, 16 Oct 2025) and msg24995 (Y. Zehavi, 18 Oct 2025), https://go.mail-archive.com/oauth@ietf.org/msg24959.html.
  - The opening problem: forwarding a DPoP token to downstream resource servers breaks because `htu` cannot match the downstream endpoint; the proposal is to relax the htu check for internal servers.
  - Madden (msg24959): backend trust in an AS-issued token "fails to guarantee that the token relates to the backend API requests being made", and "backend services put enormous trust in the edge/gateway services in any case"; he recommends the phantom-token pattern at a hardened gateway.
  - This is a practitioner statement of the placement gap with no measurement. Only these two messages were read; the thread's end state was not traced.

## K9. MCP SEP-1932 (PR #1932, open) and conformance issue #369

**SEP-1932:**
- Opened on 2025-12-05 by PieterKas. Labels: `draft`, `extension`, `security`.
- The draft text (ext-auth branch `dpop-extension.mdx`) says: "MCP servers MUST validate DPoP proofs according to RFC 9449 Section 4.3"; "MCP servers are NOT required to track jti values".
- It does not mention proxies, gateways or normalisation.

**Issue #369:**
- Opened on 2026-06-25 and still open; PR #395 is linked.
- It lists RS negative tests for: htm, "htu does not match the request target URI (ignoring query/fragment)", ath, iat, missing claims, Bearer downgrade and cnf.jkt.
- It covers a single endpoint. It does not test a proof minted for one operation and replayed against another existing operation.

## K10. HDHunter and Gudifu artefacts

- **HDHunter** (USENIX Sec '25): the USENIX page returns 200. The Zenodo record 14557763 ("HDHunter-1.0.0.zip") appeared in search results, but Zenodo returned 403 to curl. The artefact is public per that record. The full text was **not read**.
- **Gudifu** (RAID '24): the NSF-PAR full text was skimmed. It links https://github.com/bahruzjabiyev/gudifu-fuzzer (HTTP 200).

## K11. New close hits found during the search (not in the seed list)

**arXiv 2610.37474, Golinelli, Hannachi, Crispo, "When POST Becomes GET" (27 Oct 2026).** Read in full (14 pp).
- Method interchangeability (POST→GET with the body moved to the query). The oracle is response equivalence against a no-query GET baseline.
- Results: 407/10k Tranco sites (4.1%). In a CSRF-token check, invalid tokens were rejected for POST but accepted for GET (7 cases on 2 sites).
- §4 surveys frameworks: PHP, Spring MVC, ASP.NET Core, Laravel, Flask, Rails, Sinatra, Gin, Django, Express, FastAPI, NestJS, Next.js, SvelteKit, plus API technologies (GraphQL, OData, …).
- Method-override headers appear only in related work (p4, citing OWASP).
- Artefact: github.com/Golim/method-interchange.
- **G1 overlap:** method-scoped defences bypassed by an alternative method. It does not cover proof binding or gateway placement, and it does not measure override middleware.

**Mancinas Fontalvo, "Operational Realities of Sender-Constrained OAuth" (preprint on author site; PDF dated 2026-07-28; 11 pp).** Read in full.
- B1: Spring Security 6.5's bounded jti cache admits replay of honestly issued proofs above about 17 req/s (N=1000, S=60 s).
- B2: TLS termination with lossy XFCC (X-Forwarded-Client-Cert) propagation (CVE-2024-10039 Keycloak). The author tested an Envoy deployment: missing XFCC fails closed in Spring.
- B3: Keycloak audience bypass on specific flows.
- It states that DPoP is unaffected by B2 because "its binding is at the application layer above any TLS termination point" (p7). Our G1/G2 results contest this claim.
- No venue was found. Artefact: github.com/sergioemancinas/dpop-replay-threshold (200).

## K12. Found in the resume pass (2026-11-23)

**CVE-2026-37236, grpc-gateway method override.** OSV record (https://osv.dev/vulnerability/CVE-2026-37236, published 2026-08-28) read via the OSV API: grpc-gateway v2.28.0 "processes the X-HTTP-Method-Override header in ServeMux.ServeHTTP without restricting allowed methods … the request method is rewritten to an arbitrary attacker-supplied value before routing. This allows bypassing method-based access controls enforced by upstream proxies or WAFs." Fix commit 72123cd. This is a real-world G1 (method) instance in which the upstream check is a method ACL; an edge DPoP `htm` check is the same structure. Severity varies by source (OSV/Ubuntu 9.8; Red Hat Moderate) per search snippets, not read at primary pages.

**Recency searches repeated** (web, 2026-11-23): "DPoP OR sender-constrained … gateway verification bypass arXiv 2026" and "method override X-HTTP-Method-Override authorization bypass gateway 2025 2026". No academic paper measuring proof acceptance against the executed operation was found. One project changelog (devlog.croft.click, Aug 2026) describes an implementation bug where an unbound token was rebound to the proof key; it is unrelated to placement and was screened out (E3).

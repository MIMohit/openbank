# Cluster 1 — Sender-constrained tokens and request integrity: literature and novelty check

Task: task_431514dfd283. Searches run on 2026-11-22.
Scope: DPoP (RFC 9449), mTLS-bound tokens (RFC 8705), Token Binding (RFC 8471–8473), formal analyses of FAPI and OAuth, HTTP request signing (cavage, RFC 9421, SigV4, open-banking detached JWS), JOSE/JWT library flaws and differential testing, and DPoP replay state.

**How to read this file.** Each entry gives authors, title, venue, year and an identifier, all taken from search results I actually saw. I read abstracts, metadata and excerpts only, not full papers, except for the RFC 9449 text and errata page, which I fetched directly. Anything I could not confirm is marked **UNVERIFIED**. "Not found" always means not found in the searches listed in §(e). It never means the topic does not exist.

---

## (a) Annotated bibliography (28 works)

### A. Formal analyses of OAuth, OIDC, FAPI and GNAP (Web Infrastructure Model line)

1. **D. Fett, R. Küsters, G. Schmitz. "A Comprehensive Formal Security Analysis of OAuth 2.0." ACM CCS 2016, pp. 1204–1215. DOI 10.1145/2976749.2978385; arXiv 1601.01229.**
   This was the first extensive analysis of OAuth 2.0 in an expressive web model (the WIM), covering all four grant types. It found four attacks, including mix-up, which also affect OIDC, and proved the fixed protocol secure. It assumes best practices are followed. *Relevance:* it is the baseline the later FAPI proofs build on. Every guarantee is conditional on each party running all the checks the model specifies.

2. **D. Fett, R. Küsters, G. Schmitz. "The Web SSO Standard OpenID Connect: In-Depth Formal Security Analysis and Security Guidelines." IEEE CSF 2017, pp. 189–202. DOI 10.1109/CSF.2017.20; arXiv 1704.08539.**
   It proves authentication, authorization and session-integrity properties for OIDC, and gives implementer guidelines that the proofs show to be sufficient. *Relevance:* it explicitly frames the guidelines as conditions for security, which is the kind of RS/RP obligation that deployments can silently drop.

3. **D. Fett, P. Hosseyni, R. Küsters. "An Extensive Formal Security Analysis of the OpenID Financial-grade API." IEEE S&P 2019. DOI 10.1109/SP.2019.00067; arXiv 1901.11520.**
   This was the first formal analysis of an open-banking profile (FAPI 1 Read-Only and Read-Write). It found four previously unknown attacks; the abstract snippet says some bypass PKCE and **Token Binding**. It proposed fixes and proved them. *Relevance:* it is the canonical "FAPI is provably secure if implemented as modelled" result, and it already showed that Token-Binding-era sender-constraining had protocol-level gaps.

4. **P. Hosseyni, R. Küsters, T. Würtele. "Formal Security Analysis of the OpenID FAPI 2.0: Accompanying a Standardization Process." CSF 2024 (per ePrint 2024/078, which calls itself "the full version of our CSF 2024 paper with the same title"); also ePrint 2024/1540. https://eprint.iacr.org/2024/078 , https://eprint.iacr.org/2024/1540**
   This is a WIM model of the FAPI 2.0 Security Profile against the FAPI 2.0 Attacker Model. The first analysis found attacks; after the spec was revised, the authors proved the properties under the WG's strong attacker model. The authors added "an additional HTTP header for DPoP proofs" to the WIM. The RS in the protocol figure "verif[ies] validity, integrity, expiration and revocation status of at, and DPoP token binding". One reported result is that a sender-constrained token can still be misused if the attacker controls an AS the client trusts. *Relevance:* this is the **closest formal competitor**. It proves DPoP-based FAPI 2.0 secure *assuming the RS runs every check*. It does not measure whether real RSs do. CSF 2024 DOI: **UNVERIFIED** (not seen).

5. **Hosseyni, Küsters, Würtele et al. — University of Stuttgart technical report extending the analysis to FAPI 2.0 Message Signing, DCR, DCM and FAPI-CIBA (2023). https://elib.uni-stuttgart.de/bitstream/11682/13717/1/oct23-tr-opus.pdf ; OIDF announcement https://openid.net/security-analysis-fapi-2-0-completed/**
   Message Signing (signed requests and responses) is formally covered. The OIDF post notes that "a set of modeling decisions and assumptions" was needed to make the proofs go through. *Relevance:* any claim about request-signature coverage in FAPI 2.0 must be positioned against this report. Exact author list: **UNVERIFIED**.

6. **F. Helmschmidt, P. Hosseyni, R. Küsters, K. Pruiksma, C. Waldmann, T. Würtele. "The Grant Negotiation and Authorization Protocol: Attacking, Fixing, and Verifying an Emerging Standard." ESORICS 2023. DOI 10.1007/978-3-031-51479-1_12; ePrint 2023/1325.**
   This is a WIM analysis of GNAP; GNAP's key binding can use HTTP Message Signatures. It found attacks and its fixes were adopted by the WG. *Relevance:* it is the closest formal work touching HTTP-message-signature-based key proofs.

7. **"DY\*: A Modular Symbolic Verification Framework for Executable Cryptographic Protocol Code." IEEE EuroS&P 2021. HAL hal-03178425.** Authors from my own knowledge, not shown in the results I saw (**UNVERIFIED**): K. Bhargavan, A. Bichhawat, Q. H. Do, P. Hosseyni, R. Küsters, G. Schmitz, T. Würtele. The Stuttgart DY\* page is https://www.sec.uni-stuttgart.de/research/dystar/.
   It has been applied to ACME and Signal. I found **no DY\* analysis of OAuth, DPoP or FAPI** (searches S6, S9). *Relevance:* it is a possible tool for verifying *code-level* DPoP verifiers, and that is not done in the WIM work.

8. **P. Modesti, L. Freitas, Q. Shotomiwa, A. Almehrej. "Security Analysis of the Open Banking Account and Transaction API Protocol." arXiv 2003.12776 (v1 2020, v2 May 2025, 61 pp.). Earlier short version by A. Almehrej, L. Freitas, P. Modesti, "Account and Transaction Protocol of the Open Banking Standard," Springer 2020, DOI 10.1007/978-3-030-48077-6_16.**
   This analyses the UK OBIE Account and Transaction API with OFMC and ProVerif, and includes sandbox testing. Journal venue of v2: **UNVERIFIED**. *Relevance:* it is the closest "open-banking sandbox testing plus formal model" work, but it targets UK OBIE rather than CDR, and it is not about sender-constraining enforcement at the RS.

9. **Chalmers MSc thesis — Tamarin models of OAuth native-app authentication (CIBA, FIDO2, ROPC) with a "Token Binding and Proof-of-Possession" lemma section. https://odr.chalmers.se/bitstreams/6a478ad7-2825-4b5f-8044-92d7760287eb/download**
   Title, author and whether DPoP itself is modelled: **UNVERIFIED**. It is a thesis, not peer-reviewed.

### B. Standards, and the history of sender-constraining

10. **D. Fett, B. Campbell, J. Bradley, T. Lodderstedt, M. Jones, D. Waite. RFC 9449 "OAuth 2.0 Demonstrating Proof of Possession (DPoP)." IETF, Sept 2023. https://www.rfc-editor.org/rfc/rfc9449** (author list from my own knowledge of the RFC header; the RFC itself was fetched.)
    Verbatim points relevant to the user's findings (fetched directly):
    - `ath` is conditionally required: "When the DPoP proof is used in conjunction with the presentation of an access token in protected resource access … the DPoP proof MUST also contain the following claim" (§4.2).
    - §4.3 item 12: the verifier must "ensure that the value of the `ath` claim equals the hash of that access token". §7: "The resource server is required to calculate the hash of the token value presented…".
    - **§7.1 itself does not mention `ath`.** It points to §4.3 and to the `cnf.jkt` key match, and says "The resource server MUST NOT grant access … unless all checks are successful." The `ath` obligation is therefore reachable only by cross-reference. That is a plausible source of implementation omission; whether it causes omissions in practice is a hypothesis, not a finding.
    - **§4.3 has no `jti` item.** Replay handling sits in §11.1: a single-use check "may not always be feasible in practice, e.g., when multiple servers behind a single endpoint have no shared state."
    - **Errata:** only **EID 7646** (Verified, Editorial, §4.2: "authentication server" should read "authorization server"). **No erratum concerns `ath`, `htu` or RS validation** (errata page fetched 2026-11-22).

11. **B. Campbell, J. Bradley, N. Sakimura, T. Lodderstedt. RFC 8705 "OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens." IETF, Feb 2020. https://www.rfc-editor.org/rfc/rfc8705** (authors from my own knowledge, not re-checked in this session.)
    It binds tokens to the client certificate thumbprint (`cnf.x5t#S256`) and has a TLS-termination section (§6.5, text not retrieved). Related: **RFC 9440** (Client-Cert HTTP header fields), which has a field-injection appendix and notes that backends may use the header to bind tokens. A deployment guide (Connect2id) warns that a TLS-terminating proxy must strip inbound copies of the certificate header. *Relevance:* certificate binding through a proxy reduces to "trust a header", and that is an injection surface. I found no academic measurement of it.

12. **A. Popov, M. Nystroem, D. Balfanz, J. Hodges (and N. Harper for 8473). RFC 8471/8472/8473 Token Binding (Oct 2018). https://www.rfc-editor.org/rfc/rfc8471** (author names from my own knowledge, **UNVERIFIED** in this session.)
    **Why it died** (Chromium "Intent to Remove: Token Binding", https://groups.google.com/a/chromium.org/g/blink-dev/c/OkdLUyYmY1E): Chrome argued that client malware is outside its threat model, that XSS and rogue extensions are the relevant theft vectors and have better defences, and that industry adoption was low. Opponents objected that support was being pulled just before the RFCs were published and while WebAuthn depended on it. The Chrome removal version **conflicts across sources** (Wikipedia: v70; another source: v71; a blog says Edge removed it in 130): **UNVERIFIED**. Successor: Device Bound Session Credentials (W3C FPWD, https://www.w3.org/TR/dbsc/). Google reports a "significant reduction" in session theft but published no figures, and I found no peer-reviewed DBSC evaluation.

13. **T. Lodderstedt, J. Bradley, A. Labunets, D. Fett. RFC 9700 / BCP 240 "Best Current Practice for OAuth 2.0 Security." Jan 2025. https://www.rfc-editor.org/rfc/rfc9700.html**
    It recommends sender-constrained access tokens (§2.2, §4.10.1). *Relevance:* this is the normative "should" against which deployment gaps are measured.

14. **A. Backman, J. Richer, M. Sporny. RFC 9421 "HTTP Message Signatures." Feb 2024. https://www.rfc-editor.org/rfc/rfc9421** (authors from my own knowledge, not re-checked here.)
    Coverage is chosen by the signer. Its Security Considerations include canonicalization attacks (§7.5.5), non-list field values (§7.5.6) and padding through multiple field values (§7.5.7). The RFC calls itself a toolkit that "is not sufficient in creating an overall security story". Verified errata EID 8102 and 8103 exist (content not read). *Relevance:* the spec itself pushes the coverage decision onto profiles and deployers, which matches the user's finding (3).

15. **M. Cavage, M. Sporny. draft-cavage-http-signatures (versions -06 to -12, 2016–2019). https://www.ietf.org/archive/id/draft-cavage-http-signatures-10.txt**
    If `headers` is absent the default covered set is **only `Date`**. Method and path are covered only if the signer lists the `(request-target)` pseudo-header. This draft is the basis of Berlin Group NextGenPSD2 signing; vendor guides (Airlock, Holvi, Worldline) show `Digest`, `X-Request-ID` and `Date` as mandatory and `(request-target)` as optional or implementation-specific. *Relevance:* it is a direct mechanism for cross-endpoint and cross-method signature replay. I found no CVE or academic paper naming it as a vulnerability class (search S11).

16. **UK OBIE detached JWS (`x-jws-signature`, `b64=false`, `crit`). OBIE Message Signing FAQ: https://openbankinguk.github.io/knowledge-base-pub/standards/general/message-sign.html**
    OBIE notes that most JWT libraries do not support `b64`, and that from v3.1.4 onward `b64` must not be included. The signature covers the body only, not the method, URI or headers (this coverage point is from my reading of the standard: **UNVERIFIED** in this session). I found no security analysis of the coverage of detached JWS in open banking.

### C. JOSE/JWT implementation flaws and differential testing

17. **J. Yang, E. Wang, J. Chen, Q. Wang, Y. Zhang, H. Duan, W. Xie, B. Wang. "Token Time Bomb: Evaluating JWT Implementations for Vulnerability Discovery." NDSS 2026. https://www.ndss-symposium.org/ndss-paper/token-time-bomb-evaluating-jwt-implementations-for-vulnerability-discovery/**
    The JWTeemo tool does grammar-based differential fuzzing over 43 JWT libraries in 10 languages. It found 31 new vulnerabilities and 20 CVEs. Root-cause classes: sign/encrypt confusion, algorithm confusion, format confusion, differing claim checks, billion-hash and compression DoS. The IETF acknowledged the work. *Relevance:* this is the **closest methodological competitor** for any "differential testing of DPoP verifiers" paper. It targets generic JWT libraries. The snippets I saw do not mention DPoP-specific semantics (ath/htm/htu/jkt/jti/nonce), but its "different claims checking" class is adjacent. Whether it touches DPoP at all is **UNVERIFIED** (full text not read).

18. **C. Villa, S. Kim, A. Chu, A. Shakevsky, R. A. Popa. "Chai: Agentic Discovery of Cryptographic Misuse Vulnerabilities." arXiv 2606.26933 (June 2026).**
    It combines LLM-agent analysis with differential testing and "discrepancy tracing" over X.509, JWT and SAML libraries, reporting over 100 vulnerabilities. It also traces flaws through dependency graphs to downstream apps. *Relevance:* it is a 2026 competitor that could extend to DPoP or HTTP signatures cheaply. Preprint only.

19. **T. Tervoort (Secura). "Three New Attacks Against JSON Web Tokens." Black Hat USA 2023 whitepaper. https://i.blackhat.com/BH-US-23/Presentations/US-23-Tervoort-Three-New-Attacks-Against-JSON-Web-Tokens-whitepaper.pdf**
    It covers sign/encrypt confusion, polyglot tokens (python-jwt and jwcrypto parse JSON versus compact serialisation differently) and the billion-hash attack, affecting at least six implementations. This is industry work, not peer-reviewed.

20. **T. Al Rahat, Y. Feng, Y. Tian. "Cerberus: Query-driven Scalable Vulnerability Detection in OAuth Service Provider Implementations." ACM CCS 2022. arXiv 2110.01005 (earlier title OAuthShield).**
    Static analysis over system dependence graphs of OAuth *provider* libraries. It found 47 vulnerabilities in ten classes of logic flaw (24 new, 3 CVEs). *Relevance:* it is the closest "OAuth library logic-flaw" study. Whether it covers DPoP or RS-side PoP checks is **UNVERIFIED**; given the 2021–22 timing it probably does not.

21. **P. Philippaerts, D. Preuveneers, W. Joosen. "OAuch: Exploring Security Compliance in the OAuth 2.0 Ecosystem." RAID 2022. DOI 10.1145/3545948.3545955.** Follow-up: **same authors, "Revisiting OAuth 2.0 Compliance: A Two-Year Follow-Up Study." IEEE EuroS&P Workshops 2023.**
    A black-box compliance tester for 100 deployed AS/IdPs found that on average 34% of the checked countermeasures were missing. *Relevance:* it is the closest *measurement* methodology. It tests **authorization servers**, not resource servers, and DPoP coverage is **UNVERIFIED**.

22. **L. Jannett, V. Mladenov, C. Mainka, T. Wich, M. Westers, A. Mayer. "SoK: SSO-MONITOR — The Current State and Future Research Directions in Single Sign-On Security Measurements." IEEE EuroS&P 2024** (venue from a single citing source: **UNVERIFIED**). Earlier: Westers et al., "SSO-Monitor…", arXiv 2302.01024.
    It measured 89k SSO flows on the top 1M sites and found 33k violations of the OAuth BCP and 339 severe vulnerabilities. It covers client-side RP/IdP flows and is not about sender-constraining.

23. **H. Zhou, X. Zhang, H. Zhang, H. Zhang, M. Zhang, M. Yang. "A First Measurement Study on Authentication Security in Real-World Remote MCP Servers." arXiv 2605.22333 (May 2026).**
    Of 7,973 MCP servers, 30% use OAuth. All 119 testable OAuth servers had at least one flaw (325 flaws, 9 types). *Relevance:* it shows OAuth RS/AS measurement papers are currently publishable and active. It also suggests a possible venue for DPoP adoption (MCP + DPoP): **not checked**.

### D. Signature coverage and parsing differentials (analogues and building blocks)

24. **J. Somorovsky, A. Mayer, J. Schwenk, M. Kampmann, M. Jensen. "On Breaking SAML: Be Whoever You Want to Be." USENIX Security 2012, pp. 397–412.**
    XML Signature Wrapping affected 11 of 14 SAML frameworks. *Relevance:* it is the classic "the signature verifies but does not cover what the application uses" paper. It is the conceptual template for a request-signature-coverage paper, and a reviewer will cite it against novelty claims about coverage.

25. **J. Reynolds, A. Bates, M. Bailey. "Equivocal URLs: Understanding the Fragmented Space of URL Parser Implementations." ESORICS 2022. DOI 10.1007/978-3-031-17143-7_9.** Related: **Ajmani et al., SecWeb 2022** (https://secweb.work/papers/2022/ajmani2022youare.pdf; full author list **UNVERIFIED**); **Kallus & Smith, Dartmouth 2023** (https://www.cs.dartmouth.edu/~sws/pubs/ks23.pdf; venue **UNVERIFIED**).
    URL parsers disagree systematically. *Relevance:* DPoP `htu` matching and RFC 9421 `@target-uri`/`@path` both depend on URL normalisation. Parser differentials between the proof verifier and the router are a concrete, untested mechanism.

26. **B. Jabiyev, S. Sprecher, K. Onarlioglu, E. Kirda. "T-Reqs: HTTP Request Smuggling with Differential Fuzzing." ACM CCS 2021.** Follow-up: **Jabiyev, Gavazzi, Onarlioglu, Kirda. "Gudifu: Guided Differential Fuzzing for HTTP Request Parsing Discrepancies." RAID 2024.**
    Proxy and origin disagree on message boundaries and meaning. *Relevance:* when DPoP or a signature is checked at a gateway and the request is routed by the backend, a parsing discrepancy can split "what was verified" from "what was executed".

27. **B. Kallus, P. Anantharaman, M. E. Locasto, S. W. Smith. "The HTTP Garden: Discovering Parsing Vulnerabilities in HTTP/1.1 Implementations by Differential Fuzzing of Request Streams." arXiv 2405.17737 (2024).**
    It found over 100 parsing bugs in origin servers, 68 of them fixed. Peer-reviewed venue: **UNVERIFIED**.

28. **AWS SigV4 — no peer-reviewed analysis found.** Closest: a University of Amsterdam OS3 student report, "Security Evaluation on Amazon Web Services' REST API" (2019–2020, https://rp.os3.nl/2019-2020/p65/report.pdf). It concluded SigV4 is secure in practice, found a local timing correlation, and HTTP smuggling attempts did not succeed. AWS IETF-105 slides describe the canonical request. *Relevance:* SigV4 is the "fully canonicalised, method and path always covered" counter-example to cavage and detached JWS, and is useful as a design baseline.

### E. Practitioner and IETF material on DPoP replay state (grey literature, not papers)

- RFC 9449 §11.1 (above). OIDF FAPI issue "DPoP & resource leaks" (https://bitbucket.org/openid/fapi/issues/533/dpop-resource-leaks) says proof-reuse tracking was "de-emphasized somewhat in recent drafts due largely to performance/scalability concerns".
- Library docs: Attesto (Elixir) calls node-local jti caches in a cluster "a silently-broken security boundary". Duende (.NET) says a shared distributed cache is required. solid-pod-rs says bounded-cache eviction "opens a capacity-driven replay window".
- IETF individual drafts: draft-ambekar-oauth-epop (stateless client nonce); draft-mw-oauth-tls-session-bound-tokens (argues RFC 8705 does not stop replay within or across TLS connections, and proposes exporter binding); draft-nandakumar-oauth-dpop-proof (generalises DPoP beyond HTTP).
- OAuth WG thread "DPoP followup I: freshness and coverage of signature" (https://mailarchive.ietf.org/arch/msg/oauth/M2mc6BaHQyeOHajUVpVrAREr9nk) records that whether `ath` should be mandatory was debated. A 2020 post argues that without `ath` "a captured signature applied to AT1 could be replayed with AT2", and asks why there is no analogous `rth` for refresh tokens.
- OIDF announced DPoP support (including nonces) in the FAPI 2.0 conformance tests (https://openid.net/fapi-2-0-conformance-tests-support-dpop/). **Whether the suite tests that an RS *rejects* proofs with a missing or wrong `ath` is UNVERIFIED.** The suite certifies OPs and RPs, and the RS is a test fixture, so RS-side validation is probably not what gets certified (inference, not confirmed).

---

## (b) What is settled

1. **On paper, sender-constraining works.** FAPI 1 (S&P'19) and FAPI 2.0 with DPoP or mTLS (CSF'24) are proven secure in the WIM under strong attacker models, *conditional on all parties running all specified checks*. The user's own testbed agrees empirically. Any new paper claiming "DPoP or mTLS stops replay" adds nothing.
2. **OAuth and OIDC protocol-level attacks are well mapped.** That includes mix-up, code injection and session integrity (CCS'16, CSF'17, RFC 9700). Protocol-flaw hunting in plain OAuth is crowded.
3. **Generic JWT/JWS library flaws are well studied as of 2026.** Covered so far: alg confusion, `none`, sign/encrypt confusion, polyglot and format confusion, claim-check differences, DoS (Tervoort'23, Token Time Bomb NDSS'26, Chai'26). A paper about JWT signature verification alone would not be novel.
4. **Deployed authorization servers miss many BCP countermeasures** (OAuch RAID'22 and its follow-up; SSO-Monitor). This is established for the AS and IdP, and for RP/client flows.
5. **Signatures that do not cover what the application uses are exploitable.** This is the XSW lesson (USENIX'12). RFC 9421 openly delegates coverage choices to profiles.
6. **HTTP parsing differentials between proxies and origins are real and fuzzable** (T-Reqs, Gudifu, HTTP Garden). URL parser differentials are documented (Equivocal URLs).
7. **Token Binding failed for deployment and threat-model reasons, not cryptographic ones.** The reasons were browser-vendor threat models (malware out of scope), adoption, and the TLS-stack coupling. Application-layer PoP (DPoP) and DBSC are the successors.
8. **jti single-use is known to be impractical at scale.** The RFC concedes this, so "distributed replay caches are hard" is acknowledged folklore. What is missing is a measurement of the consequences (see c-3).

---

## (c) Open questions that appear to remain (each with the work most likely to invalidate novelty)

| # | Open question | Evidence it is open | Closest work that could kill the novelty |
|---|---|---|---|
| Q1 | **Do deployed and library DPoP *resource-server* verifiers actually enforce RFC 9449 §4.3 and §7?** That means `ath`, `htm`, `htu` normalisation, `iat` window, `jti`, `cnf.jkt` match, `typ=dpop+jwt`, an asymmetric-only `alg` allowlist, rejection of private-key material in `jwk`, nonce handling, and the bearer-downgrade case (DPoP-bound token sent as `Bearer`). | No measurement or differential study of DPoP verifiers found (S2, S10, S13, S24). §7.1 does not restate `ath`. No `ath` erratum. The user's Basiq finding (2) is an in-the-wild instance. | Token Time Bomb (NDSS'26), if its "different claims checking" class or its later work includes DPoP. Chai (arXiv'26). Cerberus (CCS'22). OAuch (RAID'22), if newer versions test DPoP at the AS. Full texts not read: **check these first.** |
| Q2 | **What exactly do open-banking request-signing schemes cover, and do verifiers enforce it?** The schemes are UK OBIE detached JWS, Berlin Group cavage-style, Brazil Open Finance signed JWT requests, RFC 9421 profiles, and FAPI 2.0 Message Signing. "Enforce" includes cross-endpoint and cross-method replay, header omission, `Digest` versus `Content-Digest` mismatches, and `b64` handling. | No academic coverage or replay analysis found for any of these schemes (S11, S14, S15, S16). The user's finding (3) is a live instance. | Stuttgart FAPI 2.0 Message Signing TR (2023): it formally covers FAPI-MS but not cavage or OBIE. Somorovsky et al. (USENIX'12) as the conceptual precedent. GNAP ESORICS'23 for RFC 9421-based binding. |
| Q3 | **What is the real replay window of DPoP and jti in multi-node and gateway deployments?** This covers node-local caches, cache eviction, gateway-validates/backend-trusts splits, and nonce stores that are not shared. | Only practitioner docs (Attesto, Duende, solid-pod-rs) and a FAPI issue thread. No measurement found (S21). | RFC 9449 §11.1 already concedes the problem. Reviewers may call it "known". Novelty must come from measurement and exploitation, not from pointing it out. |
| Q4 | **Do htu and target-URI matching differentials (verifier versus router URL parsing) let a proof or signature for endpoint A be accepted at endpoint B?** | URL-parser differential papers exist but none apply them to PoP or signature verifiers (S17). | Equivocal URLs (ESORICS'22); HTTP Garden; Gudifu (RAID'24). |
| Q5 | **Is there a mechanised link from the WIM FAPI 2.0 proof obligations to concrete RS code?** For example, extract the RS-side checks the CSF'24 proof relies on and test or verify implementations against them. | No DY\*/F\* or code-level verification of DPoP found (S6, S9). | Hosseyni et al. CSF'24 and ePrint 2024/1540, if a follow-up adds implementation testing. The Stuttgart group is the obvious rival. |
| Q6 | **mTLS-bound tokens behind TLS-terminating proxies (RFC 8705 + RFC 9440).** How often can the client-certificate header be injected or spoofed in real deployments, or in the default configs of popular gateways? | Only vendor guidance (Connect2id) and the RFC 9440 appendix. No measurement found (S20). | draft-mw-oauth-tls-session-bound-tokens (makes a related argument); generic header-injection literature. |
| Q7 | **Downgrade: does an RS that supports both Bearer and DPoP accept a DPoP-bound token presented as `Bearer`?** This is the user's finding (1), bearer replay across client instances. | Mentioned as a test case in a GitHub issue for a .NET library. No study found. | RFC 9449 §7.1 (the `cnf` check makes this a plain spec violation, so the novelty lies in prevalence, not in the idea). |

---

## (d) Candidate paper directions for this cluster

### D1. "Proven but Unchecked": a differential conformance study of DPoP verifiers *(recommended lead)*
**Idea.** Build a spec-derived oracle from RFC 9449 §4.3, §7, §7.1, §11 and the FAPI 2.0 SP. It would generate mutated proof/token/request triples: missing or wrong `ath`; `htm` case and verb swaps; `htu` with trailing slash, percent-encoding, port, host case, path-parameter and fragment variants; `iat` skew; reused `jti` across nodes; `jkt` mismatch; `alg` HS256 or none; private `d` in `jwk`; wrong `typ`; DPoP token sent as Bearer; nonce omission and staleness. Run these against (i) open-source RS libraries and middleware (Spring Security, Keycloak, Quarkus OIDC, Duende/.NET, node-oidc-provider/jose, Go and Rust crates, Kong/Envoy/Apigee plugins if they support DPoP) and (ii) sandbox deployments, ethically (the CDR/Basiq finding is the motivating case). Map each failure to the CSF'24 proof assumption it breaks. That turns "formally secure" into a quantified implementation gap, and it ties directly to the user's findings (1) and (2) and to the testbed result that sender-constraining works *when enforced*.
**Closest competitors.** Token Time Bomb (NDSS'26: generic JWT, not DPoP semantics as far as the snippets show); Chai (arXiv'26); Cerberus (CCS'22: AS-side OAuth logic); OAuch (RAID'22: AS compliance); Hosseyni et al. (CSF'24: formal, no implementation measurement).
**Novelty risk: MEDIUM.** The DPoP-specific RS angle was not found in any search. The risk is that the Tsinghua JWTeemo group, Chai, or the Stuttgart group publishes it first, since DPoP is the obvious next target. Mitigation: emphasise the RS-side semantics (ath, htu canonicalisation, distributed jti, bearer downgrade) and the map from proof assumptions to failures, which the generic JWT fuzzers do not do.

### D2. Signature coverage confusion in open-banking request signing
**Idea.** Compare formally and empirically what OBIE detached JWS, Berlin Group cavage signing, Brazil Open Finance signed requests, RFC 9421 profiles (including FAPI 2.0 Message Signing) and SigV4 actually bind (method, target URI, query, selected headers, body digest, freshness). Then test verifiers and sandboxes for cross-endpoint, cross-method and cross-tenant replay. This is the user's finding (3) generalised, an "XSW for HTTP APIs". Deliverables: a coverage lattice; a mutation tester; a measured replay surface; proposed minimal coverage profiles.
**Closest competitors.** Somorovsky et al. (USENIX'12) as the concept; the Stuttgart FAPI-MS TR (2023), which covers FAPI-MS formally; RFC 9421 §7.5; GNAP (ESORICS'23).
**Novelty risk: MEDIUM-LOW** for the cross-scheme empirical study (nothing found). There is a reviewer risk of "known design limitation of cavage, just sign `(request-target)`". The empirical prevalence and the verifier-side failures must carry the paper.

### D3. Split verification: gateway-checked PoP, backend-executed requests
**Idea.** In deployments where an API gateway validates DPoP, mTLS or signatures and forwards to backends (with the client certificate passed in a header per RFC 9440, and jti caches per node), show how (a) URL and HTTP parsing differentials (htu or `@target-uri` verified versus routed), (b) header injection of client-cert or "verified" headers, and (c) non-shared jti and nonce state re-open replay and theft that the protocol formally closes. Combine HTTP-Garden-style differential fuzzing with PoP semantics.
**Closest competitors.** HTTP Garden (arXiv'24), Gudifu (RAID'24), T-Reqs (CCS'21), Equivocal URLs (ESORICS'22), RFC 9440 appendix, RFC 9449 §11.1.
**Novelty risk: MEDIUM.** Each ingredient is known. The specific composition with PoP and signature semantics was not found. The user's testbed (Keycloak + ZTC reverse proxy + mock ADR) is well placed to run it.

### D4. From WIM proof to code: extracting and checking RS obligations
**Idea.** Extract the RS-side preconditions that the CSF'24 FAPI 2.0 proof relies on, express them as executable checks (or as F\*/DY\* specs), and verify or test implementations, then report which obligations the spec text states only indirectly (e.g. `ath` sits in §4.3 and §7 but not §7.1). Could be paired with D1 as its theory half.
**Closest competitors.** Hosseyni, Küsters, Würtele (CSF'24 / ePrint 2024/1540); DY\* (EuroS&P'21).
**Novelty risk: HIGH** as a standalone paper (the Stuttgart group owns this space and could do it faster). It is **low** as a section inside D1.

### D5. (Weaker) Why sender-constraining keeps failing to deploy: Token Binding → DPoP → DBSC
**Idea.** A measurement plus SoK of sender-constraining adoption (which ASs and RSs advertise `dpop_signing_alg_values_supported` or `tls_client_certificate_bound_access_tokens` in metadata, and which actually enforce it), with the Token Binding post-mortem as history.
**Closest competitors.** The Chromium removal thread; RFC 9700; SSO-Monitor SoK (EuroS&P'24); OAuch.
**Novelty risk: MEDIUM-HIGH.** Probably a short paper or workshop paper unless it is combined with D1's enforcement testing.

**Recommendation.** D1 as the core, with D2 or D3 as a second axis, under the framing "formally secure sender-constraining versus implementation-level enforcement gaps in open banking". It reuses all three of the user's Basiq findings and the testbed's negative result about risk scoring, which shows that enforcement matters, not extra scoring.

**Before committing, read the full texts of** Token Time Bomb (NDSS'26), Chai (arXiv 2606.26933), Cerberus (CCS'22), the OAuch GitHub test list, and ePrint 2024/1540 §RS, searching for "DPoP", "ath", "htu", "jkt". Also re-search arXiv and dblp for "DPoP" right before submission.

---

## (e) Searches performed (all via web search on 2026-11-22, plus direct fetch of RFC 9449 and its errata page)

- S1 `DPoP RFC 9449 security analysis formal verification`
- S2 `DPoP Tamarin OR ProVerif proof-of-possession OAuth analysis paper`
- S3 `Hosseyni Küsters Fett formal security analysis FAPI 2.0 attacker model`
- S4 `"Formal Security Analysis of the OpenID FAPI 2.0" Hosseyni Küsters Würtele CSF`
- S5 `Fett Küsters Schmitz comprehensive formal security analysis of OAuth 2.0 CCS 2016`
- S6 `DY* OAuth OpenID formal verification F* symbolic analysis "DY*" web protocols`
- S7 `"An Extensive Formal Security Analysis of the OpenID Financial-grade API" IEEE S&P 2019`
- S8 `Fett Küsters Schmitz "The Web SSO Standard OpenID Connect…" CSF 2017`
- S9 `FAPI 2.0 formal analysis DPoP model Web Infrastructure Model sender-constrained attack "DPoP"`
- S10 `arXiv 2025 DPoP "proof of possession" OAuth tokens vulnerabilities implementations empirical` (extended)
- S11 `draft-cavage HTTP signatures vulnerability signature does not cover method path headers CVE`
- S12 `Token Binding RFC 8471 why abandoned Chrome removed token binding`
- S13 `DPoP implementation study libraries ath htm htu validation measurement` (extended)
- S14 `HTTP Message Signatures RFC 9421 security analysis canonicalization attack`
- S15 `HTTP message signatures verifier implementations interoperability test suite differential RFC 9421 libraries`
- S16 `open banking API JWS detached signature b64 false vulnerability OBIE x-jws-signature analysis`
- S17 `URL parsing inconsistencies differential study academic paper parsers security`
- S18 `differential testing JWT JWS libraries vulnerabilities paper algorithm confusion study` (extended)
- S19 `"Token Time Bomb" JWT NDSS 2026 authors JWTeemo`
- S20 `RFC 8705 mutual TLS certificate-bound access tokens security analysis TLS-terminating proxy header injection`
- S21 `DPoP jti replay cache distributed resource servers nonce scalability`
- S22 `RFC 9449 errata ath claim resource server validation`, then a direct fetch of errata.rfc-editor.org/rfc9449 and rfc-editor.org/rfc/rfc9449.html
- S23 `OAuth WG mailing list DPoP ath resource server must check access token hash discussion`
- S24 `OpenID Foundation FAPI conformance suite DPoP resource server tests ath certification`
- S25 `security analysis open banking APIs empirical study banks OAuth FAPI vulnerabilities paper` (extended)
- S26 `"Security Analysis of the Open Banking Account and Transaction API Protocol" authors venue`
- S27 `Australia Consumer Data Right security analysis academic paper FAPI CDR open banking`
- S28 `Cerberus query-driven scalable vulnerability detection OAuth service provider implementations CCS`
- S29 `OAuch exploring security compliance OAuth 2.0 ecosystem Philippaerts RAID`
- S30 `"Revisiting OAuth 2.0 Compliance" two-year follow-up study Philippaerts`
- S31 `SSO-Monitor Westers authors venue 2024 single sign-on in the wild`
- S32 `"A First Measurement Study on Authentication Security in Real-World Remote MCP Servers"`
- S33 `formal security analysis Grant Negotiation and Authorization Protocol GNAP Hosseyni Küsters`
- S34 `Chai agentic discovery cryptographic misuse vulnerabilities arXiv 2606.26933 JWT`
- S35 `Tervoort "Three New Attacks Against JSON Web Tokens" Black Hat 2023 polyglot sign/encrypt confusion`
- S36 `Somorovsky "On Breaking SAML" XML signature wrapping USENIX Security 2012`
- S37 `JSON Web Token misuse measurement study in the wild websites weak secrets paper`
- S38 `AWS Signature Version 4 security analysis formal OR academic paper request signing canonical request`
- S39 `Berlin Group NextGenPSD2 signature header digest request-target analysis OR Brazil open finance JWS signed request security`
- S40 `RFC 9700 OAuth 2.0 Security Best Current Practice January 2025 sender-constrained tokens`
- S41 `Device Bound Session Credentials paper cookie theft binding evaluation`
- S42 `T-Reqs HTTP request smuggling grammar-based differential fuzzing CCS 2021`
- S43 `"HTTP Garden" OR "HTTP parsing discrepancies" proxy origin differential testing paper 2024`

**Searches that were not done (gaps):** Google Scholar and dblp directly (I used a general web index); the ACM DL full-text search; Brazil Open Finance signing specifically (S39 returned nothing on Brazil); full-text reads of the NDSS'26, Chai, Cerberus and ePrint 2024/1540 papers; the IETF OAuth WG archive beyond the first page of results; the OIDF conformance-suite test list.

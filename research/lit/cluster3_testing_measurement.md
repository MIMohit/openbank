# Cluster 3: Systematic testing and measurement of OAuth/OIDC/FAPI deployments and libraries

Investigation date: 2026-11-22. Method: web searches (listed in §e) plus a direct read of the OpenID Foundation conformance suite source at `gitlab.com/openid/conformance-suite`, commit `1bbcbc3722f8cca5f75e5df36856dc41a5285695` (committed 2026-11-19).

Labels used below:
- **[V]** I saw the title, authors, venue and URL/DOI in search results or on the publisher's page.
- **[V-partial]** Some metadata was not seen; the missing items are named.
- **UNVERIFIED** The metadata could not be confirmed.

I did not open full texts unless stated. Claims about what a paper contains come from abstracts, slides or publisher pages.

---

## 0. Headline answers to the two concrete questions

### Q1. Does the OIDF FAPI conformance suite test resource-server-side DPoP checks (ath, htm, htu, jti replay)?

**Yes, partly.** It does so in one module, against one resource endpoint that the tester supplies. I checked this directly in the source.

**Where the tests live**
- Module: `fapi2-security-profile-final-dpop-negative-tests`, class `FAPI2SPFinalDpopNegativeTests.java` in package `net.openid.conformance.fapi2spfinal`.
- First version: commit "FAPI2OP: First set of DPoP negative tests", 2022-04-11, then in the ID2 package.
- It is included in `FAPI2MessageSigningFinalTestPlan` and, through it, in `FAPI2SPFinalTestPlan`.
- It carries `@VariantNotApplicable(FAPI2SenderConstrainMethod = mtls)`, so it runs only for the DPoP variant.

**Checks it performs at the protected resource.** For each case: the expected outcome, and how a deviation is graded.

| Check | Expected | Graded |
|---|---|---|
| More than one DPoP header | reject | FAILURE |
| Malformed JWT | reject | FAILURE |
| Missing `typ`, `alg`, `jwk`, `jti`, `htm`, `htu`, `iat` | reject | FAILURE |
| **Missing `ath`** | reject | FAILURE |
| Wrong `typ` | reject | FAILURE |
| RS256 signature (only when the client key is RSA) | reject | FAILURE |
| `alg=none` | reject | FAILURE |
| Bad signature | reject | FAILURE |
| Private key inside the `jwk` header | reject | FAILURE |
| **`htm` set to `PUT`** | reject | FAILURE |
| **`htu` = real URL + `"ohnonotagain"`** | reject | FAILURE |
| `iat` ±1 h | reject | FAILURE, relaxed if the RS demanded a nonce |
| **Second use of the same `jti`** | reject | **WARNING only** (`shouldFail=false`) |
| **Wrong `ath`** | reject | FAILURE |
| Proof signed with a different key from the token's `cnf.jkt` | reject | FAILURE |
| Extra claims in header or body | accept | FAILURE if rejected |
| `htu` with or without query/fragment | accept | FAILURE if rejected |
| `htu` with uppercase scheme/host, or explicit default port | accept | WARNING only |
| No DPoP header | reject | FAILURE |
| **Token sent as `Authorization: Bearer` without a proof (downgrade)** | reject | FAILURE |
| All-caps DPoP header value | accept | WARNING if rejected |

**What the suite does not test** (from reading the source)
- **Server-provided nonces at the RS.** The source comment reads "10. … nonce claim matches the server-provided nonce value — We're not doing nonces yet". It only retries when the RS returns `use_dpop_nonce`.
- **Replay of a valid proof to a different *real* endpoint or method.** The suite uses exactly one resource URL (`SetProtectedResourceUrlToSingleResourceEndpoint`). The wrong-`htu` case appends a junk suffix to that URL. It never replays a proof minted for endpoint A, method M against an existing endpoint B, method M′.
- **`jti` replay across RS replicas, gateways, or two RSes sharing one AS.** The single same-RS `jti` reuse test is only a WARNING.
- **mTLS-bound tokens at the RS.** I found no RS negative test where a certificate-bound token is presented with a different client certificate or with none. This is "not found" from a name-grep of the 1,345 classes in `condition/client` and a grep of `AbstractFAPI2SPFinalServerTestModule`, not a proof of absence.
- **RFC 9421 HTTP Message Signatures on resource requests.** `grep -ri "signature-input"` and `grep "rfc9421|RFC9421|HTTPSIG"` over `src/main/java` returned nothing. The only related condition is `ValidateResourceResponseSignature`, which checks a JWS response body, as used by the Brazil profile.
- **The AU-CDR profile.** `ConsumerDataRightAuProfileBehavior.requiresMtlsEverywhere() = true`, so the DPoP negative module never runs for CDR. The AU-CDR plan is forced into the Message-Signing plan with mTLS.

**Who the module actually certifies**
- The plan's display name is "FAPI2-Message-Signing-Final: **Authorization server** test".
- The resource endpoint is a configuration field the tester supplies, so the certified party may point the suite at a demo RS.
- Supporting evidence: Keycloak issue #44800 says the Keycloak OAuth SIG's conformance environment "implemented the resource server by itself", and the RS DPoP tests failed because that RS did not support DPoP (https://github.com/keycloak/keycloak/issues/44800, seen as a search snippet).

**Implication for the user's Basiq finding (2), "DPoP proof accepted without `ath`"**
- The suite *does* encode this as a FAILURE. So the finding is not a "conformance suite gap" claim.
- It is a "deployed RS ≠ the RS that was certified (if any)" claim. It also applies only to ecosystems that use DPoP. CDR uses mTLS.

### Q2. Is there prior academic work that tests resource-server enforcement, as opposed to authorization-server behaviour?

**Not found** as a dedicated, peer-reviewed study of RS-side token-binding enforcement (DPoP, mTLS, signatures) across deployments or libraries. Searches 12, 15, 21, 29, 33 and 36 in §e did not find one.

What exists, and how close it comes:
- **OAuch** (RAID 2022) explicitly tests only the AS.
- **Cerberus** (CCS 2022) statically analyses OAuth "service provider" libraries. Whether it covers RS token validation is UNVERIFIED; my reading of the abstract suggests AS-side properties.
- **JWTeemo** (NDSS 2026) differentially tests JWT libraries. RSes use these to validate tokens, but it targets JWS/JWT parsing, not DPoP binding semantics.
- **MCP server measurement studies** (arXiv 2605.22333, 2026; arXiv 2608.00150, 2026) test OAuth-protected MCP servers, which *are* resource servers. They are the closest recent competitors for RS-side measurement. Neither abstract mentions DPoP or sender-constraining.
- **The MCP conformance project** has an open issue adding RS DPoP negative tests (missing/wrong `ath`) for SEP-1932: https://github.com/modelcontextprotocol/conformance/issues/369 (seen in search results). This is a non-academic but fast-moving competitor.
- **BOLA/IDOR testing work** tests RS *authorization* logic, not token binding.

---

## (a) Annotated bibliography (closest 28 works)

### A. Automated and black-box testing of SSO/OAuth/OIDC implementations

1. **Yuchen Zhou, David Evans. "SSOScan: Automated Testing of Web Applications for Single Sign-On Vulnerabilities." USENIX Security 2014.** [V] https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/zhou
   Black-box probing of relying parties that use Facebook SSO, across the top 20k sites. More than 20% of 1,660 Facebook-SSO sites had a serious flaw. Establishes black-box, client/RP-side automated scanning. No RS or token-binding focus.

2. **Ronghai Yang et al. "Model-based Security Testing: An Empirical Study on OAuth 2.0 Implementations" (OAuthTester). ACM ASIA CCS 2016.** [V-partial: the full author list was not displayed; believed to be Ronghai Yang, Guanchen Li, Wing Cheong Lau, Kehuan Zhang, Pili Hu — UNVERIFIED] DOI 10.1145/2897845.2897874 (seen via https://www.springerprofessional.de/doi/10.1145/2897845.2897874)
   Adaptive model-based testing of 4 IdPs and 500 top US/Chinese sites. Found new flaws. Establishes model-based black-box testing of OAuth flows, with AS and RP focus. It is a *prior ASIA CCS paper* on this topic, which is useful for venue fit.

3. **Christian Mainka, Vladislav Mladenov, Tobias Wich, Jörg Schwenk. "SoK: Single Sign-On Security – An Evaluation of OpenID Connect." IEEE EuroS&P 2017, pp. 251–266.** [V] https://www.nds.ruhr-uni-bochum.de/research/publications/sok-single-sign-security-evaluation-openid-connect ; PDF https://oaklandsok.github.io/papers/mainka2017.pdf
   Introduces PrOfESSOS, an evaluation-as-a-service tool that uses an honest IdP plus an attacker IdP. 75% of the officially referenced OIDC libraries were vulnerable to at least one single-phase attack. Adds the IdP-Confusion and Malicious-Endpoint attacks. The authors worked toward integrating it into OIDF certification. Scope is the RP/client side.

4. **Christian Mainka, Vladislav Mladenov, Jörg Schwenk. "Do not trust me: Using malicious IdPs for analyzing and attacking Single Sign-On."** arXiv 1412.1623 (2014). [V] https://arxiv.org/abs/1412.1623
   Introduces OpenID Attacker, the predecessor of PrOfESSOS. Establishes the malicious-party testing paradigm.

5. **Vladislav Mladenov, Christian Mainka, Jörg Schwenk. "On the security of modern Single Sign-On Protocols: Second-Order Vulnerabilities in OpenID Connect."** arXiv 1508.04324 (2015). [V-partial: peer-reviewed venue not seen] https://arxiv.org/abs/1508.04324v2
   Malicious-endpoint attacks via OIDC Discovery and Dynamic Registration.

6. **Pieter Philippaerts, Davy Preuveneers, Wouter Joosen. "OAuch: Exploring Security Compliance in the OAuth 2.0 Ecosystem." RAID 2022.** [V] DOI 10.1145/3545948.3545955 (https://unpaywall.org/10.1145%2F3545948.3545955); tool https://github.com/DistriNet/OAuch
   113 test cases derived from OAuth RFCs and the BCP, covering 42 threats, run against 100 public IdPs. Has OIDC and FAPI test sets. **It explicitly tests only the authorization server.** This is the closest "compliance-measurement" competitor. Its AS-only scope is what an RS-focused paper would differentiate against.

7. **Pieter Philippaerts, Davy Preuveneers, Wouter Joosen. "Revisiting OAuth 2.0 Compliance: A Two-Year Follow-Up Study." IEEE EuroS&P Workshops 2023, p. 521ff.** [V] https://computer.org/csdl/proceedings-article/eurospw/2023/272000a521/1OFtfPrdUcg
   Longitudinal re-measurement of the OAuch dataset. Establishes that compliance drifts over time. Still AS-only.

8. **Stefano Calzavara, Riccardo Focardi, Matteo Maffei, Clara Schneidewind, Marco Squarcina, Mauro Tempesta. "WPSE: Fortifying Web Protocols via Browser-Side Security Monitoring." USENIX Security 2018, pp. 1493–1510.** [V] https://www.usenix.org/conference/usenixsecurity18/presentation/calzavara ; arXiv 1806.09111
   Browser-side protocol monitor. Flaws found in 55 of 90 OAuth sites. Shows that specification-driven runtime enforcement is feasible on the client side; it does not touch the RS.

9. **Louis Jannett, Vladislav Mladenov, Christian Mainka, Jörg Schwenk. "DISTINCT: Identity Theft using In-Browser Communications in Dual-Window Single Sign-On." ACM CCS 2022, pp. 1553–1567.** [V] DOI 10.1145/3548606.3560692; https://github.com/RUB-NDS/DISTINCT
   Dynamic analysis of postMessage SSO flows in the Tranco top 1k. Client-side.

10. **Maximilian Westers, Tobias Wich, Louis Jannett, Vladislav Mladenov, Christian Mainka, Andreas Mayer. "SSO-Monitor: Fully-Automatic Large-Scale Landscape, Security, and Privacy Analyses of Single Sign-On in the Wild."** arXiv 2302.01024 (2023). [V-partial: peer-reviewed venue not confirmed] https://doi.org/10.48550/arXiv.2302.01024
    Measured 1,632 sites with Apple, Facebook or Google login in the Tranco 10k. Found CSRF weaknesses, secret leaks and privacy leaks. Client/RP side.

11. **Louis Jannett, Vladislav Mladenov, et al. "SoK: SSO-MONITOR — The Current State and Future Research Directions in Single Sign-On Security Measurements." 2024.** [V-partial: the venue is cited as IEEE EuroS&P in one Crossref reference; the PDF is hosted on oaklandsok.github.io; DOI not seen] https://oaklandsok.github.io/papers/jannett2024.pdf ; https://casa.rub.de/forschung/publikationen/detail/sok-sso-monitor-the-current-state-and-future-research-directions-in-single-sign-on-security-measurements
    **The most relevant SoK.** Surveys 36 SSO measurement tools and their blind spots. Measures 89k flows on the top 1M sites: 33k BCP violations and 339 severe vulnerabilities. A paper must check its "future directions" section; I have not read the full text. If it lists RS-side or sender-constrained testing as future work, cite that as motivation. If it already covers it, the novelty risk rises.

12. **Tommaso Innocenti, Matteo Golinelli, Kaan Onarlioglu, Ali Mirheidari, Bruno Crispo, Engin Kirda. "OAuth 2.0 Redirect URI Validation Falls Short, Literally." ACSAC 2023.** [V] DOI 10.1145/3627106.3627140
    16 IdPs tested; path-confusion and parameter-pollution attacks on redirect-URI validation. Led to the BCP requiring exact string matching. **It is a methodological template for "URI comparison is under-specified" work.** It bears directly on DPoP `htu` normalization, where the suite only WARNS.

### B. Static and program analysis of OAuth libraries and SDKs

13. **Tamjid Al Rahat, Yu Feng, Yuan Tian. "Cerberus: Query-driven Scalable Security Checking for OAuth Service Provider Implementations." ACM CCS 2022.** [V] DOI 10.1145/3548606.3559381; arXiv 2110.01005
    Formalizes the OAuth specification and BCP as graph queries over system dependence graphs of server-side OAuth libraries. **This is the closest library-level competitor.** Whether its properties include RS token-binding checks is UNVERIFIED and must be checked in the full text.

14. **Tamjid Al Rahat, Yu Feng, Yuan Tian. "OAuthLint: An Empirical Study on OAuth Bugs in Android Applications." IEEE/ACM ASE 2019.** [V] https://2019.ase-conferences.org/details/ase-2019-papers/19/OAuthLint-An-Empirical-Study-on-OAuth-Bugs-in-Android-Applications
    Static "anti-protocol" checking. More than 32% of popular OAuth apps had at least one anti-protocol. Client side.

15. **Rui Wang, Yuchen Zhou, Shuo Chen, Shaz Qadeer, David Evans, Yuri Gurevich. "Explicating SDKs: Uncovering Assumptions Underlying Secure Authentication and Authorization." USENIX Security 2013.** [V] https://usenix.org/conference/usenixsecurity13/technical-sessions/presentation/wang_rui
    Shows that SDK security depends on implicit developer assumptions. This framing transfers directly to RS middleware: DPoP or JWT middleware that requires the app to pass the token for `ath`, or the full URL for `htu`.

16. **"Vetting single sign-on SDK implementations via symbolic reasoning" (S3KVetter).** [V-partial: CUHK PDF seen at https://staff.ie.cuhk.edu.hk/~khzhang/my-papers/2018-sec-sso.pdf; venue believed to be USENIX Security 2018 from the file name, author list not seen — UNVERIFIED]
    Symbolic execution plus a theorem prover on 10 SSO SDKs. 7 flaw classes, 4 of them new.

### C. Empirical studies of OAuth/SSO implementations

17. **Rui Wang, Shuo Chen, XiaoFeng Wang. "Signing Me onto Your Accounts through Facebook and Google: a Traffic-Guided Security Study of Commercially Deployed Single-Sign-On Web Services." IEEE S&P 2012.** [V] https://ieee-security.org/TC/SP2012/papers/4681a365.pdf
    Traffic-guided black-box analysis; 8 logic flaws.

18. **San-Tsai Sun, Konstantin Beznosov. "The devil is in the (implementation) details: an empirical analysis of OAuth SSO systems." ACM CCS 2012, pp. 378–390.** [V] DOI 10.1145/2382196.2382238
    Implementation-level OAuth flaws in Facebook, Microsoft, Google and RPs. Establishes that formal proofs omit implementation details.

19. **Eric Y. Chen, Yutong Pei, Shuo Chen, Yuan Tian, Robert Kotcher, Patrick Tague. "OAuth Demystified for Mobile Application Developers." ACM CCS 2014, pp. 892–903.** [V] DOI 10.1145/2660267.2660323; https://dblp.org/rec/conf/ccs/ChenPCTKT14
    600+ apps; 59.7% of implementations faulty. Identifies the developer misconception that bearer tokens are bound to the app. That misconception is exactly what sender-constraining fixes, and it is why RS enforcement is the crux.

20. **Ethan Shernan, Henry Carter, Dave Tian, Patrick Traynor, Kevin Butler. "More Guidelines Than Rules: CSRF Vulnerabilities from Noncompliant OAuth 2.0 Implementations." DIMVA 2015, LNCS 9148, pp. 239–260.** [V] DOI 10.1007/978-3-319-20550-2_13
    Only 4 of 13 IdPs enforced `state`; about 25% of OAuth sites in the Alexa top 10k appeared CSRF-vulnerable. Establishes the "optional or SHOULD requirement → widespread non-enforcement" pattern. It is analogous to the RS `jti` check being a WARNING.

21. **Mohammad Ghasemisharif, Amrutha Ramesh, Stephen Checkoway, Chris Kanich, Jason Polakis. "O Single Sign-Off, Where Art Thou? An Empirical Analysis of Single Sign-On Account Hijacking and Session Management on the Web." USENIX Security 2018, pp. 1475–1492.** [V] https://www.usenix.org/conference/usenixsecurity18/presentation/ghasemisharif
    After IdP compromise, RP sessions persist; revocation does not propagate. Relevant as precedent for "tokens and sessions outlive the security event at the downstream (RS/RP) side".

22. **Ronghai Yang, Wing Cheong Lau, Tianyu Liu. "Signing into One Billion Mobile App Accounts Effortlessly with OAuth2.0." Black Hat Europe 2016 (white paper).** [V] https://www.blackhat.com/docs/eu-16/materials/eu-16-Yang-Signing-Into-Billion-Mobile-Apps-Effortlessly-With-OAuth20-wp.pdf
    App back-ends accepted tokens without verifying audience or issuer. **This is a resource-server-side token-validation failure at scale.** It is non-academic, but it is the oldest RS-side precedent found.

23. **Zidong Zhang et al. "Mini-Programs, Mega-Problems: Unveiling OAuth-based Authentication Misuses in Mini-Programs via Dynamic Analysis." arXiv 2607.08232 (2026); stated as accepted at ACM CCS 2026.** [V-partial: full author list not seen] https://arxiv.org/abs/2607.08232
    MINIAUTH: dynamic analysis of 44k WeChat and 2.7k Baidu mini-programs; 1,834 misuses, including back-end authentication bypass. Recent and top-venue, which shows that OAuth misuse measurement still lands at CCS in 2026.

### D. Library differential testing (JWT/JOSE)

24. **Jingcheng Yang, Enze Wang, Jianjun Chen, Qi Wang, Yuheng Zhang, Haixin Duan, Wei Xie, Baosheng Wang. "Token Time Bomb: Evaluating JWT Implementations for Vulnerability Discovery" (JWTeemo). NDSS 2026.** [V] https://www.ndss-symposium.org/ndss-paper/token-time-bomb-evaluating-jwt-implementations-for-vulnerability-discovery/
    Cross-library differential testing of 43 JWT libraries in 10 languages; 31 new vulnerabilities, 20 CVEs. **This is the methodological competitor for any "differential testing of RS-side DPoP validators" paper.** A DPoP proof is a JWT, so the novelty must sit in DPoP-specific binding semantics (`ath`, `htm`/`htu`/normalization, `jti`/nonce state, `cnf.jkt` matching, Bearer/DPoP scheme downgrade). It must not sit in JWS parsing.

25. **Tom Tervoort. "Three New Attacks Against JSON Web Tokens." Black Hat USA 2023 (white paper).** [V] https://i.blackhat.com/BH-US-23/Presentations/US-23-Tervoort-Three-New-Attacks-Against-JSON-Web-Tokens-whitepaper.pdf
    Parser-differential attacks across JOSE libraries, e.g. python-jwt vs jwcrypto.

### E. Formal analyses of FAPI (the "ideal RS" these papers assume)

26. **Daniel Fett, Pedram Hosseyni, Ralf Küsters. "An Extensive Formal Security Analysis of the OpenID Financial-grade API." IEEE S&P 2019.** [V] DOI 10.1109/SP.2019.00067; arXiv 1901.11520
    WIM-based proof of FAPI 1. Found 4 new attacks. RS behaviour is modelled as specified.

27. **Pedram Hosseyni, Ralf Küsters, Tim Würtele. "Formal Security Analysis of the OpenID FAPI 2.0 Family of Protocols: Accompanying a Standardization Process."** IACR ePrint 2024/1540; the earlier full version of the CSF 2024 paper is ePrint 2024/078. [V-partial: CSF 2024 proceedings title and DOI not seen] https://eprint.iacr.org/2024/1540 ; https://eprint.iacr.org/2024/078.pdf
    Formal model of FAPI 2.0 including DPoP; the WIM was extended with a DPoP header. **The security proofs assume a correctly checking RS.** An empirical paper can use exactly this: show which RS checks are load-bearing in the proof, then measure whether deployed or library RSes perform them.

28. **Daniel Fett, Ralf Küsters, Guido Schmitz. "A Comprehensive Formal Security Analysis of OAuth 2.0." ACM CCS 2016.** [V] DOI 10.1145/2976749.2978385
    WIM proof of OAuth 2.0 with fixes.

### F. Financial and healthcare API studies

29. **Paolo Modesti, Leo Freitas, Qudus Shotomiwa, Abdulaziz Almehrej. "Security Analysis of the Open Banking Account and Transaction API Protocol."** arXiv 2003.12776 (v2, 2025). [V-partial: peer-reviewed venue of the full version unclear] https://arxiv.org/abs/2003.12776
    The short version is "Account and Transaction Protocol of the Open Banking Standard", Almehrej, Freitas, Modesti, Springer 2020, DOI 10.1007/978-3-030-48077-6_16 [V]. Formal model of the UK Open Banking AIS protocol. **This is the only academic open-banking protocol analysis found.** It is formal, not a measurement of deployed RSes.

30. **Alissa Knight (Knight Ink), sponsored by Approov. "Playing with FHIR: Hacking and Securing FHIR APIs" (2021) and "All That We Let In" (2021).** [V-partial: industry reports, not peer-reviewed; the "Playing with FHIR" title is seen only as quoted in secondary coverage, e.g. https://www.scworld.com/analysis/critical-flaws-found-in-interoperability-backbone-fhir-apis-vulnerable-to-abuse ; the "All That We Let In" PDF is at https://chat.fhir.org/user_uploads/10155/gdvRUKw9vvCc5scYkxGK2NRI/FHIR-hacking-mhealth-apps-with-apis.pdf]
    Reports that 100% of the FHIR APIs tested allowed cross-patient access with one patient's token. That is a BOLA failure **at the resource server**, while the EHR authorization layers were sound. Vendor-funded, and the FHIR community questioned the methodology. Use it as motivation only.

31. **Australian Data Standards Body. "Consumer Data Right Security Review" (Feb 2025)** and **UNSW threat/risk reports for the Data Standards Chair (Feb 2024).** [V, government grey literature] https://dsb.gov.au/sites/dsb.gov.au/files/2025-02/Consumer%20Data%20Right%20Security%20Review_0.pdf ; https://www.unsw.edu.au/content/dam/pdfs/law/general/research-reports/UNSW-Threat-Report-Feb-2024.pdf
    Not academic. Establishes the CDR context, including the move to FAPI 2.0 per the DSB InfoSec CG minutes of 2025-04-02. I found **no peer-reviewed security measurement of CDR**.

### G. Very recent RS-side measurements (agentic APIs; strongest timing competitors)

32. **Huijun Zhou, Xiaohan Zhang, Haozhe Zhang, Haoyang Zhang, Mi Zhang, Min Yang. "A First Measurement Study on Authentication Security in Real-World Remote MCP Servers."** arXiv 2605.22333 (May 2026). [V] https://arxiv.org/abs/2605.22333
    7,973 live MCP servers; 40.55% expose tools without authentication; every one of 119 testable OAuth-enabled servers had at least one flaw. **This measures OAuth-protected resource servers.** From the abstract, it does not appear to cover DPoP or sender-constraining; that needs checking in the full text.

33. **Nicolás Padilla. "Exposed by Design: A Dynamic Security Assessment of Internet-Facing MCP Servers at Scale."** arXiv 2608.00150 (2026). [V, single-author preprint] https://arxiv.org/pdf/2608.00150
    Corvus framework with 34 test modules; 414 servers tested dynamically. About 92% had no OAuth (figure from secondary blogs, unverified against the PDF).

34. **MCP conformance suite, issue #369 "Server Auth: DPoP Proof Validation (SEP-1932)."** [V, GitHub, non-academic] https://github.com/modelcontextprotocol/conformance/issues/369
    Plans RS negative tests for missing or wrong `ath`. Shows that the RS-side DPoP test idea is entering standard tooling in 2026.

Excluded as not found or not verifiable:
- A "Pereira, Felber, Esteves-Veríssimo SoK on OAuth 2.0" appeared only in secondary citations; title and venue were not seen (UNVERIFIED).
- No 2024–2026 peer-reviewed DPoP implementation study was found.

---

## (b) What is settled

1. **Client/RP-side and AS-side flaws are heavily measured.** Black-box, model-based, static and dynamic tools exist for RPs and IdPs: SSOScan, OAuthTester, PrOfESSOS, WPSE, OAuthLint, S3KVetter, DISTINCT, SSO-Monitor, OAuch, Cerberus, MINIAUTH. The SSO-Monitor SoK catalogues 36 such tools. A new RP- or AS-side OAuth scanner is not novel by itself.
2. **Compliance with OAuth MUSTs and SHOULDs is low and drifts.** OAuch (RAID 2022) plus its follow-up (EuroS&PW 2023), and Shernan et al. (DIMVA 2015), establish that optional or SHOULD-level checks are widely skipped.
3. **The protocols are secure if every party checks everything.** WIM proofs exist for OAuth 2.0 (CCS 2016), FAPI 1 (S&P 2019) and FAPI 2.0 including DPoP (CSF 2024 / ePrint 2024/1540). Sender-constraining defeats token replay *in the model*. The user's testbed result, that FAPI 2.0 sender-constraining stops replay, reconfirms the model empirically and is **not novel**.
4. **JWT/JOSE library parsing differentials are a mined field.** JWTeemo (NDSS 2026), Tervoort (BH 2023) and the Bochum JOSE work cover them. Novelty cannot come from JWS-level fuzzing of DPoP proofs.
5. **The OIDF suite already encodes the core RS DPoP negative tests**, including missing or wrong `ath`, wrong `htm`, wrong `htu`, wrong key and Bearer downgrade (§0). Claiming "nobody tests RS DPoP checks" would be **false**.
6. **Open-banking and healthcare API failures are mostly authorization logic (BOLA) at the RS.** This comes from vendor reports, e.g. Knight 2021, not peer-reviewed measurement.

---

## (c) Open questions that appear to remain

Each item names the work most likely to invalidate its novelty.

| # | Open question | Evidence it is open | Closest work that could kill novelty |
|---|---|---|---|
| Q1 | **What fraction of deployed or library RS DPoP/mTLS validators actually perform each RFC 9449 §4.3 / §7.1 check** (ath, htm, htu normalization, jti cache, nonce, cnf binding, Bearer-scheme downgrade)? Measured *differentially* across libraries, gateways and SaaS AS+RS products. | No academic paper found (searches 12, 15, 21, 29, 33, 36). OIDF only tests the RS that the certified party chose. | JWTeemo (NDSS 2026) for method. Cerberus (CCS 2022), if it covers RS properties. MCP conformance #369. The SSO-Monitor SoK "future directions". |
| Q2 | **Conformance-vs-security gap: which FAPI 2.0 RS-side MUSTs can a mutant RS violate and still pass OIDF certification?** For example: `jti` reuse is only a WARNING; nonce is untested; cross-endpoint replay of a real proof is untested; mTLS RS binding has no negative test (not found); RFC 9421 is untested; CDR never exercises DPoP. | Read directly from the suite source (§0). No paper found that mutation-tests a protocol conformance suite for OAuth/FAPI (searches 26, 27). | The Fries master's thesis (RUB 2021, certified OIDC implementations still vulnerable: https://www.nds.ruhr-uni-bochum.de/media/ei/arbeiten/2021/05/03/masterthesis.pdf). OAuch. The general "test-suite adequacy / mutation testing" SE literature (not searched in depth). Risk that OIDF fixes the gaps before publication. |
| Q3 | **Replay-state semantics in horizontally scaled RSes.** Is the DPoP `jti` cache, and the nonce, per-replica, per-gateway or global? Can a proof be replayed within the `iat` window by hitting another replica or region? | RFC 9449 §11.1 leaves this to implementations. The suite tests only same-instance reuse, and only as a warning. Practitioner guides flag jti-cache sizing across RSes (decryptiondigest blog). Not found academically. | The FAPI 2.0 formal analyses (they may argue jti replay is irrelevant given the attacker model: proof replay without the private key is limited to the same `htm`/`htu`/`ath` within the window). **This bounds impact. Check the FAPI 2.0 attacker model before claiming severity.** |
| Q4 | **Coverage of signed-request schemes at the RS.** Do proprietary or RFC 9421 request signatures in financial APIs cover method, target URI, body digest and nonce? Can signatures be replayed across endpoints or methods? (The user's Basiq finding (3).) | RFC 9421 §7 warns about it. IETF 124 webbotauth slides discuss replay. The OIDF suite has no RFC 9421 tests. No academic measurement found (search 28). | IETF webbotauth replay work (draft-hoypat-httpbis-message-signatures-ekm), which could be published as an academic analysis. Classic "signature does not cover the request line" lessons, e.g. AWS SigV2-era practitioner literature (not searched). |
| Q5 | **Does sender-constraining at the RS hold across the token's whole lifetime and across APIs sharing one AS?** Consider audience/resource-indicator confusion between RSes that share an AS and a DPoP key, refresh-token binding at the AS vs RS enforcement, and token-exchange paths. | The MCP measurement covers authentication, not binding. Yang et al. BH-EU 2016 covers audience checks for bearer tokens only. | arXiv 2605.22333 (MCP) and any follow-ups. The FAPI 2.0 formal analysis (multi-RS setting may be modelled). |
| Q6 | **Open-banking ecosystem measurement:** RS enforcement across many regulated data holders (CDR, UK OBIE, Brazil OFB, PSD2) in sandboxes. | Only formal (Modesti et al.) and grey literature found. | Feasibility and ethics, not a paper, are the main risk. Regulators' own conformance programmes (e.g. the CDR Conformance Test Suite, not examined). |

---

## (d) Candidate paper directions for this cluster

### D1. "Certified but not enforced": mutation analysis of the FAPI 2.0 conformance suite's resource-server coverage *(recommended)*
- **Idea.**
  1. Derive every RS-side normative requirement from FAPI 2.0 SP, RFC 9449, RFC 8705, RFC 9421 and the AU-CDR, UK and Brazil profiles.
  2. Map each requirement to the OIDF test conditions (the source is open, so the mapping is precise).
  3. Build a reference RS plus one mutant per requirement and run the official suite. Each mutant violates exactly one requirement: skip the `jti` cache, ignore the nonce, accept a proof for another real endpoint, skip the mTLS cert-thumbprint check, accept Bearer for a DPoP-bound token at a *second* endpoint, normalize `htu` loosely, and so on.
  4. Report which mutants still certify, with real-world exploitability for each surviving mutant.
  5. Complement with differential runs of the same mutant matrix against 10–20 RS libraries and gateways (D2-lite).
  6. Disclose to OIDF and contribute upstream tests.
- **Ties to the user's work.** It explains *why* findings (2) and (3) can exist in an ecosystem that claims FAPI conformance. The Keycloak testbed provides the reference RS.
- **Closest competitors.**
  - OAuch (RAID 2022): AS-only compliance.
  - Fries' thesis (RUB 2021): certified OIDC implementations still flawed, but not mutation-based and not RS-side.
  - JWTeemo: differential, but JWT-level.
- **Novelty risk: LOW–MEDIUM.**
  - Not found: mutation testing of an OAuth/OIDC conformance suite; any RS-side coverage analysis.
  - Risk 1: OIDF closes the gaps quickly. That actually strengthens the paper as impact, but weakens "open problem" framing.
  - Risk 2: reviewers may see it as "testing a test suite" and therefore incremental, unless real deployments or libraries exhibit the surviving mutants.

### D2. RS-Diff: differential testing of resource-server sender-constraint enforcement across libraries, gateways and IdP-bundled RS middleware
- **Idea.**
  - A grammar of DPoP/mTLS/RFC 9421 *request-level* mutations covering cross-endpoint and cross-method replay, `htu` normalization differentials, scheme confusion (`DPoP`/`Bearer`/case), duplicate headers, `ath` encoding variants, nonce lifecycle, `cnf` handling for introspection-vs-JWT tokens, and multi-replica `jti`.
  - Run it against open-source RS validators: Spring Security, ASP.NET, node-oidc/jose middlewares, Envoy/Kong/APISIX/Apigee-like gateway plugins, Keycloak, Authlete, and others.
  - Discrepancies are candidate vulnerabilities.
- **Closest competitors.**
  - JWTeemo (NDSS 2026), for methodology.
  - Innocenti et al. (ACSAC 2023), for URI-comparison differentials.
  - MCP conformance #369.
- **Novelty risk: MEDIUM.** The method is not new; the target (RS binding semantics) appears new. The risk is a JWTeemo follow-up from the same group adding DPoP. Not found in searches 15, 33 and 36.

### D3. Replay windows in scaled resource servers: DPoP `jti`/nonce state under replication and multi-region deployment
- **Idea.**
  - Formalize the replay-state requirement.
  - Measure replicated RS deployments in testbeds, plus consenting real APIs if possible.
  - Quantify the replay window and success probability against load balancers.
  - Propose and evaluate a cheap consistent design: a nonce bound to an RS cluster key, or `jti` sharding by `cnf.jkt`.
- **Closest competitors.**
  - RFC 9449 §11.1.
  - The FAPI 2.0 formal analysis, whose attacker model may make proof replay low-impact.
- **Novelty risk: MEDIUM.** Impact is the bigger risk: replay needs a captured proof plus a token. The user's testbed found that sender-constraining stops theft, so reviewers may ask "so what". It works best as a section of D1 or D2, not a standalone paper.

### D4. Signed-request coverage in financial APIs: what signatures actually bind
- **Idea.**
  - Catalogue request-signing schemes in open-banking and fintech APIs: RFC 9421, the Berlin Group/NextGenPSD2 signature profile, proprietary JWS-detached schemes, and the Basiq-style scheme from finding (3).
  - Extract covered components and test cross-endpoint and cross-method replay plus body substitution.
  - Map the results to RFC 9421 §7.
- **Closest competitors.**
  - IETF webbotauth replay slides (IETF 124) and the EKM draft.
  - Practitioner write-ups.
- **Novelty risk: MEDIUM–HIGH.** The population is small. The underlying lesson ("sign the method and URI") is old, so reviewers may deem it known. Stronger if combined with automated extraction of the covered-component policy from SDKs or docs.

### D5. Ecosystem measurement of resource-server enforcement across regulated open-banking sandboxes (CDR, UK, Brazil, PSD2)
- **Idea.** Systematically apply D2's matrix to public sandboxes of data holders and aggregators.
- **Closest competitors.**
  - Modesti et al. (formal).
  - Knight's FHIR reports (vendor).
  - Regulators' own conformance suites.
- **Novelty risk: LOW on novelty, HIGH on feasibility and ethics.** Sandboxes may not reflect production, access requires accreditation, and terms of use may forbid testing. Only pursue it with permissions.

**Recommendation for ASIA CCS 2027:** D1 as the spine, with D2-lite (library and gateway differential) for real-world findings and D3 as one section. This uses the existing Keycloak/OPA testbed and the Basiq findings as motivating cases. It also avoids the settled claim that sender-constraining works.

---

## (e) Searches performed

All were web searches unless marked SRC (direct source inspection).

1. OpenID Foundation FAPI 2.0 conformance suite DPoP resource server negative tests ath htm htu
2. PrOfESSOS OpenID Connect evaluation security testing Mainka Mladenov Schwenk
3. OAuthTester model-based security testing OAuth 2.0 Yang Li Lau
4. DPoP implementation security analysis RFC 9449 vulnerabilities libraries paper 2024 2025
5. SRC: GitLab API tree listing of `src/main/java/net/openid/conformance/fapi2spfinal` (3 pages)
6. SRC: downloaded `FAPI2SPFinalDpopNegativeTests.java`, `FAPI2SPFinalCheckDpopProofNbfExp.java`, `FAPI2SPFinalEnsureHolderOfKeyRequired.java`, `FAPI2SPFinalAccessTokenTypeHeaderCaseSensitivity.java`, `FAPI2SPFinalTestPlan.java`, `FAPI2MessageSigningFinalTestPlan.java`, `ConsumerDataRightAuProfileBehavior.java`
7. SRC: commit history of `FAPI2SPFinalDpopNegativeTests.java` (2022-04-11 to 2026-06-25)
8. SRC: listing of the 1,345 classes in `condition/client`; grep for HTTP-signature or RFC 9421 classes (none)
9. SRC: shallow clone at commit 1bbcbc3 (2026-11-19). Grep for `signature-input`, `rfc9421`, `HTTPSIG` (none); `SetDpopHtuToDifferentUrl` (appends "ohnonotagain"); resource-server test plans (none RS-only); mTLS RS negative conditions (none found)
10. OAuch OAuth 2.0 authorization server security evaluation tool Philippaerts Preuveneers Joosen
11. "OAuth demystified" mobile app developers Chen Pei Shi Tian CCS 2014
12. resource server enforcement OAuth access token validation empirical study APIs audience scope check measurement
13. Shernan Carter Tian Traynor Butler "More guidelines than rules" CSRF OAuth DIMVA 2015
14. Ghasemisharif … "O Single Sign-Off, Where Art Thou" USENIX Security 2018
15. differential testing JWT libraries vulnerabilities JWS validation paper
16. Wang Chen Wang "Signing me onto your accounts through Facebook and Google" IEEE S&P 2012
17. Sun Beznosov "The devil is in the (implementation) details" OAuth CCS 2012
18. WPSE web protocol security enforcer Calzavara Focardi USENIX Security 2018
19. SSO-Monitor Westers Wich Jannett Mainka Mladenov … large-scale SSO analysis
20. OAuth OpenID Connect security measurement 2024 2025 USENIX Security NDSS CCS
21. SMART on FHIR API security vulnerabilities study Knight "Playing with FHIR"
22. Rahat Feng Tian "Cerberus" OAuth service provider implementations CCS 2022
23. OAuthLint Android OAuth static analysis Rahat Feng Tian
24. PSD2 open banking API security analysis paper vulnerabilities
25. Fett Hosseyni Küsters FAPI formal analysis IEEE S&P 2019
26. Hosseyni Küsters Würtele formal security analysis FAPI 2.0 CSF 2024 DPoP
27. broken object level authorization detection REST API black-box testing (BOLA)
28. HTTP Message Signatures RFC 9421 security analysis covered components replay
29. arXiv 2025 2026 DPoP / sender-constrained / proof-of-possession empirical evaluation
30. Yang Lau Liu "Signing into one billion mobile app accounts" / S3KVetter
31. SoK OAuth security systematization web API authorization survey 2023–2025
32. "OAuth 2.0 Redirect URI Validation Falls Short, Literally" ACSAC 2023
33. DISTINCT dual-window SSO CCS 2022
34. "Consumer Data Right" Australia security analysis academic paper OAuth FAPI
35. "Security Analysis of the Open Banking Account and Transaction API Protocol"
36. SSOScan Zhou Evans USENIX Security 2014
37. API gateway access-token validation inconsistency microservices empirical study 2024
38. Philippaerts "Revisiting OAuth 2.0 Compliance" 2023
39. OpenID certified implementations vulnerabilities conformance testing not sufficient
40. access token audience confusion cross-service token reuse measurement OAuth resource server
41. SMART on FHIR security analysis academic paper OAuth EHR apps
42. "A First Measurement Study on Authentication Security in Real-World Remote MCP Servers"
43. "Mini-Programs, Mega-Problems" OAuth misuse arXiv 2607.08232
44. "Token Time Bomb" JWTeemo NDSS 2026 authors
45. "Explicating SDKs" USENIX Security 2013
46. PSD2 XS2A bank APIs empirical security study Berlin Group sandbox
47. "protected resource"/"resource server" OAuth black-box testing tool RFC 8705 evaluation
48. "Exposed by Design" MCP servers arXiv 2608.00150
49. Mladenov Mainka … SoK SSO / second-order vulnerabilities venue
50. "SoK: SSO-MONITOR" venue and DOI
51. keycloak issue 44800 FAPI 2.0 DPoP conformance resource server
52. OAuth library resource server DPoP validation missing ath CVE / GHSA

**Not searched, and worth doing before committing to a direction:**
- Full text of the SSO-Monitor SoK (future-work section).
- Full text of Cerberus (does it cover RS checks?).
- Full text of arXiv 2605.22333 (any DPoP?).
- dblp keyword search "DPoP" and "proof-of-possession" for 2025–2026.
- The OIDF GitLab issue tracker for open issues on RS nonce, jti or mTLS RS tests.
- The CDR Conformance Test Suite (ACCC) scope.
- Mutation testing of conformance or test suites in the SE literature (ICSE/ISSTA).

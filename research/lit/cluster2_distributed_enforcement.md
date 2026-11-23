# Cluster 2: Where authorization guarantees get lost between layers of distributed API infrastructure

Literature and novelty investigation, 2026-11-22. Task task_c522f1dc0103.

**Method and caveats.** About 55 web searches (see §e), plus direct reads of 7 arXiv/mail-archive pages through a fetch agent. Each entry below has a verification tag:
- **[V-page]**: I read the abstract or landing page directly. Title, authors and date are confirmed.
- **[V-meta]**: bibliographic data comes from search-result metadata such as USENIX, dblp, crossref, NSF-PAR or Springer listings. I did not read the full text.
- **[UNVERIFIED]**: seen only second-hand.

No full PDFs were read. Claims about a paper's content are therefore abstract-level only. "Not found" always means "not found in the searches listed in §e". It never means the work does not exist.

---

## (a) Annotated bibliography (30 entries, grouped)

### A. Proxy/backend parser differentials (the "semantic gap" family)

1. **B. Jabiyev, S. Sprecher, K. Onarlioglu, E. Kirda. "T-Reqs: HTTP Request Smuggling with Differential Fuzzing." ACM CCS 2021.** DOI 10.1145/3460120.3485384 (crossref). [V-meta]
   - Grammar-based black-box differential fuzzing of HTTP/1 request lines and headers across server pairs.
   - It established that automated discovery of smuggling discrepancies works.
   - The oracle is *parsing disagreement* (body or message boundaries). Authorization is not part of it.
2. **B. Jabiyev, S. Sprecher, A. Gavazzi, T. Innocenti, K. Onarlioglu, E. Kirda. "FRAMESHIFTER: Security Implications of HTTP/2-to-HTTP/1 Conversion Anomalies." USENIX Security 2022, pp. 1061–1075.** https://www.usenix.org/conference/usenixsecurity22/presentation/jabiyev [V-meta]
   - First systematic study of H2→H1 conversion anomalies in 8 proxies and 4 CDNs.
   - Attacks covered: smuggling, request blackholing, DoS.
3. **B. Jabiyev, A. Gavazzi, K. Onarlioglu, E. Kirda. "Gudifu: Guided Differential Fuzzing for HTTP Request Parsing Discrepancies." RAID 2024.** DOI 10.1145/3678890.3678904. NSF-PAR: https://par.nsf.gov/biblio/10615789 [V-meta]
   - Graybox, coverage-guided, whole-request differential fuzzing of proxies.
   - Finds significantly more discrepancies than T-Reqs.
4. **K. Mu, J. Chen, J. Zhuge, Q. Li, H. Duan, N. Feamster. "The Silent Danger in HTTP: Identifying HTTP Desync Vulnerabilities with Gray-box Testing" (HDHunter). USENIX Security 2025, pp. 743–762.** https://www.usenix.org/conference/usenixsecurity25/presentation/mu [V-meta]
   - Gray-box coverage-directed differential testing.
   - Adds response-side desync.
   - This is the current state of the art for finding desync.
5. **B. Kallus, P. Anantharaman, M. E. Locasto, S. W. Smith. "The HTTP Garden: Discovering Parsing Vulnerabilities in HTTP/1.1 Implementations by Differential Fuzzing of Request Streams." arXiv 2405.17737 (2024).** https://arxiv.org/abs/2405.17737 [V-meta]. Peer-reviewed venue not found.
   - Differential fuzzing of origin servers, not just gateways, with stream-level mutation.
6. **K. Shen, J. Lu, Y. Yang, et al. "HDiff: A Semi-automatic Framework for Discovering Semantic Gap Attack in HTTP Implementations." IEEE/IFIP DSN 2022, pp. 1–13.** DOI 10.1109/DSN53405.2022.00014 [V-meta]
   - Extracts rules from RFC text and generates requests from a grammar.
   - Coined or popularised "semantic gap attack" for HTTP.
7. **S. A. Akhavani et al. (Northeastern / Dartmouth). "WAFFLED: Exploiting Parsing Discrepancies to Bypass Web Application Firewalls." arXiv 2503.10846 (v4, Mar 2026).** https://arxiv.org/abs/2503.10846 [V-meta]. A secondary list says ACSAC 2025; that venue is **UNVERIFIED**.
   - **Closest structural analogue to this cluster's question.** The *security-check layer* (the WAF) and the *executing layer* (the framework) parse content-types differently.
   - Reports 1,207 bypasses across 5 WAFs.
   - The oracle is "the check passes, the app executes the payload". It does not involve tokens, DPoP or signatures.
8. **C. Topcuoglu, K. Onarlioglu, S. Sprecher, E. Kirda. "HTTP Request Synchronization Defeats Discrepancy Attacks." arXiv 2510.09952 (Oct 2025).** https://arxiv.org/abs/2510.09952 [V-page]
   - **Defence-side competitor.** Each proxy attaches its processing history to the request (HTTP extension headers), so later hops can check consistency with earlier hops.
   - Implemented for Apache, NGINX, HAProxy, Varnish and Cloudflare.
   - It is a non-cryptographic consistency mechanism. It does not reason about authorization proofs.
9. **E. Nygren, M. Bishop (Akamai). "HTTP/1.1 Request Smuggling Defense using Cryptographic Message Binding." IETF draft-nygren-httpbis-http11-request-binding (-00 Oct 2025, -01 Jul 2026), individual draft.** https://datatracker.ietf.org/doc/draft-nygren-httpbis-http11-request-binding/ [V-meta]
   - Hop-by-hop serial numbers plus a binding keyed from TLS exporters.
   - It is hop-by-hop, *not* end-to-end from client proof to backend execution.
10. **S. A. Mirheidari, S. Arshad, K. Onarlioglu, B. Crispo, E. Kirda, W. Robertson. "Cached and Confused: Web Cache Deception in the Wild." USENIX Security 2020, pp. 665–682.** https://www.usenix.org/conference/usenixsecurity20/presentation/mirheidari [V-meta]
    - Path confusion: a cache and an origin interpret the same URL differently.
    - Measured on Alexa top-5K sites.
    - Follow-up: Mirheidari et al., "Web Cache Deception Escalates!", USENIX Security 2022. https://www.usenix.org/conference/usenixsecurity22/presentation/mirheidari [V-meta]
11. **J. Chen, J. Jiang, H. Duan, N. Weaver, T. Wan, V. Paxson. "Host of Troubles: Multiple Host Ambiguities in HTTP Implementations." ACM CCS 2016, pp. 1516–1527.** dblp: https://dblp.org/rec/conf/ccs/ChenJDWWP16 [V-meta]
    - Ambiguous Host interpretation between parties leads to cache poisoning and *firewall/WAF bypass*.
    - The canonical "two parties disagree on the target" paper.
12. **H. V. Nguyen, L. Lo Iacono, H. Federrath. "Your Cache Has Fallen: Cache-Poisoned Denial-of-Service Attack." ACM CCS 2019, pp. 1915–1936.** DOI 10.1145/3319535.3354215 [V-meta]
13. **A. Büttner, H. V. Nguyen, N. Gruschka, L. Lo Iacono. "Less is Often More: Header Whitelisting as Semantic Gap Mitigation in HTTP-Based Software Systems." IFIP SEC 2021, IFIP AICT 625, pp. 332–347.** DOI 10.1007/978-3-030-78120-0_22 [V-meta]
    - Finds that most semantic-gap vulnerabilities come from header handling.
    - Explicitly lists *authentication bypass* as an outcome.
14. **S. Ali, S. W. Smith. "A Survey of Parser Differential Anti-Patterns." LangSec Workshop @ IEEE S&P 2023.** https://langsec.org/spw23/papers/Ali_LangSec23.pdf [V-meta]
    - Root-cause taxonomy.
    - Includes reverse-proxy `../` cases such as F5 CVE-2020-5902.
15. **Practitioner (non-peer-reviewed), included because the academic papers cite or build on them:**
    - J. Kettle, "HTTP Desync Attacks: Request Smuggling Reborn", PortSwigger / Black Hat USA & EU 2019. https://portswigger.net/research/http-desync-attacks [V-meta]
    - J. Kettle, "HTTP/1.1 Must Die: The Desync Endgame", Black Hat USA 2025. https://portswigger.net/research/http1-must-die [V-meta]
    - M. Doyhenard, "Gotta Cache 'em All: Bending the Rules of Web Cache Exploitation", Black Hat USA / DEF CON 32, 2024. https://portswigger.net/research/gotta-cache-em-all [V-meta]
    - D. Thatcher, "Practical HTTP Header Smuggling", Black Hat EU 2021. https://i.blackhat.com/EU-21/Wednesday/EU-21-Thatcher-Practical-HTTP-Header-Smuggling-wp.pdf [V-meta] Shows an AWS API Gateway resource-policy IP restriction bypassed with header mutations: a *gateway authorization check* defeated by a header differential.

### B. Proof and signature coverage (DPoP / RFC 9421 / FAPI formal work)

16. **P. Hosseyni, R. Küsters, T. Würtele. Formal security analysis of FAPI 2.0 (Web Infrastructure Model).** IACR ePrint 2024/078 (attacks plus first formal model) https://eprint.iacr.org/2024/078 and ePrint 2024/1540 (FAPI 2.0 with extensions such as CIBA, proofs under the FAPI WG attacker model) https://eprint.iacr.org/2024/1540 [V-meta]
    - Per the search snippets, the WIM was used "as-is except for an additional HTTP header for DPoP proofs".
    - **Implication to check in the full text:** the model treats the resource server as a single HTTP endpoint that sees the client's request. It models no TLS-terminating intermediary that rewrites the method or URI before execution. This is my reading of the snippets and has **not** been verified in the PDFs.
    - Background: D. Fett, P. Hosseyni, R. Küsters, "An Extensive Formal Security Analysis of the OpenID Financial-grade API", IEEE S&P 2019, arXiv 1901.11520 [V-meta]
17. **OpenID Foundation, "Formal Security Analysis of FAPI 2.0 Message Signing, DCR, DCM and FAPI-CIBA Completed."** https://openid.net/security-analysis-fapi-2-0-completed/ (Stuttgart technical report, Oct 2023, co-funded by the Australian Government.) [V-meta]
18. **RFC 9449 (DPoP), D. Fett, B. Campbell, J. Bradley, T. Lodderstedt, M. Jones, D. Waite, 2023.** https://datatracker.ietf.org/doc/html/rfc9449 [V-meta]
    - htm/htu are compared against "the HTTP URI value for the HTTP request in which the JWT was received", ignoring query and fragment.
    - The RFC states explicitly that DPoP does not protect payload or header integrity.
    - **This is the specification fact the cluster's research question rests on:** the binding is to the *verifier's* view of the request.
19. **B. Allam, "[OAUTH-WG] rfc9449", oauth@ietf.org, 29 Jun 2026**, with an attached proposal "Proposed Modification to RFC 9449: Making htm and htu Optional to Enable Wider Adoption". http://www.mail-archive.com/oauth@ietf.org/msg26175.html [V-page]
    - Argues that reverse proxies, load balancers, gateways and meshes rewrite URIs, so htu validation breaks.
    - Proposes reclassifying htm/htu from MUST to OPTIONAL, with a "possession-only profile" for proxied deployments.
    - Claims that TLS, aud, scope and RAR `locations` already cover relay protection.
    - Mentions Transaction Tokens as a workaround.
    - **This is direct evidence that the "proof vs. execution" gap is a live standards issue in 2026 and that there is no empirical data either way.** No WG decision was found.
20. **RFC 9421 (HTTP Message Signatures), A. Backman, J. Richer, M. Sporny, 2024.** https://www.rfc-editor.org/rfc/rfc9421
    - The security considerations cover canonicalization attacks, insufficient coverage, and reverse proxies changing `@target-uri`.
    - Draft-17 warns that an attacker could "confuse the inputs to the verifier" when proxy and backend see different contexts. [V-meta, from search snippets of the RFC/draft text]
21. **RFC 9440 (Client-Cert HTTP header), B. Campbell, M. Bishop, 2023.** https://www.rfc-editor.org/rfc/rfc9440.html [V-meta]
    - A standardised *header-based* propagation of mTLS identity from a TLS-terminating proxy to the origin. RFC 8705 cert-bound tokens behind a proxy depend on it.
    - The trust in that header is exactly the layer-crossing assumption this cluster is about.
22. **draft-ietf-oauth-transaction-tokens (A. Tulshibagwale, G. Fletcher, P. Kasselman), -07 Jan 2026.** https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-07 [V-meta]
    - Internal re-issuance of identity and authorization context inside a trust domain: the edge token is exchanged for an internal Txn-Token.
    - Standardises the point at which client-proof binding is *intentionally* dropped.
23. **RFC 9700 (OAuth 2.0 Security BCP), T. Lodderstedt, J. Bradley, A. Labunets, D. Fett, Jan 2025.** https://www.rfc-editor.org/rfc/rfc9700.html [V-meta]
    - Recommends sender-constraining (§4.10.1).
    - I found no specific guidance on intermediaries (search 45); the body text was not read.

### C. Gateway / mesh authorization enforcement (real-world evidence, mostly CVEs)

24. **Gateway-authorization path-divergence CVE cluster (advisories, not papers).** [V-meta, advisory pages]
    - Traefik CVE-2026-40912 (GHSA-6jwx-7vp4-9847): StripPrefixRegex plus ForwardAuth; ForwardAuth approves while the backend normalises dot-segments.
    - Traefik CVE-2026-88009 (GHSA-f52w-8j3h-j724): a rootless request-target is routed and authorized as "/" but forwarded verbatim.
    - Traefik CVE-2026-39858: header-alias forged trust context past ForwardAuth.
    - opa-envoy-plugin CVE-2026-26205: `input.parsed_path` differs from the path the backend serves.
    - Istio CVE-2021-31920 (`//`, `%2F` path bypass of AuthorizationPolicy) and CVE-2021-39156 / CVE-2021-39155.
    - Envoy CVE-2021-32777 (ext_authz multi-value headers).
    - Istio bulletin 2026-006 (path-parameter RBAC bypass, e.g. `/admin;x`). https://istio.io/latest/news/security/istio-security-2026-006/
    - Envoy advisory GHSA-xcx5-93pw-jw2w: the un-normalised path is used for routing and *all* L7 filters, including ext_authz.
    - **These show that "the policy decision point (PDP) sees request A, the backend executes request A′" recurs across products. I found no academic paper that systematises this class with an authorization-decision oracle.**
25. **R. Pang et al. "Zanzibar: Google's Consistent, Global Authorization System." USENIX ATC 2019, pp. 33–46.** https://www.usenix.org/conference/atc19/presentation/pang [V-meta]
    - External consistency ("zookies") for ACL updates versus content.
    - The canonical treatment of the *new-enemy / stale-ACL* TOCTOU problem inside one authorization service. It does not cover crossing gateways or tokens.
26. **Microservice authorization consistency (journal/workshop, not top-tier):**
    - "Towards automated formal verification of authorization policy in microservice systems", Cluster Computing (Springer), 2026. https://link.springer.com/article/10.1007/s10586-026-06522-x [V-meta; authors not recorded]
    - "On automated RBAC assessment by constructing a centralized perspective for microservice mesh", PeerJ CS (via PMC). https://pmc.ncbi.nlm.nih.gov/articles/PMC7924674/ [V-meta; authors not recorded]
    - Both use static analysis or SMT to find *policy* inconsistencies across services. Neither looks at request-interpretation differentials.

### D. BOLA/BFLA tooling and runtime enforcement

27. **A. Wu, Z. Feng, R. Feng, Z. Xing, Y. Liu, et al. "Rethinking Broken Object Level Authorization Attacks Under Zero Trust Principle" (BOLAZ). arXiv 2507.02309.** Search metadata gives ACM DOI 10.1145/3833417; the arXiv page lists no venue. [V-page; venue UNVERIFIED]
    - Static taint tracking of resource IDs, producer/consumer API classification, 35 new BOLAs in 10 projects.
28. **BACFuzz: "Exposing the Silence on Broken Access Control Vulnerabilities in Web Applications", arXiv 2507.15984 (2025).** [V-meta; authors not recorded]
    - Graybox fuzzer for BOLA/BFLA in PHP apps.
    - Related work: BacAlarm, arXiv 2512.19997; ABSENTIA, arXiv 2610.00977 [V-meta].
29. **M. Ndebugre. "BACGUARD: Fact-Grounded Runtime Mitigation of Broken Access Control." arXiv 2611.10157 (Nov 2026).** [V-page]
    - A *reverse proxy* that re-derives authorization facts from session stores and DB ownership.
    - Its probes found duplicate-slash normalisation causing missed routes, i.e. it ran into the proxy/backend differential itself.
    - Related: B. Kaur, "Broken Object Level Authorization in the Wild: An Empirical Taxonomy from 100+ Bug Bounty Disclosures", arXiv 2605.25865 [V-page].

### E. Revocation, continuous access evaluation, consent / Open Banking

30. **Revocation / CAE:**
    - ERNW White Paper 80, "Token Theft in Microsoft Entra ID" (2026). https://static.ernw.de/whitepaper/ERNW_White_Paper_80_Token_Theft_1.0_signed.pdf [V-meta; authors not recorded]
      - Measured CAE support in **33 of 740** first-party resource providers.
      - Revocation latency ranges from about 10 s (SharePoint/Teams) to about 5 min (Exchange).
      - Grey literature, but the only empirical CAE measurement found.
    - OpenID CAEP 1.0 Final (29 Aug 2025). https://openid.net/specs/openid-caep-1_0-final.html [V-meta]
    - K. Hatakeyama, D. Kotani, Y. Okabe, "Zero Trust Federation: Sharing Context under User Control toward Zero Trust in Identity Federation", PerCom Workshops 2021, pp. 514–519, arXiv 2209.11025 [V-meta]
    - Follow-up: Hirai, Kotani, Okabe, "Linking Contexts from Distinct Data Sources in Zero Trust Federation", ETAA 2022, LNCS 13782 [V-meta]. This one uses CAEP.
    - "Protect the Gate" (HM Munich, 2023, https://seclab.cs.hm.edu/assets/pdf/th-cae-2023.pdf) appears to be a thesis or report on CAE deployment. Authors not confirmed: **UNVERIFIED**.
    - No peer-reviewed measurement of OAuth revocation or introspection-cache latency was found (search 19). An arXiv survey, 2507.16870, cites one ("[20]"), which I could not identify: **UNVERIFIED**.

    **Open Banking:**
    - **P. Modesti, L. Freitas, Q. Shotomiwa, A. Almehrej. "Security Analysis of the Open Banking Account and Transaction API Protocol." Cyber Security and Applications 100097 (2025), arXiv 2003.12776.** DOI 10.1016/j.csa.2025.100097 [V-page]
      - AnBx/OFMC/ProVerif model of the UK OBIE consent → authorisation → resource flow, plus NatWest sandbox tests.
      - **The only formal Open Banking API analysis found.**
    - Gabert, "Short paper: How to attack PSD2 internet banking", Financial Cryptography (year unknown): **UNVERIFIED**, seen only as a citation in arXiv 2206.13358.
    - No USENIX, CCS, NDSS, S&P, EuroS&P or FC paper on CDR, Brazil Open Finance or OBIE API security was found (searches 13, 14, 41, 49).
    - **CDR consent revocation is specified bidirectionally** (holder ⇄ recipient `cdr_arrangement_revocation_endpoint`, `/arrangements/revoke`). Seen only in vendor documentation (WSO2, SecureAuth, Cloudentity) and CDR guidance, e.g. https://cds.ob.docs.wso2.com/en/latest/learn/arrangement-revocation-api/. The mTLS requirement on recipient endpoints was dropped in CDS v1.15.0 [V-meta, vendor docs]. No academic study of how revocation propagates was found.

**Adjacent, not counted above:**
- "Access Control as Verified Parse Constraints" (S. Iammongkol, Z. Huang, D. Eyers, arXiv 2609.12488, Sep 2026, [V-page]) verifies the *gateway's* parser with EverParse/seL4. It is one-sided and does not compare against the backend's view.
- "Trust Boundary Semantic Gaps" (D. Kim, J.-Y. Choi, J. Lee, arXiv 2607.01711, Jul 2026, [V-meta]) is a design-time taxonomy (Identity/Spatial/Temporal/Interpretation) built from 75 incidents. It is conceptual and HTTP-agnostic, but its "Interpretation" and "Temporal" dimensions name this cluster's two axes, so it should be cited and differentiated.
- "Proof-of-Continuity" (arXiv 2607.08906, [V-meta]) argues that sender-constrained tokens bind to a key, not to the causal request. Conceptually close to direction D1; it is not empirical.

---

## (b) What is settled

1. **Proxy/backend parser differentials are real, common and automatically discoverable.** T-Reqs, FRAMESHIFTER, Gudifu, HDHunter, HTTP Garden and HDiff all show it. Black-box, graybox and coverage-guided differential fuzzing is a mature methodology. A pure "new HTTP differential fuzzer" paper will be judged against HDHunter (USENIX 2025) and Gudifu.
2. **A security check placed in one layer can be bypassed by a differential with the executing layer.** WAFFLED (WAF vs. framework), Host of Troubles (firewall/WAF bypass), Cached and Confused (cache vs. origin) and Thatcher (AWS API Gateway resource policy) all show it. This is accepted at top venues.
3. **Defences for request-interpretation consistency across hops exist as proposals.** Examples: HTTP Request Synchronization (processing-history headers), the Nygren/Bishop hop-by-hop binding draft, and header whitelisting. None of them involves the *client's* authorization proof.
4. **Gateway or mesh PDPs evaluating a different path than the backend serves is a recurring vulnerability.** The Istio/Envoy CVEs (2021) and the Traefik/OPA-envoy CVEs (2026) are well documented, but only as product advisories.
5. **FAPI 2.0 (with DPoP) has formal proofs in the WIM** under the FAPI WG attacker model, with the resource server modelled as a single endpoint (pending full-text check). The UK OBIE A&T API has an AnBx/ProVerif model.
6. **DPoP binds htm/htu as seen by the verifier and does not protect headers or body**, by design (RFC 9449). The OAuth WG has an open 2026 proposal to make htm/htu optional *because* intermediaries rewrite them.
7. **Self-contained JWT revocation is bounded by token lifetime unless the RS introspects or receives push signals.** RFC 7009/7662 and the CAE documentation agree on this. The only measurement found is ERNW WP80 (grey literature), and it shows patchy CAE coverage.
8. **Zanzibar-style systems solve ACL-update consistency inside one authorization service.** They do not cover tokens cached at an edge.

---

## (c) Open questions that appear to remain (each with the closest work that could invalidate its novelty)

| # | Open question | Closest work that could kill novelty | Searches that found nothing closer |
|---|---|---|---|
| Q1 | **The proof-to-execution gap.** Behind real gateways, how often does the (method, URI) that a DPoP proof or RFC 9421 / FAPI-message-signing signature was verified against differ from the (method, route, handler) the backend executes? Which verify-placement topologies (edge-verify, origin-verify, both) are exploitable? | WAFFLED (same structure, but the oracle is a WAF); Gudifu/HDHunter (methodology); Allam 2026 OAuth-WG post (raises the issue, no data); RFC 9421 §7 text; arXiv 2607.08906 (conceptual) | 8, 9, 12, 46, 50, 54, 56 |
| Q2 | **Oracle shift.** A differential tester whose oracle is *"the PDP (ext_authz / ForwardAuth / OPA / auth_request / DPoP verifier) allowed request A, and the backend executed A′ ≠ A"* rather than a parsing disagreement. The 2026 Traefik/OPA CVEs suggest the class is under-tested. | HDHunter, Gudifu, HTTP Garden (could each be retrofitted); BACGUARD (runs into the issue but does not study it); the Envoy advisory | 24, 28, 35, 42 |
| Q3 | **What htm/htu actually buys in practice.** If htm/htu become optional (Allam), what concrete cross-endpoint/cross-method replay becomes possible across real API surfaces, e.g. CDR/FAPI resource-server route sets? Conversely, how often does strict htu break legitimate proxied traffic? This links to Basiq finding #3 (signature not covering method/URI). | Allam 2026 post; Hosseyni et al. (formal proofs may already show htu is needed or unnecessary under their model; check the full text) | 8, 9, 45, 50 |
| Q4 | **Formal model with intermediaries.** Do the FAPI 2.0 WIM security properties survive a TLS-terminating gateway that (i) verifies DPoP or mTLS and forwards identity via headers (RFC 9440, X-User), or (ii) re-issues internal tokens (Txn-Tokens / RFC 8693)? What is the minimal "canonicalization contract" needed? | Hosseyni/Küsters/Würtele ePrint 2024/078 and 2024/1540 (if their model already includes intermediaries, novelty drops sharply; full text not checked); Modesti 2025 | 11, 29, 30, 48, 50 |
| Q5 | **Revocation and consent-withdrawal propagation latency across layers in Open Banking.** Consumer withdraws on the holder's dashboard → arrangement revocation → AS token invalidation → gateway introspection cache → RS. What is the end-to-end window, and is any of it measured? | ERNW WP80 (CAE latencies, Entra only); Modesti 2025 (models the consent state but not its timing); CDR CTS guidance | 19, 20, 33, 39, 47 |
| Q6 | **Consent integrity across layers.** Does the data the backend returns stay within the consented accounts/scopes when consent is enforced at the AS/gateway but data filtering happens in the backend? This is BOLA-within-consent. | Modesti 2025; BOLAZ / BACFuzz (generic BOLA) | 13, 14, 16, 34, 41 |
| Q7 | **Header-based identity propagation as an attack surface at scale.** How common are spoofable identity headers or identity-header aliasing between gateways and frameworks (underscore/dash, case, duplicates) in the authorization context specifically? | Büttner 2021; Thatcher BH-EU-21; Traefik CVE-2026-39858; Telekom Security research (practitioner) | 23, 46, 52 |

---

## (d) Candidate paper directions (3–5) with closest competitor and an honest novelty-risk rating

### D1. "Proof ≠ Execution": systematising and measuring the gap between what a sender-constraining proof binds and what the backend executes
- **Idea.**
  - Define the property formally: the client's proof covers (m, u); the verifier's view is (m_v, u_v); the backend executes (m_b, route_b). Security requires that the binding implies (m_b, route_b) = f(m, u).
  - Build a harness that places DPoP verifiers and RFC 9421 verifiers at edge and origin behind real proxy/gateway stacks: NGINX, Envoy/Istio, Traefik, Kong, HAProxy, Cloudflare/AWS API GW where testable, Keycloak/Spring/.NET resource servers.
  - Fuzz with known discrepancy primitives from T-Reqs, Gudifu, HDHunter and Doyhenard, using the oracle "proof accepted, and a different handler or method executed".
  - Evaluate signature-coverage designs, including FAPI message signing and the Basiq-style signature that omits method/URI.
- **Why it might be novel.**
  - Every differential paper found uses parsing disagreement, WAF verdicts or cache state as the oracle. None uses *proof-of-possession or signature coverage*.
  - The OAuth WG debate (Allam, Jun 2026) shows practitioners have no data.
  - It links directly to the user's Basiq findings #2 (missing ath) and #3 (method/URI not covered), and to the openbank testbed.
- **Closest competitors.** WAFFLED (structure); HDHunter and Gudifu (methodology); HTTP Request Synchronization (a defence that might already neutralise it); arXiv 2607.08906 (concept).
- **Novelty risk: MEDIUM.** The attack primitives are known; the contribution is the oracle, the proof-binding semantics, a measurement across verifier placements, and a fix such as a "canonical-request binding" profile or an htu canonicalization contract. Reviewers may call it "WAFFLED for DPoP" unless there are real, CVE-grade findings in mainstream DPoP/RFC 9421 libraries or gateways. **Mitigation:** aim for concrete vulnerable deployments, including in the CDR/FAPI ecosystem's reference gateways.

### D2. A PDP-vs-backend differential tester for gateway authorization plugins (ext_authz, ForwardAuth, OPA-Envoy, auth_request, oauth2-proxy)
- **Idea.**
  - Generalise the 2026 Traefik/OPA-envoy CVE class: for each gateway authorization mechanism, extract the request view the PDP receives (path, headers, method) and compare it with what the upstream application framework routes.
  - Coverage-guided generation, with Gudifu-style guidance on the gateway side and a route-table oracle on the backend side.
- **Closest competitors.** HDHunter (USENIX 2025), Gudifu (RAID 2024), Büttner 2021, Istio/Envoy advisories. A follow-up from the Northeastern/Akamai group (Kirda/Onarlioglu) is plausible, given their trajectory: T-Reqs → FRAMESHIFTER → Gudifu → Request Synchronization.
- **Novelty risk: MEDIUM-HIGH.** The space is crowded with strong groups. The differentiator is the authorization oracle plus breadth across PDP plugins. D2 could be folded into D1 as its "PDP-at-edge" half, which strengthens D1.

### D3. Formalising the intermediary: FAPI 2.0 / DPoP guarantees under TLS-terminating gateways, header propagation and token re-issuance
- **Idea.**
  - Extend a symbolic model (WIM, or Tamarin/ProVerif for tractability) with an intermediary role that terminates TLS, verifies or forwards DPoP and mTLS (RFC 9440), rewrites URIs, and optionally exchanges tokens (RFC 8693 / Txn-Tokens).
  - Prove which FAPI goals survive under which canonicalization assumptions, and produce counterexamples matching D1's empirical findings.
- **Closest competitors.** Hosseyni/Küsters/Würtele ePrint 2024/078 and 2024/1540; Fett et al. S&P 2019; Modesti 2025.
- **Novelty risk: MEDIUM**, conditional on confirming that the Stuttgart model has no rewriting intermediary. Execution risk is high: WIM proofs are heavy, and Tamarin would need abstraction. Best used as a formal core paired with D1's measurements.

### D4. Revocation and consent-withdrawal windows across layers in Open Banking (CDR as the case study)
- **Idea.**
  - Measure, in the openbank testbed and the available sandboxes, the end-to-end time between consent withdrawal or arrangement revocation and the moment a captured, sender-constrained token stops working at the RS behind a gateway.
  - Vary the components: JWT vs. introspection, gateway cache TTL, CAEP/SSF push, bidirectional arrangement-revocation failures.
  - Model it as a TOCTOU-window metric and compare with the Entra CAE numbers.
- **Closest competitors.** ERNW WP80 (CAE, Entra only, grey literature); Modesti 2025; Zanzibar (consistency concept).
- **Novelty risk: LOW-MEDIUM on novelty, HIGH on impact and acceptance.** The only realistic venue is a measurement paper. Without real-ecosystem data (production CDR holders), ASIACCS reviewers may see it as configuration benchmarking. The user's earlier finding that continuous risk-scoring adds little also cuts against a "CAEP fixes it" story. It works better as a section of D1 or D5 than as a standalone paper.

### D5. Consent integrity across layers: is consent enforced where data is produced?
- **Idea.**
  - In CDR/OBIE/Brazil, consent (accounts and scopes, duration) is checked at the AS or gateway, but the backend enforces the account-ID filter.
  - Test for BOLA-within-consent, where a token with valid consent for account X retrieves account Y via ID manipulation, endpoint aliasing or parser differentials. Also test for scope drift after consent amendment.
  - Formalise "consent integrity" as a property connecting the consent object to returned data.
- **Closest competitors.** Modesti 2025 (formal, UK, no data-plane check); BOLAZ / BACFuzz (generic BOLA).
- **Novelty risk: MEDIUM.** No academic work on Open Banking data-plane consent enforcement was found. The risks are thin evaluation (sandboxes only), ethics and disclosure constraints, and possible findings that amount to "a sandbox bug". Pairs well with D1 under the theme "authorization guarantees lost between layers in Open Banking".

**Recommendation from this cluster:** **D1, with D2's PDP-oracle and D3-lite (a small Tamarin model of the canonicalization contract) folded in**, evaluated on FAPI/CDR-style stacks. It is the most direct continuation of the Basiq findings, it targets an open 2026 standards debate that has no data, and none of the 55 searches found an academic paper with a proof-binding oracle. **Before committing:**
1. Read Hosseyni et al. 2024/1540 in full, checking for intermediaries or URI canonicalization.
2. Read Topcuoglu et al. 2510.09952 in full, checking whether request synchronization would already cover DPoP htu.
3. Check WAFFLED's final venue and whether its related-work section mentions tokens or signatures.
4. Re-run searches for any 2026 CCS/NDSS papers on "DPoP" + "proxy".

---

## (e) Searches performed (WebSearch unless noted)

1. Jabiyev "T-Reqs" HTTP request smuggling CCS 2021
2. "Gudifu" HTTP smuggling guided differential fuzzing
3. Jabiyev "FRAMESHIFTER" HTTP/2 USENIX Security
4. "Cached and Confused" web cache deception path confusion USENIX 2020
5. arXiv 2510.09952 HTTP Request Synchronization authors
6. "HTTP Garden" Kallus differential fuzzing venue
7. WAFFLED parsing discrepancies WAF Akhavani ACSAC 2025
8. DPoP RFC 9449 security analysis formal htu htm proxy URI normalization (extended)
9. oauth@ietf.org DPoP htm htu optional proxy intermediated deployments (extended)
10. "The Silent Danger in HTTP" HDHunter USENIX 2025
11. formal analysis FAPI 2.0 Hosseyni Küsters Würtele DPoP WIM
12. RFC 9421 covered components proxy rewriting @target-uri security
13. open banking security analysis USENIX/CCS/FC PSD2 APIs (extended)
14. Brazil Open Finance / Consumer Data Right security measurement academic (extended)
15. microservice authorization empirical study service mesh 2023–2024 (extended)
16. BOLA detection tool academic REST API fuzzing authorization (extended)
17. "Host of Troubles" CCS 2016
18. NDSS 2024-31 paper identification
19. OAuth token revocation latency / introspection caching measurement (extended)
20. CAEP / Shared Signals academic security analysis (extended)
21. "Protect the Gate" CAE HM Munich authors
22. Zanzibar USENIX ATC 2019
23. header-based identity propagation gateway X-Forwarded / X-User spoofing academic (extended)
24. URL parsing differential path normalization access-control bypass proxy 2023–2025 (extended)
25. "Access Control as Verified Parse Constraints" arXiv
26. BACGUARD arXiv
27. "Gotta cache 'em all" Doyhenard
28. Traefik forwardAuth bypass path normalization CVE 2025/2026
29. RFC 9440 Client-Cert / RFC 8705 TLS-terminating proxy
30. RFC 8693 token exchange security analysis confused deputy (extended)
31. draft-nygren-httpbis-http11-request-binding
32. Hatakeyama "Zero Trust Federation" CAEP
33. TOCTOU authorization web revocation academic (extended)
34. consent integrity open banking formal analysis OBIE PSD2 (extended)
35. Envoy ext_authz / OPA / Istio AuthorizationPolicy path normalization CVE
36. OAuth security in-the-wild measurement / DPoP adoption 2023–2025 (extended)
37. HDiff DSN 2022 semantic gap
38. "Your Cache Has Fallen" CCS 2019
39. CDR Arrangement Revocation endpoint consent withdrawal propagation
40. financial data aggregators screen scraping security academic (extended)
41. dblp "open banking" security conference 2022–2025 (extended)
42. microservices API gateway inconsistent access-control enforcement CCS/S&P/USENIX (extended)
43. mail-archive msg26175 "Making htm and htu Optional"
44. Kettle "HTTP Desync Attacks" 2019
45. RFC 9700 reverse proxy / sender-constrained guidance
46. request smuggling authentication/authorization bypass gateway JWT academic
47. Microsoft CAE revocation evaluation / bypass study
48. draft-ietf-oauth-transaction-tokens authors
49. PSD2 SCA security analysis FC/EuroS&P/USENIX (extended)
50. DPoP formal verification Tamarin/ProVerif
51. SoK parser differentials HTTP intermediaries
52. "Less is Often More" Büttner IFIP SEC 2021
53. "A Survey of Parser Differential Anti-Patterns" authors
54. HTTP message signatures / request-signing canonicalization semantic gap academic (extended)
55. "Trust Boundary Semantic Gaps" arXiv 2607.01711
56. sender-constrained / PoP tokens at API gateway offloading academic 2025–2026 (extended)

**Direct page reads (fetch agent):**
- mail-archive oauth msg26175
- arXiv abstract pages 2609.12488, 2510.09952, 2605.25865, 2003.12776, 2611.10157, 2507.02309


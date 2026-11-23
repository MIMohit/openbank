# From an Open Banking audit to an ASIA CCS 2027 paper: research directions and blueprint

Prepared 2026-11-22. The supporting literature reviews are in `research/lit/`:
- `cluster1_pop_tokens.md`: sender-constrained tokens, signatures and JOSE libraries (28 works, 43 searches).
- `cluster2_distributed_enforcement.md`: proxies, gateways, policy decision points (PDPs), revocation and consent (30 works, 56 searches).
- `cluster3_testing_measurement.md`: OAuth/OIDC/FAPI testing and measurement, plus a direct read of the OpenID Foundation (OIDF) conformance-suite source (34 works, 52 searches).

**Scope of the evidence.** Each citation below was seen by the reviewing agent in search results or on a landing page. Almost no full PDFs were read. Content claims about papers are therefore *abstract-level*. Items marked **UNVERIFIED** could not be confirmed. "Not found" always means "not found in the logged searches". It never means the work does not exist. Re-check novelty before writing.

---

## 1. Executive assessment of the previous research

**What the Basiq work is.** It is a competent implementation audit of one sandbox. It found three weaknesses and disclosed them responsibly. For a top venue, each finding has a specific limitation:

| Finding | What it actually is | Why it cannot carry a top-venue paper |
|---|---|---|
| (1) Bearer replay across client instances | The deployment did not sender-constrain, or accepted a bound token as `Bearer`. | This is a straightforward violation of RFC 9449 §7.1 / RFC 8705. The OIDF suite already tests the Bearer downgrade as a FAILURE (cluster 3 §0). It counts as one deployment's bug. |
| (2) DPoP proof accepted without `ath` | The resource server (RS) skipped an RFC 9449 §4.3 check. | The OIDF suite tests missing and wrong `ath` as a FAILURE (`FAPI2SPFinalDpopNegativeTests`). So this is a case of "the deployed RS is not the certified RS", not a gap in the standard or the suite. Note also that AU-CDR runs mTLS everywhere, so the suite's DPoP module never runs for CDR. |
| (3) Signature replay across endpoints and methods | The signature's covered components omit the method or the target URI. | This is a known design property of cavage-style signing, where `(request-target)` is optional. RFC 9421 §7 warns about it. The lesson "sign what you execute" dates back to XML Signature Wrapping (Somorovsky et al., USENIX Sec 2012). |

**What the follow-up testbed adds** (`paper/manuscript.md`): it confirms empirically that FAPI 2.0 sender-constraining stops replay and theft. The formal proofs already establish this, and the Hosseyni/Küsters/Würtele CSF'24 model includes DPoP. It also gives an honest negative result: continuous risk scoring adds little, and an adaptive adversary defeats it 30/30.

**Verdict.** None of this is a new contribution by itself, and rewriting it would not reach ASIA CCS. The previous work still has two real assets:
1. A recurring pattern: all three findings are cases where **the request the binding check verified is not the request that got executed**. That pattern generalises.
2. Working infrastructure: Keycloak with DPoP, a reverse-proxy policy enforcement point (PEP), OPA, a Basiq-isomorphic resource API, and an attack harness.

Do not pursue the Zero Trust / risk-scoring line further. Your own data shows it is a dead end.

---

## 2. Research landscape and closest related work

### What is settled (do not claim any of this)
1. **Sender-constraining is provably secure if every party runs every check.** Sources:
   - Fett, Küsters, Schmitz, CCS 2016, doi:10.1145/2976749.2978385.
   - Fett, Hosseyni, Küsters, IEEE S&P 2019, doi:10.1109/SP.2019.00067.
   - Hosseyni, Küsters, Würtele, CSF 2024 (ePrint 2024/078) and ePrint 2024/1540. Their Web Infrastructure Model (WIM) was extended with a DPoP header.
2. **OAuth/OIDC client-, RP- and AS-side flaws are heavily measured.** Tools include SSOScan (USENIX'14), OAuthTester (ASIA CCS'16, doi:10.1145/2897845.2897874), PrOfESSOS (EuroS&P'17), WPSE (USENIX'18), OAuch (RAID'22, doi:10.1145/3545948.3545955; AS-only by design), Cerberus (CCS'22, doi:10.1145/3548606.3559381) and MINIAUTH (CCS'26 per arXiv 2607.08232). The SSO-Monitor SoK (EuroS&P'24, venue UNVERIFIED) catalogues 36 tools.
3. **JWT/JOSE library differentials are mined.** Token Time Bomb / JWTeemo (NDSS 2026: 43 libraries, 20 CVEs), Tervoort (Black Hat 2023) and Chai (arXiv 2606.26933) cover them.
4. **Proxy/backend parsing differentials are real and fuzzable.**
   - Fuzzers: T-Reqs (CCS'21, doi:10.1145/3460120.3485384), FRAMESHIFTER (USENIX'22), Gudifu (RAID'24, doi:10.1145/3678890.3678904), HDHunter (USENIX'25), HTTP Garden (arXiv 2405.17737), HDiff (DSN'22).
   - Security-check bypasses: Host of Troubles (CCS'16), Cached and Confused (USENIX'20), WAFFLED (arXiv 2503.10846; ACSAC'25 is UNVERIFIED).
   - Proposed defences: HTTP Request Synchronization (arXiv 2510.09952) and draft-nygren-httpbis-http11-request-binding.
5. **The OIDF FAPI 2.0 suite tests core RS DPoP checks.** It does this against one tester-supplied resource URL (cluster 3 §0, read from source at commit 1bbcbc3).

### Where the open space appears to be (all "not found", not "proven absent")
- **No paper was found that uses *proof or signature acceptance* as the differential oracle.** Every proxy-differential paper's oracle is a parsing disagreement, a WAF verdict or cache state. None asks: "the verifier accepted proof π for request view V, and the backend executed a different operation."
- **This is a live standards dispute with no data.** On 29 June 2026, B. Allam proposed on the OAuth WG list making DPoP `htm`/`htu` *optional* because proxies rewrite them (mail-archive oauth msg26175). The reviewing agent read the page, but no WG outcome was found.
- **Gateway PDP and backend divergence recurs, but only as product advisories.** Examples: Traefik CVE-2026-40912, CVE-2026-88009 and CVE-2026-39858; opa-envoy-plugin CVE-2026-26205; Istio CVE-2021-31920 and bulletin 2026-006; Envoy GHSA-xcx5-93pw-jw2w. No academic systematisation with an authorization oracle was found.
- **The formal model appears to have no rewriting intermediary.** The FAPI 2.0 WIM model *appears* to treat the RS as a single endpoint that sees the client's request. This comes from snippets only and is **not verified in the PDF**. It is the single most important novelty check (see §10).
- **There is no peer-reviewed study of RS-side sender-constraint enforcement.** Closest are JWTeemo (JWT level), the MCP RS measurements (arXiv 2605.22333 and 2608.00150, no DPoP in their abstracts) and MCP conformance issue #369 (adds RS `ath` tests).

### Closest works that could invalidate the recommended direction
| Threat to novelty | Why it is close | What would distinguish us |
|---|---|---|
| WAFFLED (arXiv 2503.10846) | Same structure: a check layer and an execute layer disagree. | A cryptographic binding oracle rather than a WAF verdict. A formal property. By-design under-binding as well as parser bugs. |
| HDHunter / Gudifu / HTTP Garden | Mature differential HTTP fuzzing. | We reuse their primitives. The contribution is the oracle and the semantics, not the fuzzer. |
| HTTP Request Synchronization (arXiv 2510.09952) | Hop-to-hop consistency defence that might already neutralise the problem. | Must be evaluated as a baseline. It does not bind to the client's proof. |
| Hosseyni et al. ePrint 2024/1540 | If it models intermediaries or URI canonicalisation, the formal angle dies. | Read it first. |
| "Proof-of-Continuity" (arXiv 2607.08906) | Argues conceptually that PoP binds to a key, not to the causal request. | Not empirical. We measure and break real stacks. |
| "Trust Boundary Semantic Gaps" (arXiv 2607.01711) | Taxonomy with "Interpretation" and "Temporal" gaps. | HTTP-agnostic and design-time. Cite and differentiate. |

---

## 3. Research directions (ten, deliberately different)

Format for each: **A** title · **B** question · **C** hypothesis · **D** novelty claim (testable) · **E** contribution · **F** relation to prior work · **G** why it matters · **H** feasibility · **I** ASIA CCS fit and objections · **J** main risk.

### Direction 1: Proof ≠ Execution: the binding-soundness gap between sender-constraint verification and request execution
- **A.** *Proof ≠ Execution: When Sender-Constrained Tokens Bind the Verifier's Request, Not the Executed One.*
- **B.** In layered API deployments, does accepting a DPoP proof, mTLS binding or request signature imply that the backend executes the operation the proof was minted for?
- **C.** It does not. Binding soundness fails in three ways:
  - **(G1) Under-binding by design.** `htu` excludes the query. The proof covers no headers or body. Method-override mechanisms exist. GraphQL and JSON-RPC send every operation to a single endpoint.
  - **(G2) Interpretation differentials.** The verifier and the router parse the method or URI differently.
  - **(G3) Propagation.** The binding result travels as a spoofable header (RFC 9440 Client-Cert, X-Forwarded-Client-Cert, custom "verified" headers).
- **D.** A testable claim: there exist mainstream gateway × framework topologies, in default or documented configurations, where a request accepted under proof π executes an operation outside op(π). No prior work measures acceptance of a sender-constraint proof as an oracle (not found in about 150 searches across the three clusters).
- **E.** A formal binding-soundness property. A measurement of G1 over API description corpora. A differential harness with a proof-acceptance oracle across gateways, verifier placements and frameworks. Disclosed vulnerabilities. A canonical-request binding defence evaluated against baselines, plus empirical data for the htm/htu-optional debate.
- **F.**
  - *Reusable evidence:* Basiq finding (3) as motivating example; finding (2) as the "deployed ≠ certified" illustration.
  - *Reusable infrastructure:* the Keycloak DPoP realm, the zt-controller (an edge PEP), mock-adr-api (backend), the attack runner.
  - *Reusable threat knowledge:* the FAPI attacker model and DPoP check semantics.
  - *Must be redone:* all measurement, on new gateway and framework stacks.
  - *Cannot be claimed:* that DPoP stops replay, that Basiq lacked `ath`, and the ZT results.
- **G.** FAPI 2.0 deployments (UK, Brazil, AU moving to FAPI 2.0), healthcare (SMART on FHIR backends behind gateways), MCP servers adopting DPoP (SEP-1932), and any enterprise API whose gateway verifies the binding while microservices execute. Affected parties: the account holder whose resources a leaked proof or a malicious client can act on.
- **H.** High. All components are open source and run in Docker. It extends what you already built. Additional needs:
  - Gateway plugins (Envoy ext_authz, Traefik ForwardAuth, Kong, NGINX auth_request, APISIX).
  - 6–8 backend frameworks.
  - Tamarin, for an optional small model.
- **I.** Web & Network Security track. Objections: "WAFFLED for DPoP"; "RFC 9449 already says it does not protect the query or body"; "the leaked-proof attacker is weak"; "these are misconfigurations". All are addressed in §8.
- **J.** Current gateway and framework versions may normalise consistently, so G2 yields nothing, and G1 then reads as "known by design". The novelty then collapses to a position paper.

### Direction 2: RS-Diff: differential testing of resource-server sender-constraint verifiers
- **A.** *Who Checks the Binding? Differential Testing of DPoP and mTLS Enforcement at Resource Servers.*
- **B.** Do RS libraries and middleware implement every RFC 9449 §4.3/§7 and RFC 8705 check consistently?
- **C.** Checks that are reachable only by cross-reference are skipped, and `jti`, nonce and `htu` normalisation diverge. `ath` is an example: it is in §4.3 and §7 but not restated in §7.1.
- **D.** First cross-implementation measurement of RS binding semantics, as distinct from JWS parsing.
- **E.** A spec-derived mutation grammar, a run across 15–25 RS stacks, CVEs.
- **F.** Directly generalises Basiq findings (1) and (2). Reuses the Keycloak harness.
- **G.** Every DPoP adopter.
- **H.** High.
- **I.** Fits. Expected objection: "JWTeemo already did differential JWT testing; the OIDF suite already tests these checks".
- **J.** The OIDF suite already tests most checks, so mature libraries may pass. JWTeemo's group could publish a DPoP follow-up first. Medium novelty risk.

### Direction 3: Certified but not enforced: mutation analysis of FAPI conformance coverage at the RS
- **A.** *Certified but Not Enforced: How Much of FAPI 2.0's Resource-Server Security Does Conformance Testing Observe?*
- **B.** Which RS-side MUSTs can an RS violate and still pass OIDF certification?
- **C.** Several such violations exist, as read from source:
  - `jti` reuse is only a WARNING.
  - The RS nonce is untested ("not doing nonces yet").
  - There is a single resource URL, so cross-endpoint replay of a real proof is untested.
  - No mTLS RS negative test was found.
  - There are no RFC 9421 tests.
  - The certified party may point the suite at a demo RS.
- **D.** First mutation-adequacy study of an OAuth/OIDC conformance suite (not found).
- **E.** Requirement-to-test mapping, about 30 mutant RSs, an adequacy score, upstream tests.
- **F.** Explains *why* your findings (2) and (3) can coexist with FAPI claims.
- **G.** Regulators that rely on certification (CDR, UK, Brazil).
- **H.** Very high. The suite is open source.
- **I.** Usability & Measurement or Software Security track. Expected objection: "testing a test suite is incremental".
- **J.** The OIDF fixes the gaps quickly, and the result looks like a bug report against a test suite. Best used as a *section* of Direction 1 or 2.

### Direction 4: Signature coverage confusion in financial request signing
- **A.** *What Did You Sign? Coverage Confusion in Financial API Request Signatures.*
- **B.** What do UK OBIE detached JWS, Berlin Group cavage-style signing, Brazil signed requests, FAPI 2.0 Message Signing and RFC 9421 profiles bind, and do verifiers enforce it?
- **C.** Several schemes leave the method, URI or query unbound by default. OBIE detached JWS appears to cover only the body; that coverage claim is UNVERIFIED.
- **D.** First cross-scheme coverage lattice and replay measurement (not found).
- **E.** Coverage formalisation, a mutation tester, a replay surface.
- **F.** Basiq finding (3) generalised.
- **G.** PSD2 banks across the EU and UK.
- **H.** Medium. Access to verifiers is limited to sandboxes and SDKs.
- **I.** Fits. Expected objection: "the lesson 'sign (request-target)' is known since XSW".
- **J.** It reads as "known design weakness, small population". It is better folded into Direction 1 as the signature arm of G1.

### Direction 5: Replay state in horizontally scaled resource servers
- **A.** *One Proof, Many Replicas: DPoP Replay Windows under Load Balancing.*
- **B.** Is `jti` and nonce state global, per replica or per region in practice, and what replay window results?
- **C.** Node-local caches are the default. Library documentation (Attesto, Duende, solid-pod-rs) says so.
- **D.** First measurement of replay windows across deployment topologies.
- **E.** A topology matrix, a window model, a sharded-cache defence.
- **F.** Builds on your replay PoCs.
- **G.** Large multi-region RSs.
- **H.** High.
- **I.** Fits. Expected objection: "RFC 9449 §11.1 already concedes this".
- **J.** Low impact. The attacker needs the token *and* a proof, and only within the `iat` window. Reviewers will ask "so what". Works only as a section.

### Direction 6: mTLS binding through TLS-terminating proxies
- **A.** *The Certificate Is a Header Now: Certificate-Bound Tokens Behind TLS Termination.*
- **B.** When RFC 8705 binding is checked at the backend via RFC 9440 or X-Forwarded-Client-Cert, can clients inject or alias the header?
- **C.** Default gateway configs and header aliasing (case, underscore and dash, duplicates) allow injection in some stacks.
- **D.** First measurement of RFC 9440-style propagation in the authorization context (not found).
- **E.** Gateway × framework header-trust matrix, exploits, a safe-configuration checker.
- **F.** Relevant to CDR, which uses mTLS everywhere. This is the CDR-relevant counterpart of your DPoP findings.
- **G.** Every mTLS-bound FAPI deployment behind a load balancer.
- **H.** High.
- **I.** Fits. Expected objection: "header injection is old (Büttner IFIP SEC 2021; Thatcher BH-EU 2021)".
- **J.** Incremental if stand-alone. **Best as axis G3 of Direction 1.**

### Direction 7: Formal model of FAPI 2.0 with rewriting intermediaries and token re-issuance
- **A.** *Binding Laundering: FAPI 2.0 Guarantees under Gateways, Header Propagation and Transaction Tokens.*
- **B.** Which FAPI 2.0 security properties survive a gateway that verifies, rewrites, forwards identity, or re-issues internal tokens (RFC 8693 / Txn-Tokens)?
- **C.** The properties hold only under a canonicalisation contract, which is stated nowhere.
- **D.** First symbolic model with an intermediary role, *if* ePrint 2024/1540 has none.
- **E.** Tamarin/ProVerif model, attacks, minimal sufficient contract.
- **F.** Theory companion to Direction 1.
- **G.** Standards bodies.
- **H.** Medium-low. Proof engineering is heavy and the Stuttgart group owns the WIM.
- **I.** Formal Methods track. Expected objection: "toy model versus the WIM".
- **J.** The Stuttgart group publishes first, or the abstraction is too coarse. **Use only as a small Tamarin section inside Direction 1.**

### Direction 8: Consent integrity across layers in Open Banking
- **A.** *Consented Here, Served There: Data-Plane Consent Enforcement in Open Banking APIs.*
- **B.** When consent is checked at the AS or gateway but account filtering happens in the backend, can a validly consented token reach unconsented data?
- **C.** "BOLA within consent" via ID manipulation, endpoint aliasing and scope drift after consent amendment.
- **D.** First data-plane consent-integrity study (Modesti et al. 2025, doi:10.1016/j.csa.2025.100097, models UK OBIE consent but not the data plane).
- **E.** Formal consent-integrity property, tests, case studies.
- **F.** Your consent-flow analysis plus mock-adr-api ownership enforcement.
- **G.** Consumers in regulated data sharing.
- **H.** Low-medium. Real tests need accredited sandboxes and permission, which raises ethics and terms-of-service questions.
- **I.** Fits. Expected objection: "it's just BOLA".
- **J.** Without real data holders, the evaluation is a toy. With them, the results are sandbox bugs.

### Direction 9: Revocation and consent-withdrawal propagation windows
- **A.** *How Long Does "Revoke" Take? End-to-End Consent Withdrawal Latency in Layered API Deployments.*
- **B.** What is the window between consent withdrawal and the moment a bound token stops working at the RS?
- **C.** Gateway introspection caches and JWT lifetimes dominate, and CAEP/SSF is rare. ERNW WP80 found Entra CAE in 33 of 740 services; that is grey literature.
- **D.** First peer-reviewed end-to-end measurement (not found).
- **E.** TOCTOU-window metric, testbed matrix.
- **F.** Reuses the testbed.
- **G.** Consumers who revoke after a breach.
- **H.** High in the testbed, low in reality.
- **I.** Measurement track. Expected objection: "configuration benchmarking".
- **J.** It is a configuration benchmark without ecosystem data. Weak for acceptance.

### Direction 10: SoK on sender-constraining, from Token Binding to DPoP and DBSC
- **A.** *SoK: Why Proof-of-Possession Keeps Failing at the Last Hop.*
- **B.** Across Token Binding, mTLS, DPoP, DBSC and HTTP signatures, where does the guarantee get lost between specification, implementation and deployment?
- **C.** The failures concentrate at the verification locus, not in the cryptography.
- **D.** An SoK needs *new evaluation*, which would be Direction 1's data.
- **E.** Taxonomy plus evaluation.
- **F.** All of your prior work.
- **G.** Standards bodies.
- **H.** Medium.
- **I.** SoK papers are accepted only with real evaluation.
- **J.** Without original data it is a survey. It is only viable *after* Direction 1.

---

## 4. Comparative assessment

Ratings: H = high, M = medium, L = low. For the two "risk" rows, L is good.

| Dimension | D1 Proof≠Exec | D2 RS-Diff | D3 Cert-mutation | D4 Sig coverage | D5 Replay state | D6 mTLS header | D7 Formal interm. | D8 Consent | D9 Revocation | D10 SoK |
|---|---|---|---|---|---|---|---|---|---|---|
| Novelty vs closest work | **M-H** | M | M-H | M | L-M | L-M | M (conditional) | M | L-M | L |
| Importance | **H** | M-H | M | M | L-M | M | M | M-H | M | M |
| Technical depth | **H** | M | M | M | M | L-M | H | M | L | M |
| Generalises beyond one provider | **H** | H | M | M | H | H | H | L-M | M | H |
| Feasibility | **M-H** | H | H | M | H | H | L-M | L-M | H | M |
| Reproducible evidence | **H** (open source) | H | H | M | H | H | H | L | M | M |
| Defensible security claim | **M-H** | M | M | M | L | M | M | M | L | L |
| ASIA CCS fit | **H** | H | M | M | M | M | M | M | L-M | M |
| Risk: rejected as incremental | **M** | M-H | M-H | M-H | H | H | M | M | H | H |
| Risk: rejected for weak evaluation | **L-M** | L | L | M | M | L | M | H | H | M |

**Ranking:** D1 > D2 > D3 > D8 > D7 > D4 > D6 > D5 > D9 > D10.

**Why D1 wins.**
- It is the only direction where the *oracle itself* is new.
- It answers an open 2026 standards question for which no data exists.
- It subsumes the strongest parts of D4 (signature under-binding), D6 (header propagation) and D7 (a small formal model) as axes, without becoming a grab-bag. All of them are the same property: binding soundness.
- It has a falsifiable kill experiment that takes about two weeks.

D2 and D3 are the fallbacks. They are lower-risk but more likely to be judged incremental.

---

## 5. The strongest direction

**Proof ≠ Execution: binding soundness of sender-constrained API requests in layered deployments.**

**The core insight.** A sender-constraint guarantee does not hold end to end. It holds at the point where the binding is checked. FAPI's proofs and RFC 9449 bind the token, and the proof's (htm, htu), to *the verifier's view* of the request. Real deployments separate the verifier from the executor: a gateway, a PDP plugin or middleware sits in front of a router, method-override middleware and handlers. Whenever the two views can diverge, the guarantee silently degrades. The divergence can come from the design (G1), from parsing (G2) or from propagation (G3). This is the common root of your Basiq findings (3) and (2). Neither the formal analyses nor the differential-HTTP literature has measured it, as far as the searches found.

---

## 6. Detailed technical blueprint

### 6.1 System model
- **Client C** holds key k and token T bound to k (`cnf.jkt`, or `cnf.x5t#S256`). It sends request r with proof π = (htm, htu, ath, jti, iat[, nonce]) or a signature σ over covered components.
- **Verifier V**: an edge gateway plugin (Envoy ext_authz, Traefik ForwardAuth, NGINX auth_request, Kong or APISIX plugin), or an origin middleware. It computes the view v(r) = (m_v, u_v) and accepts if π is consistent with v(r) and T.
- **Policy decision point P** (optional): OPA, or a consent check on the path.
- **Executor E**: framework router, method-override middleware, handler. It computes the executed operation x(r) = (m_x, route_x, op_x).
- **Binding soundness.** For all r, r′ accepted under the same π: x(r) = x(r′). Equivalently, an accepted proof determines a unique executed operation. Define the **binding resolution** of π as |{x(r) : r accepted under π}|. Sound means resolution 1.
- **Authorization soundness with a PDP** (consent, confused deputy): if P approves the resource ρ named in v(r), then E acts on ρ.

### 6.2 Threat model (two adversaries, each needed for a different gap)
- **A_leak (proof-leak adversary).**
  - *Has:* one valid (T, π) pair for a request r₀. Sources: logs, a debugging proxy, a compromised intermediary log, or a leaked resource request. Check whether the FAPI 2.0 Attacker Model's leaked-request capabilities include this; if they do, A_leak is *in-model*. This must be verified in the FAPI 2.0 Attacker Model text.
  - *Cannot:* access k, mint new proofs, or break TLS.
  - *Goal:* execute an operation different from op(r₀) within the `iat` window, possibly at a different replica so that `jti` does not stop it.
  - *Exploits:* G1 and G2.
- **A_client (legitimate but malicious client).**
  - *Has:* an accredited or compromised client with its own valid T and k, and consent for resource set R.
  - *Goal:* make P or V approve ρ ∈ R while E acts on ρ′ ∉ R, or on a non-consented operation. This is a confused deputy.
  - *Exploits:* G2 and G3.
  - This adversary matters for Open Banking because accredited data recipients are the realistic insiders.
- **Excluded, with reasons:**
  - A network attacker: TLS is assumed, and sender-constraining already wins.
  - A malicious gateway operator: trivially wins.
  - Malware on the client device: it holds k, which is out of scope and is what your previous paper measured.

### 6.3 Hypotheses
- **H1 (under-binding by design, G1).** In real API descriptions, a non-trivial fraction of state-changing operations are not uniquely determined by (method, path without query). In mainstream frameworks, documented method-override or query-dispatch features make m_x ≠ htm possible.
  - *Falsified if:* nearly all operations in the finance and health specs are uniquely identified by (method, path), and no mainstream framework enables override in any common configuration.
- **H2 (interpretation differential, G2).** For a meaningful subset of N gateway × framework topologies with edge verification, there exist requests accepted under π whose route_x ≠ route(htu).
  - *Falsified if:* current versions of all tested combinations normalise consistently against the full primitive set.
- **H3 (propagation and confused deputy, G3).** In at least one mainstream gateway-PDP integration, A_client can obtain execution on ρ′ ∉ R, or can spoof a propagated binding or certificate header.
  - *Falsified if:* all patched versions resist this.
- **H4 (defence).** Verifier-to-executor canonical binding removes G2 and G3 with low overhead and few false rejections of legitimate proxied traffic. One design: the executor re-checks htu/htm against *its own routed view*. Another: the verifier passes a MAC over its canonical view, which the executor compares. In both cases, measure the low overhead and the low false-rejection rate.
  - *Falsified if:* legitimate rewriting topologies cause a high false-rejection rate. That would support the Allam position, and is still a publishable data point, but a different paper.
- **H5 (optional, formal).** In a Tamarin model, the FAPI 2.0 resource-access property holds with origin verification. It fails with edge verification under a non-injective normalisation. It is restored by the canonical binding.

### 6.4 Technical approach
1. **Instrumented oracle.** Wrap each verifier to log v(r) and the decision. Wrap each executor (framework middleware at the route-match point) to log x(r). An oracle violation is "accepted, and x(r) ≠ op(π)". Your zt-controller already *is* an edge verifier; refactor it into one of several verifier placements.
2. **Primitive library.** Two parts:
   - *G2 primitives* from T-Reqs, Gudifu, HDHunter, WAFFLED and Doyhenard: dot-segments, `%2F`/`%2e`, `;` matrix parameters, duplicate slashes, absolute-form and rootless request targets, Host vs `:authority`, X-Forwarded-Prefix and strip-prefix rewrites, H2→H1 conversion, case folding.
   - *G1 primitives:* `X-HTTP-Method-Override` / `X-Method-Override` / `_method`, query-dispatched actions, GraphQL operation swaps under the same POST /graphql proof, content-type switching.
3. **Topology matrix.**
   - Gateways: Envoy (ext_authz and a JWT/DPoP filter if one exists), Traefik ForwardAuth, NGINX auth_request, Kong, APISIX, HAProxy.
   - Verifier placements: edge, origin, both.
   - Frameworks: Spring Boot, ASP.NET Core, Express, FastAPI/Starlette, Django, Go (chi / net/http), Rails, Laravel.
   - *Which have native DPoP RS support must be confirmed in week 1 (UNVERIFIED).* Where none exists, use one shared, audited reference verifier so the variable under test is the *placement*, not the verifier.
4. **G1 measurement.**
   - Corpus: the APIs.guru OpenAPI directory, plus the finance and health specs you can name and justify (CDR, UK OBIE, FDX, Berlin Group NextGenPSD2, FHIR).
   - Metric: the fraction of state-changing operations that share a (method, path-template) key with another operation of different privilege, which happens through query or body dispatch.
   - Separate count: GraphQL and JSON-RPC endpoints.
   - Sampling rule: the whole directory, plus a stratified analysis by domain. Report the denominator honestly.
5. **G3 tests.** Header-trust matrix for RFC 9440, X-Forwarded-Client-Cert, and "verified" headers. Inject, alias (case, `_`/`-`, duplicates) and test stripping under default and documented configs.
6. **Signature arm.** Run the same oracle on RFC 9421 verifiers (choose `@method`/`@target-uri` coverage) and on a cavage-style verifier without `(request-target)`. This is where Basiq finding (3) becomes one data point among many.
7. **Defence.** Implement the executor-side re-check and the verifier-to-executor MAC. Compare against:
   - origin-only verification;
   - HTTP Request Synchronization, if its artefact is available;
   - strict normalisation configs.
8. **Small formal model (optional; drop if time is short).** Tamarin with an intermediary rule that applies a normalisation function. This yields the counterexample and the sufficient condition.

**Expected challenges.**
- Few gateways may verify DPoP natively. Mitigation: treat "verifier placement" as the variable, and use ext_authz and ForwardAuth to put your verifier at the edge. That is exactly how real deployments add DPoP.
- Version churn: pin versions and report them.
- Keeping G1 claims honest: RFC 9449 *says* it excludes the query, so the novelty is consequence and prevalence, not discovery.

### 6.5 Security invariants to state in the paper
1. Every component that influences x(r) must be bound in π or σ, or be invariant across all accepted requests.
2. The verifier's canonical view must equal the executor's routing input.
3. A binding result propagated in a header must be unforgeable from outside the trust boundary: stripped at ingress and authenticated hop to hop.

---

## 7. Experimental and evaluation plan

| # | Experiment | Supports | Falsifies | Public infrastructure? |
|---|---|---|---|---|
| E1 | G1 corpus measurement over OpenAPI and GraphQL specs | A meaningful share of finance and health state-changing operations are indistinguishable by (method, path) | The share is negligible | Yes |
| E2 | Method-override / query-dispatch survey across 8 frameworks: default and documented configs, plus GitHub code search for enablement prevalence | Override is reachable in common configs | It is off everywhere and rarely enabled | Yes |
| E3 | Differential matrix: gateways × placements × frameworks × primitives, with the binding oracle | Several topologies have resolution > 1 | None do, on current versions | Yes (Docker) |
| E4 | A_client confused-deputy tests with an OPA/consent PDP at the edge, on mock-adr-api | Approve ρ, execute ρ′ | All resist | Yes |
| E5 | G3 header-trust matrix | Injectable or aliasable in default or documented configs | All strip correctly | Yes |
| E6 | Signature arm (RFC 9421 and cavage-style) | The same failure class appears for signatures | Signatures always cover the executed view | Yes, using libraries |
| E7 | Defence: security (re-run E3–E5), latency (p50/p99), and false rejection on legitimate rewriting configs (strip-prefix, path versioning, H2→H1) | Removes the attacks with small cost and few false rejections | High false rejection | Yes |
| E8 | Baselines: origin-only verification, HTTP Request Synchronization, strict normalisation | The defence is needed beyond these | A baseline already suffices (then the paper becomes a measurement paper) | Partly |
| E9 | Ablation: remove each binding component (htm, htu, ath, query, body digest) and measure the resulting resolution | Quantifies what each claim buys. This is the data the htm/htu-optional debate lacks | n/a (descriptive) | Yes |
| E10 | Optional Tamarin model | Sufficiency of the canonical binding | The model shows a gap in the defence | Yes |

**Provider cooperation.** The core paper needs none. Testing real Open Banking sandboxes (Basiq, if it is still available, or others) is optional, needs written permission, and should be limited to confirming that a topology class exists. Do not test production. Report vendor findings through coordinated disclosure, and report CVE IDs only once assigned.

**Reproducibility.** Release a Docker Compose matrix with pinned versions, the primitive corpus, the oracle wrappers and the analysis scripts. This extends the reproducibility practice you already have (`make verify-manuscript`).

---

## 8. Proposed contributions (introduction-ready; each depends on completed work)

1. **Binding soundness.** We define binding soundness for sender-constrained API requests. It is a property relating what a DPoP proof, mTLS binding or request signature authenticates to what the backend executes. We identify three ways it fails: under-binding, interpretation differentials and binding propagation.
2. **Measurement.** We measure under-binding across *N* public API descriptions and *M* web frameworks. We quantify how often a single accepted proof can correspond to more than one executed operation. *(Numbers to be filled from E1/E2.)*
3. **Differential testing.** We build a differential harness whose oracle is proof acceptance rather than parsing disagreement. With it we evaluate *K* gateway × verifier-placement × framework topologies and report the vulnerable classes found and disclosed. *(Contingent on E3–E6.)*
4. **Defence and data for the standards debate.** We design and evaluate verifier-to-executor canonical binding, against origin-only verification and HTTP request synchronization, reporting security, overhead and false rejection. We also provide the first data on what DPoP's `htm`/`htu` claims protect, for the standards discussion about making them optional. *(Contingent on E7–E9.)*

### Paper outline (12 pages)
| Section | Pages | Must establish |
|---|---|---|
| 1 Introduction | 1.25 | The binding-locus insight, the htm/htu-optional debate, contributions |
| 2 Background | 1.0 | DPoP, mTLS, RFC 9421, layered verification topologies |
| 3 Binding soundness and threat model | 1.5 | Formal property, G1/G2/G3, A_leak and A_client, scope |
| 4 Under-binding by design (E1, E2, E9) | 1.5 | Prevalence data |
| 5 Differential harness and results (E3–E6) | 2.5 | Oracle design, matrix, findings, case studies, disclosure |
| 6 Defence (E7, E8, optional E10) | 1.75 | Design, security, overhead, false rejection, baselines |
| 7 Discussion | 1.0 | Standards recommendations (keep htm/htu; add an executor-view contract), Open Banking, FHIR and MCP implications, limitations |
| 8 Related work | 1.0 | Proxy differentials, formal FAPI, RS testing, JWT differentials |
| 9 Conclusion | 0.5 | |
| Appendices | — | Primitive corpus, full matrix, Tamarin model, ethics |

### Reviewer objections
1. **"This is WAFFLED/HDHunter applied to DPoP."**
   - *Valid?* Partly. The primitives are borrowed.
   - *Address:* make the oracle, the formal property and G1/G3 central. G1 and G3 involve no parsing bug at all. State explicitly what is reused.
2. **"RFC 9449 already says DPoP does not protect the query or body, so G1 is known."**
   - *Valid.* The fact is known.
   - *Address:* claim consequence and prevalence (E1, E2, E9), not discovery. Show concrete operation-swaps in realistic finance and health APIs.
3. **"A_leak is weak: a leaked proof plus token within seconds is an unrealistic capability."**
   - *Valid in part.*
   - *Address:* anchor A_leak in the FAPI 2.0 Attacker Model's leakage assumptions, if they apply (verify this). Lead with A_client, the legitimate malicious client, which needs no leak.
4. **"These are misconfigurations and vendor bugs, not a fundamental issue."**
   - *Valid unless shown otherwise.*
   - *Address:* show the failures in *default or documented* configs across several independent products, and explain the shared cause (no executor-view contract in any specification).
5. **"Docker testbeds are not real deployments."**
   - *Valid.*
   - *Address:* evaluate real, unmodified gateway and framework releases, show how common they are in real deployments, and add permitted sandbox confirmations where possible.
6. **"HTTP Request Synchronization already solves G2."**
   - *Possibly valid.*
   - *Address:* E8 baseline. If it does, reposition the defence on G1 and G3, and report the result honestly.
7. **"The formal analysis already covers intermediaries."**
   - *Unknown.*
   - *Address:* read ePrint 2024/1540 in week 1. If it does, drop H5 and cite it as support.

---

## 9. Critical reviewer assessment (as a skeptical ASIA CCS reviewer)

1. **Most important insight.** Sender-constraint guarantees are a property of the verification point, not of the request the backend runs. Layered deployments break that equivalence in measurable ways.
2. **Why the community needs it.** FAPI 2.0 and DPoP are being mandated (FAPI 2.0 Final in Feb 2025; MCP is adopting DPoP). The IETF is debating weakening htm/htu, without data either way.
3. **Closest work.** WAFFLED (structure), HDHunter and Gudifu (method), Hosseyni et al. CSF'24 (formal guarantee), HTTP Request Synchronization (defence).
4. **Technical difference.** The oracle is cryptographic-binding acceptance. The property is formal. Under-binding by design and binding propagation involve no parser bug.
5. **Rejected as a conventional audit?** Not if the paper leads with the property and the cross-product matrix. It would be if it leads with vendor CVEs.
6. **Rejected as a minor DPoP extension?** That is a real risk if the G2 results are thin and the paper rests on G1, which is known by design.
7. **Enough evidence?** It depends on E3. The idea is untested at present, and nothing in this document is a result.
8. **Generalisable?** Yes, if the matrix spans at least 5 gateways and at least 6 frameworks and includes signatures.
9. **Significant enough?** Yes with at least several independent vulnerable topology classes plus the defence. No with one or two vendor bugs.
10. **Most likely rejection reason.** "Known primitives applied to a new header; the findings are configuration-dependent; the impact on the leaked-proof attacker is bounded."

**Honest preliminary assessment.** This is a credible ASIA CCS direction with a real gap and a live standards hook. Its acceptance hinges entirely on E3 and E4 producing several independent, default-configuration violations. I am not assigning a probability; there is no basis for one.

---

## 10. Feasibility and execution roadmap (independent researcher)

**Deadline check first (UNVERIFIED).** ASIA CCS has historically used more than one submission cycle, but I have not verified the 2027 dates. Today is 2026-11-22. If the last 2027 deadline falls before about March 2027, a rigorous version is not realistic for that cycle. Plan to target the cycle after it, or an equivalent venue such as ACSAC, EuroS&P or RAID, instead of rushing. Check the official CFP this week.

| When | Work | Exit criterion |
|---|---|---|
| **Week 1** | Novelty kill-reads, in this order:<br>• ePrint 2024/1540 and 2024/078: is the RS a single endpoint, and is there any intermediary or normalisation?<br>• FAPI 2.0 Attacker Model: leaked resource requests?<br>• arXiv 2510.09952 (does Request Synchronization cover DPoP?)<br>• WAFFLED (venue; any token or signature content)<br>• arXiv 2607.08906 and 2607.01711<br>• JWTeemo (any DPoP?)<br>• The Allam thread and its replies<br>• Searches: dblp and Scholar for "DPoP" and "proof-of-possession" for 2025–26; OAuth WG archive; CCS/NDSS 2026 accepted lists | Kill if a paper already measures proof acceptance against executed routes |
| **Week 2** | Choose RS verifiers and gateways. Confirm which have native DPoP. Write the oracle wrappers. Re-target your zt-controller as the "edge verifier" component | Matrix defined, with pinned versions |
| **Weeks 2–3: the kill experiment** | 3 gateways (Envoy ext_authz, Traefik ForwardAuth, NGINX auth_request) × 4 frameworks (Spring, Express, FastAPI, ASP.NET) × about 40 primitives, edge verification, oracle on. In parallel, E2 (method-override survey) | **Go** if at least 2 independent topology classes show resolution > 1 on current versions, *or* G1 is reachable in default or common configs of at least 2 major frameworks |
| **Week 4: abandonment point** | If there are zero divergences and G1 is trivial: stop D1. Pivot to D2 + D3 (RS-Diff with conformance mutation analysis), reusing the same harness | Decision recorded |
| Weeks 5–8 | Full matrix (E3–E6), E1 corpus, disclosure to vendors | Findings stable and disclosed |
| Weeks 9–11 | Defence and baselines (E7–E9); optional Tamarin (E10) | Overhead and false rejection measured |
| Weeks 12–14 | Write, artefact packaging, internal review | Submission-ready |

**Minimum viable prototype.**
- One gateway with ext_authz calling your DPoP verifier.
- One backend framework with a router hook logging x(r).
- 10 primitives, including method override.
- The oracle.

That is buildable in days from the existing repository.

**Evidence needed before committing to the full paper:**
- At least 2 independent G2 or G3 violation classes on current releases, *or* strong G1 prevalence plus at least 1 G2 class.
- Confirmation that the formal model has no intermediary, or that the paper does not depend on it.

---

## 11. Go/no-go recommendation

**Conditional GO on Direction 1**, gated by the week-1 reading and the weeks 2–3 kill experiment. Fallback: D2 + D3 on the same harness. **NO-GO** on extending the Zero Trust / risk-scoring line, on adding Open Banking providers, and on D9 and D10 as stand-alone papers.

### Final answer

*If I were an independent researcher trying to turn this work into a competitive ASIA CCS 2027 paper:* I would pursue **Proof ≠ Execution: binding soundness of sender-constrained requests in layered API deployments.**

**Why this direction:**
- It is the one direction where the novelty survives comparison with the closest work. The differential-HTTP literature has never used proof acceptance as its oracle. The FAPI formal proofs assume the verifier sees the executed request.
- It generalises your three Basiq findings into a single property instead of three bugs.
- It reuses the testbed you already built.
- It answers a live 2026 IETF question (should htm/htu become optional?) that currently has no data.

**First experiment (two to three weeks).** Put your DPoP verifier at the edge behind Envoy ext_authz, Traefik ForwardAuth and NGINX auth_request. Put Spring, Express, FastAPI and ASP.NET backends behind them, and instrument each router to log the operation it actually executes. Replay one valid (token, proof) pair with about 40 mutations:
- method-override headers and `_method`;
- query-dispatched actions;
- dot-segment, encoded-slash, matrix-parameter and absolute-form paths;
- strip-prefix rewrites.

Count how often an accepted proof maps to more than one executed operation. If no current topology yields a divergence and method override is unreachable in common configs, abandon the direction at week 4 and fall back to RS-Diff with conformance mutation analysis.

Before even that, spend one day reading ePrint 2024/1540 to confirm that the FAPI 2.0 model has no rewriting intermediary.

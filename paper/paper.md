# What Does Continuous Zero Trust Add Over FAPI 2.0? An Empirical Measurement of Context-Bound Enforcement for Open Banking APIs Against Device-Resident and Account-Takeover Adversaries

*(Shorter alternative title: "Beyond Proof-of-Possession: Measuring Context-Bound Zero Trust Enforcement for Open Banking APIs.")*

**Status of this version (V2).** Every `[FILL]` placeholder in V1 has been replaced with a measured value. Every number in §7, §9 and §12 is reproduced by the released pipeline and traces to a named file under `data/tables/` or `data/figures/`; the file is cited inline at first use. No results are invented, and results that contradict the pre-registered expectation — there are two, in §7.1 and §7.2 — are reported as they came out. The five `[VERIFY]` comparator citations in V1 have been checked against their sources and are now full references in §References; one of them had the wrong venue in V1 and is corrected there.

---

## Abstract

Open Banking APIs increasingly adopt the FAPI 2.0 security profile, which mandates sender-constrained access tokens via DPoP or mTLS and thereby neutralizes network-level token replay and theft of tokens without the associated key. This raises a question that, to our knowledge, has not been answered with measurement: once a deployment is already FAPI 2.0-correct, what does an additional layer of continuous, context-bound Zero Trust enforcement actually buy, and at what cost? We build a reproducible, fully synthetic Open Banking testbed — a Basiq-isomorphic Accredited Data Recipient API, a Keycloak identity provider configured to the FAPI 2.0 DPoP profile, and a Zero Trust controller that performs per-request device-binding, telemetry, rule-based risk scoring, and adaptive `ALLOW`/`CHALLENGE`/`DENY` decisions — and we evaluate three configurations under an identical attacker suite: a weak bearer-token baseline (B0), a standards-correct FAPI 2.0/DPoP baseline (B1), and the proposed continuous-enforcement system (P). Crucially, our attacker taxonomy includes adversaries that DPoP alone does not stop: device-resident key abuse and account takeover from a newly enrolled device.

We find that for network replay and token-theft-without-key, B1 already blocks 100% of attacks (A1 and A2 both 0/30 successful, risk difference −1.00 versus B0) and P adds no measurable security benefit. For the adversaries that motivate a contextual layer the picture is mixed and, in one case, negative. Against account takeover from a new device, B1 blocks nothing (30/30 successful) while P reduces the adversary to 11/30, a risk difference of −0.633 (95% CI [−0.806, −0.461], odds ratio 0.010); but against device-resident key abuse — the case we designated as the crux — P blocks nothing at all (30/30 successful, identical to B1), because the only signal that distinguishes it is a call-rate rule priced below the challenge threshold. The cost is a median +6.2 ms and p99 +27.6 ms per request (Cliff's δ = 0.58, large), dominated by the policy-engine round trip (9.39 ms of P's 17.09 ms mean) rather than cryptography (DPoP verification: 0.19 ms), together with +11.5 percentage points of controller CPU and +5.0 MiB of memory, and a false-deny rate on legitimate traffic of 7.4% overall — 3.8% under stable context and 97.3% under context drift.

An ablation attributes the entire A4 gain to the conjunction of device-binding and contextual signals — neither alone reduces A4 below 0.967 — and attributes 100% of the usability cost to the geo-velocity rule in the contextual group, which contributes almost none of the detection on its own. A threshold sweep over the recorded risk scores shows the operating point is badly chosen rather than the signals being absent: lowering the challenge threshold from 0.40 to 0.30 would block 100% of A4 at no additional false-deny cost, while catching device-resident abuse would require a threshold at which essentially all legitimate traffic is refused. We release the testbed, attack suite, and analysis pipeline to support replication. Our contribution is not a new mechanism but a measured characterization of the security/cost boundary of continuous Zero Trust enforcement over a modern financial-API baseline — including where that boundary falls short of its own design intent.

**Keywords:** Open Banking, FAPI 2.0, DPoP, Zero Trust, continuous authorization, session hijacking, account takeover, empirical security evaluation.

---

## 1. Introduction

Open Banking has expanded rapidly under regulatory mandates such as the EU's PSD2 [1] and Australia's Consumer Data Right [2], exposing consumer-permissioned financial data through standardized APIs and correspondingly enlarging the attack surface across heterogeneous devices, networks, and third parties. A recurring concern in both formal and empirical literature is that session-level and token-level compromise — session hijacking, token replay, and account takeover — remain viable even where strong cryptography is deployed [17, 18, 19, 20].

The industry response has consolidated around the Financial-grade API (FAPI) 2.0 Security Profile, which mandates Pushed Authorization Requests, PKCE for all clients, and sender-constrained access tokens via either mTLS (RFC 8705) or DPoP (RFC 9449). The FAPI 2.0 Security Profile and Attacker Model reached Final status in February 2025 following an OpenID Foundation membership vote (82 approve, 0 object, 14 abstain) [23]. Sender-constraining is significant: by binding a token to a client-held key and requiring a fresh proof-of-possession on each call, it renders a stolen bearer token unusable to any party lacking the private key. This directly defeats the classic network-interception and browser-storage-exfiltration attacks that motivate much prior work. Commodity identity infrastructure now supports this natively — Keycloak 26.4 promoted DPoP from a preview feature to full support and ships dedicated `fapi-2-dpop-security-profile` client policy profiles that pass the FAPI 2.0 conformance suite [24]; that release is the identity provider our testbed uses.

This creates a subtle and, we argue, unresolved research question. Much of the security benefit attributed to "Zero Trust for Open Banking" in recent architectural proposals is, in fact, already delivered by a correctly configured FAPI 2.0 baseline. The genuinely open question is what a further layer of continuous, context-bound Zero Trust enforcement — per-request telemetry, device-binding beyond token possession, risk scoring, and adaptive challenge/deny — contributes on top of that baseline, and what it costs. This matters precisely for the adversaries that proof-of-possession does not stop: an attacker operating on the legitimate device (and therefore able to produce valid DPoP proofs), and an attacker who takes over an account and enrolls or uses their own device. For these, cryptographic sender-constraining is silent, and only behavioral/contextual enforcement can respond.

Existing work does not answer this question with measurement. Formal analyses establish protocol-level guarantees and attacks but do not quantify runtime enforcement trade-offs [17, 18, 19]. Empirical studies of anomalous API behavior demonstrate that behavioral signals discriminate compromised sessions [20] but are not integrated with, or measured against, a sender-constrained baseline. Recent architectural proposals for Zero Trust in banking API gateways are explicitly conceptual, presenting PDP/PEP/PIP components and standards mappings with a methodology of "literature review, component identification, architectural modelling, standards-based evaluation, and recommendation development" and no implementation or evaluation [25]. Game-theoretic Zero Trust authentication frameworks derive belief-threshold policies analytically [22, 26] but in other domains and without a financial-API measurement. What is missing is a controlled, reproducible measurement of the security benefit and operational cost of continuous Zero Trust enforcement relative to a FAPI 2.0-correct baseline.

**Research questions.**

- **RQ1.** Against a standards-correct FAPI 2.0/DPoP baseline, which classes of Open Banking attacks remain feasible, and which of these does a continuous context-bound enforcement layer detect or prevent?
- **RQ2.** What per-request latency, throughput, and resource overhead does continuous enforcement impose relative to (a) plain bearer OAuth and (b) FAPI 2.0/DPoP, across increasing load?
- **RQ3.** Which enforcement components (device-binding, contextual risk, velocity) are responsible for the security gains, and which drive the cost and the false-challenge rate?

**Hypotheses.** H1: B1 already neutralizes network- and theft-based token attacks (A1, A2). H2: B1 is vulnerable to device-resident and ATO-class adversaries (A3, A4) and P reduces them. H3: the added per-request cost is dominated by policy/telemetry rather than cryptography. H4: the ablation attributes the security gain and the false-challenge cost to identifiable components.

**Approach.** We implement a fully synthetic testbed comprising a Basiq-isomorphic ADR API, a Keycloak IdP configured to the FAPI 2.0 DPoP profile, and a Zero Trust controller, and we evaluate three configurations (B0, B1, P) under an identical, executable attacker suite that explicitly includes device-resident and ATO-class adversaries, plus a legitimate workload with context drift to measure false challenges.

**Contributions.**

1. An executable attacker taxonomy for Open Banking session/token/ATO threats, mapped to what DPoP does and does not mitigate, making explicit the regime where a contextual layer is the only remaining defense (§4, §6).
2. A reproducible testbed and measurement of the security benefit and operational cost of continuous Zero Trust enforcement over a FAPI 2.0/DPoP baseline (§5, §7), released as open artifacts.
3. An ablation attributing the security gains and the false-challenge cost to specific enforcement components (§7.4), turning "we combined mechanisms" into a quantified statement of what the combination buys — and, here, of what it fails to buy.
4. A measurement-integrity discipline for this class of testbed (§6.1), and a threshold-sensitivity analysis (§7.6) that separates "the contextual signal is absent" from "the signal is present but mis-priced" — a distinction our own results turn on.

We deliberately do not claim a new cryptographic primitive, a new protocol, or a new equilibrium concept; the mechanisms are standard, and our contribution is the measured characterization of their combination.

---

## 2. Background

*(Compressed relative to V0 — keeping only what the measurement needs.)*

**2.1 Sender-constrained tokens and DPoP.** DPoP (RFC 9449) binds an access token to a client-held key by embedding the JWK SHA-256 thumbprint in the token's `cnf.jkt` confirmation claim; on each request the client presents a signed DPoP proof JWT carrying `htm`, `htu`, `iat`, `jti`, and `ath`, which the resource server verifies against the bound thumbprint and for freshness/replay. This yields sender-constraining without the PKI overhead of mTLS, making it suitable for public clients (SPAs, mobile). (Correcting the V0 error: the confirmation is `cnf.jkt` — a thumbprint — not `cnf.jwk`.)

**2.2 FAPI 2.0.** The FAPI 2.0 Security Profile composes PAR, PKCE (S256), sender-constrained tokens (mTLS or DPoP), short-lived tokens, and refresh rotation, and has been subject to formal security analysis [18]. It is the appropriate baseline for any modern Open Banking security claim; comparing a proposed system only against plain bearer OAuth overstates novelty.

**2.3 Zero Trust Architecture.** NIST SP 800-207 [9, 10] frames Zero Trust around per-request verification and continuous, context-aware policy via a Policy Decision Point / Policy Enforcement Point / Policy Information Point decomposition. Applied to APIs, the salient shift is from session-established trust to request-level, continuously re-evaluated trust. One consequence of that shift is under-discussed and turns out to matter here: continuous re-evaluation requires *continuity of identity* across requests, which means the state it accumulates must be keyed on something the client cannot choose (§5.3, §9.4).

**2.4 Cryptographic primitives.** We use standard ECC (ES256) for signatures; the security of sender-constraining rests on the unforgeability of these signatures. ECC is an enabling choice, not a contribution. (The V0 AES/Argon2/PQC material is not load-bearing for the measurement and has been cut.)

---

## 3. Related Work

**3.1 Formal analyses of Open Banking protocols.** Fett et al. [17] give the first extensive formal analysis of FAPI, uncovering session-integrity and authorization attacks that persist under partial or incorrect composition of PKCE, token binding, and mTLS. Hosseyni et al. [18] extend this to FAPI 2.0 under a stronger attacker (malicious browsers, network adversaries, leaked TLS-protected messages), motivating sender-constrained tokens. Modesti et al. [19] formally analyze the UK Open Banking Account and Transaction API under unbounded parallel sessions, exposing session-isolation and authorization weaknesses. These works establish protocol-level guarantees and attacks; they do not measure runtime enforcement trade-offs, which is our focus.

**3.2 Empirical and behavioral analyses.** Behbehani et al. [20] show that behavioral features (request frequency, connection duration, repeated access) discriminate anomalous Open Banking API access, implicitly supporting continuous trust evaluation. Wilson and Tam [21] survey Open Banking security across technological, regulatory, and behavioral dimensions. Neither integrates behavioral enforcement with a sender-constrained baseline or quantifies the marginal benefit — the gap we address. Our §7.1 result is a partial negative for this line of work as applied at the enforcement layer: a call-rate feature that discriminates in an offline classifier does not, at the thresholds a deployment would plausibly ship, change an online decision.

**3.3 Game-theoretic and threshold-policy Zero Trust.** Ge and Zhu [22] (GAZETA) model Zero Trust authentication as a Markov game with one-sided incomplete information, continuously updating a trust score and deriving policies from equilibrium analysis. Ge, Li and Zhu [26] derive an explainable belief-threshold defense policy for scenario-agnostic zero-trust defense as a POMDP with meta-learned adaptation, targeting compromised-account detection. We note explicitly that belief-threshold structures for Zero Trust are established results; accordingly we do not claim a novel equilibrium concept, and we position any analytical model in this paper as a supporting, calibrated interpretation of measured behavior rather than a contribution (see Appendix A). Our §7.6 threshold sweep is the empirical counterpart to that literature's analytical thresholds, and it shows that on this workload the threshold's placement, not its existence, is what determines whether the defense works.

**3.4 Architectural Zero Trust for banking APIs.** Sitorus and Hutagaol [25] design a Zero Trust API-gateway architecture for digital banking using a PDP/PEP/PIP decomposition and standards mappings; the paper is explicitly conceptual, with no implementation or empirical evaluation. Daah et al. [27] evaluate Zero Trust with blockchain-anchored identity for financial-industry networks via OMNeT++ simulation. These are, respectively, conceptual and simulation-oriented; our contribution is an implemented, attacked, and measured comparison isolating the delta over FAPI 2.0.

**3.5 Synthesis and gap.** The literature establishes (i) formal protocol guarantees and attacks, (ii) that behavioral signals discriminate compromise, and (iii) analytical belief-threshold policies. What remains unmeasured is the security benefit and operational cost of continuous, context-bound enforcement relative to a FAPI 2.0-correct baseline, particularly for adversaries that sender-constraining does not stop. This is an evaluation/measurement gap, and it is the gap this paper fills.

**Gap matrix.**

| Work | Problem | Method | Mechanism | Evaluation | Gap vs. ours |
|---|---|---|---|---|---|
| Fett [17]; Hosseyni [18] | FAPI(2.0) integrity | Formal | PKCE/mTLS/DPoP | Proofs/attacks | No runtime cost/benefit measurement |
| Modesti [19] | UK OB API | Formal | Session isolation | Unbounded sessions | No enforcement measurement |
| Behbehani [20] | Anomalous access | ML | Behavioral | Empirical | Not vs. sender-constrained baseline |
| GAZETA [22]; Ge/Li/Zhu [26] | Stolen creds / ATO | Game / POMDP | Belief threshold | Equilibrium / meta-learning | Other domain; not measured on a financial API |
| Sitorus & Hutagaol [25] | Banking API gateway | Conceptual | PDP/PEP/PIP | None | Not implemented / attacked / measured |
| Daah et al. [27] | Financial ZT | Simulation | ZT + detection | OMNeT++ simulation | Not isolating the delta over FAPI 2.0 |
| **This work** | **Delta over FAPI 2.0** | **Implemented + attacked + measured** | **DPoP + context** | **B0/B1/P + ablation + threshold sweep** | — |

---

## 4. Threat Model

We consider an adversary seeking unauthorized access to protected Open Banking resources via session/token compromise. We make the standard cryptographic assumption that ECDSA and JWT signatures are unforgeable, and that protocol checks are correctly enforced.

**Adversary capabilities considered.** The adversary may intercept and manipulate network traffic; obtain access tokens via interception or client-side exfiltration; replay captured requests; and, critically, operate on the legitimate device (able to invoke the device key) or take over an account and use a different device. We distinguish these because sender-constraining defeats the first group but is silent on the last two.

**Adversary control over request metadata.** We assume the adversary controls every value they send, including any self-reported device identifier, fingerprint, geo tag or session id. This assumption is load-bearing for the design in §5.3 and for the validity of the measurement in §6.1, and it is the assumption a testbed of this kind most easily violates by accident.

**Explicitly in scope** (unlike the V0 draft). Device-resident key abuse and account takeover from a new device are in scope, because they are the only regime in which a contextual enforcement layer can beat a FAPI 2.0 baseline. Scoping them out would eliminate the paper's measurable delta.

**Out of scope.** Kernel-level malware that silently exfiltrates the private key to an arbitrary remote host is out of scope (though behavioral detection may partially mitigate); we do not claim to defend a fully compromised OS. Attacks on the IdP or on the cryptographic primitives themselves are out of scope.

**Adversary–defense map** (as designed; §7.1 reports which parts held):

| Adversary | Capability | Stopped by B1 (FAPI 2.0)? | Intended role of P (context) |
|---|---|---|---|
| Network/MITM replay | Resend captured request | Yes (`jti`/`iat`) | Redundant |
| Token theft w/o key | Token, not key | Yes (`cnf.jkt` mismatch) | Redundant |
| Device-resident abuse | Can sign on device | No | Primary defense (telemetry/velocity/risk) |
| ATO, new device | Valid creds, own device | No | Device/geo/velocity mismatch → CHALLENGE/DENY |
| BOLA/BFLA | Access others' objects | Partial (object checks) | Consent-scope + object-level policy |
| Velocity/consent abuse | High volume / out-of-scope | No | Rate/consent rules |

---

## 5. System Under Test

We evaluate three configurations sharing one codebase, selected by configuration (not separate systems), so differences are attributable to the enforcement layer rather than implementation variance.

**5.1 B0 — Weak baseline.** Plain OAuth 2.0 bearer tokens, no sender-constraining, no contextual policy. Included only as a reference point.

**5.2 B1 — FAPI 2.0-correct baseline (the real comparator).** Keycloak configured to the FAPI 2.0 DPoP client profile: PAR, PKCE (S256), DPoP sender-constrained tokens (`cnf.jkt`), short-lived access tokens (300 s), refresh rotation. The controller performs standard token and DPoP verification (JWS signature against the realm JWKS, issuer and expiry, thumbprint match against `cnf.jkt`, `htm`/`htu`, `iat` skew within ±60 s, `jti` replay cache, `ath`) and proxies approved requests. No telemetry, risk, or adaptive policy.

**5.3 P — Proposed continuous enforcement.** B1 plus, on every request: telemetry collection, per-subject device-key registry, deterministic rule-based risk scoring yielding a legitimacy belief `b ∈ [0,1]` (`risk = 1 − b`), and an OPA-evaluated adaptive decision — `ALLOW` if `risk < τ_allow`, `CHALLENGE` if `τ_allow ≤ risk < τ_deny`, `DENY` if `risk ≥ τ_deny`, with the shipped operating point `τ_allow = 0.40`, `τ_deny = 0.70`. Risk scoring is rule-based, not learned, to keep decisions auditable and deterministic. The rules, grouped by the component they belong to (the grouping is what makes §7.4 interpretable):

| Rule | Signal | Penalty | Component |
|---|---|---|---|
| R1 | DPoP key does not match the token's `cnf.jkt` | 0.80 | device-binding |
| R2 | Subject presenting a device key/fingerprint it has not used before | 0.35 | device-binding |
| R3 | Geo velocity above 500 km/h | 0.60 | context (telemetry PIP) |
| R4 | Call rate above 30 req/min | 0.25 | velocity |
| R5 | Session continuity below 0.50 | 0.20 | context (telemetry PIP) |
| R6 | DPoP failure rate above 0.10 | 0.20 | context (telemetry PIP) |

Penalties are additive and capped at 1.0.

**Keying of continuous-trust state.** All state the controller accumulates about a subject — sliding-window call rate, last-seen geography, session continuity, DPoP-failure history, and the set of device keys the subject has used — is keyed on the `sub` claim of the access token verified in stage 1, and device identity is taken from the token's `cnf.jkt` thumbprint. Neither is client-choosable. This is not an implementation detail. Under the §4 assumption that the adversary controls every value they send, keying continuous-trust state on a self-reported `x-device-id` header gives every adversary an empty history by construction, and no behavioral rule can fire against an adversary who simply invents a device identifier. The same reasoning forces the enrollment policy: the first key observed for a subject establishes the baseline, and later unknown keys are reported without being auto-enrolled, because auto-enrolling would make the adversary's key "known" after one request and only the first request of a new-device attack would ever score as anomalous. We record this because it is the difference between a contextual layer that can be evaded for free and one that cannot, and because it is easy to get wrong in a way that no test detects.

**5.4 Components.** User device (EC P-256 keypair, DPoP proof signing); Keycloak IdP (token issuance, `cnf.jkt` binding); Zero Trust controller (PEP+PDP: token verification, DPoP verification, telemetry, device registry, risk, OPA policy, reverse proxy); OPA policy engine (`zt.rego`); mock Basiq-isomorphic ADR resource server (`/users`, `/accounts`, `/transactions`, `/consents`, with per-object ownership to make BOLA/BFLA testable). Figure `data/figures/fig3_latency.png` (right panel) shows the realised per-stage decomposition of this pipeline and replaces V0's broken `Figure ??` references.

**5.5 Enforcement invariant.** Across B1 and P, possession of an access token alone is never sufficient: a valid DPoP proof bound to the token's `cnf.jkt` is required. P additionally requires the request to pass contextual risk evaluation. This invariant is what the attacks in §6 probe.

---

## 6. Attack Suite (methodology)

We implement six executable attacks, each run against B0/B1/P with fixed seeds and repeated 30 times per cell. Success = the adversary obtains protected data or performs the unauthorized action, judged by the resource server returning data (HTTP 200), not by the controller's decision alone. For each we log attempts, successes, the stage at which blocking occurred, detection, and time-to-detect.

- **A1 Network replay** — capture a valid request and resend it verbatim. The captured request is by definition one the victim already sent, so the harness issues the original once (uncounted) before replaying, and every counted attempt is a true replay. (Probes redundancy of P; expect B1 sufficient.)
- **A2 Token theft without key** — use a stolen token from a fresh context lacking the device key. (Expect B1 sufficient via `cnf.jkt` mismatch.)
- **A3 Device-resident key abuse** — operate on the legitimate device with valid DPoP proofs but anomalous behavior: a burst across a mix of the victim's own endpoints, with no sleep. (The crux: expect B1 insufficient, P responds.)
- **A4 ATO from a new device** — the adversary holds the victim's credentials and runs the token flow themselves, so Keycloak issues them a genuine access token whose `cnf.jkt` is *their own* key's thumbprint. Every FAPI 2.0 check passes on its own terms; only the device's novelty to this subject, and its geography, distinguish it. (Expect B1 insufficient for authenticated misuse, P responds.)
- **A5 BOLA/BFLA** — authenticated access to another user's account object and its transaction collection. The victim object is a real account belonging to a different synthetic user, derived from the documented generator seed, so a refusal is an ownership decision rather than a 404. (Measures object/consent-level enforcement.)
- **A6 Velocity/consent abuse** — abnormal volume from a valid session on a valid key. (Expect only P throttles/denies.)

We additionally run a legitimate workload with context drift (5% of requests carry a changed geography and source network, simulating travel or a mobile handover) to measure P's false-challenge and false-deny rates, so the security benefit is reported against its usability cost.

### 6.1 Measurement integrity: what the attacker is and is not allowed to tell the defender

A testbed in which the attack harness and the defense share a process is trivially able to leak ground truth from one to the other, and the leak is not always visible in the results — it looks like detection. We therefore state the rule we hold the suite to: **no enforcement decision may read a value that exists only because the harness knows the request is an attack.** Two consequences are worth recording, because in both cases an earlier version of this testbed violated the rule and produced a substantially better-looking result.

*The attack-context oracle.* The risk engine contains a rule (R7) that scores any request carrying an `x-attack-context: true` header at 0.90 — nearly the deny threshold on its own. Four of the six attacks set that header on every request. P's apparent blocking of those attacks was therefore, in large part, the attack simulator telling the risk engine that it was an attack. The tell was A6, the one attack that deliberately did not set the header: it succeeded on 100% of attempts in P while the self-tagging attacks were fully blocked. In the results reported here the header is never sent and R7 is disabled; it is retained behind an explicit `--oracle-tag` switch and reported separately in §7.1 as a **detection ceiling** — what this enforcement pipeline would block given a perfect detector — because that ceiling is a genuinely useful quantity as long as it is never confused with detection. `data/tables/table7_risk_components.csv` reports which rules fired in each population and is the standing check on this: the `attack_context` column reads 0.0 on every primary row.

*Scenario fidelity.* Three further defects would each have inflated the defense's apparent performance, and we name them because they are the kind of thing a reader cannot check from a results table. A4 originally replayed the *victim's* token while signing with a different key — a `cnf.jkt` mismatch, and thus a second copy of A2 — which made B1 appear to stop the attack that exists precisely because B1 cannot. A5 targeted an object identifier no synthetic account carried, so every attempt returned "not found" and was scored as blocked without an ownership check ever running. A3 drove half its traffic at a nonexistent account for the same reason. All three are corrected here; A4's correction changes B1's A4 success rate from 0.000 to 1.000, which is the value the design predicts.

*Per-attack isolation.* The controller's continuous-trust state is reset before each attack, and a short legitimate warm-up (10 requests from the victim's enrolled device) then establishes the subject's baseline. Both halves are necessary: without the reset, A6's call-rate signal inherits A3's burst and A4's device signal inherits A2's foreign key; without the warm-up there is no baseline for a new device or a new geography to be inconsistent with, and a new-device adversary is indistinguishable from a first-time legitimate user. Warm-up requests are labelled and excluded from every reported rate.

---

## 7. Results

All numbers below are produced by the released pipeline (`make attacks && make experiments && make scaling && make attacks-oracle && make ablation && make analysis`) and are cited to the file that contains them.

### 7.1 Attack outcomes (RQ1)

**Table 1 — attack success rate by configuration (Wilson 95% CIs, n = 30 attempts per cell).** Source: `data/tables/table1_taxonomy.csv`; plotted in `data/figures/fig2_attack_success_rate.png`.

| Attack | B0 | B1 | P | Stopped by B1? | P adds value? |
|---|---|---|---|---|---|
| A1 Network token replay | 1.000 [0.886, 1.000] | 0.000 [0.000, 0.114] | 0.000 [0.000, 0.114] | Yes | No |
| A2 Token theft without key | 1.000 [0.886, 1.000] | 0.000 [0.000, 0.114] | 0.000 [0.000, 0.114] | Yes | No |
| A3 Device-resident key abuse | 1.000 [0.886, 1.000] | 1.000 [0.886, 1.000] | **1.000 [0.886, 1.000]** | No | **No** |
| A4 ATO from new device | 1.000 [0.886, 1.000] | 1.000 [0.886, 1.000] | **0.367 [0.219, 0.545]** | No | **Yes** |
| A5 BOLA/BFLA | 0.000 [0.000, 0.114] | 0.000 [0.000, 0.114] | 0.000 [0.000, 0.114] | Yes | No |
| A6 Velocity/consent abuse | 1.000 [0.886, 1.000] | 1.000 [0.886, 1.000] | **1.000 [0.886, 1.000]** | No | **No** |

**Effect sizes** (`data/tables/table_effect_sizes.csv`). B1 versus B0: risk difference −1.000 (95% CI [−1.000, −1.000], OR 0.0003) for both A1 and A2; −0.333 ([−0.424, −0.242], OR 0.203) pooled across A1–A6. P versus B1: risk difference −0.633 ([−0.806, −0.461], OR 0.010) for A4; 0.000 for every other attack; −0.106 ([−0.208, −0.003], OR 0.653) pooled.

**H1 held.** Sender-constraining alone reduces network replay and token-theft-without-key from certainty to zero. The `jti` replay cache blocks A1 at DPoP verification and the `cnf.jkt` thumbprint comparison blocks A2 at the same stage; neither attack ever reaches the risk engine, which is why both read 0.0 across every rule in `data/tables/table7_risk_components.csv`. P adds nothing here, exactly as designed, and a deployment that is already FAPI 2.0-correct should not expect a contextual layer to help against these adversaries.

**H2 held for A4 and failed for A3.** This is the paper's central result and it is half a negative one.

Against account takeover from a new device, B1 is defenseless — 30 of 30 attempts succeed, because the attacker's token is genuinely issued to the attacker's own key and every FAPI 2.0 check passes on its own terms — while P reduces the adversary to 11 of 30. `data/tables/table7_risk_components.csv` shows why: across A4's requests the unknown-device rule fires on 100%, session continuity on 33.3%, geo velocity on 3.3% and call rate on 30.0%, for a mean risk of 0.507 against a deny threshold of 0.70 and a challenge threshold of 0.40. The self-declared attack tag fires on 0%. This is organic detection from evidence the adversary cannot suppress without abandoning the attack.

Against device-resident key abuse, P blocks nothing: 30 of 30, identical to B1 and to B0. We had designated A3 the crux attack, and the contextual layer does not touch it. The reason is visible in the same table: the only rule that fires on A3 is the call rate, on 30.0% of its requests, contributing 0.25 — and 0.25 is below the 0.40 challenge threshold, so a request that trips the velocity rule and nothing else is allowed. A6 fails for exactly the same reason and with the same 0.075 mean risk. At the shipped operating point the velocity rule cannot, on its own, change any decision; it can only reinforce another rule. §7.6 quantifies what changing that would cost.

A5 is refused in all three configurations, including B0, because object-level ownership is enforced at the resource server and not by the enforcement layer under test. It is reported for completeness; it does not discriminate between configurations and should not be read as evidence for any of them.

**Detection ceiling (secondary measurement).** Re-running the identical suite with the oracle tag enabled — every attack request declaring itself an attack to the risk engine — takes P to 0.000 on all six attacks (`data/tables/table1b_oracle_ceiling.csv`), while B1 is unchanged because it has no risk engine to inform. Two readings follow. First, the enforcement machinery downstream of detection is sound: given a correct verdict, the PDP/PEP path converts it into a block every time. Second, and more important for anyone building on this testbed, the entire difference between "P blocks 2 of 6 attacks" and "P blocks 6 of 6" is the quality of the detector, and a testbed that leaks ground truth into the detector measures the second number while appearing to measure the first.

### 7.2 False-challenge cost (RQ1/RQ3)

**Table 2 — CHALLENGE and DENY rates on legitimate traffic, stable vs. drifting context.** Source: `data/tables/table2_false_challenge.csv`. Legitimate workload, 20 concurrent users, 60 s per configuration, warm-up excluded.

| Config | Context | n | False-challenge rate | False-deny rate | Total friction |
|---|---|---|---|---|---|
| B0 | stable | 1865 | 0.000 [0.000, 0.002] | 0.000 [0.000, 0.002] | 0.000 [0.000, 0.002] |
| B0 | drift | 73 | 0.000 [0.000, 0.050] | 0.000 [0.000, 0.050] | 0.000 [0.000, 0.050] |
| B1 | stable | 1838 | 0.000 [0.000, 0.002] | 0.000 [0.000, 0.002] | 0.000 [0.000, 0.002] |
| B1 | drift | 74 | 0.000 [0.000, 0.049] | 0.000 [0.000, 0.049] | 0.000 [0.000, 0.049] |
| P | stable | 1846 | 0.000 [0.000, 0.002] | **0.0385 [0.031, 0.048]** | 0.0385 [0.031, 0.048] |
| P | drift | 74 | 0.000 [0.000, 0.049] | **0.973 [0.907, 0.993]** | 0.973 [0.907, 0.993] |
| P | all | 1920 | 0.000 [0.000, 0.002] | **0.074 [0.064, 0.087]** | 0.074 [0.064, 0.087] |

B0 and B1 impose no friction on legitimate traffic by construction: neither evaluates contextual risk, so neither can refuse a request that passes its credential checks.

Three things in P's column deserve comment, and none of them is flattering.

First, essentially every request whose context drifts is refused: 72 of 74. The geo-velocity rule synthesises a 1000 km displacement for any change of region and divides by the elapsed interval, so at request rates measured in milliseconds *any* region change implies an impossible velocity. The rule is, at this request rate, not a velocity test but a "region changed" test.

Second, the friction is roughly double the drift fraction. The workload's configured 5% drift probability produced 74 of 1920 drift-labelled requests (3.9%) in this run, and total friction was 7.4% — 72 denials among drift requests and a near-identical 71 among stable ones. A per-request geo-velocity rule punishes the return journey exactly as hard as the departure, so each excursion costs two refusals: the request that moves the context and the next request that moves it back. The stable-context denial rate is therefore not an independent false-positive rate at all; it is the shadow of the drift rate.

Third, the adaptive `CHALLENGE` band is never used: P issues 143 denials and zero challenges. Risk on this workload is bimodal — 0.25 when only the call-rate rule fires (98–100% of legitimate requests) and 0.85 when geo velocity fires alongside it — so the distribution steps straight over the [0.40, 0.70) challenge band. The system is nominally adaptive and empirically binary. A step-up challenge is the mechanism that is supposed to make contextual enforcement tolerable for legitimate users, and on this workload it never fires.

### 7.3 Performance (RQ2)

**Table 3 — per-request latency by configuration.** Source: `data/tables/table3_latency.csv`; distribution, CDF and stage breakdown in `data/figures/fig3_latency.png`. Legitimate traffic, 20 users, 60 s, warm-up excluded.

| Config | n | p50 (ms) | p95 (ms) | p99 (ms) | mean (ms) [95% CI] |
|---|---|---|---|---|---|
| B0 | 1938 | 6.83 | 18.56 | 28.90 | 8.72 [8.50, 8.96] |
| B1 | 1912 | 7.42 | 19.86 | 30.35 | 9.47 [9.23, 9.75] |
| P | 1920 | 13.64 | 36.96 | 57.95 | 17.09 [16.57, 17.65] |

P versus B1: **+6.22 ms at the median, +17.10 ms at p95, +27.60 ms at p99**, mean +7.62 ms. Cliff's δ = 0.580 (large). B1 versus B0: +0.60 ms at the median, Cliff's δ = 0.115 (negligible) — sender-constraining is close to free.

**Mean per-stage latency (ms)**, same source:

| Config | token_verify | dpop_verify | telemetry + device registry | risk | policy (OPA) | proxy |
|---|---|---|---|---|---|---|
| B0 | — | — | — | — | — | 8.658 |
| B1 | 0.274 | 0.222 | 0.002 | — | — | 8.945 |
| P | 0.247 | 0.186 | 0.155 | 0.007 | **9.386** | 7.084 |

**H3 held, emphatically.** Cryptography is not the cost. DPoP proof verification — ES256 signature check, thumbprint comparison, `ath` hash, replay-cache lookup — costs 0.19 ms, about 1% of P's mean request. The policy round trip to OPA costs 9.39 ms, 55% of P's mean request and larger than the entire backend call it guards. Telemetry collection and risk scoring together cost 0.16 ms. The added cost of continuous enforcement in this implementation is, almost entirely, one HTTP round trip to an out-of-process policy engine, and it is an implementation choice rather than a property of continuous enforcement: an in-process or sidecar-colocated PDP, or a decision cache, would remove most of it. (P's mean `proxy` figure is lower than B1's because denied requests never reach the proxy; the ALLOW-only mean, 17.72 ms, is in the same table.)

**Table 8 — latency and achieved throughput vs. concurrency.** Source: `data/tables/table8_scaling.csv`; plotted in `data/figures/fig4_scaling.png`. 30 s per cell, warm-up excluded.

| Config | Users | Achieved req/s | p50 (ms) | p95 (ms) | p99 (ms) | mean (ms) |
|---|---|---|---|---|---|---|
| B0 | 5 | 8.37 | 11.09 | 22.37 | 33.38 | 12.04 |
| B0 | 10 | 17.69 | 9.46 | 21.35 | 27.64 | 10.73 |
| B0 | 20 | 35.22 | 6.73 | 19.83 | 27.99 | 8.86 |
| B0 | 40 | 71.48 | 5.30 | 17.29 | 23.63 | 7.54 |
| B1 | 5 | 8.57 | 11.70 | 23.22 | 33.25 | 12.61 |
| B1 | 10 | 18.26 | 9.54 | 21.37 | 29.05 | 10.84 |
| B1 | 20 | 35.65 | 7.23 | 21.55 | 36.04 | 9.62 |
| B1 | 40 | 72.49 | 5.74 | 18.18 | 28.15 | 7.91 |
| P | 5 | 8.89 | 19.54 | 36.59 | 50.71 | 20.78 |
| P | 10 | 17.51 | 14.47 | 35.57 | 48.71 | 17.51 |
| P | 20 | 35.49 | 13.02 | 44.93 | 83.87 | 17.85 |
| P | 40 | 68.06 | 15.38 | 47.40 | 510.76 | 28.00 |

The P−B1 median gap is roughly constant in absolute terms across the range (+7.8, +4.9, +5.8, +9.6 ms at 5/10/20/40 users): continuous enforcement adds a fixed per-request cost rather than degrading super-linearly with load. Achieved throughput differs by at most 6.1% across configurations at 40 users (B0 71.5, B1 72.5, P 68.1 req/s), but the workload is closed-loop with think time and none of the configurations was driven to saturation, so **we do not report a throughput ceiling and no claim should be read into these figures beyond "P did not become the bottleneck at the loads tested."** P's p99 at 40 users (510.8 ms) is a tail outlier on a single 30 s cell and we do not interpret it.

**Table 4 — controller CPU and memory during the legitimate workload.** Source: `data/tables/table4_resource_overhead.csv`; 27 `docker stats` samples per configuration at ~2 s intervals.

| Config | CPU mean (%) | CPU p95 (%) | CPU peak (%) | Mem mean (MiB) | Mem peak (MiB) | ΔCPU vs B0 (pp) | ΔMem vs B0 (MiB) |
|---|---|---|---|---|---|---|---|
| B0 | 22.54 | 26.04 | 26.74 | 56.85 | 57.99 | — | — |
| B1 | 24.10 | 29.37 | 30.65 | 57.31 | 58.23 | +1.56 | +0.46 |
| P | 34.05 | 42.22 | 46.13 | 61.84 | 65.58 | **+11.51** | **+4.99** |

Sender-constraining costs +1.6 pp of one core and half a megabyte. Continuous enforcement costs +11.5 pp and 5 MiB — a 51% relative increase in CPU over B0, consistent with the latency breakdown, since the dominant added work is serialising a policy input document and awaiting an HTTP response. Memory growth is modest and bounded by the sliding windows (60 s per subject) and the per-subject key registry.

### 7.4 Ablation (RQ3)

**Table 5 — attack success and legitimate-traffic friction per ablation cell.** Source: `data/tables/table5_ablation.csv`; plotted in `data/figures/fig5_ablation.png`. Each cell runs the full attack suite (30 attempts × 6 attacks) and a 60 s drifting legitimate workload.

| Cell | A1 | A2 | A3 | A4 | A5 | A6 | Pooled attack success | Friction (stable) | Friction (drift) |
|---|---|---|---|---|---|---|---|---|---|
| **P** | 0.000 | 0.000 | 1.000 | **0.367** | 0.000 | 1.000 | 0.394 [0.326, 0.467] | 0.039 | 0.973 |
| P − device-binding | 0.000 | 0.000 | 1.000 | **0.967** | 0.000 | 1.000 | 0.494 [0.422, 0.567] | 0.038 | 0.973 |
| P − context | 0.000 | 0.000 | 1.000 | **1.000** | 0.000 | 1.000 | 0.500 [0.428, 0.572] | **0.000** | **0.000** |
| P − velocity | 0.000 | 0.000 | 1.000 | **0.667** | 0.000 | 1.000 | 0.444 [0.374, 0.517] | 0.038 | 0.973 |
| B1 | 0.000 | 0.000 | 1.000 | 1.000 | 0.000 | 1.000 | 0.500 [0.428, 0.572] | 0.000 | 0.000 |

Cells are defined by feature flags on one codebase: *P − device-binding* disables the `cnf.jkt` binding check and rules R1/R2; *P − context* disables the telemetry PIP and with it R3, R5 and R6; *P − velocity* disables R4 alone. Device binding is deliberately not part of "context": it is keyed on the token's `cnf.jkt` rather than on the telemetry PIP, which is what lets the two be ablated independently. *P − velocity* is a strict subset of *P − context*.

**H4 held as a measurement, and the attribution is uncomfortable.**

*No single component detects A4.* Removing device binding takes A4 from 0.367 to 0.967; removing context takes it to 1.000. Neither component alone is close to sufficient — with context intact but device binding gone the adversary still succeeds 29 times in 30, and with device binding intact but context gone, 30 times in 30. Detection is the *additive conjunction* crossing a threshold: the unknown-device penalty is 0.35, which is below `τ_allow = 0.40`, so on its own it is inert, and it becomes actionable only when session-continuity (0.20) or call-rate (0.25) evidence is added to it. Removing the velocity rule alone, which fires on only 30% of A4's requests, still costs nearly half the gain (0.367 → 0.667). This is a fragile mechanism: it works by the arithmetic of several sub-threshold penalties summing past a threshold, not by any one signal being decisive.

*One component supplies all the cost and almost none of the benefit.* Friction is identical across P, P − device-binding and P − velocity (3.8–3.9% stable, 97.3% drift) and falls to exactly zero in P − context. Every false denial in this system comes from the contextual group — specifically from geo velocity, which `data/tables/table7_risk_components.csv` shows firing on 97.3% of drifting legitimate requests and 3.85% of stable ones, against 3.3% of A4's requests. The component a deployer would most want to switch off on usability grounds is the one whose removal costs the most security, but it earns that security almost entirely by topping up another rule rather than by discriminating on its own.

*Device binding is free.* Removing it raises A4 from 0.367 to 0.967 — a 0.60 absolute difference, the largest of any single ablation — and it costs nothing measurable in friction, CPU or latency. If a deployer adopts one thing from P, it is the per-subject device-key registry.

### 7.5 What the risk rules actually did

**Table 7 — rule firing rates by population (P, organic).** Source: `data/tables/table7_risk_components.csv`.

| Population | n | unknown device (R2) | geo velocity (R3) | call rate (R4) | session continuity (R5) | attack tag (R7) | mean risk |
|---|---|---|---|---|---|---|---|
| Attack A1 | 30 | 0.000 | 0.000 | 0.000 | 0.000 | **0.000** | 0.000 |
| Attack A2 | 30 | 0.000 | 0.000 | 0.000 | 0.000 | **0.000** | 0.000 |
| Attack A3 | 30 | 0.000 | 0.000 | 0.300 | 0.000 | **0.000** | 0.075 |
| Attack A4 | 30 | **1.000** | 0.033 | 0.300 | **0.333** | **0.000** | **0.507** |
| Attack A5 | 30 | 0.000 | 0.000 | 0.300 | 0.000 | **0.000** | 0.075 |
| Attack A6 | 30 | 0.000 | 0.000 | 0.300 | 0.000 | **0.000** | 0.075 |
| Legitimate (stable) | 1846 | 0.000 | 0.0385 | 1.000 | 0.000 | **0.000** | 0.273 |
| Legitimate (drift) | 74 | 0.000 | **0.973** | 1.000 | 0.000 | **0.000** | 0.834 |

Rules R1 and R6 never fire in the primary runs and are omitted: R1 is pre-empted by the binding check in DPoP verification, and R6's DPoP-failure history never crosses its 0.10 threshold within a single reset window. A1 and A2 read zero on every rule because they are refused before risk scoring. The `attack tag` column is the audit trail for §6.1: it is zero everywhere.

The most consequential row is the legitimate-stable one. The call-rate rule fires on **100%** of legitimate requests under this workload — 20 concurrent clients of one subject easily exceed 30 requests per minute — so the rule that is supposed to catch velocity abuse is saturated by ordinary traffic and carries no information. It is also why A3 and A6 sit at exactly the same mean risk (0.075) as A5, an attack that has nothing to do with volume.

### 7.6 Threshold sensitivity

Reporting a single operating point cannot distinguish "the contextual signal is absent" from "the signal is present but priced below the threshold". Because the risk score is recorded on every request, the decision each request would have received under a different `τ_allow` can be recomputed exactly, at no experimental cost. Requests refused by a credential check are counted as blocked at every threshold, since no threshold changes them.

**Table 6 (selected rows) — decisions recomputed over the measured risk scores.** Source: `data/tables/table6_threshold_sensitivity.csv`; full curve in `data/figures/fig6_threshold_sensitivity.png`.

| τ_allow | Attack requests blocked | A3 blocked | A4 blocked | A6 blocked | Legitimate stable refused | Legitimate drift refused |
|---|---|---|---|---|---|---|
| ≤ 0.25 | 0.650 | 0.300 | 1.000 | 0.300 | **1.000** | 1.000 |
| 0.30 | 0.500 | 0.000 | **1.000** | 0.000 | **0.0385** | 0.973 |
| **0.40 (shipped)** | 0.439 | 0.000 | 0.633 | 0.000 | 0.0385 | 0.973 |
| 0.65 | 0.339 | 0.000 | 0.033 | 0.000 | 0.0385 | 0.973 |

Two findings.

**The shipped operating point is simply mis-set for A4.** Moving `τ_allow` from 0.40 to 0.30 blocks 100% of A4 requests — up from 63.3% — at *identical* legitimate friction, because no legitimate request in this workload scores in [0.30, 0.40). The 0.35 unknown-device penalty falls just on the wrong side of the shipped threshold. P's headline A4 number is an artifact of threshold placement rather than of the signal's strength, and that is a tuning finding a deployer can act on immediately.

**Catching device-resident and velocity abuse is not a tuning problem.** A3 and A6 only begin to be blocked at `τ_allow ≤ 0.25`, where the call-rate rule alone becomes actionable — and at that threshold the same rule refuses **100%** of legitimate traffic, stable and drifting alike, because ordinary concurrent use of one account also exceeds 30 requests per minute. There is no threshold at which this rule set separates A3 or A6 from the legitimate workload. The failure is in the signal, not the operating point: an absolute per-subject call-rate threshold cannot distinguish an adversary driving a burst through a session from the account's own legitimate clients driving a burst through the same session. Discriminating them needs a signal this rule set does not have — per-device or per-client rate rather than per-subject, a baseline-relative rather than absolute threshold, or an endpoint-mix or inter-arrival-regularity feature of the kind Behbehani et al. [20] use offline.

### 7.7 Summary of findings

Against a FAPI 2.0-correct baseline, continuous context-bound enforcement bought exactly one thing on this testbed: detection of account takeover from a newly enrolled device, reducing a certain compromise (30/30) to 11/30 at the shipped thresholds and to 0/30 at a threshold that costs no additional friction. It bought nothing against device-resident key abuse or velocity abuse — the adversaries the contextual layer exists for — because the only rule that addresses them is saturated by legitimate traffic and priced below the challenge threshold. It cost +6.2 ms median and +27.6 ms p99 per request (Cliff's δ = 0.58), +11.5 pp CPU, +5.0 MiB memory, and a 7.4% false-deny rate on legitimate traffic that rises to 97.3% whenever the client's context changes. The ablation attributes the security gain to the conjunction of device binding and contextual evidence (neither suffices alone) and 100% of the usability cost to the geo-velocity rule. The detection ceiling measured with a perfect oracle is 6/6 attacks blocked, which locates the entire remaining gap in detection quality rather than in the enforcement machinery.

---

## 8. Experimental Methodology

*(Written to sit before Results in the final layout, or as a subsection of §5–6.)*

**Configurations & isolation.** B0/B1/P and all ablation cells are selected by environment-variable feature flags in one controller codebase; the mock API and IdP are held constant, so measured differences are attributable to the enforcement layer. Each cell's active flag set is recorded in every JSONL record it produces, and each cell carries a distinct run label so that ablations sharing a mode remain separable in analysis.

**Baselines.** The primary comparator is B1 (FAPI 2.0-correct). B0 is reported only to contextualize how much of the benefit is already standard. All security claims are stated as P − B1.

**Repetitions & statistics.** Each attack cell is 30 attempts with fixed seeds (A1–A5) and the same for A6; each performance cell is a 60 s run at 20 concurrent users (~1900 requests after warm-up exclusion), and each scaling cell a 30 s run. Proportions (attack success, challenge/deny rate) are reported with Wilson 95% intervals; latency with medians, p95/p99 and bootstrap 95% CIs on the mean (2000 resamples); P-vs-B1 differences with effect sizes — Cliff's δ for latency, risk difference with a 95% CI and a Haldane–Anscombe odds ratio for attack success — rather than p-values alone. Cliff's δ is computed from the Mann–Whitney U identity and checked against the pairwise definition in `analysis/tests/test_stats.py`.

**Warm-up.** Each workload begins against a freshly restarted controller, and the first 5 s of every run is excluded. This is not cosmetic: before the exclusion, the lowest-concurrency scaling cell reported a 53 ms median against 11 ms after, which would have made the least-loaded cell appear the slowest.

**Environment.** Single documented host: Apple M5, 10 cores, 16 GiB RAM, macOS 26.6.2 (build 25G83); Docker Engine 29.4.1 with Docker Compose 5.1.3. Images: Keycloak 26.4.4 (`quay.io/keycloak/keycloak:26.4.4`), OPA 0.70.0, controller and mock API built from the repository on Python 3.12.14 (FastAPI 0.115.0, uvicorn 0.30.6, httpx 0.27.2, cryptography 43.0.1, python-jose 3.3.0, cachetools 5.5.0). Load generator (Locust 2.31.3) runs on the host, on loopback to the controller's published port; all inter-service traffic is on a single Docker bridge network. Analysis runs on Python 3.12.13 with numpy 2.1.2, scipy 1.14.1, pandas 2.2.3, matplotlib 3.9.2. The host is a laptop rather than a dedicated benchmarking machine; we therefore report distributions and effect sizes rather than single figures, and we flag single-cell tail outliers rather than interpreting them.

**Measurement integrity.** The rule stated in §6.1 — no enforcement decision may read a value that exists only because the harness knows the request is an attack — is enforced by construction (the oracle rule is disabled by default and gated behind an explicit switch) and audited after the fact by `data/tables/table7_risk_components.csv`, which reports the oracle rule's firing rate in every population.

**Artifacts.** Testbed, attack suite, load profiles, raw JSONL, and the analysis pipeline are released with a one-command bring-up (see Data Availability). Every table and figure cited in §7 is regenerated by `make analysis` from the raw records.

---

## 9. Discussion

### 9.1 What continuous enforcement adds over FAPI 2.0

The boundary this paper set out to characterize turns out to be narrower than the Zero-Trust-for-Open-Banking literature implies, and narrower than we expected.

On one side of it, the result is clean and unsurprising: a FAPI 2.0-correct deployment already neutralizes the network-interception and browser-exfiltration adversaries that motivate much of the field, completely and at negligible cost (+0.6 ms median, Cliff's δ = 0.115, +1.6 pp CPU). Proposals that demonstrate a Zero Trust layer defeating token replay or stolen-token reuse are demonstrating something the baseline already does. For those adversaries, a contextual layer is pure cost.

On the other side, the contextual layer's value is real but far more specific than "it handles the adversaries DPoP cannot". It handled exactly one of them. Account takeover from a newly enrolled device is detectable because the adversary must present a key the account has never used, and that key's thumbprint is bound into a token the adversary cannot forge — so the evidence is unforgeable and unavoidable. Device-resident abuse is not detectable by this rule set at any threshold, because the adversary presents the account's own key from the account's own context and the only remaining difference is a rate that the account's own legitimate clients also exceed. The distinction between the two cases is not "context" versus "no context" — it is whether the adversary is *forced* to produce evidence they cannot suppress. That, rather than the presence of a telemetry pipeline, is what a deployer should look for when judging whether a contextual layer will help against a given adversary.

The corollary is a caution about the field's framing. "Continuous, context-aware enforcement" names an architecture, not a capability. The architecture worked here — the PDP/PEP path converted a correct verdict into a block on 100% of requests, as the oracle ceiling shows — and it still blocked only two of six attacks, because four of the six produced no evidence the detector could use. Evaluations that report the architecture's response to attacks it has been told about, or to adversaries who happen to differ from legitimate users along an axis the rule set already watches, will systematically overstate what the architecture delivers.

### 9.2 Cost model

The added cost is not where the design intuition puts it. Sender-constraining — the part involving cryptography — costs 0.19 ms per request, about 1% of P's mean. The contextual layer's own work, telemetry collection and rule evaluation, costs 0.16 ms. The remaining 9.39 ms, 55% of P's mean request and more than the backend call it protects, is a single HTTP round trip to an out-of-process policy engine.

For gateway deployment this is the most actionable finding in §7.3, because it is almost entirely an architectural choice rather than a property of continuous authorization. A colocated sidecar, an in-process policy library, or a decision cache keyed on the (risk-bucket, check-outcome) tuple would each remove most of it; the rule set here is deterministic and its input space is small, so caching is straightforward. A deployer should read the P−B1 delta as "one policy round trip", not as "the price of Zero Trust", and should budget accordingly. The resource figures point the same way: +11.5 pp of one core for work that is dominated by serialising a policy document and awaiting a response.

The scaling sweep supports treating this as a fixed per-request tax. The P−B1 median gap stays within 4.9–9.6 ms from 5 to 40 concurrent users, and throughput stays within 6% across configurations. We did not drive the system to saturation and make no claim about behaviour there.

### 9.3 Usability trade-off

A defense that blocks A3/A4 but over-challenges legitimate users is not a net win. On the measured numbers it is worse than that: this configuration blocks A4 only partially, blocks A3 not at all, and refuses 97.3% of legitimate requests whose context drifts — and 7.4% of all legitimate requests at a 5% drift rate. In a production Open Banking deployment, refusing roughly one request in thirteen for users who move between networks would be disqualifying on its own.

Three aspects generalize beyond our parameter choices.

*A per-request geo-velocity rule is the wrong shape.* At request rates measured in milliseconds, any change of region implies an impossible velocity, so the rule degenerates into "region changed" and fires on the return journey as hard as on the departure — which is why 5% drift produces 7.4% friction. Velocity reasoning belongs at session or login granularity, where the elapsed time between observations is long enough for the physics to mean anything, not on every call.

*The adaptive band was never used.* P issued 143 denials and zero challenges. The measured risk distribution is bimodal — 0.25 when only the saturated call-rate rule fires, 0.85 when geo velocity joins it — and steps straight over the [0.40, 0.70) challenge window. Step-up authentication is the mechanism that is supposed to make contextual enforcement survivable for legitimate users, and an additive rule set with a handful of coarse penalties does not produce the graded scores it needs. This is a design-level observation, not a tuning one: adaptive enforcement requires a risk signal with intermediate values, and coarse additive penalties do not supply them.

*The cost and the benefit are not separable here.* §7.4 shows that removing the contextual group removes all friction and also most of the A4 detection, even though geo velocity fires on only 3.3% of A4's requests. The contextual rules earn their security by topping up a sub-threshold device penalty, while earning their cost by firing on legitimate drift. A deployer cannot keep the benefit and drop the cost by ablating a component; they would have to re-price the device signal so that it is actionable on its own — which §7.6 shows is a one-line threshold change.

### 9.4 Failure modes and misconfiguration

The V0 draft's failure-mode list — improper DPoP clock skew weakening replay protection or causing false rejections, stale device-key lifecycle management admitting replay, poorly calibrated thresholds either over-challenging or under-protecting — is retained, and the measurement supplies evidence for the third item: a 0.10 change in `τ_allow` is the difference between blocking 63% and 100% of A4 at identical usability cost (§7.6). Threshold calibration is not a tuning detail in a system whose penalties are coarse and additive; it decides outcomes.

We add three failure modes that this work surfaced and that we believe generalize to any implementation of this architecture.

*Keying trust state on attacker-controlled identity.* Continuous authorization accumulates state about a subject, and the key it accumulates under determines whether an adversary can escape their own history. Keying it on a self-reported device header — the obvious choice, since that is where fingerprint and geography arrive — lets an adversary reset every behavioral signal by inventing a device identifier, and nothing in the system reports an anomaly, because from its point of view a new device with no history is exactly what a first-time legitimate user looks like. The state must be keyed on a verified claim: the token's `sub` for the subject, and `cnf.jkt` for the device.

*Baselines that the adversary overwrites.* A signal defined as "differs from the previous request" is erased by the adversary's own first request. In an early version of this testbed, only the first request of a new-device attack was anomalous and the remaining twenty-nine scored clean, because the attacker's fingerprint had become the new baseline. Comparison must be against an established baseline set that unknown values do not silently join. The same reasoning applies to enrollment: auto-enrolling an unrecognised device key on first use converts the device signal into a one-request alarm.

*Rules that saturate on legitimate traffic.* An absolute per-subject call-rate threshold that ordinary concurrent use exceeds is not a detector; it is a constant. Ours fired on 100% of legitimate requests, which is why A3, A5 and A6 all score an identical 0.075 and why no threshold separates them from the workload. A rate rule needs a denominator the legitimate population does not routinely exceed — per-device or per-client rather than per-subject, or a baseline-relative rather than absolute threshold.

Each of these is silent in the sense that matters: none produces an error, a failed test, or an anomalous metric. They surface only when an attack that should be caught is not, or — worse, and this is the case that motivated §6.1 — when an attack that should not be caught is, for a reason the results table cannot show.

### 9.5 Threats to validity

*Construct validity.* Success is measured as the resource server returning data, which is the right construct for "did the adversary obtain protected data" but makes A5 insensitive to the enforcement layer, since ownership is enforced downstream in all three configurations. The geo signal is synthetic: region codes with an assumed 1000 km separation, not real geolocation, so §7.2's drift numbers characterise the *rule's shape* rather than a real travel workload's false-positive rate.

*Internal validity.* The single Keycloak test identity means the legitimate workload is one subject with one enrolled device driving concurrent clients, which is what saturates the per-subject call-rate rule (§7.5). A workload spread over many subjects would lower that rule's firing rate on legitimate traffic and could change the threshold sweep's shape, though not the A3 conclusion, since A3's adversary shares the victim's subject by definition. The host is a laptop under Docker Desktop; we report distributions and effect sizes, and we flag rather than interpret single-cell tail outliers.

*External validity.* Synthetic data and a mock API limit external validity; results characterize authorization-semantic behavior and per-request cost, not bank-specific data effects. The attacker set, though covering the discriminating cases, is not exhaustive. Rule-based risk scoring is a deliberate design choice for auditability, and a learned detector — which is what [20] suggests for exactly the A3/A6 regime where our rules fail — may well shift the security/false-positive trade-off; that comparison is left to future work and our negative result for A3 should be read as a result about this rule set at these thresholds, not about contextual detection in general.

---

## 10. Limitations

The evaluation uses a synthetic, mock Open Banking environment rather than production infrastructure; results characterize authorization-semantic behavior and per-request cost, not bank-specific data effects. Device compromise at the OS/kernel level is out of scope. Risk scoring is rule-based; learned models may shift both the security/false-positive trade-off and the cost profile, and our A3/A6 negative result is specific to this rule set. Threshold calibration is illustrative; §7.6 shows how much turns on it, and production tuning would require operational telemetry. The legitimate workload exercises a single subject, which saturates the per-subject rate rule. Throughput was not driven to saturation, so no capacity claim is made. These limitations bound the claims to the measured regime.

---

## 11. Ethics and Responsible Research

All experiments use synthetic data and a locally simulated ADR API; no real banking systems, production or staging endpoints, customer data, or credentials are involved. The identity provider, policy engine, resource server and all credentials are local to the testbed and are published as part of it. The attack implementations target only the authors' own local testbed and are provided to enable replication of the defensive evaluation, not as general-purpose offensive tooling. Because no external or third-party systems are touched, no vulnerability disclosure is applicable; had any real system been tested, coordinated disclosure would have been followed. Synthetic-data generation avoids any personal or financial information.

---

## 12. Conclusion

FAPI 2.0's mandatory sender-constraining already neutralizes the network- and theft-based token attacks that motivate much Open Banking security work — completely, and for +0.6 ms per request — which reframes the question for Zero Trust from "does proof-of-possession help" to "what does continuous context-bound enforcement add beyond it, and at what cost."

Using a reproducible, fully synthetic testbed and an identical attacker suite across a weak baseline, a FAPI 2.0-correct baseline, and a continuous-enforcement system, we measure that delta as narrow, specific, and expensive. Continuous enforcement was necessary and effective for exactly one adversary: account takeover from a newly enrolled device, which B1 cannot touch (30/30 successful) and which P reduces to 11/30 at the shipped operating point — and to 0/30 at a challenge threshold 0.10 lower, at no additional usability cost. It was ineffective against device-resident key abuse and velocity abuse (30/30 in both P and B1), because the only rule addressing them fires on 100% of legitimate traffic and is priced below the challenge threshold, so no threshold separates them from the workload. The cost was +6.2 ms median and +27.6 ms p99 per request (Cliff's δ = 0.58, large), +11.5 percentage points of controller CPU, +5.0 MiB of memory, and a 7.4% false-deny rate on legitimate traffic that reaches 97.3% under context drift. The ablation attributes the security gain to the conjunction of device-binding and contextual evidence — neither component alone reduces the attack below 0.967 — and 100% of the usability cost to the geo-velocity rule, which contributes almost none of the detection by itself. Device binding on its own is free: it costs nothing measurable in latency, CPU or friction.

The practical takeaway for Open Banking deployers is that on a FAPI 2.0-correct baseline the per-subject device-key registry is the component worth adopting first — it is where the measured security benefit comes from, it costs nothing, and it works because the adversary cannot avoid presenting a key the account has never used — while per-request geo-velocity and absolute call-rate rules should be treated as liabilities until they are re-shaped, since here they supplied all of the usability cost and no independent detection.

Two methodological points we would press on anyone measuring this class of system. First, a defense must never be scored on evidence that exists only because the harness knows the request is an attack; with a self-declared attack tag enabled, this same system blocks 6 of 6 attacks instead of 2 of 6, and the difference is invisible in the results table. Second, report the threshold sweep alongside the operating point, because "the contextual signal is absent" and "the signal is present but priced below the threshold" are different findings with different remedies, and on this system both occurred — one for each of the two adversaries the contextual layer was built for.

We release all artifacts to support replication and extension. Future work includes learned risk models for the device-resident regime where our rules fail, rate and continuity signals with denominators legitimate traffic does not saturate, formal analysis of partial-deployment failure modes, and validation on production-grade workloads.

---

## Data Availability

The testbed source code (mock ADR API, Keycloak configuration, Zero Trust controller, OPA policies), attack suite, load profiles, raw measurement records, and the analysis pipeline are released at **https://github.com/MIMohit/openbank** (branch `open-bank`). All tables and figures cited in §7 are committed under `data/tables/` and `data/figures/` and are regenerated from the raw JSONL records by `make analysis`. All data are synthetic and generated by the released scripts.

*Archival note (action required before submission):* no Zenodo deposit has been created yet, so no DOI exists and none is stated here. A versioned archive should be minted from the submission-time commit and its DOI inserted in this section. This replaces V0's "available upon reasonable request", which contradicts an open-testbed claim and is disfavoured at the target venue.

---

## Declaration of Generative AI Use

Generative AI tools were used during the preparation of this work: for drafting and editing prose across the manuscript, for implementing and debugging parts of the testbed, attack suite and analysis pipeline, and for reviewing the measurement methodology — including identifying the measurement-integrity defects described in §6.1. All experiments were executed on the authors' own infrastructure, and every number reported in §7, §9 and §12 was produced by the released pipeline from recorded measurements and verified against the committed files under `data/tables/`. No results, citations or references were generated without verification against a primary source. The authors reviewed and take full responsibility for the entire content of the manuscript, including all claims, code and data.

*Note: this statement should be reconciled with the V0 declaration's wording before submission if the target venue prescribes a specific form.*

---

## Appendix A — Belief-threshold model (demoted, optional)

If retained, this appendix must present the belief-state formulation strictly as a calibrated interpretation of measured controller behaviour: define `UpdateBelief` concretely, estimate its parameters from measured telemetry, and validate that the resulting thresholds predict the system's empirical `CHALLENGE`/`DENY` decisions. Position it explicitly as a quantal-response Stackelberg equilibrium over a belief-MDP and cite GAZETA [22] and the threshold-POMDP line [26]. Do not claim a new equilibrium concept, and do not include un-instantiated "proof sketches."

The measurements now available make the instantiation feasible but also constrain what it can honestly claim. `risk = 1 − b` is recorded per request, so the empirical belief distribution is directly observable (§7.5), and the threshold sweep in §7.6 is precisely the policy's operating characteristic. Two properties of the measured distribution would have to be confronted rather than smoothed over: it is bimodal, taking essentially two values (0.25 and 0.85) on the legitimate workload, and the `CHALLENGE` action is never selected in practice. A belief-threshold model fitted to this system would therefore be a model of a two-state detector with a degenerate middle action, which is a weaker and less interesting object than the analytical literature's. **Our recommendation is to cut this appendix.** An un-grounded formalism weakens an otherwise empirical paper, and the grounded version here would mostly restate §7.6 in heavier notation.

## Appendix B — Optional formal partial-deployment analysis (future/secondary)

If pursued: model the composed checks (DPoP proof + controller verification + rebinding) in Tamarin/ProVerif under a Dolev–Yao attacker augmented with token theft, and show which partial deployments or misconfigurations (skew, missing resource-server check) reintroduce replay. A "misconfiguration reintroduces the attack" result complements the measurements and is independently publishable. §7.4's ablation is the empirical analogue and gives the formal analysis concrete cells to target: `P − device-binding` is a partial deployment in which the `cnf.jkt` binding check is absent from both the controller and the policy, and it measurably reintroduces the new-device adversary (A4: 0.367 → 0.967).

---

## References

The numbered citations [1], [2], [9], [10] and [17]–[22] carry over from the V0 bibliography and retain their V0 keys; that bibliography file is not part of this repository and must be carried over with the manuscript. The entries below are the comparators that V1 marked `[VERIFY]`; each has been checked against its primary source and is now a full reference.

- **[23]** OpenID Foundation. *FAPI 2.0 Security Profile* (Final). Approved February 2025. https://openid.net/specs/fapi-security-profile-2_0-final.html — *Verified:* Final-specification approval announcement and vote record (82 approve / 0 object / 14 abstain), https://openid.net/fapi-2-security-profile-attacker-model-final-specifications-approved/
- **[24]** Keycloak project. *Keycloak 26.4.0 release announcement*, September 2025. https://www.keycloak.org/2025/09/keycloak-2640-released — *Verified:* DPoP promoted from preview to full support; `fapi-2-dpop-security-profile` and `fapi-2-dpop-message-signing` client profiles added and passing the FAPI 2.0 conformance suite. This release (26.4.4) is the IdP used in the testbed.
- **[25]** R. S. Sitorus and B. J. Hutagaol. "Designing a Zero Trust Architecture for Securing API Gateways in Digital Banking Systems." *Journal of Information Systems and Informatics*, 7(3):2589–2601, 2025. DOI: 10.51519/journalisi.v7i3.1219 — *Verified:* the paper states its methodology as "literature review, component identification, architectural modelling, standards-based evaluation, and recommendation development" and presents a conceptual model with no implementation or empirical evaluation, which is the basis for our characterization of it in §3.4 and the gap matrix.
- **[26]** Y. Ge, T. Li and Q. Zhu. "Scenario-Agnostic Zero-Trust Defense with Explainable Threshold Policy: A Meta-Learning Approach." arXiv:2303.03349, March 2023; accepted to IEEE INFOCOM AidTSP 2023. https://arxiv.org/abs/2303.03349 — *Verified:* authors, title, identifier and venue confirmed from the arXiv record. V1's tentative attribution "Ge/Li/Zhu" was correct.
- **[27]** C. Daah, A. Qureshi, I. Awan and S. Konur. "Simulation-based evaluation of advanced threat detection and response in financial industry networks using zero trust and blockchain technology." *Simulation Modelling Practice and Theory*, 138:103027, 2025. — **Correction:** V1 cited this as *Computers & Security*, 2025. The venue is *Simulation Modelling Practice and Theory*; the citation is corrected here and in §3.4. The same group's related framework paper is C. Daah et al., "Enhancing Zero Trust Models in the Financial Industry through Blockchain Integration: A Proposed Framework," *Electronics* 13(5):865, 2024, should a second citation be wanted.

**Outstanding verification.** None among the comparators above. The V0-inherited keys [1], [2], [9], [10], [17]–[22] were not re-verified here because the V0 bibliography is not in this repository; they should be checked against it for consistency (in particular that [22] is Ge and Zhu's GAZETA, distinct from [26] above) when the two documents are merged.

---

## Change log vs. V1

- Every `[FILL]` replaced with a measured value, each cited to the file under `data/tables/` or `data/figures/` that contains it.
- All five `[VERIFY]` comparators resolved to full references (§References); the Daah et al. venue is corrected from *Computers & Security* to *Simulation Modelling Practice and Theory*.
- §6.1 added: the measurement-integrity rule and the four defects it caught, including the self-declared attack tag that had been supplying most of P's apparent detection.
- §7.6 and Table 6 added (threshold sensitivity), and §7.5 and Table 7 added (rule firing rates), both because the measured results could not be interpreted without them.
- Table 8 and `fig4_scaling.png` added: RQ2 asks for the overhead across increasing load and V1 measured a single concurrency level.
- H2 is reported as half-failed: P does not touch A3, the attack the draft designated as the crux. §7.1, §9.1, §9.3 and §12 are written to that result rather than to the expectation.
- §5.3 now states how continuous-trust state is keyed and why; §9.4 adds three failure modes surfaced by the measurement.
- Appendix A carries a recommendation to cut, on the evidence of the measured (bimodal, `CHALLENGE`-free) belief distribution.
- Data Availability states the real repository URL; the Zenodo DOI is flagged as not yet minted rather than left as a placeholder.

## Change log vs. V0 (retained from V1, for reference)

- Reframed from "novel architecture + new equilibrium" to "empirical measurement of P − B1", removing the two overclaimed novelty axes.
- Abstract made honest and measurement-shaped; empirical claims now match the evidence.
- B1 (FAPI 2.0) baseline introduced as the real comparator; B0 demoted to reference.
- Device-resident and ATO adversaries moved in-scope (they are the paper's reason to exist over FAPI 2.0).
- `cnf.jkt` correction throughout (was incorrectly `cnf.jwk`).
- Game-theoretic section demoted to an optional, must-be-instantiated appendix; "new equilibrium concept" claim removed; closest comparators (GAZETA, threshold-POMDP) cited and differentiated.
- Crypto background trimmed to what the measurement needs.
- Data Availability changed from "upon request" to real artifact release.
- Broken `Figure ??` references replaced with the generated figures.

# Novelty update after literature pass 2 (W20, 2026-11-24)

This updates `../novelty_memo.md` (pass 1, G0 = PASS). Pass 1 searched academic databases and standards. The literature review **missed the practitioner literature entirely**: none of the Tsai, xvnpw, Doyhenard or UABScan works, nor the 2021–2026 CVE families screened here, appear in `../screening.csv`. The only exceptions are the five advisories in pass-1 S047–S052. W16's disclosure triage (`../../disclosure/TRIAGE.md`) did find the xvnpw Kong post, but only as an advisory reference for one item. It never reached the novelty memo. It also missed the one CCS'25 paper that studies our E4 mechanism directly. That gap was serious, and it changes the verdicts below.

**Evidence levels:**
- **FT** means the full text was read.
- **ABS** means the abstract or advisory text was read.
- **TITLE** means only the title or metadata was seen.

Bracketed keys refer to `refs_pass2.bib` (`p2:`) or `../refs.bib`. Screening records are in `screening.csv` (84 items: 28 include, 30 background, 26 exclude). The queries are in `SEARCH_LOG.md`.

## 0. Verdict table (blunt)

| # | Claim | Verdict | One-line reason |
|---|---|---|---|
| C1 | **Binding-soundness property**: an accepted proof π ⇒ the executor runs exactly op(π) | **Novel as a formal property and oracle for PoP proofs; the underlying insight is KNOWN** | "check(view₁) then use(view₂)" has been the explicit framing since Tsai 2018. Audience injection (S&P'26) is the closest structural analogue for signed artefacts. Nobody states or measures it for DPoP/PoP binding. |
| C2 | **G1 proof-bound dispatch** (query/body/override outside htm/htu) | **Mechanism KNOWN (by spec, and in a 2016 IETF design); measurement is novel** | RFC 9449 excludes query/body by design. draft-ietf-oauth-signed-http-request (2016) already offered `q`/`h`/`b` binding and was abandoned. Method override is pre-empted by Golinelli (now **ACSAC'26**) and grpc-gateway CVE-2026-37236. |
| C3 | **G2 differentials under A_leak** (binding resolution > 1) | **PARTIALLY PRE-EMPTED. Every mechanism is known; the binding-level consequence is not.** | `#`-in-path (Istio CVE-2021-39156 / Envoy CVE-2021-32779, HAProxy CVE-2023-45539) and encoded-slash and dot-segment splits are long-standing CVE classes. **RC-W13-A (APISIX) is not a new class.** It sits in a family with 2 CVEs from Oct/Nov 2026, and the `%2F` raw-forwarding is the *intended* post-fix behaviour (§C3). What is new is that these splits defeat a *cryptographic* htu binding and change the executed *operation* for a leaked proof. |
| C4 | **E4 authorization soundness** (A_client, gateway path policy ≠ router) | **KNOWN. Do not claim it as a finding.** | xvnpw 2021–22 published exactly the Kong/ingress-nginx/APISIX raw-`$request_uri` PDP split. UABScan (CCS'25) catalogues every routing feature behind RC1/RC3–RC6. NginxBuster (CCS'26) covers nginx auth config splits. There are more than 10 2026 CVEs in Traefik, Envoy, APISIX, Heimdall and Oathkeeper. |
| C5 | **A1 claim ablation** (what htm/htu/ath/+query/+digest buy) | **Novel as an empirical ablation; the design space is KNOWN** | The 2016 signed-HTTP-request draft, RFC 9421 component coverage and RFC 9530 digests already define the knobs. No one has measured what each claim prevents against a mutation corpus or replay set. The "htm is necessary" result directly answers the 2026 OAuth WG proposal. |
| C6a | **D-A** (verify on the executor's routed view) | **PARTIALLY PRE-EMPTED as a principle; novel only as a PoP-binding instantiation** | The standard remedy for this whole family is to "authorise on the same canonical path the router uses": UABScan Finding III, Spring CVE-2016-5007 → MvcRequestMatcher, Emissary/Envoy `normalize_path`, Istio fragment strip, Heimdall/APISIX 2026 fixes. |
| C6b | **D-B** (verifier → executor view MAC) | **No pre-emption found in pass 2** (pass-1 neighbours still apply: Request Synchronization, the nygren binding draft, CREHMA) | Nothing in the practitioner or CVE literature binds the verifier's accepted view to the executor's routed view cryptographically. RC-W13-D (the forged `X-Verified-View` passes kong/haproxy) must be reported with it. |

The **G0 PASS stands, narrowly**. The paper's defensible novelty is:
- (i) the binding-soundness *oracle and formalisation* for sender-constrained proofs;
- (ii) the *measurement* that known G1 and G2 mechanisms translate into **operation substitution under a valid leaked proof**, on current releases;
- (iii) A1;
- (iv) D-B.

Anything that reads as "we discovered that gateways and backends normalise paths differently" will be rejected by any reviewer who knows Tsai 2018, xvnpw 2021 or UABScan 2025.

---

## C1. Binding-soundness property

**What prior work establishes:**
- **Tsai, "Breaking Parser Logic" (BH USA 2018)** [p2:tsai2018breaking, FT] frames every bug as `if (check(data)) use(data)` with inconsistent parsing between check and use. The talk generalises this to the "multi-layered architecture" (reverse proxy vs Java backend). That is our C1 sentence for ACLs, eight years earlier. It has no cryptographic proof and no formal property.
- **Audience Injection (Hosseyni, Küsters, Würtele, S&P'26)** [p2:hosseyni2026audience, ABS] shows that a validly signed client-authentication assertion intended for one endpoint is accepted at another, because audience binding is ambiguous across two or more endpoints. This is the closest *structural* analogue to A_leak: a valid signed artefact is accepted, and the operation is the wrong one. It is the same group whose FAPI model pass 1 found to have an atomic RS. The authors now attack cross-endpoint binding, but at the AS/token-endpoint layer and on the `aud` claim, not RS-side `htu` with a verifier/executor split. **This is the most likely reviewer comparison and must be cited and differentiated.**
- **Gallo, "Beyond Proof of Possession" (arXiv 2611.07159)** [p2:gallo2026beyond, ABS] and TBSG (pass 1) argue conceptually that PoP ≠ authorisation of an execution. They contain no HTTP and no measurement.
- **UABScan** [p2:zhang2025uabscan, FT] names the root cause "inconsistency between routing and authentication". The concept is the same; its check is a string matcher, not a proof.

**Bearing:** the *property* (proof acceptance ⇒ exactly op(π), with binding resolution as the metric) and the *oracle* are not in the literature. The *intuition* is. The paper must not present "the verifier's view differs from the executor's view" as an insight.

**Positioning sentences (use verbatim or close):**
> "That a security check and the component that acts on a request can interpret the same request differently is well known for path-based access control [Tsai 2018; xvnpw 2021; Zhang et al. CCS'25]. We ask the corresponding question for *cryptographic* request binding: when a verifier accepts a DPoP proof for its view of a request, does the backend execute exactly the operation the proof was bound to?"
>
> "Binding soundness is the request-level analogue of the audience binding that Hosseyni et al. showed to be ambiguous for signed client assertions across endpoints [S&P'26]: there, a valid assertion is accepted at the wrong endpoint; here, a valid proof is accepted for one operation and another is executed."

---

## C2. G1 proof-bound dispatch

**What prior work establishes:**
- **RFC 9449** (pass 1) excludes query and fragment from `htu` and has no body or header claim. G1 is therefore *documented behaviour* (W16 TRIAGE agrees).
- **draft-ietf-oauth-signed-http-request-03 (Richer, Bradley, Tschofenig, 2016)** [p2:richer2016signedhttp, FT]. A PoP-signed request object with OPTIONAL `m`, `u`, `p`, `q` (hashed query map), `h` (hashed headers) and `b` (body hash). **The OAuth WG designed query, header and body binding for PoP in 2016 and let it expire.** The draft mentions proxies or intermediaries 0 times. Pass 1 missed it.
- **Golinelli et al., "When POST Becomes GET"** is now **ACSAC 2026** (accepted list). Pass 1 cited the arXiv version. It covers method interchangeability within an application.
- **grpc-gateway CVE-2026-37236** (pass 1) covers method override bypassing upstream method ACLs.
- **Next.js CVE-2025-29927** [p2:nextjs2025_29927, TITLE/ABS] shows a client header changing which code path runs (middleware skipped). It is a single-framework instance of "a header outside the checked view changes execution".

**Bearing:** nothing new about the *mechanism*. What is new: measuring how often a proof-bound request can be redirected by uncovered dispatch inputs (E1/E2 prevalence), and the evidence that method override is enabled **by default** in Rails (non-API) and Laravel. W16 attributes the latter to framework docs, not to a paper.

**Positioning sentences:**
> "RFC 9449 deliberately leaves the query, headers and body outside the proof; an earlier OAuth design that did cover them [draft-ietf-oauth-signed-http-request] was not standardised. We do not claim this under-binding as a vulnerability; we measure its consequence: how many operations a single valid proof can reach through standard dispatch and method-override features, several of which are enabled by default."
>
> "Method override as an access-control bypass is known [Golinelli et al. ACSAC'26; CVE-2026-37236]; our contribution is to show that it survives a proof-bound `htm` because the override is resolved after verification."

---

## C3. G2 differentials under A_leak

**What prior work establishes, by mechanism:**

| Our mechanism | Prior instances (all with a path ACL or route policy as the check, none with a PoP proof) |
|---|---|
| `#` kept in the path by the backend while the verifier strips it (kill RC6, ext-routes X1, ext-fw) | **Istio CVE-2021-39156 / Envoy CVE-2021-32779** [p2:istio2021_008, ABS]: `/user/profile#section1` bypasses DENY `/user/profile` and reaches the backend as `/user/profile%23section1`. **HAProxy CVE-2023-45539** rejects `#`. uvicorn discussion #1222 (W16). |
| Encoded slash: the check sees a decoded view and the upstream gets raw `%2f` (RC-W13-A, APISIX) | **Envoy CVE-2021-29492** [p2:envoy2021_29492]; xvnpw `..%2F` on APISIX 2021 [p2:xvnpw2021apisix, FT]; **APISIX CVE-2026-94269** (Oct 2026, fixed 3.19.0) and **CVE-2026-124680** (Nov 2026, fixed 3.20.0) [p2:apisix2026_124680, ABS + source] |
| Dot segment reaching a catch-all (ext-routes X3) | Traefik CVE-2026-40912 [FT advisory], Heimdall CVE-2026-42274, Oathkeeper CVE-2026-33494, Envoy CVE-2026-73551 (`..;`) |
| Path primitive catalogue in general | Tsai 2018 (`;`, `..;/`), Doyhenard 2024 (delimiters `;` `.` `%00` `%0a`, decoding and dot-segment discrepancies) [FT], Tiurin 2018, UABScan's 13 routing features [FT] |

**RC-W13-A must be reclassified (this contradicts `binding/disclosure/TRIAGE.md`, which says "NEW").**

Primary source, read 2026-11-24: in APISIX **3.21.0**, `apisix/init.lua` lines 643–662 (`uri_normalized_by_nginx`) were added by **PR #14035** (merged 2026-10-26) as the fix for CVE-2026-124680. The function overwrites the upstream URI with the router-matched path **only when nginx did more than percent-decode or merge slashes**. When the difference is percent-encoding only, APISIX keeps forwarding the original request line *so that encoded data such as `%2F` survives*. The Corgea analysis (screening P2-073) quotes the release note: "/a/./b%2Fc now reaches the upstream as /a/b/c", which only applies when a dot segment is present.

So, on 3.21.0, a request whose only anomaly is `%2f` is **deliberately** forwarded raw while routing ran on the decoded `$uri`. That is the upstream half of RC-W13-A, and it is a design decision the APISIX PMC took in October 2026 while fixing the same family.

Separately, `forward-auth.lua` line 254 sets `X-Forwarded-Uri = ctx.var.request_uri`, the **raw** value. That conflicts with the ext-gw report's statement that the verifier received the decoded `$uri`. Someone (W21 owns the APISIX mechanism) must reconcile this before any claim or disclosure. Whatever the exact header path, RC-W13-A is at best a **variant, or a consequence of an accepted residual, of CVE-2026-124680**, not a new class.

A disclosure that calls it new would be embarrassing. If it is reported at all, it should be framed as "the CVE-2026-124680 fix intentionally keeps `%2F` raw; with forward-auth and a decoding verifier this still yields a split".

The **Istio CVE-2021-39156 remedy is instructive for our `#` result.** Istio strips the fragment *before both authorisation and routing*, so the stripped path is the one that gets forwarded. An RFC 9449 verifier also strips the fragment, but *only from the checked view*, while nginx forwards the raw target. In our setting the "fix" behaviour is applied to one side only and becomes the cause of the split. This is a genuinely new and citable observation.

**Bearing:** novelty lies in the *composition and consequence*:
- the binding check is cryptographic and passes, and the executed op ≠ op(π) (binding resolution > 1);
- the mechanisms hold on current releases (the hits are on nginx 1.30.7, Kong 3.9.5 and APISIX 3.21.0, which is post-fix for CVE-2026-124680; our envoy v1.39.6 and traefik v3.7.19 pins are post-fix for CVE-2026-73551 and CVE-2026-88009);
- a nested route turns a path differential into an **operation** change (ext-routes X1).

The mechanisms themselves are not novel.

**Positioning sentences:**
> "Every interpretation differential we observe belongs to a known CVE family (fragment handling [CVE-2021-39156], encoded slashes [CVE-2021-29492, CVE-2026-124680], dot segments [CVE-2026-40912, CVE-2026-73551]); prior work and advisories treat them as bypasses of path-based policies. We show that the same differentials defeat a cryptographic binding: the verifier accepts a valid proof for the request it sees, and the backend executes a different operation."
>
> "Notably, the RFC 9449 verifier's own normalisation—discarding the fragment—is the remedy Istio adopted for CVE-2021-39156; applied only to the verifier's view while the gateway forwards the raw target, it creates the split rather than closing it."

---

## C4. E4 authorization soundness (A_client + path policy)

**What prior work establishes:**
- **xvnpw (2021–22)** [p2:xvnpw2021kong, p2:xvnpw2022ingress, p2:xvnpw2021apisix, p2:xvnpw2021traefik, p2:xvnpw2021emissary, p2:xvnpw2021tips, all FT].
  - Kong with a custom external-auth plugin that forwards `ngx.var.request_uri` to the auth service, while Kong normalises upstream, gives a `/public/../protected` bypass. **This is our e4 RC2, configuration and payload included.**
  - ingress-nginx `auth-url` leaks the raw URI and allows `..%2F` bypass. HackerOne closed it as informative, and nginx said raw `$request_uri` is obviously un-normalised.
  - APISIX CVE-2021-43557. Traefik, HAProxy and Emissary are not exploitable, for the same reason our HAProxy shows 0.
  - The "tips" post describes the privilege-escalation variant: **a valid JWT plus traversal reaches an endpoint the policy denies**. That is our A_client threat model.
- **UABScan (Zhang et al., CCS'25)** [FT]. Of 53 real vulnerabilities:
  - root causes are relative-path (18/53) and semicolon (19/53);
  - the 13 routing features include case-insensitive matching, multiple slashes and trailing slash;
  - auth checks are `startsWith`, `endsWith` or `contains`.
  - That maps one-to-one onto e4 RC1 (Kestrel `/../`), RC3/RC4 (case-insensitive), RC5 (Spring `;`) and RC6 (Rails `//`). They found 94 vulnerabilities and 31 CVEs. The study is in-application (Java filter vs router); ours places the policy at a gateway PDP.
- **NginxBuster (Sadeghi et al., CCS'26, presented 2026-11-18)** [p2:sadeghi2026nginxbuster, ABS only]. Seven classes of nginx *configuration-semantic* auth bypass, including URI normalisation and location ordering. They flagged 11.8% of 1,344 GitHub configs and confirmed 144. This is **concurrent work on our nginx `auth_request` placement**, and its full text has not been read: **risk**.
- **Tsai 2018** (`..;/`, Nuxeo ACL-vs-container table) and **Spring CVE-2016-5007** (Spring Security vs Spring MVC matcher mismatch → MvcRequestMatcher).
- **2026 CVE wave:**
  - Traefik CVE-2026-40912, -48020 and **-88009** (opaque request-target: forwardAuth sees `/`, backend gets the real target);
  - Envoy CVE-2026-73551, -73511 and -73553 (`;` parameters);
  - APISIX CVE-2026-94269 and -124680;
  - Heimdall CVE-2026-42274 and Oathkeeper CVE-2026-33494 (PDPs matching raw paths).

**Bearing:** E4 RC1–RC7 are **known** as a class. The vendor position (W16 TRIAGE, xvnpw/HackerOne) is "documented behaviour". The only defensible framing is **prevalence and composition**:
- these splits are present on current releases across 3 gateways × N frameworks in default or documented configurations;
- they are orthogonal to sender-constraining: a valid DPoP proof neither helps nor hinders them;
- D-A closes them while D-B does not (§C6).

Presenting any RC as a discovery is indefensible.

**Positioning sentences:**
> "Path-policy bypasses caused by gateway/backend normalisation differences are well documented, from practitioner research on external-authorisation plugins [xvnpw 2021–22; Tsai 2018] to systematic studies of routing/authentication inconsistencies in Java applications [Zhang et al. CCS'25] and nginx configurations [Sadeghi et al. CCS'26], and continue to produce CVEs in current gateways (e.g., Traefik CVE-2026-88009, APISIX CVE-2026-124680, Envoy CVE-2026-73551). We include them (E4) not as new findings but to show that sender-constraining is orthogonal to them: a client holding a valid, correctly verified DPoP proof can still reach operations its gateway policy denies."

---

## C5. A1 claim ablation

**What prior work establishes:**
- **Design knobs:**
  - draft-ietf-oauth-signed-http-request (2016): `m`/`u`/`p`/`q`/`h`/`b`, all OPTIONAL;
  - RFC 9421: covered components are a deployment choice (pass 1);
  - RFC 9530 `Content-Digest`, whose recipient must check body = digest. A1 relies on exactly that.
- **Audience Injection (S&P'26)** shows that under-specified *binding claims* in signed artefacts are an active research and standards topic (aud, not htm/htu).
- The **2026 OAuth WG proposal to make htm/htu optional** (pass 1, [allam2026thread]) has had no empirical input so far.
- **No work measures** what each claim prevents against a mutation corpus or cross-op replay set.

**Bearing:** novel as measurement. Three results matter most to the standards discussion and are not anticipated anywhere:
1. "htm is invisible to path mutation but necessary against same-path method swap (192 hits without it)";
2. "+query fixes exactly the query class but inherits the fragment differential";
3. "body binding needs a body-seeing hop because edge verifiers never see the body".

**Positioning sentences:**
> "Binding more of the request is an old idea—the 2016 OAuth signed-request draft covered query, headers and body—and RFC 9421 makes coverage configurable. What has been missing is evidence of what each claim actually buys in a layered deployment. Our ablation provides it, and directly informs the current proposal to make `htm`/`htu` optional."

---

## C6. D-A and D-B

**What prior work establishes:**
- **"Check the view you execute" is the textbook fix:**
  - UABScan Finding III: sanitise to the router's form before checking;
  - Spring CVE-2016-5007: use MvcRequestMatcher, i.e. the router's matcher;
  - Emissary/Envoy `normalize_path` + `KEEP_UNCHANGED` (xvnpw: "path was normalized everywhere... also in authentication service");
  - Istio CVE-2021-39156: strip the fragment for authz *and* routing;
  - APISIX PR #14035: forward the matched path;
  - Heimdall 0.17.14: normalise before rules;
  - CWE-647.
- **D-A** (verify the executor's routed view) is that principle placed at the origin and applied to a PoP proof.
- **D-B** (verifier→executor HMAC over jti, method, canonical path and jkt). Neither pass found an equivalent. The closest neighbours are still Request Synchronization (hop-level, not public), the nygren request-binding draft and CREHMA (pass 1). "Access Control as Verified Parse Constraints" (arXiv 2609.12488) verifies gateway enforcement code against a single parse and is orthogonal.

**Bearing:**
- **D-A** is partially pre-empted (principle known); the PoP instantiation and its measured costs are new. Those costs are 43% attributable false rejection on path-rewriting scenarios and no tolerance for strip-prefix without a path map.
- **D-B** has no prior instance found. Report it honestly with two caveats:
  - it restores *binding* soundness but not *policy* soundness: 36 E4 dot-segment violations survive, because the PDP matched the raw path;
  - it depends on stripping `X-Verified-View` at the boundary (RC-W13-D: kong and haproxy pass a forged one).

**Positioning sentences:**
> "D-A applies the standard remedy for normalisation bypasses—authorise the representation the router acts on [Spring CVE-2016-5007; Zhang et al. CCS'25; APISIX PR #14035]—to proof verification. D-B is, to our knowledge, the first mechanism that cryptographically ties the view a PoP verifier accepted to the operation the executor dispatches; unlike hop-level request synchronisation [Topcuoglu et al.], it binds to the client's proof rather than to the previous hop."

---

## G3 implications (not one of the six claims, but found here)

- **Traefik CVE-2026-88009** (opaque or absolute-form request-target bypasses forwardAuth) is a concrete current instance of the GATE_DECISION open item "absolute-form target not in the E4 battery". Our traefik pin v3.7.19 is post-fix, but the primitive belongs in the battery.
- **oauth2-proxy CVE-2025-64484** (underscore header variants bypass `X-Forwarded-*` stripping, and the upstream normalises `_`→`-`) is a header-*name* differential that our G3 battery does not appear to include for `X-Verified-*` / `X-Client-Cert`. **This may be a cheap way to strengthen or break the "X-Verified-Sub spoofing blocked by every gateway" result.**
- **APISIX CVE-2026-124679** (forward-auth `allow_degradation` passes client copies of upstream headers) is G3-type and fixed in 3.20.0.

---

## Works that MUST be cited (pass-2 additions; pass-1 must-cites still apply)

| Key | Where | Why |
|---|---|---|
| p2:tsai2018breaking | intro, related work, G2 | origin of the check/use parser-inconsistency framing; `;`/`..;/` proxy vs backend |
| p2:xvnpw2021kong, p2:xvnpw2022ingress, p2:xvnpw2021apisix (+ traefik/emissary) | E4, G2 | exact prior art for the raw-`$request_uri` PDP split (e4 RC2) and the A_client variant |
| p2:zhang2025uabscan | E4, related work | systematic academic study of routing/auth inconsistencies; maps onto RC1, RC3–RC6 |
| p2:sadeghi2026nginxbuster | E4, related work | concurrent CCS'26 work on nginx auth bypass incl. URI normalisation |
| p2:hosseyni2026audience | C1, threat model | closest structural analogue (signed artefact accepted at the wrong endpoint); same group as the FAPI model |
| p2:golinelli2026post | G1 | **update the venue to ACSAC 2026** |
| p2:richer2016signedhttp | G1, A1 | query/header/body PoP binding was designed in 2016 |
| p2:istio2021_008 | G2 `#` | fragment-in-path authz bypass; its remedy explains our split |
| p2:envoy2021_29492, p2:apisix2026_124680, p2:apisix2026_94269 | G2 `%2f`, RC-W13-A | encoded-slash family; APISIX intentionally keeps `%2F` raw after the fix |
| p2:traefik2026_88009, p2:envoy2026_73551 / p2:istio2026_006 | G2/E4 currency | 2026 instances; evidence the class is live on current releases |
| p2:spring2016_5007 | D-A | canonical "use the router's matcher" remedy |
| p2:doyhenard2024gotta | G2 primitives | delimiter and normalisation discrepancy catalogue (cache oracle) |

**Should cite (space permitting):** p2:heimdall2026_42274, p2:oathkeeper2026_33494, p2:tsai2024confusion, p2:tiurin2018reverse, p2:oauth2proxy2025_64484 (if the G3 battery is extended), p2:gallo2026beyond, p2:choi2026spca, p2:peng2026h3act.

**Read before camera-ready:**
- NginxBuster (full text);
- PathFault (ICISC, title only; may overlap with G2 exploit generation).

## Residual risks and coverage gaps (do not hide these)

1. **Concurrent work.** NginxBuster (CCS'26, presented 2026-11-18) was read only at abstract level. If its seven classes include `auth_request` with `$request_uri`, our nginx E4 rows are pre-empted *academically* too, not just by practitioners.
2. **Venues not screenable today.**
   - The NDSS 2027 list is unavailable (the URL serves the 2017 list).
   - The S&P 2027 page lists no papers.
   - USENIX Security 2027 cycle pages are placeholders.
   - The EuroS&P 2026 accepted-paper page returns 403 (program.html was used).
   - **Re-run §R before submission.**
3. **Search coverage.**
   - Google Scholar was blocked (403).
   - The dblp web/API was blocked; dblp was covered through SPARQL, title-substring only, so abstract-only matches are missed.
   - arXiv rate-limited one call.
   - Single reviewer.
4. **Abstract-level items:** NginxBuster, Audience Injection, SPCA, H3Act, Gallo and all advisories. The practitioner talks by Tiurin and on ProxyShell are TITLE-level only.
5. **Secondary-source CVEs:** CVE-2026-2880 (fastify/middie) and CVE-2026-39852 (Quarkus) are **UNVERIFIED** and must not be cited without the primary advisory.

## §R. Recency check: what was screened and found
Keyword set used on every list: DPoP, possession, sender, OAuth, token, gateway, proxy, parser/parsing, differential, discrepancy, normalisation, canonical, URL/URI, path, HTTP, request, smuggling/desync, access control, authorisation, bypass, cache, WAF, GraphQL, API, routing, confusion, inconsistency.

| Venue | Relevant hits |
|---|---|
| CCS 2026 | **NginxBuster** (include); eMicro (background); OAuth mini-programs, RESTGuardian, PORTA, patch-guided routing (exclude) |
| S&P 2026 | **Audience Injection** (include); OAuth account linking, differential-fuzzing repair (exclude) |
| USENIX Sec 2026 | H3Act (background); Opossum, post-filtering access control (exclude) |
| NDSS 2026 | Token Time Bomb = JWTeemo (pass 1); Authentication Maze (exclude) |
| ACSAC 2026 | **When POST Becomes GET** (venue update) |
| AsiaCCS 2026 | nothing relevant (RESTing-LLAMA, 2PC signatures excluded) |
| EuroS&P 2026 (program) | nothing relevant |
| NDSS 2027, S&P 2027, USENIX 2027 | not available on 2026-11-24 |
| arXiv cs.CR 2026 | no DPoP, sender-constrained or path-normalisation paper. Gallo 2611.07159 (background); verified-parse gateway 2609.12488 (background); BAC detectors (exclude) |

**No 2024–2026 peer-reviewed paper was found that uses DPoP or any PoP proof acceptance as an oracle against the executed operation.** The pass-1 RQ-L1 answer still holds.

# Defence evaluation: E7 security, E8 baselines, A2 ablation, performance, false rejection (W17)

Worker **w17**, run 2026-11-23 on the shared 16 GB / 10-core macOS arm64 laptop (Docker Desktop 29.4.1, 10-CPU / 8 GB VM).
All topologies are real components brought up with `orchestrator.up --stubs off`, **one topology at a time**, and torn down after
each run. Compose projects are `w17-bh-*`; other containers are `w17-*`. Nothing under `harness/` was edited (§9 lists the local
work-arounds). Every number in this report traces to a file under `runs/`, `runs/frr/`, `results/` or `analysis/`.

**Defences and baselines** (CONTRACT §3/§4/§8, `harness/defence/README.md`)

| name | what is deployed | where the binding check looks |
|---|---|---|
| **B-edge** (status quo) | gateway (default profile) calls the verifier (rfc3986) on the client's view | gateway's view of the raw request |
| **B-origin** | `placement=origin`, executor `VERIFY_MODE=origin-raw` (the gateway does not verify) | raw target as the executor received it |
| **B-strict** | gateway **strict** profile, verifier rfc3986 | edge, after strict input rejection |
| **B-optional** | edge verifier with the htm/htu checks **disabled** (`bh-verifier:w17-optional`, a 3-line flag in a copy) | signature/ath/jti/iat only |
| **D-A** | `placement=origin`, executor `VERIFY_MODE=origin-routed` (effective method + matched route, params substituted, no query) | executor's routed view |
| **D-B** | edge verifier `VIEW_MAC=on` + executor `bh-exec-<fw>:defence` (`DEFENCE=db`): HMAC over (jti, method, canon path, jkt) recomputed from the routed view | verifier view == executor routed view |
| **D-C** | verifier `HTU_CANON=strict` + gateway **strict** profile | edge, after strict input rejection |

D-B exists for fastapi, express, spring and aspnet only (W11 patches); it is `n/a` for rails.

---

## 0. Summary (what each defence fixes)

| class (A_leak witnesses) | D-A origin-routed | D-B view MAC | D-C strict edge | B-origin | B-strict |
|---|---|---|---|---|---|
| G1 query dispatch `?op=` (55, + 2 `#` landing in the query) | ✘ 57/57 remain | ✘ 57/57 remain | ✘ 57/57 | ✘ | ✘ |
| G1 body dispatch (GraphQL `operationName`, content-type relabel, `_method` form to /graphql) (89) | ✘ 89/89 | ✘ 89/89 | ✘ 89/89 | ✘ | ✘ |
| G1 method override (`X-HTTP-Method-Override`, `_method` query/body) (31) | ✔ 0 | ✔ 0 | ✘ 31/31 | ✘ | ✘ |
| G2 `#` kept in the path by the origin server (28) | ✔ 0 | ✔ 0 | ✘ 28/28 | ✘ | ✘ |
| G2 APISIX decoded-view / raw-`%2f` split (12) | ✔ 0 | ✔ 0 | ✔ 0 | ✔ 0 | ✔ 0 |
| G2 dot-segment into a catch-all (12) | ✔ 0 | ✔ 0 | ✔ 0 | ✘ 12/12 | ✔ 0 |
| **all 229** | **146** | **146** | **205** | **217** | **205** |
| E4 (A_client + PDP), 52 violations | **0** | **36** (all dot-segment) | 4 (case-fold) | 31 | 4 |
| attributable false rejection, all scenarios | 43.2 % | 43.2 % | 28.8 % | 40.0 % | 28.8 % |
| … on non-rewriting scenarios only (S0, S4, S5) | 5.3 % (16/300) | 5.3 % (16/300) | 48.0 % (144/300) | 0 % | 48.0 % |

The two executor-view defences behave the same on every A_leak witness. **D-A and D-B close exactly the G2 path-view splits and the
method override.** They leave **all query and body dispatch** in place, because D-A's htu and D-B's MAC are path-only, as
CONTRACT §10 specifies. They differ under A_client. D-A runs the gateway's *policy* on the executor's routed view, so it closes every
E4 class. D-B binds execution to the verifier's **canonical** view, and the PDP matched the **raw** path, so the dot-segment classes
(E4-RC1/RC2) survive D-B. In those cases D-B restores *binding* soundness (the executor runs exactly the canonical view the proof was
checked against) but not *policy* soundness.

D-C (strict canonical edge) and the gateway-only B-strict give **identical** results everywhere. On the nginx, APISIX and Kong
witnesses, the strict gateway profiles reject every request that `HTU_CANON=strict` would have rejected first, so `HTU_CANON=strict`
added nothing. They fix `%2f` and dot-segments but not `#`, override or G1. They also reject every percent-encoded id.
B-optional reproduces every witness: no witness depends on a failed htm/htu check, by construction. On the full depth-1 corpus it
adds 29–47 hits per stack (§3).

Neither D-A nor D-B tolerates a path-rewriting gateway without a public→internal path map. Strip-prefix, version rewrite and
trailing-slash normalisation were **100 % rejected** by D-A, D-B and B-origin (§5). The catch-all route
(`/files/{path:path}`) is a false reject in all 4 frameworks under D-A and D-B: the shared D-A/D-B encoder escapes `/` inside a
multi-segment parameter (§5.2).

---

## 1. Step 1: `:defence` images, unit tests, e2e

* W11's shipped patches predate W15's `ROUTES=v2` code. `aspnet-defence-db.patch` no longer applies with `patch`: one hunk fails on
  context drift. Every anchor in W11's `make_patches.py` EDITS table still matches exactly once, so
  `scripts/apply_db.py` imports that table unchanged and applies it to fresh copies of the **current** executor sources under
  `build/src/executors/<fw>`. It also writes the regenerated diffs to `build/patches/<fw>-defence-db.v2.patch` (the v2 + defence
  merge asked for in the task).
* `scripts/build_defence.sh` appends one line to each copied Dockerfile, `ENV ROUTES=v2 DEFENCE=db VIEW_MAC_KEY=bh-test-view-mac-key`.
  The key is the topology default test key; the orchestrator cannot pass executor env, so it is baked in. It is not a deployment key.
  The script then builds `bh-exec-{fastapi,express,spring,aspnet}:defence` one at a time (ids in §8). `:latest` and `:v2` were never
  touched.
* **Unit tests**, run on a copy of `harness/defence` (`build/defence-tests`, `results/unit/`): Python **75 passed**, Node **38 passed**,
  Java **76** (6 + 70, 0 failures), C# **76 passed**. These equal W11's numbers.
* **e2e** (`scripts/run_e2e.sh`, a copy of W11's script using the `:defence` images; `results/e2e/`): all 7 cases × 4 frameworks give
  results **identical to W11's** (`results/e2e/summary.txt`). Method override → 401 `view_mac_mismatch`; query dispatch → 200
  `accountAction.close` (not covered); lifted header → 401; missing/duplicate header → 401; benign v1/v2 → 200.

## 2. E7: re-running the confirmed hit sets under each defence

### 2.1 Case sets and ground truth
`scripts/build_casesets.py` takes, **verbatim** from each experiment's `reruns/<topology>/cases.jsonl`, every hit case whose rerun
outcome was `confirmed` (3/3), plus every depth-0 baseline. It merges them per stack (11 sources, `cases/*.jsonl`, provenance in
`cases/*.meta.jsonl`):

| source stack | from | witnesses |
|---|---|---|
| nginx default × {fastapi, express, spring, aspnet} × override {off, on} | `kill` (W9) + `ext-routes` (W15, v2 routes) | 189 |
| APISIX default × express / aspnet, override off (`%2f`, RC-W13-A) | `ext-gw` (W13) | 41 |
| Kong default × fastapi, override off (`#`, RC-W13-B) | `ext-gw` | 19 |

229 A_leak witnesses in total (identical requests across stacks count once per stack). **Class is assigned by mechanism and
observed effect.** A `_method` form body sent to `/graphql` changes the op through **body** dispatch (`graphql.unknown`), not through
an override. A fragment that lands in the **query** (`op=freeze#frag`) is a G1-query effect, as in kill RC7.
**Route space.** All configurations use the v2 route space (`ROUTES=v2`, a superset of v1): `bh-exec-<fw>:v2` for B-* / D-A / D-C,
and `:defence` (v2 + D-B) for D-B. Ground truth op(π) was regenerated on `:v2` for all 17 base ops × 8 (framework, override) pairs,
sent directly with `VERIFY_MODE=off` (`scripts/groundtruth.sh`, `groundtruth/`). All 136 are conformant. Runs use W15's
`ext_run_matrix.py` (copied), which registers the v2 base ops for minting.
**E4** (A_client + PDP) replays W12's 29-vector battery (`../e4/cases.jsonl`, W12's runner and oracle used unchanged) on one
representative topology per class (E4 REPORT §7), with the `:v2` / `:defence` executors and `bh-pdp-{allow,block}` in the verifier
slot. Under D-B the PDP emits `X-Verified-View` (it returns `verifier.core` response headers).

### 2.2 Results, A_leak (binding oracle `oracle.correlate`; `analysis/e7_tables.md`, `analysis/e7_aleak_long.csv`)

Remaining hits per class (out of the B-edge witnesses):

| class (witnesses) | B-edge | B-origin | B-strict | B-optional | D-A | D-B | D-C |
|---|---|---|---|---|---|---|---|
| G1-query (55) | 55 | 55 | 55 | 55 | 55 | 55 | 55 |
| G1-query, `#` landing in the query (2) | 2 | 2 | 2 | 2 | 2 | 2 | 2 |
| G1-body (89) | 89 | 89 | 89 | 89 | 89 | 89 | 89 |
| G1-override (31) | 31 | 31 | 31 | 31 | **0** | **0** | 31 |
| G2-# (28) | 28 | 28 | 28 | 28 | **0** | **0** | 28 |
| G2-%2f (12) | 12 | **0** | **0** | 12 | **0** | **0** | **0** |
| G2-dot (12) | 12 | 12 | **0** | 12 | **0** | **0** | **0** |
| **all (229)** | **229** | **217** | **205** | **229** | **146** | **146** | **205** |
| new hits on baseline cases | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| baselines not executed as op(π) | 0/175 | 0/175 | 0/175 | 0/175 | 8/175 | 8/175 | 0/175 |

Where the stopped witnesses were stopped:

| | B-origin | B-strict | D-A | D-B | D-C |
|---|---|---|---|---|---|
| verifier deny (`htu_mismatch` / `htm_mismatch`) | 12 | 0 | 83 | 0 | 0 |
| executor deny (D-B `view_mac_mismatch`) | 0 | 0 | 0 | 83 | 0 |
| gateway 400 (strict profile) | 0 | 24 | 0 | 0 | 24 |

Per source (`analysis/e7_per_source.md`):

| source (witnesses) | B-edge | B-origin | B-strict | B-optional | D-A | D-B | D-C |
|---|---|---|---|---|---|---|---|
| ngx-fastapi-ovoff (27) | 27 | 27 | 25 | 27 | 14 | 14 | 25 |
| ngx-fastapi-ovon (39) | 39 | 39 | 37 | 39 | 14 | 14 | 37 |
| ngx-express-ovoff (17) | 17 | 17 | 15 | 17 | 15 | 15 | 15 |
| ngx-express-ovon (22) | 22 | 22 | 20 | 22 | 11 | 11 | 20 |
| ngx-spring-ovoff (16) | 16 | 16 | 14 | 16 | 14 | 14 | 14 |
| ngx-spring-ovon (17) | 17 | 17 | 15 | 17 | 11 | 11 | 15 |
| ngx-aspnet-ovoff (14) | 14 | 14 | 14 | 14 | 14 | 14 | 14 |
| ngx-aspnet-ovon (17) | 17 | 17 | 17 | 17 | 11 | 11 | 17 |
| apisix-express-ovoff (21) | 21 | 15 | 15 | 21 | 15 | 15 | 15 |
| apisix-aspnet-ovoff (20) | 20 | 14 | 14 | 20 | 14 | 14 | 14 |
| kong-fastapi-ovoff (19) | 19 | 19 | 19 | 19 | 13 | 13 | 19 |

What each configuration fixes, and why:
* **D-A** checks htm against the effective method after override, and htu against the matched route. Override, `#` (the route
  param `acc-alice-1#frag` is re-encoded as `%23frag`), `%2f` and dot-segment catch-all params all become `htu/htm_mismatch`. It
  cannot see the query or the body, so 146 G1 dispatch hits remain.
* **D-B** gives the same set as D-A, enforced at the executor as `view_mac_mismatch`. All gateways propagated the verifier's
  `X-Verified-View`: no `view_mac_missing` occurred on any baseline.
* **D-C = B-strict.** The nginx/APISIX/Kong strict profiles return 400 for `%2f` and for raw/encoded dot-segments *before* the
  verifier, so `HTU_CANON=strict` never fired (0 verifier denies). `#` survives: none of the strict profiles rejects a `#` in the
  target, and the verifier strips the fragment in every mode (§10).
* **B-origin** (raw target re-verified at the executor) closes only APISIX `%2f`: the executor receives the raw `%2f`, so htu
  mismatches. It keeps `#` and dot-segments. The verifier's RFC 3986 normalisation turns `reports/./logo.png` back into the htu, while
  the catch-all executes `path="reports/./logo.png"`. This is the A3 result again.
* **B-optional** adds nothing on this witness set, because a witness by definition passed the full verifier. Its security delta
  shows on the full corpus (§3).

### 2.3 Results, E4 (A_client; W12 authorization oracle; `analysis/e4_by_cfg.csv`, `analysis/e4_by_family.md`)

Violations per representative topology, by vector family:

| E4 topology (class) | B-edge | B-origin | B-strict | D-A | D-B | D-C |
|---|---|---|---|---|---|---|
| RC1 aspnet nginx allow-list | dotseg 7, encdotseg 2 | dotseg 7, encdotseg 2 | 0 | **0** | dotseg 7, encdotseg 2 | 0 |
| RC2 Kong fastapi allow-list | dotseg 7, encdotseg 2 | 0 | 0 | **0** | dotseg 7, encdotseg 2 | 0 |
| RC3 aspnet nginx blocklist | case 2, dotseg 7, encdotseg 2 | case 2, dotseg 7, encdotseg 2 | case 2 | **0** | dotseg 7, encdotseg 2 | case 2 |
| RC4 express nginx blocklist | case 2 | case 2 | case 2 | **0** | 0 | case 2 |
| RC5 spring nginx blocklist | matrix 3 | matrix 3 | 0 | **0** | 0 | 0 |
| RC6 rails nginx blocklist | dslash 3 | dslash 3 | 0 | **0** | n/a | 0 |
| RC7 Kong spring blocklist | dotseg 7, dslash 3, encdotseg 2, matrix 3 | matrix 3 | 0 | **0** | dotseg 7, encdotseg 2 | 0 |
| **total** | **52** | **31** | **4** | **0** | **36** (of 49 applicable) | **4** |
| legit-* vectors executed | 21/21 | 21/21 | 21/21 | 21/21 | 18/18 | 21/21 |

B-edge reproduces W12's confirmed counts exactly (9/9/11/2/3/3/15). Under **D-A** the PDP sits in the verifier slot and the executor
asks it about the **routed** view, so the policy matches what will execute and every class closes, with no legitimate vector lost.
**D-B** closes case-fold, matrix and `//` (the routed template differs from the verifier's view). It does not close `/../`: the
verifier canonicalises `acc-alice-1/../acc-bob-1` to `acc-bob-1`, which is exactly what Kestrel and Kong execute, so the MAC matches.
The split is between the PDP's raw-path match and the canonical view, outside what the MAC covers. W12's own fix
(`POLICY_NORMALIZE=rfc3986`, E4 REPORT §10) is the complement D-B needs.

## 3. E8: baseline deltas

| baseline | A_leak witnesses remaining | E4 violations remaining | attributable FRR |
|---|---|---|---|
| B-edge | 229 | 52 | 0 % (reference) |
| B-origin | 217 (−12: APISIX `%2f`) | 31 (−21: Kong `/../` and `//`; Kestrel `/../` and Spring `;` stay) | 40.0 % |
| B-strict | 205 (−24: `%2f`, dot) | 4 (case-fold only) | 28.8 % |
| B-optional | 229 (witness set) | n/a* | not measured |
| D-A | 146 (−83) | 0 | 43.2 % |
| D-B | 146 (−83) | 36 | 43.2 % |
| D-C | 205 (−24) | 4 | 28.8 % |

\* Under A_client the proof always matches the request, so disabling htm/htu is a no-op. It was not run.

**What the htm/htu checks buy** (B-optional vs B-edge on the **full** W15 depth-1 corpus, 581 cases;
`runs/e8full/`, `analysis/e8_full_corpus.md`):

| stack | config | verifier allow | hits | hits by primitive group |
|---|---|---|---|---|
| nginx/fastapi/override on | B-edge | 401 | 23 | hdr-xhmo 12, frag 9, dot 2 |
| | B-optional | 509 | **52** | matrix 14, hdr-xhmo 12, frag 9, other g2 7, dot 6, pct2f/trailing/abs-form/prefix 1 each |
| nginx/express/override on | B-edge | 401 | 11 | fmethod 3, hdr-xhmo 3, qmethod 3, dot 2 |
| | B-optional | 509 | **58** | dot 18, matrix 14, other g2 7, pct2f 7, override 9, trailing/abs-form/prefix 1 each |

Making the htm/htu binding optional (as several deployments treat DPoP) multiplies the hits 2.3× and 5.3× on these two stacks. The
added hits are path mutations the verifier would have rejected as `htu_mismatch`.

## 4. A2: leave-one-out over D-B's canonicalisation steps

**Method** (`scripts/a2_ablation.py`, `analysis/a2_tables.md`, `analysis/a2_long.csv`). D-B accepts iff `UPPER(view_method) ==
UPPER(exec_method)`, `canon(view_uri) == canon(substitute(template, params))`, and no parameter is `.`/`..`. jti and jkt are equal on
both sides. The check is therefore replayed **offline** with W11's own `viewmac.canon_path` / `substitute` over the B-edge logs
(the verifier view plus the executor's route/params/method for the same jti). **Validation:** the offline model agrees with the live
D-B runs on **472/472** cases, including every live false reject. Ablations, one step removed at a time:
`-pct` (decoded params inserted without the D-A/D-B encoder), `-dot` (no `.`/`..` guard, no `remove_dot_segments` on the executor
side), `-case` (case-insensitive compare), `-slash` (`//` merged on both sides), `-prefix` (mount prefix dropped; version-agnostic
compare), and the references `-method` (path-only MAC) and `-pct-slash` (a pair).

Cells for witness rows count witnesses accepted, i.e. **hits that come back**. Cells for legit/FRR rows count legitimate requests
accepted.

| set | group (n) | full | -pct | -dot | -case | -slash | -prefix | -method | -pct-slash |
|---|---|---|---|---|---|---|---|---|---|
| E7 | G1-override (31) | 0 | 0 | 0 | 0 | 0 | 0 | **31** | 0 |
| E7 | G2-# (28) | 0 | **28** | 0 | 0 | 0 | 0 | 0 | **28** |
| E7 | G2-%2f (12) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **6** |
| E7 | G2-dot (12) | 0 | **8** | 0 | 0 | 0 | 0 | 0 | **12** |
| E7 | G1-query / -body (146) | 146 | 146 | 146 | 146 | 146 | 146 | 146 | 146 |
| E4 | case (4) | 0 | 0 | 0 | **4** | 0 | 0 | 0 | 0 |
| E4 | dslash (6) | 0 | 0 | 0 | 0 | **6** | 0 | 0 | **6** |
| E4 | matrix (6) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| E4 | dotseg + encdotseg (36) | 36 | 36 | 36 | 36 | 36 | 36 | 36 | 36 |
| E7 | legit baselines (175) | 167 | 173 | 167 | 167 | 167 | 167 | 167 | 175 |
| FRR | S0 identity (68) | 64 | 67 | 64 | 64 | 64 | 64 | 64 | 68 |
| FRR | S4 pct-encoded ids (164) | 156 | **92** | 156 | 156 | 156 | 156 | 156 | 92 |
| FRR | S1/S2/S3 rewrites (200) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| E4 | legit (21) | 21 | 21 | 21 | 21 | 21 | 21 | 21 | 21 |

Reading:
* **The percent-encoder is the load-bearing step.** Without it, all 28 `#` hits come back (`acc-alice-1#frag` inserted raw is
  stripped as a fragment by `canon_path`), and so do 8 of 12 dot-segment hits. Together with slash merging, all 12 dot hits and the 6
  express `%2f` hits come back. The aspnet `%2f` hits keep `%2f` literally in the route value and stay closed. Removing it also
  *reduces* false rejects on the catch-all (173 vs 167 baselines accepted) but *raises* them on encoded ids (92 vs 156).
* **Method binding** is what closes the override class (31).
* **Not folding case** and **not merging slashes** are what close E4's case-fold (4) and `//` (6) classes. A "lenient" D-B that
  folded case or merged slashes would reopen them.
* **`-dot` and `-prefix` bring nothing back** on our witnesses. The verifier already resolves dots, no witness had a `.`/`..`
  parameter, and under A_leak the request path must equal the htu at the verifier, so a version-agnostic prefix map cannot be
  exploited without a rewriting gateway. They are defence-in-depth here, not load-bearing (W11's README describes the `..`-parameter
  seam analytically).
* **No ablation touches G1 query/body, E4 dot-segment, or the path-rewrite false rejects.** These are outside what a path-only view
  binding can express.

## 5. False rejection on legitimate rewrites (task item 6)

### 5.1 Setup
`scripts/frr_client.py` generates the legitimate request set from `../ext-routes/bench-api.v2.openapi.yaml`: all 17 path × method
operations, with parameter values and bodies from the registered base ops, which mirror the spec examples. It sends them in
6 scenarios. Each request carries a fresh **valid** proof whose htu is the public URL **exactly as sent** (no query).
* **S0 identity** (control).
* **S1 strip-prefix mount:** `/svc/api/...` → `/api/...`.
* **S2 versioned rewrite:** `/api/latest/...` → `/api/v1/...`.
* **S3 trailing slash:** the gateway strips a trailing `/`.
* **S4 percent-encoded ids:** `%2D`, `%2d`, `%20`, UTF-8 `%C3%A9`, `%2F`.
* **S5 H2→H1:** h2c with prior knowledge via curl/nghttp2 1.68.1; nginx proxies HTTP/1.1.

The rewrites are injected by `scripts/frr_nginx.py` into the **orchestrator-generated** nginx.conf after `orchestrator.up`, followed
by `nginx -s reload`. The rendered `/api/` location is copied verbatim with one `rewrite … break` line, plus `http2 on;`. The
gateway is nginx 1.30.7, and the frameworks are fastapi, express, spring and aspnet. That gives 129 requests per framework,
516 per configuration and 3,096 in total (`runs/frr/`, `analysis/frr_long.csv`).
**Attributable** false reject means B-edge executed the request correctly, with the same framework and the same request, and the
configuration did not. This nets out framework behaviour: Starlette and Spring return 404 on a `%2F` id with no defence at all.

### 5.2 Results (`analysis/frr_tables.md`, `analysis/frr_summary.json`)

Attributable false rejects / requests B-edge served:

| scenario | B-edge | B-origin | B-strict | D-A | D-B | D-C |
|---|---|---|---|---|---|---|
| S0 identity | 0/68 | 0/68 | 0/68 | 4/68 | 4/68 | 0/68 |
| S1 strip-prefix | 0/68 | **68/68** | 0/68 | **68/68** | **68/68** | 0/68 |
| S2 version rewrite | 0/64 | **64/64** | 0/64 | **64/64** | **64/64** | 0/64 |
| S3 trailing slash | 0/68 | **68/68** | 0/68 | **68/68** | **68/68** | 0/68 |
| S4 pct-encoded ids | 0/164 | 0/164 | **144/164** | 8/164 | 8/164 | **144/164** |
| S5 h2→h1 | 0/68 | 0/68 | 0/68 | 4/68 | 4/68 | 0/68 |
| **all** | **0/500** | **200/500** | **144/500** | **216/500** | **216/500** | **144/500** |
| FRR [95 % Wilson CI] | 0.0 % [0.0, 0.8] | 40.0 % [35.8, 44.4] | 28.8 % [25.0, 32.9] | 43.2 % [38.9, 47.6] | 43.2 % [38.9, 47.6] | 28.8 % [25.0, 32.9] |

Raw failures, including framework 404s: B-edge 16/516 (`%2F` ids on fastapi and spring).

Causes:
* **Rewrites (S1–S3): D-A, D-B and B-origin reject 100 %.** The proof is bound to the *public* URI, and the executor-side view is the
  *internal* one: the routed template, or the raw rewritten target. D-B reports `view_mac_mismatch`, D-A and B-origin
  `htu_mismatch`. This is inherent: an executor-side view defence needs the gateway's public→internal path map (or the verifier must
  MAC the *rewritten* path the gateway forwards). Neither W11's D-B nor the D-A spec has one. The edge-only configurations (B-edge,
  B-strict, D-C) are unaffected because they verify the public view.
* **Catch-all (S0/S5, 1 request × 4 frameworks):** D-A and D-B escape `/` inside the multi-segment parameter `reports/logo.png` →
  `reports%2Flogo.png` ≠ the verifier's `/files/reports/logo.png`. The same seam appears as 8/175 baseline failures in E7. W11's
  encoder predates W15's catch-all route. The fix is to keep `/` literal for wildcard parameters and apply the `.`/`..` guard per
  segment.
* **`%2F` in an id (S4, aspnet, 8 requests):** Kestrel keeps `%2F` encoded in the route value, and the encoder double-encodes it to
  `%252F`. W11 predicted exactly this fail-closed case (`EncodedSlashParamFailsClosed`). Express decodes the value and re-encodes it,
  so it matches.
* **Strict profiles (B-strict, D-C):** the nginx strict deny-list returns **400 for every percent-encoded id**: `%2D`, `%20`,
  `%C3%A9`, `%2F`.
* **H2→H1** costs nothing beyond the catch-all seam: nginx re-frames the request, and method and target survive.
* On **non-rewriting** traffic (S0+S4+S5), D-A and D-B false-reject **16/300 = 5.3 %**, all caused by the two encoder seams above.
  B-origin false-rejects 0 %, and D-C/B-strict 48.0 %.

The scenario mix is synthetic, so the "all" row depends on how much rewritten traffic one assumes. The per-scenario rows are the
result.

## 6. Performance (task item 5)

PERF_SECTION

## 7. Determinism

Every E7/E8 configuration was replayed **twice** on freshly started topologies: `runs/` and `runs_rep2/`, rep 2 queued after perf
(`scripts/phase3.sh`). The witnesses themselves were already 3/3-confirmed upstream.

REP2_SECTION

## 8. Provenance

| image | id |
|---|---|
| `bh-exec-fastapi:defence` | `sha256:b985137bf76e` |
| `bh-exec-express:defence` | `sha256:e713363509ad` |
| `bh-exec-spring:defence` | `sha256:63ac61e83f12` |
| `bh-exec-aspnet:defence` | `sha256:df600480d9ff` |
| `bh-exec-{fastapi,express,spring,aspnet,rails}:v2` | `8955b9a3f6fe`, `c9605a0a520f`, `68f4b8ad37a1`, `8e8dd4011848`, `843848b529d7` (W15, unchanged) |
| `bh-verifier:latest` | `sha256:263f3231d20f` (W3, unchanged) |
| `bh-verifier:w17-optional` | `sha256:764dbe1b3582` (copy + `BINDING_CHECKS=off`; diff in `build/verifier-optional/core.py.diff`) |
| `bh-pdp-allow:latest` / `bh-pdp-block:latest` | `8981036e677c` / `8515bfc52ef2` (W12, unchanged) |
| gateways | `nginx:1.30.7-alpine` `caf4e1e032a2`, `kong:3.9.5` `e9b87ddd0e60`, `apache/apisix:3.21.0-debian` `1741a8e1186e` |
| load generator | `grafana/k6:1.3.0` |

Per-run image ids are in `runs/**/images.json`, and the full list in `analysis/images.md`. The Docker clock skew was 0 s at sweep
start (`sweep_progress.log`). There were 0 `iat_skew` denials.

## 9. Deviations, work-arounds and limitations (honest list)

1. **Host artefact in origin placement.** nginx's and Kong's *default* profiles rewrite `Host` to `executor:8080`. App-side
   verification (D-A, B-origin) then denies **every** request, legitimate ones included, as `htu_mismatch`, which is ext-fw's A3.2
   artefact. The first D-A sweep hit exactly this: 149/175 baselines were denied. It is kept for the record in
   `runs_invalid/da_default_profile_host_rewrite/` and **not used**. For D-A and B-origin on nginx and Kong I therefore use the
   **recommended** profile, which differs only by Host preservation (nginx: also X-Forwarded-*, keep-alive, and directives equal to
   nginx defaults; Kong: `preserve_host=true` only). This keeps `orchestrator.up` unmodified, and the kill/ext-gw experiments
   measured default == recommended for every hit.
2. **Executor env.** The orchestrator passes no `DEFENCE`, `VIEW_MAC_KEY` or `ROUTES` to the executor, so these are baked into the
   `:defence` image (§1). `BINDING_CHECKS=off` is baked into `bh-verifier:w17-optional`. W18's `bh-verifier:ablate` did not exist
   when this ran.
3. **FRR rewrites** are injected into the generated nginx.conf after `orchestrator.up` (no gateway renderer supports rewrites). The
   generated configs are copied into each `runs/frr/**/generated/`. FRR was measured on nginx only.
4. **D-B scope.** D-B covers 4 of 8 frameworks (W11), so RC6/rails is `n/a`. D-A covers all 8, but only frameworks present in the
   hit sources were run: fastapi, express, spring, aspnet and rails.
5. **Witness-set design.** E7 re-runs only the confirmed witnesses plus baselines; it does not re-run the full corpora under each
   defence. New hits *introduced* by a defence would only show on the baselines (0 found) or on the E8 full-corpus runs, which were
   done for B-optional only. This choice follows from "re-run the CONFIRMED hit sets".
6. **A2 is offline.** It is exact for D-B's decision function: 472/472 agreement with the live runs. It does not re-run the
   framework, so ablated variants are assumed not to change routing, which they cannot.
7. **Perf:** see §6 for the laptop caveat. Numbers are **preliminary pending a dedicated Linux server**.

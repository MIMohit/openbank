# Ablations A1, A4, A5 (W18)

Worker **w18**, run 2026-11-23. Every run used real components (`orchestrator.up --stubs off`), one topology at a time,
under compose projects `w18-bh-*`, and each topology was torn down afterwards. Every number below comes from a file
under `binding/experiments/ablation/` (paths given in each section). The scripts that produce them are listed in
`README.md`.

Pinned components: gateway **nginx 1.30.7-alpine** for A1; the A5 strict runs use the W6 pins (envoy v1.39.6,
traefik v3.7.19, kong 3.9.5, apache/apisix 3.21.0-debian, haproxy 3.2.27). Executors are `bh-exec-{fastapi,spring,rails,laravel,aspnet}:v2`
(`ROUTES=v2`; 17 base ops). The verifier is **`bh-verifier:ablate`** (`sha256:ba28b0f1ffa7…`), a copy of `harness/verifier`
plus `bind.py` and `digest_gate.py`. With `BIND_CLAIMS=full` it passes all 124 original verifier tests, plus 6 new
`test_bind.py` tests. The E4 PDP images are `bh-pdp-{allow,block}:latest` (W12).

---

## A1. Binding-claim ablation: what htm, htu and ath buy, and what query/body binding fixes

### Design
`BIND_CLAIMS` variants, implemented in `verifier_ablate/bind.py`:

| variant | verifier behaviour | proof (minter_ablate.mint_bound) |
|---|---|---|
| `full` | RFC 9449 §4.3: htm, htu (path only; query and fragment ignored), ath | standard |
| `no-htm` / `no-htu` / `no-ath` | that claim is neither required nor checked | standard |
| `+query` | htu **includes the query**. The query is compared after RFC 3986 percent-encoding normalisation (`QUERY_CANON=rfc3986`; `exact` and `sorted` are also built). A missing query is bound too: no `?` must meet no `?`. | htu = htu + `?` + the canonical query |
| `+digest` | the proof claim `cdig` must equal the request's single `Content-Digest` header (RFC 9530, sha-256). **And** a body-seeing hop (`digest_gate`, inserted between nginx and the executor) rejects any request whose body does not match that header, or that has a missing or duplicated header. | claim `cdig` = Content-Digest(canonical body); the header is sent |
| `digest-nogate` | as `+digest`, but without the gate: the edge verifier binds only the header | same |
| `+query,+digest` | both | both |

**Why `+digest` needs two halves (minimal sound variant).** nginx `auth_request` sends the verification subrequest with
`proxy_pass_request_body off` (`runs/*/generated/gateway/nginx.conf`), and HAProxy's Lua adapter sends no body either.
So an edge verifier never sees the content. A sound body binding therefore needs (1) the proof to cover the
Content-Digest value, which the verifier checks, and (2) a component that holds the body to check body = digest, which
RFC 9530 §2 calls the recipient check. Neither half alone is sound. We use an experimental proof claim (`cdig`) rather
than an RFC 9421 signature over `content-digest`. The security argument is the same: a signature covers the header,
and the header covers the body. RFC 9449 defines no body-binding claim.

**Case sets.**
- `cases.jsonl`: the kill-style exhaustive depth-1 A_leak set over all 17 base ops (the 13 v1 kill ops plus the 4 v2
  ops) × (84 W7 primitives + the 2 W15 `x-frag-*` primitives), plus 17 baselines. 1,239 cases.
- `cases_swap.jsonl`: 357 cases. The leaked proof for op p is replayed on the canonical request of each other op q (272),
  or with another request method (68), plus 17 baselines.

The swap set is needed because the A_leak primitive catalogue never rewrites the request-line method, and never moves
the path to another op (§A1.2).

**Matrix.** 8 variants × nginx default edge × {fastapi, spring, rails, laravel} (`:v2`) × override {off, on}
= **64 topologies × 1,239 cases = 79,296 requests**, plus **64 × 357 = 22,848** swap requests. There were 0 transport
errors. Ground truth (`groundtruth/`) covers all 17 ops for every (framework, override) pair, with 0 nonconformant.

### A1.1 Hits per variant (kill-style set; `analysis/a1_variant_summary.csv`, `a1_variant_mechanism.csv`)

| variant | verifier allow | gate deny | **hits** | G1 | G2 | other path | S1 | max res | Δ vs full |
|---|---|---|---|---|---|---|---|---|---|
| full | 6,888 | 0 | **192** | 132 | 60 | 0 | 128 | 6 | n/a |
| no-htm | 6,888 | 0 | 192 | 132 | 60 | 0 | 128 | 6 | **identical hit set** |
| no-ath | 6,888 | 0 | 192 | 132 | 60 | 0 | 128 | 6 | **identical hit set** |
| no-htu | 8,688 | 0 | **432** | 132 | 128 | 172 | 344 | **10** | +240, −0 |
| +query | 6,168 | 0 | **147** | 87 | 60 | 0 | 84 | 6 | +0, **−45** |
| digest-nogate | 6,888 | 0 | 192 | 132 | 60 | 0 | 128 | 6 | **identical hit set** |
| +digest (with gate) | 6,888 | 712 | **129** | 69 | 60 | 0 | 114 | 6 | +0, **−63** |
| +query,+digest | 6,168 | 712 | **84** | 24 | 60 | 0 | 70 | 6 | +0, **−108** (= 45 + 63) |

"G1" counts the by-design mechanisms M1–M5 plus M7. "G2" counts M6, M8 and M9. "Other path" counts hits that appear
only when htu is not checked, by primitive family: matrix-param 108, backslash 36, prefix-rewrite 16, absolute-form 8,
trailing-slash 4. These hits are reached through path primitives the htu check normally rejects. no-htu also adds
22 `%2f` (M8-shaped) hits and 46 dot-segment hits. Baseline false rejection was **0 in all 64 topologies**.

By mechanism (hits summed over the 8 topologies per variant):

| mechanism | full | no-htu | +query | +digest | +query,+digest |
|---|---|---|---|---|---|
| M1 query dispatch (G1) | 40 | 40 | **0** | 40 | **0** |
| M2 JSON-body dispatch (G1) | 26 | 26 | 26 | **0** | **0** |
| M4 `_method` form body replaces JSON (G1) | 29 | 29 | 29 | **0** | **0** |
| M5b POST-only override → PUT/DELETE (G1) | 22 | 22 | 17 | 14 | **9** |
| M5a header override on any method (G1, fastapi) | 9 | 9 | 9 | 9 | **9** |
| M3 Content-Type relabel (G1) | 2 | 2 | 2 | 2 | **2** |
| M7 `#` inside the query value (G1 effect, G2 vehicle) | 4 | 4 | **4** | 4 | **4** |
| M6 `#` kept in the path (G2) | 44 | 44 | 44 | 44 | **44** |
| M9 dot segment captured by a catch-all (G2) | 16 | 62 | 16 | 16 | **16** |
| M8 decoded-view `%2f` split | 0 | 22 | 0 | 0 | 0 |

Per-cell values (variant × framework × override) are in `analysis/a1_per_topology.csv`. For example, fastapi/on goes
39 → 34 (+query) → 31 (+digest) → 26 (both); spring/off goes 16 → 11 → 8 → **3**.

### A1.2 What htm/htu/ath buy: cross-op replay (swap set; `analysis/a1_runs_swap_variant_summary.csv`)

| variant | hits (8 topologies) | per topology | max resolution | kind |
|---|---|---|---|---|
| full, no-ath, +query, digest-nogate, +digest, +query,+digest | **0** | 0 | 1 | n/a |
| **no-htm** | **192** | 24 | **4** | 96 method-only swaps (same path, other method → sibling op) + 96 cross-op swaps that share the path |
| **no-htu** | **720** | 90 | **9** | every same-method cross-op replay (e.g. a `getAccount` proof runs `adminListUsers`, `me`, …) |

### A1.3 Findings
1. **htu does nearly all the work against request mutation.** On the kill-style set, htu accounts for every verifier
   deny (1,800 of 1,800 denials are `htu_mismatch`). Removing it more than doubles the hits (192 → 432) and raises
   binding resolution from 6 to 10. On the swap set it prevents 720 cross-op replays (resolution 9).
2. **htm buys nothing against the mutation catalogue, but it is what stops method-swap replay.** No A_leak primitive
   rewrites the request-line method, so `no-htm` = `full` on 1,239 cases × 8 topologies. With a swapped method, a leaked
   proof runs the sibling op on the same path (192 hits, resolution 4). htm is therefore **necessary, not redundant**.
   This bears directly on the IETF "htm/htu optional" question: dropping htm is invisible to a path-mutation corpus but
   reopens trivial same-path replay.
3. **ath buys nothing in A_leak** (identical hit set). This is expected: the attacker replays the proof with the token it
   was minted for. ath matters only when a proof can be paired with a *different* token of the same key, and that case
   is not in this threat model or case set.
4. **Query binding (+query) removes exactly the query-dispatch class.** It removes M1 (40 → 0) and the query-carried
   override (M5b via `?_method=`, 5 hits), 45 hits in total, and it never adds a hit. It does **not** fix `?op=freeze#frag`
   (M7, 4 hits). The verifier's RFC 3986 parse puts `#frag` in the fragment and the query still matches, while uvicorn,
   Go and FrankenPHP keep `#frag` inside the query value. Query binding inherits the fragment differential.
5. **Body binding (+digest) removes the body-dispatch classes, but only with a body-seeing hop.** With the gate it
   removes M2 (26 → 0), M4 (29 → 0) and 8 form-body overrides (M5b 22 → 14), 63 hits in total, and the gate rejected 712
   body-mismatched requests. **Without the gate (`digest-nogate`) the hit set is identical to `full`**: binding the
   Content-Digest *header* at an `auth_request` edge buys nothing, because the attacker keeps the leaked header and
   swaps the body.
6. **What is left after binding query and body (84 hits) is header-carried semantics plus the G2 path differentials.**
   That means `X-HTTP-Method-Override` (M5a 9, M5b 9), the `Content-Type` relabel (M3 2), the `#` in path or query
   (M6 44, M7 4) and the dot-segment catch-all (M9 16). **All 60 G2 hits survive every binding variant.** Covering more
   of the request does not fix interpretation differentials. Only canonicalisation at, or agreement between, the
   verifier and the router does.

### A1.4 Legit-traffic false rejection (`legit/runs/*/legit.jsonl`)
There are 18 legitimate requests (`scripts/legit.py`). Each client signs exactly what it sends: unsorted and multi-param
queries, `%7E`, lower- and upper-case hex, `%20` and `+`, `%5B…%5D`, duplicate keys, a bare flag, and JSON bodies,
including one sent with `Transfer-Encoding: chunked`, plus PUT, DELETE and an empty GET. Executor fastapi:v2.

| verifier | nginx 1.30.7 default (forwards `$request_uri` verbatim) | HAProxy 3.2.27 recommended (`percent-decode-unreserved`, `percent-to-uppercase`) + `normalize-uri query-sort-by-name` |
|---|---|---|
| full | 0 / 18 | 0 / 18 |
| +query, `QUERY_CANON=exact` | 0 / 18 | **4 / 18** (2 reordered, `%7E`→`~`, `%c3`→`%C3`) |
| +query, `rfc3986` (default) | 0 / 18 | **2 / 18** (the 2 reordered queries) |
| +query, `sorted` | 0 / 18 | 0 / 18 |
| +digest (gate) | 0 / 18 (incl. chunked: nginx de-chunks; the digest is over the content) | **18 / 18**: the Lua forward-auth adapter forwards only `Authorization` and `DPoP`, so the verifier never receives `Content-Digest` (`digest_header_missing`) |
| +query,+digest | 0 / 18 | 18 / 18 (same cause) |

Reading:
- Through a proxy that forwards the raw target, which is nginx's default for `auth_request` (`$request_uri`), query
  binding causes no false rejection.
- Behind a hop that re-encodes the query (HAProxy's *recommended* normalisers run before the authz action), naive exact
  matching rejects 22%. RFC 3986 normalisation absorbs the re-encoding but not reordering. Only a sorted comparison
  absorbs `query-sort-by-name`. That comparison is still safe against the M1 attacks (40 → 0 hits are removed by
  `rfc3986`, and sorting is stable for duplicate keys), but sorted comparison was not run against the full attack set.
- For +digest, the false-rejection risk is integration, not transformation. The gateway's auth adapter must forward
  `Content-Digest`, and a body-holding hop must check it. Neither gateway altered body bytes. Body-rewriting hops
  (decompression, JSON re-serialisation) were not tested.

---

## A4. Primitive-family leave-one-out (existing data, no new runs)

**Sources.**
- Binding (A_leak) hits: `hits_all.jsonl` of kill (680), ext-gw (1,368), ext-fw (694) and ext-routes (226),
  **2,968 raw hits** pooled as recorded.
- Authorization (A_client): `e4/analysis/violations_all.csv`, **325 violations**, 7 classes, with the class membership
  taken from `e4/analysis/classes.json`.

**Root-cause classes.** `scripts/mech.py` maps each hit to a mechanism (resolving component × differential), following
GATE_DECISION.md. The mapping reproduces every per-RC count in the source reports: ext-gw 96 `%2f` / 72 `#` / 12 RC7;
ext-routes 98 POST override + 18 any-method = 116 G1, 56 dot-segment, 54 fragment.

### A4.1 Binding hits (`analysis/a4_binding_family_loo.csv`, `a4_binding_mechanisms.csv`)

| primitive family (group) | hits | share of hits | share of G2 hits | mechanisms reached | LOO: hits left | LOO: mechanisms lost (of 10) |
|---|---|---|---|---|---|---|
| query-dispatch-switch (G1) | 975 | 32.9% | 0 | M1 | 67.2% | M1 |
| method-override-body (G1) | 700 | 23.6% | 0 | M4, M5b | 76.4% | M4 |
| graphql-operation-switch (G1) | 650 | 21.9% | 0 | M2 | 78.1% | M2 |
| **fragment (G2)** | 234 | 7.9% | **56.6%** | M6, M7 | 92.1% | **M6, M7** (G2 mechanisms 3 → 2) |
| method-override-header (G1) | 136 | 4.6% | 0 | M5a, M5b | 95.4% | M5a |
| content-type-switch (G1) | 101 | 3.4% | 0 | M3 | 96.6% | M3 |
| **encoded-slash (G2)** | 96 | 3.2% | **27.4%** | M8 | 96.8% | **M8** (G2 3 → 2) |
| **dot-segment (G2)** | 56 | 1.9% | **16.0%** | M9 | 98.1% | **M9** (G2 3 → 2) |
| method-override-query (G1) | 20 | 0.7% | 0 | M5b | 99.3% | none |

- **Primitive group shares.** G1 primitives drive 2,582 of the 2,968 hits (87.0%) and G2 primitives drive 386 (13.0%).
  Of the 386, 350 are G2 mechanisms and 36 are M7 (a G1 effect). G3 primitives drive 0 binding hits.
- **Only 9 of the 29 catalogue families produce any binding hit** (W15's `x-frag` primitives are counted under
  fragment): all 6 G1 families and 3 of the 18 G2 families. The other 15 G2 families and all 5 G3 families produce none.
- **Every root-cause class but one depends on a single family.** Leaving out one family removes its mechanism in 9 of 9
  cases. The exception is M5b (POST-only override), which three override families (header, body, query) reach
  redundantly, so no single LOO removes it.
- Each G2 mechanism hangs on exactly one family: `#` → M6/M7, `%2f` → M8, dot segment → M9. So the G2 evidence is
  **fragile to catalogue coverage**. Dropping the fragment family alone removes the class the gate decision rests on (M6).
- Per-experiment family shares are in `analysis/a4_binding_family_by_exp.csv`.

### A4.2 Authorization violations, E4 (`analysis/a4_e4_family_loo.csv`, `a4_e4_family_loo_merged.csv`)

| vector family | violations | share | classes reached | LOO: classes left (of 7) |
|---|---|---|---|---|
| dot segment (`dotseg` + `encdotseg`) | 220 | 67.7% | aspnet dot-segment (RC1), kong dot-segment (RC2) | **5** (both strict-allowlist breakers lost) |
| case | 36 | 11.1% | aspnet case-fold, express case-fold | 5 |
| matrix | 36 | 11.1% | spring matrix-param | 6 |
| double slash | 33 | 10.2% | rails double-slash, kong double-slash | 5 |

Split, `dotseg` alone holds 168 violations and `encdotseg` alone 52, but **neither loses a class** because the two are
redundant. The two classes that defeat a strict default-deny allowlist (RC1, RC2) both depend only on the dot-segment
family.

---

## A5. Gateway profiles: default vs recommended vs strict

### A5.1 Binding hits, existing default/recommended data (`analysis/a5_binding_profiles_existing.csv`, edge placement)
In every experiment and on every gateway, **recommended = default, hit for hit**: kill (nginx, traefik, envoy), ext-gw
(kong, apisix, haproxy) and ext-fw (nginx, traefik, envoy). Examples: kill nginx 122/122 (12 G2/12 G2),
ext-gw apisix 252/252 (48 M8/48 M8), ext-gw kong 234/234 (36 M6/36 M6). The vendors' recommended normalisation does not
touch G1, which is by design, and it also does not touch the three binding-G2 mechanisms. ext-routes ran default only.

### A5.2 Binding G2 under strict (new runs; `strict/runs/`, `analysis/a5_g2_profiles_new.csv`)
**Set-up.** The G2 case set has 176 cases: baselines plus every case of the fragment, encoded-slash, dot-segment and
`x-frag` families. It ran on 5 gateways × {fastapi, aspnet, spring} (`:v2`) × {strict, plus default and recommended
controls on the same set}, override off, giving 45 topologies.

**Result.** Cell = hits (mechanisms). Spring had at most 2 hits (M9) anywhere, and aspnet hits appear only on apisix (M8).

| gateway | fastapi default | fastapi recommended | **fastapi strict** | aspnet def / rec / **strict** | spring def / rec / **strict** |
|---|---|---|---|---|---|
| nginx | 14 (M6 11, M7 1, M9 2) | 14 | **12 (M6 11, M7 1)** | 0 / 0 / 0 | 2 (M9) / 2 / **0** |
| kong | 11 (M6) | 11 | **11 (M6)** | 0 / 0 / 0 | 0 / 0 / 0 |
| apisix | 2 (M8 1, M7 1) | 2 | **0** | 9 (M8) / 9 / **0** | 0 / 0 / 0 |
| envoy | 2 (M9) | **0** | **0** | 0 / 0 / 0 | 2 (M9) / **0** / 0 |
| traefik | 1 (M7) | 1 | **1 (M7)** | 0 / 0 / 0 | 0 / 0 / 0 |

- **Strict removes M8** (APISIX `%2f`) **and M9** (dot segments). Envoy's *recommended* profile already removes M9.
- **Strict does not remove M6 (`#` kept in the path) on nginx or kong**, and that includes the operation-changing
  `deleteAccount → deleteStatement` (`x-frag-statements-sid`).
- The cause is harness-defined. The strict deny regex (`gateways/common.py` `STRICT_DENY_PATH_REGEX`) lists `%23` but
  not a raw `#`. nginx and kong forward the raw `#`, while envoy, traefik and apisix strip or reject it natively.
- **M7 (`#` in the query) survives strict on nginx and traefik.** The regex is applied to the path only.
- Strict also lowers verifier allows on nginx/kong/apisix from 74–91 to 40. Gateway 400s rise accordingly. Baselines:
  17/17 OK in every cell.

### A5.3 Authorization (E4) under strict (new runs; `strict/runs_e4/`, `analysis/a5_e4_strict_new.csv`)
The E4 battery (29 vectors) ran on 6 gateways × {aspnet, spring} × strict × PDP {allow, block}, 24 topologies. It is
compared with W12's default and recommended data restricted to the same frameworks (`e4/analysis/violations_all.csv`).

| class | default | recommended | **strict** |
|---|---|---|---|
| **RC1** aspnet `/../` (allowlist breaker) | 27 allow + 27 block (nginx, envoy, haproxy) | 11 + 11 (nginx, haproxy) | **0 + 0** |
| **RC2** kong `/../` upstream normalisation (allowlist breaker) | 18 + 18 (kong × aspnet, spring) | 18 + 18 | **0 + 0** |
| kong `//` | 6 (block) | 6 | **0** |
| aspnet case-fold (blocklist only) | 12 (6 gateways) | 12 | **12 (6 gateways, unchanged)** |
| spring `;` matrix (blocklist only) | 18 (6 gateways) | 18 | **6 (envoy, traefik)** |

- **Strict eliminates both strict-allowlist breakers (RC1, RC2).** Kong's recommended profile does not remove RC2 at all
  (18 → 18), and strict does.
- Strict leaves the blocklist-only classes. aspnet case-insensitive routing is untouched by any profile. Spring's `;`
  survives on envoy and traefik strict, because those profiles use native rejection and do not apply the harness `;`
  rule.

### A5 reading
The vendors' recommended profiles change nothing for binding hits, and they only partly fix E4. The harness strict
profiles fix every E4 allowlist breaker and the `%2f`/dot-segment binding classes. They do not fix the `#` differential
on nginx or kong (a deny-list gap: raw `#`), header-carried semantics, or case folding. Strict profiles are
harness-defined (gateways/README.md), so they are a ceiling, not vendor defaults.

---

## Determinism reruns and ddmin
**Reruns** (`scripts/rerun_all.sh`, `scripts/rerun_outcome.py`; outcomes in `reruns/rerun_outcome.jsonl` and
`strict/reruns/rerun_outcome.jsonl`). Every topology with hits was rerun 3 times, each time on a fresh topology (up, run,
down), with its hit cases plus the 17 baselines. A hit counts as *confirmed* only if all 3 reps run the same executor op
with the same path parameters.

| set | hits | confirmed 3/3 | flaky | irreproducible | not rerun |
|---|---|---|---|---|---|
| A1 kill-style (64 topologies) | 1,560 | **1,176** | 0 | 0 | 384 (`no-htm`, `no-ath`: hit sets identical to `full`, which is confirmed) |
| A5 G2 strict/default/recommended (17 topologies with hits) | 106 | **106** | 0 | 0 | 0 |

The swap set, the legit false-rejection runs and the E4 strict runs were not rerun. E4 is deterministic by construction:
a PDP decision is a function of the request.

*Infrastructure incident, disclosed.* The first pass of the A1 reruns ran while the host was repeatedly stalled
(session interruptions; single runs took 400–3,084 s instead of about 20 s). In 8 rep runs, all in `+query` and
`digest-nogate` (listed in `skew_reps.txt`), the verifier denied every request, baselines included, with `iat_skew`.
The proofs were minted before the stall and checked after it. Those 8 runs showed 0 hits and made 140 hits look
flaky. They were re-run unchanged on fresh topologies (`reruns_skewfix.log`, 0 `iat_skew` denials), and every hit then
reproduced 3/3. No primary run (`runs/`, `runs_swap/`, `strict/`, `legit/`) contains an `iat_skew` denial.

**ddmin** (`scripts/ddmin_hit.py` against a live topology, `ddmin/*.json`, `ddmin/ddmin.log`). 17 representative hits
were selected by `scripts/ddmin_select.py`: one per (variant, mechanism) among the `+query,+digest` residuals and the new `no-htu` families, and one per (gateway, mechanism) among the strict-profile survivors. All 17 still hit after
minimisation. The minimal requests show three things:

| topology (variant) | primitive | units full→min | minimal request | executor ran |
|---|---|---|---|---|
| no-htu fastapi/off | g2-backslash | 3→3 | `DELETE /api/v1/admin/users/..\u-1` | adminDeleteUser `{id: ..\u-1}` |
| no-htu fastapi/off | g2-matrix-jsessionid | 15→15 | `DELETE /api/v1/admin/users/u-1;jsessionid=abc` | adminDeleteUser `{id: u-1;jsessionid=abc}` |
| no-htu fastapi/off | g2-dot-enc | 4→4 | `GET /api/v1/files/reports/%2e/logo.png` | catchAllFile `reports/./logo.png` |
| no-htu fastapi/off | g2-pct2f-before-last | 3→3 | `GET /api/v1/files/reports/%2flogo.png` | catchAllFile `reports//logo.png` |
| no-htu fastapi/off | g2-trailing-slash | 1→1 | `GET /api/v1/files/reports/logo.png/` | catchAllFile |
| no-htu fastapi/off | g2-abs-form-diff-path, g2-prefix-v1-to-v2 | 28→7, 1→1 | `GET /api/v2/accounts/acc-alice-1` | getAccountV2 |
| +query,+digest fastapi/off | g2-fragment (M7) | 5→1 | `POST …/actions?op=freeze#` | accountAction.unknown |
| +query,+digest fastapi/off | g2-fragment (M6) | 5→5 | `DELETE /api/v1/admin/users/u-1#frag` | adminDeleteUser `{id: u-1#frag}` |
| +query,+digest fastapi/off | g2-dot-enc (M9) | 4→4 | `GET /api/v1/files/reports/%2e/logo.png` | catchAllFile |
| +query,+digest fastapi/on | g1-hdr-xhmo-get / -delete (M5a/M5b) | 1→1 | `DELETE …` + `X-HTTP-Method-Override: GET`; `POST …` + `X-HTTP-Method-Override: DELETE` | getAccount; deleteAccount |
| +query,+digest spring/off | g1-ct-urlencoded (M3) | 1→1 | `POST /api/v1/graphql` + `Content-Type: application/x-www-form-urlencoded` | graphql.unknown |
| strict nginx, kong fastapi | g2-fragment (M6) | 5→5 | `DELETE /api/v1/admin/users/u-1#frag` | adminDeleteUser |
| strict nginx, traefik fastapi | g2-fragment (M7) | 5→1 | `POST …/actions?op=freezeg` | accountAction.unknown |

1. **The no-htu "other path" hits need htu only.** Each is a single path primitive that a path-only htu check rejects.
2. **What survives `+query,+digest` is irreducible header or path content.** The single `X-HTTP-Method-Override` or
   `Content-Type` header, the raw `#` in the path, and the `%2e` segment cannot be reduced further.
3. **M7 is a G1 effect carried by a G2 vehicle; ddmin shows it directly.** Where the query is not bound (`full` under
   the strict profile on nginx and traefik), the `#frag` minimises away to a plain query edit (`?op=freezeg`, i.e. M1
   query dispatch). Where the query *is* bound, the minimum is `?op=freeze#`: the fragment is exactly what lets the
   query edit past the query binding. This also means the strict-profile M7 counts in A5.2 are query dispatch that the
   `#` primitive happened to carry. Only under +query is M7 a fragment differential.

## Open issues and caveats
- A1 uses one gateway (nginx default). `+digest` soundness relies on the inserted `digest_gate` hop: the topology is
  modified at runtime (documented in README.md), not by the orchestrator.
- HAProxy + `+digest` was measured only for legitimate traffic, and was 100% rejected because its Lua adapter does not
  forward `Content-Digest`. A version with the adapter forwarding the header was not built (gateways/ is W6-owned).
- The swap set, legit runs and E4 strict runs were not rerun 3x (see Determinism reruns).
- `QUERY_CANON=sorted` was measured for false rejection only, not on the attack set.
- A4 pools raw hits across experiments with different matrices, so shares weight experiments by size. Per-experiment
  shares are in `a4_binding_family_by_exp.csv`.
- Strict-profile gap: the harness `STRICT_DENY_PATH_REGEX` should include a raw `#` (and be applied to the query for M7).
  Reported here, not changed, because gateways/ belongs to W6.

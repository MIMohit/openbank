# E4 — the malicious-but-legitimate client against a gateway policy decision point (W12)

**Independent G2/G3 authorization-soundness classes found: 7 (all G2; 0 G3).**
Across 5 distinct resolving components (ASP.NET/Kestrel, Express, Spring, Rails, Kong);
**2 of the 7 defeat the strict default-DENY allow-list** (the strongest policy style) on
current releases under the **recommended** profile. This clears the CONTRACT §12 hard-kill
bar (≥ 2 independent G2/G3 classes) with margin. Full root causes with citations:
[`ROOT_CAUSES.md`](ROOT_CAUSES.md); disclosure candidates: [`FINDINGS.csv`](FINDINGS.csv).

Data: 50 topologies with hits out of 96 run, 29-vector A_client battery, real components
(`orchestrator.up --stubs off`), run 2026-11-23. Every number traces to
`runs/*/{violations.jsonl,outcomes.csv}`, `analysis/*.csv`, `reruns/*/rerun_outcome.json`,
`ddmin/*.json` and `native/runs/*/`.

**What the kill experiment did not test.** W9 (`experiments/kill/`) asked the *binding*
question — given one proof, does the backend run exactly `op(π)`? — and found by-design G1
everywhere, one weak G2 (`#`/RC6) and **zero** owner/route substitution, because every path
mutation was either denied by the verifier or 404ed, and there was **no authorization layer
above the proof** whose decision a path differential could split. E4 adds exactly that layer:
a **policy decision point** that authorizes each request by **matching its path** against an
ownership/role policy on top of the RFC 9449 check. That is where the path differential bites.

---

## 1. Threat model (A_client)

`alice` holds a valid access token (`cnf.jkt` = her DPoP key thumbprint) and her DPoP private
key. She is not compromised; she is a legitimate tenant acting maliciously. For every crafted
request she mints a **fresh, valid** DPoP proof with `htu = origin + the exact mutated path`
and `htm = the method`, so the RFC 9449 §4.3 check **passes** — the proof is never the
obstacle; the **path policy** is the only thing between her and a forbidden operation. This is
strictly weaker than A_leak (no stolen secret). Targets: admin routes (`adminListUsers`,
`adminDeleteUser`) and bob's accounts (`acc-bob-1`, v1 and v2).

## 2. The PDP (`binding/harness/pdp/`)

`bh-pdp` is a drop-in verifier replacement exposing the same adapters (`/authz/fwd`,
`/authz/orig`, `/authz/envoy/{rest}`, `/health`), run in the `verifier` slot. Per request it
(1) runs the **real** `verifier.core.verify` (imported, not reimplemented) on the view `v(r)`,
then (2) applies a **path policy** to the **same view**. Decision = proof-valid ∧ policy-allow.
It logs the view, both sub-decisions and the matched rule to `pdp.jsonl`, and a verifier-format
record to `verifier.jsonl` for the oracle. Two realistic policy styles (full detail:
[`pdp/README.md`](../../harness/pdp/README.md)):

| policy | default | rule styles | reads like |
|---|---|---|---|
| `allowlist` | **DENY** | segment-aware **prefix** + **exact** allow rules for alice's own resources | a per-tenant edge allow-list / OPA `path startswith` |
| `blocklist` | **ALLOW** | **regex** deny rules `^/api/v[12]/admin(?:/\|$)` and a non-alice account-id regex | an RBAC `requestMatchers("/api/*/admin/**").denyAll()` |

`POLICY_NORMALIZE=rfc3986` runs the verifier's canonicaliser before matching (the measured
mitigation, §9). Unit tests: 18/18 pass (`pdp/tests/`).

## 3. Mutations (`cases.jsonl`, 29 vectors)

alice mints a matching proof for each (so the proof always passes); `e4_runner.py` sends the
exact wire bytes over a raw socket (no HTTP-library normalisation). Families: dot-segment
`/../` + `%2e%2e` (`dotseg-*`,`encdotseg-*`), matrix `;` (`matrix-*`), double-slash `//`
(`dslash-*`), `.json` suffix (`json-*`), case fold (`case-*`), trailing slash (`trail-*`),
`%2F` in id (`encslash-*`), plus `direct-*` (forbidden control, must deny) and `legit-*`
(alice's own, must allow). **Not included:** absolute-form targets and `X-Original-URL` /
`X-Rewrite-URL` headers — see §11 Limitations.

## 4. Oracle (`e4_oracle.py`, reuses `oracle.correlate`)

Authorization-soundness **violation** = PDP **allowed** (`verifier.jsonl` decision `allow`,
`sub=alice`) **AND** the executor acted on a forbidden resource/op (`op_id ∈
{adminListUsers, adminDeleteUser}`, or a path param whose **decoded** value is **exactly**
`acc-bob-1`), with `status < 400` and `denied=false`. Conservative: an id that merely
*contains* `acc-bob-1` (e.g. a `%2F`-mangled `acc-alice-1/../acc-bob-1` looked up verbatim) is
**not** counted (`allowed_other`). All violations graded **S1** (owner-crossing or admin).

---

## 5. Results — matrix

325 confirmed violations across 50 topologies. Matrix: gateways {nginx, traefik, envoy, kong,
apisix, haproxy} × policies {allowlist=A, blocklist=B} × profiles {default=d, recommended=r} ×
frameworks {spring, aspnet, rails, express, laravel, fastapi}, edge placement, `--stubs off`.
Cell = violations per topology, shown `A:d/r  B:d/r` (96 topologies run; combos driven by the
W5 leads, ≥ 36 as required).

Each cell is `A:d/r · B:d/r` (allow-list default/recommended · blocklist default/recommended);
`–` = that combination was **not** in the run worklist (not "0 violations"). **Bold** = defeats
the strict allow-list (A column > 0).

| gw \ fw | spring | aspnet | rails | express | laravel | fastapi |
|---|---|---|---|---|---|---|
| **nginx**   | 0/0 · 3/3 | **9/9** · 11/11 | 0/0 · 3/3 | 0/– · 2/– | 0/– · –/– | 0/– · –/– |
| **traefik** | 0/0 · 3/3 | 0/0 · 2/2 | 0/0 · 0/0 | 0/– · 2/– | 0/– · –/– | 0/– · –/– |
| **envoy**   | 0/0 · 3/3 | **9/0** · 11/2 | 0/0 · 3/0 | 0/– · 2/– | 0/– · –/– | 0/– · –/– |
| **kong**    | **9/9** · 15/15 | **9/9** · 14/14 | **9/9** · 12/12 | **9/–** · 14/– | **9/–** · –/– | **9/–** · –/– |
| **apisix**  | 0/0 · 3/3 | 0/0 · 2/2 | 0/0 · 0/0 | 0/– · 2/– | 0/– · –/– | 0/– · –/– |
| **haproxy** | 0/0 · 3/3 | **9/2** · 11/4 | 0/0 · 3/0 | 0/– · 2/– | 0/– · –/– | 0/– · –/– |

Reading it: **Kong is hit for every framework under both policies and
both profiles** (the gateway resolves the path upstream regardless of backend); **ASP.NET** is
hit behind the pass-through gateways (nginx/envoy/haproxy); Spring/Rails/Express appear only
under the blocklist (their differentials dodge a deny-regex but not the strict allow-list).
Traefik/APISIX forward a path the verifier then rejects on `htu` mismatch (148 `htu_mismatch`
denials total) — they are **not** vulnerable to the dot-segment/`//` classes, only to the
framework case/matrix classes that they forward raw.

## 6. Independent root-cause classes

An independent class = a distinct *(resolving component, parsing differential)*. 7 classes,
all **G2**, all **S1**. Detail + citations: [`ROOT_CAUSES.md`](ROOT_CAUSES.md).

| id | class | component | differential | policy | profile | gateways | n_topo | n_viol | breaks strict allow-list? |
|---|---|---|---|---|---|---|---|---|---|
| E4-RC1 | framework | ASP.NET/Kestrel | resolves `/../` pre-route | allow + block | def + rec | nginx, envoy(def), haproxy | 10 | 76 | **yes** |
| E4-RC2 | **gateway** | **Kong** | normalises upstream, auths on raw — `/../` | allow + block | def + rec | kong (all 6 fw) | 16 | 144 | **yes** |
| E4-RC3 | framework | ASP.NET | case-insensitive routing | block | def + rec | all 6 | 12 | 24 | no |
| E4-RC4 | framework | Express | case-insensitive routing | block | def | all 6 | 6 | 12 | no |
| E4-RC5 | framework | Spring MVC | strips matrix `;` params | block | def + rec | all 6 | 12 | 36 | no |
| E4-RC6 | framework | Rails | collapses `//` (squeeze) | block | def + rec | nginx, envoy, haproxy | 4 | 12 | no |
| E4-RC7 | **gateway** | **Kong** | normalises upstream, auths on raw — `//` | block | def + rec | kong | 7 | 21 | no |

Even under the strictest grouping (by resolving component alone) there are **5** independent
classes. The 2 dot-segment classes (RC1, RC2) are the headline: they defeat a correctly
written **default-DENY per-tenant allow-list** — the recommended policy style — on four of the
six gateways, including under their recommended profiles.

## 7. Reruns — 3× on fresh topologies

One representative topology per class, each re-run 3× with a fresh `orchestrator.up`/`.down`
per rep (`rerun_e4.sh`). **Every vector confirmed in all 3 reps; 0 flaky, 0 irreproducible.**

| class | topology | reps | confirmed vectors | flaky |
|---|---|---|---|---|
| RC1 aspnet dot-seg (allow) | w12-allow-ngx-aspnet-def | 3 | 9 | 0 |
| RC2 kong dot-seg (allow) | w12-allow-kng-fastapi-def | 3 | 9 | 0 |
| RC3 aspnet case | w12-block-ngx-aspnet-def | 3 | 11 | 0 |
| RC4 express case | w12-block-ngx-express-def | 3 | 2 | 0 |
| RC5 spring matrix | w12-block-ngx-spring-def | 3 | 3 | 0 |
| RC6 rails `//` | w12-block-ngx-rails-def | 3 | 3 | 0 |
| RC7 kong `//` | w12-block-kng-spring-def | 3 | 15 | 0 |

## 8. ddmin minimisation (`ddmin/`)

Each distinct differential was ddmin-minimised against a live topology (`e4_ddmin.py`): the
canonical reference is the matching `direct-*` control (the plain forbidden request the PDP
correctly denies), and ddmin reduces the request delta to the minimal change that flips the
PDP to **allow** while the executor still routes to the forbidden op. In every case the
`direct-*` baseline was denied and the minimal request still hit.

| differential | topology / vector | units | minimal request line | reading |
|---|---|---|---|---|
| dot-segment (framework) | aspnet / dotseg-bob-get | 15→15 | `GET /api/v1/accounts/acc-alice-1/../acc-bob-1` | irreducible: alice-prefix fools the policy, `/../acc-bob-1` reaches bob |
| dot-segment (gateway) | kong / dotseg-bob-get | 15→15 | `GET /api/v1/accounts/acc-alice-1/../acc-bob-1` | irreducible, same shape |
| case-fold | aspnet / case-admin-list | 5→5 | `GET /api/v1/ADMIN/users` | all 5 letters needed (route must spell `admin`) |
| matrix-param | spring / matrix-accounts-bob | 4→1 | `GET /api/v1/accounts;/acc-bob-1` | **one `;`** defeats the deny-regex |
| double-slash | rails / dslash-accounts-bob | 1→1 | `GET /api/v1//accounts/acc-bob-1` | **one extra `/`** |

## 9. Gateway-native path ACLs (`native/`, task item 2)

Tested whether a gateway's **own** native ACL (keyed on its routing view) is sound where the
raw-view external PDP is not. Configs generated by copying the W6 renderer output into
`native/configs/` (never editing `gateways/`). Same 29-vector battery; a violation = the DPoP
proof accepted **and** a forbidden op executed, i.e. the native ACL was bypassed.

| native config | profile | violations | survived | verdict |
|---|---|---|---|---|
| **nginx** `location ~` admin-deny + non-alice-deny | default | 2 | `case-admin-{list,del}` only | **closes the entire dot-segment class and enforces ownership** (nginx matches on the normalised, decoded, dot-segment-resolved URI); only the case-sensitive `location ~` regex misses `/ADMIN` (a one-char `~*` fix) |
| **envoy RBAC** admin-prefix, `normalize_path:false` (vendor **default**) | default | 13 | all `dotseg-*`/`encdotseg-*` admin + bob, `case-admin-*`, `direct-bob-*` | **bypassed** — RBAC sees the raw path, `/../` to admin isn't matched |
| **envoy RBAC** admin-prefix, `normalize_path:true` (**recommended**) | default | 9 | `case-admin-*`, `direct-bob-*`, `dotseg-bob-*` | dot-segment→**admin** bypass **closed**; survivors are outside this admin-only RBAC's scope (it never enforced ownership) plus the case-sensitive prefix |

Lesson: authorizing on the **routing view** (nginx native) is decisively better than a
raw-view external PDP — it closed RC1/RC2 and ownership outright — but it does **not** rescue a
policy-authoring bug (case-sensitivity) or an incomplete rule set (Envoy's admin-only RBAC).

## 10. Defences

- **`POLICY_NORMALIZE=rfc3986` on the PDP** (runs the verifier's canonicaliser before
  matching): closes the two dot-segment classes (RC1, RC2) — `remove_dot_segments` makes the
  PDP see the same `/api/v1/admin/...` the router will. It does **not** close case-fold,
  matrix, or `//`, because rfc3986 normalisation deliberately does not fold case, strip `;`,
  or collapse slashes. A sound PDP must canonicalise with the *union* of every downstream
  router's normalisation — the paper's recommendation.
- **Envoy recommended `normalize_path`/`merge_slashes`** closes RC1 and RC6 at the edge for
  Envoy (why envoy-recommended is largely absent from §5), and RC1's admin case in native RBAC
  (§9). It is **off by default** — that default is the hazard.
- **Case-fold the deny rules** (RC3/RC4) and **strip matrix params / collapse slashes before
  matching** (RC5/RC6): policy-authoring fixes independent of the view.
- **The strict default-DENY allow-list** already defeats 5 of the 7 classes; only the two
  dot-segment classes pierce it, and `POLICY_NORMALIZE=rfc3986` closes those.

## 11. Skepticism / harness artefacts

- **Clock skew (the W9 Docker-sleep warning):** checked — across all 50 sweep runs the
  PDP/verifier emitted **zero** `iat`/skew/expired/future denials (reasons were only `ok`,
  `policy_deny:*`, `auth_missing`, `htu_mismatch`). No reps needed redoing; the sweep ran on a
  non-skewed clock.
- **Conservative owner-crossing:** the oracle requires the decoded id to equal `acc-bob-1`
  exactly, so `%2F`-mangled ids (`encslash-bob-get`) that the app looks up verbatim are
  reported `allowed_other`, never counted — the harness under-counts rather than over-counts.
- **Null vectors (not bugs):** `.json` and trailing-slash were `pdp_denied` in all 96 runs
  each (the suffix sits after the segment the deny-regex already anchored); `%2F` never a clean
  hit (Tomcat 400 / Laravel 404 / non-bob decoded id). Reported for completeness.
- **`htu_mismatch` (148)** is the *expected* signal that Traefik/APISIX/Envoy-recommended
  rewrote the path before the PDP so alice's `htu` no longer matched — i.e. those configs are
  **sound** against those vectors, which is why they are absent from §6.
- `direct-*` controls denied everywhere; `legit-*` controls allowed and sound everywhere — the
  PDP is neither over- nor under-blocking on the baseline.

## 12. Disclosure candidates

See [`FINDINGS.csv`](FINDINGS.csv): E4-RC1..RC7 (G2 differentials) + E4-N1/N2 (native-ACL
informational). Per task, **vendors were not contacted**. Each product behaves per its own
documentation; the findings are the **composition** (a path-authorization layer keyed on a
view the downstream router normalises differently). The two Kong classes (RC2/RC7) are the
most product-specific: an *internal* inconsistency between Kong's forward-auth view
(`$request_uri`, raw) and its normalised upstream proxy path.

## 13. Limitations

- **Coverage gaps in the matrix worklist (the `–` cells in §5):** 96 of the full
  6×2×2×6 = 144 cells were run, prioritising the combos the W5 leads implicate. Not run:
  laravel and fastapi under the blocklist (both profiles) and under the recommended profile;
  express under the recommended profile (both policies). Spring/aspnet/rails ran under both
  policies and both profiles. The classes found are therefore lower bounds — in particular
  laravel/fastapi were only exercised against the allow-list default.
- **G3 not exercised:** the implemented battery omits the **absolute-form** target and the
  `X-Original-URL` / `X-Rewrite-URL` header-rewrite vectors the task listed. No G3 propagation
  hit occurred among the vectors that *were* sent (consistent with W9's zero-G3), but the
  header-rewrite probe is genuinely **open**, not shown-null. A follow-up should add those
  vectors to `gen_cases.py` and re-run the implicated topologies.
- **Single tenant:** the PDP authorizes only `alice`; a general multi-tenant PDP is not built.
- **ddmin** was run for one representative per differential (5), not per hit; the per-hit
  reproducibility is covered by the 3× reruns instead.

# Binding oracle: specification

Owner: W2 (this file only). W7 owns the implementation in `binding/harness/oracle/`.
Normative source: `binding/CONTRACT.md` §6. This file makes §6 precise. Where it
goes beyond §6, the passage is marked **[interpretation]** and is listed under
"Contract interpretations" in `binding/paper/README.md`. The paper-facing summary is
`binding/paper/appendix/oracle.tex`; keep the two consistent.

Terms used here: base op `b`, proof `π`, verifier view `v(r)`, executed operation
`x̂(r) = (op_id, path_params)`. They follow `paper/sections/model.tex`.

---

## 1. Inputs

For one topology `<id>` (a `harness/orchestrator/topologies/<id>.yaml`):

| Source | File | Key fields |
|---|---|---|
| Runner | `harness/logs/<id>/runner.jsonl` | `case_id`, `base_op_id`, `base_method`, `base_path`, `primitive_ids`, `client`, `jti`, `status`, `body`, `raw_request_b64` |
| Verifier | `harness/logs/<id>/verifier.jsonl` | `jti`, `adapter`, `view_method`, `view_uri`, `decision`, `reason`, `sub`, `jkt` |
| Executor | `harness/logs/<id>/executor.jsonl` | `jti`, `op_id`, `route_template`, `raw_method`, `effective_method`, `raw_target`, `path_params`, `query`, `trust_headers`, `denied`, `status` |
| Topology | `<id>.yaml` | `gateway`, `profile`, `placement`, `framework`, `override`, `verifier.canon`, `verifier.view_mac` |
| Ground truth | `harness/logs/groundtruth/<framework>.jsonl` (§2) | `base_op_id`, `base_method`, `base_path`, `op_id`, `path_params` |

**[interpretation]** The runner must record the `jti` of the proof it minted for each
case in `runner.jsonl`. §6 does not list it, but without it no join is possible.
If W7 instead derives it by decoding the `DPoP` header in `raw_request_b64`, that is
equivalent, as long as the decoded value is used.

## 2. Ground truth

`op(π)` for base op `b` in framework `F` is the pair `(op_id, path_params)` that `F`'s
executor returns when the **canonical request** for `b` is sent:

- directly to the executor container (no gateway), with `VERIFY_MODE=off`;
- with `OVERRIDE` equal to the value in the topology under evaluation;
- as the canonical raw request: method `base_method`, origin-form target `base_path`,
  `Host: api.bench.test`, the base op's canonical query or body if it has one
  (for example `?op=freeze` for `accountAction.freeze`, or `{"operationName":"getProfile"}` for
  `graphql.getProfile`), and valid `Authorization` and `DPoP` headers.

The ground-truth run is a precondition. If `op(π).op_id ≠ b`, or the status is ≥ 400, the
executor does not conform for `b`. All cases for `(F, b)` are then excluded and reported
under `nonconformant`, never as hits. W4's conformance suite should make this empty.

**[interpretation]** The oracle compares against the measured ground truth `op(π)`, not
against the table in §3 of the contract. The two coincide for a conformant executor. The
measured value also captures the path parameters, which the table does not.

## 3. Joining records

All records for one case are joined on the proof's `jti`. Each case mints a fresh proof,
so each `jti` belongs to exactly one case. For each case, the oracle collects:

- `R`: the runner record (exactly one);
- `VS`: all verifier records with that `jti` (zero or more);
- `XS`: all executor records with that `jti` (zero or more).

## 4. Hit definition

Let `placement ∈ {edge, origin, both}`. A case is a **hit** iff there is an executor
record `x ∈ XS` such that all of A, B and C hold.

**(A) Accepted.**
- `edge`: some `v ∈ VS` has `decision = "allow"`.
- `origin`: `x.denied = false`, and the executor's own call to the verifier
  (`adapter = "orig"` in `VS`) shows `allow`.
- `both`: both conditions above.

**(B) Different operation.** `x.op_id ∉ {b, "NOT_FOUND"}`, **or**
**[interpretation]** `x.op_id = b` and `x.path_params ≠ op(π).path_params`.
The second disjunct, a *resource substitution*, is required by the severity rule in
§6 ("a different `{id}` / owner" is S1), which would otherwise never fire. It is the
case `getAccount(acc-alice-1)` → `getAccount(acc-bob-1)` under one proof. Path
parameters are compared after percent-decoding, exactly as logged by the framework.

**(C) Succeeded.** `x.status < 400`.

The oracle also stores the **deviation kind** of each hit, used in §7:
- `method`: `x.effective_method ≠ base_method`;
- `route`: `x.route_template ≠` the ground-truth template;
- `dispatch`: same template and method, different `op_id` (query or body dispatch);
- `resource`: same `op_id`, different `path_params`.

When more than one kind applies, the oracle records all of them.

A hit witnesses binding resolution ≥ 2 for `(topology, b)`, because the canonical request
is accepted and executes `op(π)`.

### Empirical resolution

For each `(topology, b)`, the oracle reports
`res_hat = |{op(π)} ∪ {x̂(x) : x satisfies (A) and (C) and op_id ≠ NOT_FOUND}|`
over all cases with base `b`. It is a lower bound on `res_D(π)`.

## 5. Severity

Severity is assigned from the executed record `x`, never from the primitive:

| Severity | Condition on `x` (first match wins) |
|---|---|
| **S1** | `x.effective_method ∈ {PUT, DELETE, PATCH}`, or `x.op_id ∈ {updateAccount, deleteAccount, accountAction.*, createTransfer, graphql.deleteProfile, adminListUsers, adminDeleteUser}`, or deviation kind `resource` (a different `{id}` or owner) |
| **S2** | any other read: `listAccounts`, `getAccount`, `getAccountV2`, `me`, `graphql.getProfile` |
| **S3** | `health`, `publicFile` |

Notes:
- `adminListUsers` is a read, but it is S1 because it crosses a privilege boundary
  (§6 lists `admin*` as S1).
- `accountAction.unknown` and `graphql.unknown` are S1 when reached. They show that
  dispatch is attacker-selectable even when the handler is a no-op.
- `POST` to `createTransfer` is S1. A plain `POST` that executes a read op is graded by
  its `op_id`.

## 6. Missing `jti` and unmatched records

| Situation | Classification | Counted as hit? |
|---|---|---|
| Executor record with `jti = null`, meaning the `DPoP` header is missing or unparseable at the executor | `uncorrelated_exec`. The oracle reports the count per topology and attributes it to a case only through a unique `raw_target` and timestamp window match, and then only as `uncorrelated_candidate` | **No.** Reported separately for manual triage |
| Runner record with no executor record | `not_executed`: the gateway or verifier rejected the request, or the router never reached a handler | No |
| Runner record with executor records but no verifier record, in `edge` or `both` placement | `verifier_bypass`: the gateway forwarded the request without consulting the verifier | **No** binding hit. Reported as its own finding class `B0` with the same severity scale. It is an authorization bypass, not a binding failure, and must not inflate binding results |
| Verifier `allow`, no executor record | `allowed_not_executed` | No |
| Several executor records for one `jti` (pipelining, smuggling, internal retry) | Each record is evaluated. A case is a hit if any record qualifies; such hits are flagged `multi_exec` | Yes, if any record qualifies |
| Several verifier records for one `jti` (retries, `both` placement) | (A) uses the rule for the placement. In `edge`, any `allow` counts. If records disagree, the oracle flags `verifier_inconsistent` | As per (A) |
| Verifier record whose `jti` matches no runner record | `orphan_verifier`; reported | No |

## 7. What does NOT count as a hit

- The executed operation equals the base op, with the same path parameters, even if query, headers or
  body were changed. That outcome is binding-sound by definition.
- `op_id = NOT_FOUND`, any status ≥ 400, or `denied = true`.
- 3xx responses where the executor log shows no handler op, for example a framework
  trailing-slash redirect logged as `NOT_FOUND`. A 3xx with a real handler `op_id` does count.
- Differences only in response formatting, framework name, or the spelling of the method
  (for example `get` versus `GET`) that leave `op_id` and `path_params` unchanged.
- Gateway-level rejections (4xx/5xx) before the executor.
- A hit in a topology whose ground truth is `nonconformant` (§2).
- `verifier_bypass` (B0) and `uncorrelated_*` records, which are reported but not counted.
- **G3 propagation without an operation change** is not a §4 hit. It is reported by the
  separate predicate in §8.

## 8. G3 propagation predicate (separate from §4)

**[interpretation]** The §6 hit definition only observes operation changes. G3 also covers
spoofed identity and certificate headers whose effect on the bench API is not an
`op_id` change. The oracle therefore also reports a **propagation finding**. It is raised
when a G3 case injected header `h` with marker value `m`, the header's normalised name is in
the executor's `trust_headers` filter (contract §3), and `x.trust_headers[h']`
contains `m` for some `h'` that equals `h` after case folding and `_`/`-` folding. The
finding is graded S1 if `h'` is an identity or certificate header (`x-verified-*`,
`x-client-cert`, `client-cert`, `x-forwarded-client-cert`, `x-auth-*`). Otherwise it is S2
(`x-forwarded-*`, `x-original-*`). Propagation findings go to `propagation.jsonl` and are
counted separately from binding hits in the paper.

## 9. Deduplication by root-cause signature

Many cases express one bug. Before counting, hits are grouped by:

```
signature = (gateway, profile, placement, framework, override, verifier.canon,
             minimal_primitive_set, class, deviation_kinds)
```

- `minimal_primitive_set`: the sorted primitive ids after minimisation. If cases with
  primitive sets `P` and `P' ⊂ P` are both hits on the same topology and base op with the
  same deviation kinds, `P` is folded into `P'`.
- `class`: the union of the primitives' classes (`g1`, `g2`, `g3`).

The paper reports:
1. raw hits;
2. unique signatures;
3. **independent topology classes**: signatures re-grouped by the component that
   causes the divergence. G2 signatures that share gateway, profile and primitive set
   across all frameworks are one gateway-level class. Signatures specific to one
   framework, such as override, are one framework-level class.

The go/no-go criterion in the plan ("≥ 2 independent topology classes with
resolution > 1") is evaluated on item 3. Assigning the causing component needs a
person to read the logged views. The oracle emits a candidate assignment, and a reviewer
confirms it in `hits_reviewed.csv`.

## 10. Determinism

- Every hit is re-run **3 times**, each with a freshly minted proof (new `jti` and
  `iat`) against a freshly started topology (`orchestrator.down` then `.up`).
- `confirmed`: hit in 3 of 3 reruns. Only confirmed hits enter the paper's counts.
- `flaky`: hit in 1 or 2 of 3 reruns. Reported separately with the rerun outcomes. Not counted.
- `irreproducible`: hit in 0 of 3 reruns. Dropped, but kept in the raw log.
- The oracle itself is a pure function of the log files and topology YAML. Running it
  twice over the same logs must produce byte-identical `hits.jsonl` (sorted by `case_id`)
  and the same summary CSV. W7's tests should check this.
- Clock: `iat` freshness is the verifier's concern. The oracle never judges timing.
  A verifier `deny` with `reason` mentioning `iat` on a rerun is recorded as
  `rerun_timing_deny`, and the rerun is retried once.

## 11. Outputs

- `harness/logs/<id>/hits.jsonl`: one line per hit, with fields: `case_id`, `jti`, `topology`,
  `base_op_id`, `exec_op_id`, `base_path_params`, `exec_path_params`, `primitive_ids`,
  `class`, `deviation_kinds`, `severity`, `view_method`, `view_uri`, `raw_method`,
  `effective_method`, `raw_target`, `route_template`, `status`, `multi_exec`,
  `signature`, `rerun` (`confirmed|flaky|irreproducible|pending`).
- `harness/logs/<id>/propagation.jsonl` (§8), `harness/logs/<id>/oracle_other.jsonl`
  (B0, uncorrelated, nonconformant, orphan records).
- `harness/logs/summary.csv`: one row per topology, with columns `topology, cases, accepted,
  hits_raw, hits_confirmed, S1, S2, S3, signatures, max_res_hat, b0, propagation, uncorrelated`.

Every number in the paper (`paper/numbers.tex`) must be traceable to these files.

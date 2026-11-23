# bh-pdp — policy decision point (W12, E4)

**What it is.** A drop-in replacement for the reference verifier (CONTRACT §4) that adds a
**path-based ownership/role authorization** layer on top of the RFC 9449 DPoP proof check.
It exposes the **same adapters** as the verifier — `ANY /authz/fwd`, `ANY /authz/orig`,
`ANY /authz/envoy/{rest}`, `GET /health` — so the orchestrator runs it in the `verifier`
slot (`verifier.image: bh-pdp-<policy>:latest`) with no change to `gateways/` or
`orchestrator/`. For each request it:

1. extracts the view `v(r)` exactly as the reference verifier does (per adapter), and runs
   the **real verifier core** — `verifier.core.verify` is **imported, not reimplemented**
   (the `verifier` package is copied into the image);
2. if the proof is valid, applies a **path policy** (`policy.py`) to the **same view**;
3. decision = proof-valid ∧ policy-allow. On allow it returns the verifier's
   `X-Verified-*` headers (200); on deny it returns 401 with `WWW-Authenticate` (for a proof
   failure) or a `policy_deny:<rule>` reason.

It logs the view, both sub-decisions, the matched rule and matched path to `/logs/pdp.jsonl`,
and **also** writes a standard verifier-format record to `/logs/verifier.jsonl` (decision
folds proof ∧ policy) so the binding/E4 oracle reads it unchanged.

**Subject.** Fixed to `alice` (the E4 malicious-but-legitimate client). Permitted:
`/api/v1/accounts/acc-alice-1` (+subpaths), `/api/v2/accounts/acc-alice-1`, `/api/v1/me`,
`/api/v1/public/*`, `/api/v1/health`, `/api/v1/transfers`, `/api/v1/graphql`. Not permitted:
admin routes, any account id ≠ `acc-alice-1`.

**Two policy styles** (`policy.py`, both written the way a real gateway operator writes them):

| policy | default | rule styles | reads like |
|---|---|---|---|
| `allowlist` | **DENY** | segment-aware **prefix** + **exact** allow rules | a per-tenant edge allow-list / OPA `path startswith` |
| `blocklist` | **ALLOW** | **regex** deny rules (`^/api/v[12]/admin(?:/\|$)`, non-alice account id) | an RBAC `requestMatchers("/api/*/admin/**").denyAll()` |

Each `Rule` records its `style` so a bypass can be attributed to a rule-writing idiom.

**Normalisation switch.** `POLICY_NORMALIZE=off` (default) matches the **raw** view path,
exactly as a gateway keying on `$request_uri` / `X-Original-URI` does. `POLICY_NORMALIZE=rfc3986`
runs the verifier's own canonicaliser (`verifier.canon`: remove_dot_segments, %-decode
unreserved — **no** slash-collapse, `;`/`.json` stripping, or case-folding) before matching.
This is the measured mitigation (see `experiments/e4/REPORT.md` §Defences): it closes the
dot-segment classes but **not** case-fold, `//` or matrix-param, which rfc3986 does not touch.

**Images (baked env, because the orchestrator forwards only the standard verifier env):**
`bh-pdp-allow`, `bh-pdp-block` (POLICY_NORMALIZE=off), and `bh-pdp-allow-n`, `bh-pdp-block-n`
(POLICY_NORMALIZE=rfc3986). `bh-pdp:latest` is the base.

## How to run

The base image reads `POLICY` and `POLICY_NORMALIZE` from the **environment** (the Dockerfile
defaults them to `allowlist`/`off`). Because the orchestrator forwards only the standard
verifier env (CONTRACT §12), each variant bakes its env as a thin child layer:

```sh
# base (from binding/harness)
docker build -f pdp/Dockerfile -t bh-pdp:latest .
# variants: FROM bh-pdp:latest with the policy env baked in
for v in "allow allowlist off" "block blocklist off" "allow-n allowlist rfc3986" "block-n blocklist rfc3986"; do
  set -- $v
  printf 'FROM bh-pdp:latest\nENV POLICY=%s POLICY_NORMALIZE=%s\n' "$2" "$3" \
    | docker build -t "bh-pdp-$1:latest" -f - .
done
```
This yields `bh-pdp-allow` (allowlist/off), `bh-pdp-block` (blocklist/off), `bh-pdp-allow-n`
(allowlist/rfc3986) and `bh-pdp-block-n` (blocklist/rfc3986) — confirmed by
`docker history bh-pdp-block:latest` (`ENV POLICY=blocklist POLICY_NORMALIZE=off`). A topology
selects one via `verifier: {image: bh-pdp-allow:latest, canon: rfc3986}`.

## How to test

```sh
# unit tests (18): policy decisions + end-to-end through each adapter with a real minted proof
PYTHONPATH=/Users/mimohit/openbank/binding/harness \
  ../verifier/.venv/bin/python -m pytest pdp/tests/ -q      # 18 passed
```
`tests/test_policy.py` (13) covers both policy styles, each rule style, and the normalising
vs raw differential. `tests/test_server.py` (5) runs a real minted proof through each adapter
and checks proof∧policy, that a dot-segment traversal is allowed on the raw view and closed by
the normalising PDP, and that an invalid proof is denied.

## Known limitations
- Subject is hard-wired to `alice` (the E4 threat); it is not a general multi-tenant PDP.
- `POLICY_NORMALIZE` offers only `off` and `rfc3986`; it deliberately does **not** collapse
  slashes, strip `;`/`.json`, or fold case, so those differentials survive it (that is the
  point of measuring it). A production PDP would need a stricter canonicaliser aligned with
  every downstream router — which is the paper's recommendation, not a shipped feature here.
- The policy is path-only (ownership/role); it does not inspect query, body or method
  override (those are the G1 surface covered elsewhere).

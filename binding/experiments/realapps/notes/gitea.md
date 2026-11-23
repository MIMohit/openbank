# App 1 — Gitea 1.22.6 (Go net/http + chi router)

## Why this app
- **Popularity / deployment fit:** Gitea is a widely self-hosted Git forge; its official docs
  provide a reverse-proxy section that recommends running it behind **nginx** (and other proxies)
  and gives the exact `proxy_pass http://localhost:3000` server block + `client_max_body_size`
  advice (docs.gitea.com/usage/reverse-proxies). Deployments that want access control in front of
  Gitea commonly add an auth proxy / forward-auth at that nginx layer. This is exactly the
  edge-gateway + path-policy deployment the paper studies.
- **Route table makes our classes impactful:** the REST API has a deep, same-method nested tree
  under a per-object prefix — `GET /api/v1/repos/{owner}/{repo}` and, under it,
  `/issues`, `/branches`, `/commits`, `/tags`, `/contents/{path}`, … — i.e. the
  `/{id}/<sub>` shape RC6 needs, plus a natural **per-tenant prefix** (`/repos/{owner}/`) and an
  **admin** prefix (`/api/v1/admin/`) that operators protect by path.
- **Server stack:** Go `net/http` + chi — one of the three stacks kill RC6 identified as keeping
  `#` in the path. Lets us test the RC6 `#` differential on a real route table.

## Pin
`gitea/gitea:1.22.6`, digest `sha256:538658de667c5d098a274f2f63aa6ec891d88f670cdd5282cf27221ba747dda4`.
SQLite, single container. Seed: users `alice`(admin)+`bob`, public repos `alice/demo` (with an
issue) and `bob/public-b` (`seed.sh`). Gateway = **nginx:1.30.7-alpine** with the harness
`default-edge` config verbatim (auth_request → `/authz/orig`, `X-Original-URI $request_uri`),
only the upstream (`app:3000`) and location prefix (`/`) changed. Reference verifier =
`bh-verifier:latest` (HTU_CANON=rfc3986). PDP = `pdp/server.py` (imports the real
`verifier.core`) run inside `bh-verifier:latest`.

## Oracle
The app's own router log line gives the executed operation, e.g.
`router: completed GET /api/v1/repos/alice/demo … 200 OK … @ repo/repo.go:528(repo.Get)` —
the handler symbol (`repo.Get`, `repo.ListIssues`, …) **is** op(π). Plus the JSON body
(`owner.login`) identifies the resource actually served. Both are recorded per probe.

## A_leak (binding, RC6 `#`): NEGATIVE — differential fires at routing, defeated by id lookup
Proof minted for `GET /api/v1/repos/alice/demo`. nginx forwards the raw `#` (confirmed: the app
log shows `app_saw=/api/v1/repos/alice/demo#/issues`), the verifier strips `#…` as a fragment
(RFC 3986 / RFC 9449 §4.3) → **allow**. Go `net/http` keeps `#…` in `URL.Path` (ParseRequestURI
"assumes url has no #fragment suffix" and does not split it), and the `/` after `#` becomes a new
path segment, so chi dispatches into the **nested route subtree** — measured: `frag-issues` lands
in the issues group handler (`v1.Routes.func2.10.repoAssignment.2`) vs `func2.8` for the base —
**the operation routing does change**. But every `/api/v1/repos/{owner}/{repo}/…` route runs
Gitea's `repoAssignment` middleware first, which looks the repo up **by exact (lower_name) name**;
the `#`-mangled segment (`demo#`) matches no repo → **404** for all `#` variants. So status ≥ 400,
**no hit**. This is a precise, real-world confirmation of RC6's "practical severity low" caveat:
the `#` reaches a different route but the id it corrupts must resolve, and Gitea validates it.
Data: `runs/gitea/aleak.jsonl` (6 controls 200; 7 `#` variants all 404, verifier allow).

## A_client (authorization, per-tenant): 2 confirmed bypass classes on blocklist policies
alice holds a valid proof; the **gateway path policy** is the only control between her and bob's
repo. Both repos are public, so Gitea serves bob's content to anyone who reaches the route — the
policy is the sole tenant boundary (same model as E4). Policies in `apps/gitea/policies/`:
- `allowlist-tenant` — default **DENY**, allow prefix `/api/v1/repos/alice/` (per-tenant edge allow-list).
- `blocklist-regex` — default **ALLOW**, deny `^/api/v1/repos/(?!alice(/|$))` + `^/api/v1/admin`.
- `blocklist-literal` — default **ALLOW**, deny literal prefix `/api/v1/repos/bob/` + admin.

Hits (PDP `allow`, status 200, body `owner.login=="bob"`), 3/3 deterministic
(`reruns/gitea/*`):

| policy | vector | target | result |
|---|---|---|---|
| blocklist-regex | `dslash-after-v1` | `/api/v1//repos/bob/public-b` | **HIT** cross-tenant read |
| blocklist-regex | `dslash-leading` | `//api/v1/repos/bob/public-b` | **HIT** |
| blocklist-literal | `dslash-after-v1` | `/api/v1//repos/bob/public-b` | **HIT** |
| blocklist-literal | `dslash-leading` | `//api/v1/repos/bob/public-b` | **HIT** |
| blocklist-literal | `dslash-in-repos` | `/api/v1/repos//bob/public-b` | **HIT** |
| blocklist-literal | `case-owner-Bob` | `/api/v1/repos/Bob/public-b` | **HIT** (case-fold) |
| blocklist-literal | `case-owner-BOB` | `/api/v1/repos/BOB/public-b` | **HIT** (case-fold) |
| allowlist-tenant (+`-n`) | all | — | **no hit** (default-DENY allow-list resists; Gitea does not collapse `/../`, `%2f`, `;`) |

ddmin (`ddmin/gitea_aclient_ddmin.jsonl`): the minimal delta is **one inserted `/`** before `bob`
(`/api/v1/repos//bob/public-b`) or **one case-flipped char** (`/api/v1/repos/boB/public-b`);
reverting to `/api/v1/repos/bob/public-b` restores the DENY.

### Root cause (verifier/PDP view vs Gitea routing)
1. **nginx** default profile (`merge_slashes on`, the default) normalises `$uri` for *location*
   matching but forwards **`$request_uri` raw** to both the auth subrequest (`X-Original-URI
   $request_uri`) and upstream (`proxy_pass http://app:3000;`, no URI part). Measured: the app
   receives the raw `//` and raw case. (nginx proxy_pass docs: without a URI part the request URI
   is passed unchanged.)
2. **PDP** keys on that raw `X-Original-URI`. The anchored deny regex `^/api/v1/repos/…` and the
   literal prefix `/api/v1/repos/bob/` both **fail to match** a path mangled by `//` or by case →
   the default-ALLOW blocklist lets it through (matched rule = `<default>`).
3. **Gitea** collapses empty path segments and looks repos up case-insensitively (owner/repo are
   stored/queried as `lower_name`; measured: `//`, `/BOB/` all resolve to `bob` and return 200),
   so it serves **bob's** repo.
The split is PDP(raw, literal/anchored) vs Gitea(slash-collapsed, case-folded). Same mechanism
family as E4 RC4/RC6 (Express case-fold, Rails `//` collapse) and the GATE_DECISION "blocklist
policies only" row — now on a **real** app, a **real** per-tenant deployment, with a **real**
cross-tenant read as impact.

### What is NOT affected
- The default-**DENY** per-tenant allow-list (`allowlist-tenant`) is **not** bypassed by any vector
  here: `//`/case do not start with the allowed `/api/v1/repos/alice/` prefix, and Gitea rejects
  `/../`, `%2f`, `;` (404), so the allow-list cannot be tricked into routing to bob. Operators who
  use default-deny allow-lists keyed on the tenant prefix are safe against these vectors.
- `/../`, `%2f`-in-id, `;matrix` all **404** on Gitea (chi matches literal segments; no dot-segment
  collapse, no `%2f` decode-to-slash for routing) — so the dot-segment / encoded-slash classes
  (E4 RC1/RC2, ext-gw RC-W13-A) do **not** bite Gitea.
- The Gitea **admin** API additionally enforces its own admin-token check, so even a policy bypass
  to `/api/v1/admin/*` is stopped by the app (not relied on here; the per-tenant read is the clean
  impact).

## Reproduce
```
cd apps/gitea
docker compose -f docker-compose.yml up -d && ./seed.sh          # verifier stack (A_leak), port 18100
PYTHONPATH=…/harness …/orchestrator/.venv/bin/python ../../scripts/probe_lib.py aleak_spec.json ../../runs/gitea/aleak.jsonl
docker compose -f docker-compose.yml down
docker compose -f docker-compose.pdp.yml up -d                   # PDP stack (A_client), port 18101
bash ../../scripts/run_aclient_policies.sh "$PWD" "$PWD/aclient_spec.json" ../../runs/gitea/aclient blocklist-regex blocklist-literal allowlist-tenant allowlist-tenant-n
docker compose -f docker-compose.pdp.yml down
```

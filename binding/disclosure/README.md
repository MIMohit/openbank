# binding/disclosure — novelty & prior-art triage (W16)

## What this is
Disclosure triage for every candidate produced by the project's experiments:
prior-art search, novelty classification, per-vendor draft reports, and a
summary table. Produced by worker **w16** per `binding/CONTRACT.md` §0/§13.

## Contents
| Path | Content |
|---|---|
| `TRIAGE.md` | The triage table: candidate, component/version, class, classification, evidence URLs, vendor policy, recommended action, and what the paper may claim as new. Classification counts at the top. |
| `drafts/apisix-forward-auth-encoded-slash.md` | NEW. APISIX `forward-auth` decoded-view vs raw `%2f` upstream (RC-W13-A). Has an OPEN verification item (§7) to resolve before sending. |
| `drafts/uvicorn-fragment-request-target.md` | KNOWN-UNFIXED. uvicorn/h11 keeps `#` in the path (kill RC6). |
| `drafts/caddy-frankenphp-fragment-request-target.md` | KNOWN-UNFIXED. FrankenPHP/Caddy percent-encodes `#` (ext-fw W14-F2). |
| `drafts/go-nethttp-fragment-request-target.md` | KNOWN-UNFIXED / by-design. Go net/http keeps `#` (ext-fw W14-F1). Lowest priority. |

## Rules honored (CONTRACT §0, §13, task brief)
- **No vendor was contacted. Nothing was posted publicly. No issues opened. No
  git commits.** All drafts begin with "DRAFT — NOT SENT".
- Read-only web research (vendor advisories, NVD/CVE, issue trackers, docs,
  PortSwigger/path-normalization literature, and the CVEs already in
  `binding/lit/`) + local inspection of measured evidence only.
- **Nothing fabricated.** Where the published source conflicted with a measured
  result (APISIX `forward-auth` uses `ctx.var.request_uri`, which should be raw,
  yet the verifier received a decoded path), the conflict is stated and a
  local confirmation is required before disclosure — see the APISIX draft §7.

## How to reproduce a candidate
From `binding/harness` (one topology at a time; tear down after):
```sh
# APISIX encoded-slash:
bash ../experiments/ext-gw/scripts/run_one.sh w13-apisix-default-edge-aspnet-ovoff
# uvicorn '#':
bash ../experiments/kill/scripts/run_one.sh w9-nginx-default-edge-fastapi-ovoff
# go-chi / laravel '#':
bash ../experiments/ext-fw/scripts/run_one_hostfix.sh w14-nginx-default-edge-go-chi-ovoff ../experiments/ext-fw/runs
bash ../experiments/ext-fw/scripts/run_one_hostfix.sh w14-nginx-default-edge-laravel-ovoff ../experiments/ext-fw/runs
```
Minimal requests are in each experiment's `ddmin/*.json`.

## Known limitations
- The APISIX mechanism attribution ("$uri vs $request_uri") is not yet pinned to
  the exact internal variable; the *observed behavior* is confirmed, the *cause*
  is not. See the draft's §7.
- Prior-art "not found" means not found in the logged searches (2026-11-23), not
  "does not exist". The literature baseline is `binding/lit/`.
- No new live fuzzing was run here; classification rests on the existing
  experiment evidence plus prior-art search.

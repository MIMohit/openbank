# Proof ≠ Execution: binding soundness of sender-constrained API requests

Research project measuring whether accepting a DPoP proof (or an mTLS binding, or an HTTP signature) at one component guarantees that the backend executes the operation the proof was minted for, when verification and execution are split across gateways, policy decision points and web frameworks.

Everything lives under [`binding/`](binding/):

| Path | Contents |
|---|---|
| `binding/CONTRACT.md` | Shared interfaces and ownership used to build the harness |
| `binding/lit/` | Systematic literature review: protocol, screening/extraction logs, novelty memo, bibliography |
| `binding/prevalence/` | E1 (API-description corpus) and E2 (framework method-override) prevalence measurements |
| `binding/harness/` | Minter, reference DPoP verifier, PDP, 8 framework executors, 6 gateway configs, orchestrator, mutator, runner, oracle, defence |
| `binding/experiments/` | Kill experiment, extension rounds (ext-gw, ext-fw, ext-routes, e4), ablations, defence evaluation, gate decision |
| `binding/disclosure/` | Prior-art triage of findings and unsent disclosure drafts |
| `binding/paper/` | The paper (ACM sigconf, LaTeX) |

## Raw data
Raw per-request logs (`*.jsonl`, about 3 GB) and cloned corpora are not committed (see `binding/.gitignore`). Analysis CSVs, reports, minimised requests and summaries are committed. Raw logs will be archived separately for the artefact.

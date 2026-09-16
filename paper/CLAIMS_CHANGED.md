# Claims removed, weakened or reframed in the rewrite

Deliverable for §21.6 of the brief: every claim that the previous manuscript made and the rewritten manuscript does not, or makes differently, with the evidence that forced the change. Ordered by how much it matters.

The previous manuscript is recoverable from git history at commit `b2d4253` (`paper/paper.md`). Nothing below is a stylistic preference; each entry is a claim that the data does not support in the form it was stated.

---

## 1. Substantive claims that changed

### 1.1 "P reduces the adversary to 11/30 … this is organic detection from evidence the adversary cannot suppress"

**Was:** presented as the paper's one positive security result, with the 11/30 figure carrying the H2 hypothesis.

**Now:** reported as a measurement against a non-adaptive adversary, immediately followed by the per-request mechanism and by the adaptive measurement that erases it.

**Why.** Reading `data/raw/atk_P.jsonl` request by request shows the 11 successes are exactly requests 11–21 — the interval in which the unknown-device penalty (0.35) is the only rule firing, and 0.35 is below τ_allow = 0.40. The flanking refusals come from session continuity (which self-extinguishes as the adversary's own traffic dilutes the baseline) and from the call-rate window (which only engages after 30 events accumulate). Both are bookkeeping artefacts. The implied prediction was tested: attack A7, an adversary who paces at 4.0 s and mimics the victim's self-reported context — capabilities the threat model already granted — succeeds on **30 of 30** (`table9_adaptive_adversary.csv`). The clause "evidence the adversary cannot suppress" was accurate about the *evidence* and wrong about the *outcome*: the evidence was collected on 100% of requests and never changed a decision.

### 1.2 "H2 held for A4"

**Was:** the hypothesis that continuous enforcement reduces the ATO-class adversary was reported as held for A4 and failed for A3.

**Now:** the hypothesis framing is removed. The result is stated as: continuous enforcement changed the outcome of one of six attacks against a non-adaptive adversary, and of none against an adaptive one, at the shipped operating point.

**Why.** A hypothesis that holds against an adversary who does not attempt to evade and fails against one who does has not held in any sense a security claim can use.

### 1.3 "If a deployer adopts one thing from P, it is the per-subject device-key registry"

**Was:** stated unconditionally, on the evidence that removing it costs the most security and that it costs nothing measurable.

**Now:** retained as to cost, made conditional as to benefit: the registry is the only component that observes evidence the adversary cannot suppress, it costs nothing measurable, **and adopting it is useless unless its penalty is priced to be actionable on its own.**

**Why.** At 0.35 against τ_allow = 0.40 the registry's signal cannot change any decision by itself (`table6_threshold_sensitivity.csv`; §9.2). The ablation figure of 0.367 → 0.967 measures the registry's contribution *in conjunction with transient rules*, not its standalone value, which is zero at the shipped operating point.

### 1.4 "The shipped operating point is simply mis-set for A4 … a tuning finding a deployer can act on immediately"

**Was:** inferred from the threshold recomputation alone.

**Now:** retained and strengthened, but on live evidence rather than recomputation. τ_allow = 0.30 was run against both the naive and the adaptive adversary and refuses the adaptive one on 30/30 at both paces.

**Why.** A recomputation over recorded scores is sound arithmetic but is not a measurement of the system at that operating point. The claim now rests on runs, and the remedy is validated against the adversary that broke the original result rather than only against the one it was derived from.

### 1.5 B1 described as "FAPI 2.0-correct … PAR, PKCE (S256), DPoP … refresh rotation"

**Was:** B1 presented as a FAPI 2.0-correct baseline without qualification.

**Now:** B1 is described as a faithful comparator for FAPI 2.0's **sender-constraining** provisions, with an explicit statement that the measured data path begins at the resource API and does not exercise the authorization endpoint, so PAR and PKCE are configured in the realm and not on the measured path; and that mTLS-based sender-constraining is not evaluated at all.

**Why.** The attack harness and the load generator obtain tokens through a direct grant (`client_sim/flows.py`, `attacks/runner.py`) in order to acquire correctly bound tokens without simulating a browser redirect. The paper's argument turns only on sender-constraining, so the narrowed claim is sufficient — but the wider claim was not supported by the measured path.

### 1.6 "the adaptive CHALLENGE band is never used … because risk is bimodal"

**Was:** attributed to bimodality of the risk distribution alone.

**Now:** the bimodality is retained, and the mechanism is added: the call-rate rule fires on 100% of legitimate traffic and is what carries every geo-velocity event from the challenge band (0.60) into the deny band (0.85). In the first seconds of a run, before the window fills, the same events produced the only 8 challenges the system ever issued.

**Why.** Recomputed from `data/raw/exp_P.jsonl`. The distinction matters because it changes the remedy: bimodality alone suggests re-grading the penalties, whereas the measured cause is one uninformative rule acting as a constant offset.

### 1.7 "3.8% false-deny rate under stable context"

**Was:** reported in a table column headed as a false-deny rate for stable-context traffic, alongside a note that it is "the shadow of the drift rate".

**Now:** the note is promoted out of a parenthetical into the finding, and the manuscript states explicitly that the stable-context figure is **not an independent false-positive rate**: each context excursion costs two refusals, the departure and the return, and the 71 stable-labelled refusals are the return legs of the 72 drift-labelled ones.

**Why.** `data/raw/exp_P.jsonl` shows all 143 refusals carry the identical rule pair, split 72 drift / 71 stable. Quoting 3.85% as a stable-traffic false-positive rate would double-count the same 74 excursions as two independent phenomena.

---

## 2. Claims removed entirely

### 2.1 The belief-threshold / game-theoretic appendix

**Removed.** The previous manuscript carried it as an optional appendix whose own text recommended cutting it, on the grounds that the measured belief distribution is bimodal with a degenerate middle action and a fitted model would restate the threshold sweep in heavier notation. We agree and have cut it. The substantive observation — that the measured distribution is a poor fit for the analytical literature's assumptions — is retained in §3.3 and §11.4 as a one-line empirical remark, which is what it is.

### 2.2 The formal partial-deployment appendix

**Removed as an appendix.** It described work not done, in the imperative ("if pursued: model the composed checks in Tamarin/ProVerif…"). A manuscript should not contain instructions to its author. The idea is retained where it belongs: as a future-work item in §14 and as a recommendation in `ASSESSMENT.md`, with the observation that the ablation cells give a formal analysis concrete targets.

### 2.3 Version status, change logs, and editorial scaffolding

**Removed.** "Status of this version (V2)", "Change log vs. V1", "Change log vs. V0", "(Compressed relative to V0)", "(demoted, optional)", "*(Written to sit before Results in the final layout)*", "Shorter alternative title", "Note: this statement should be reconciled …", and the references section's admission that the bibliography "is not part of this repository and must be carried over with the manuscript". None of these belong in a submission, and the last was a genuine defect: the manuscript cited fourteen sources that did not exist in any file.

### 2.4 The unverifiable reference set

**Removed and replaced.** The previous reference list carried numbered citations [1], [2], [9], [10] and [17]–[22] inherited from a bibliography that was not in the repository, and explicitly flagged them as unverified. Every reference in the rewritten manuscript was checked against Crossref or the primary source document; the list contains 26 entries and no `[REFERENCE TO VERIFY]` markers, because entries that could not be verified were not retained. Two inherited attributions were wrong and are corrected: the first FAPI formal analysis is by Fett, Hosseyni and Küsters (not Fett, Küsters and Schmitz), and the UK Open Banking analysis is by Modesti, Freitas, Shotomiwa and Almehrej in *Cyber Security and Applications* 3:100097 (2025).

### 2.5 "82 approve, 0 object, 14 abstain"

**Removed.** The FAPI 2.0 approval vote tally was cited in the introduction. The Final status and its February 2025 date are verified and retained; the vote tally is not load-bearing and was dropped rather than carried on a secondary source.

---

## 3. Claims retained unchanged, and why they survive

For completeness, the claims the audit checked and did not change:

- **B1 eliminates A1 and A2** (0/30 from 30/30, risk difference −1.000). Verified against `table1_taxonomy.csv` and the raw records; both attacks are refused at proof verification and never reach the risk engine, which is confirmed independently by their all-zero rows in `table7_risk_components.csv`.
- **P changes nothing for A3 and A6** (30/30 in all three configurations). Verified; the only rule that fires is the call rate, on 30% of requests, contributing 0.25 against a 0.40 threshold.
- **The cost decomposition**: 9.39 ms policy round trip (55% of the request), 0.19 ms DPoP verification (~1%), 0.16 ms telemetry and risk. Verified against `table3_latency.csv`.
- **The measurement-integrity account** of the self-declared attack tag and the three scenario-fidelity defects. Verified against the code and the standing audit column, which reads 0.000 in every population including the new adaptive cells.
- **The detection ceiling**: 6/6 blocked with a perfect detector. Verified against `table1b_oracle_ceiling.csv`.
- **No capacity or throughput claim.** The previous manuscript already refused to make one; the rewrite keeps that refusal and the reason for it.

---

## 4. One code change, and why it changes no number

`checks.cnf_jkt_match` in the per-request record was set from the *presence* of the `cnf.jkt` claim at token verification, not from a verified thumbprint comparison, so A2's records read `cnf_jkt_match: true` on requests that were refused precisely for a thumbprint mismatch. The field now means what it says, and a separate `cnf_jkt_present` carries the claim-presence fact.

This affects no reported quantity, and that was checked rather than assumed: the analysis classifies a request as credential-refused if *any* of `token_valid`, `dpop_valid`, `jti_replayed` or `cnf_jkt_match` indicates a failure, and re-running that classification over all 482 attack records of `atk_P.jsonl` and `atk_B1.jsonl` with and without the `cnf_jkt_match` term gives identical results on 482 of 482, because every affected request is already classified by `dpop_valid = false`. A live smoke test after the change confirms A1, A2 and A4 produce the same decisions as before.

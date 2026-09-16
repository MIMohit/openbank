# Assessment: reviewer simulation and what must change before submission

This document accompanies `paper/manuscript.md`. It is not part of the manuscript. It contains (1) a simulated peer review at *Computers & Security* standard, (2) the direct answers to "what must change before submission", and (3) the prioritised list of additional experiments and system modifications.

It is written against the rewritten manuscript, after the audit described in §1 below. Where the review identifies a problem that the rewrite already fixed, it says so; where it identifies one that writing cannot fix, it says that too.

---

## 1. What the audit found

The audit read the full implementation (controller, policy, resource server, identity-provider realms, attack suite, client simulator, load generator, analysis pipeline), the committed raw records, the ten result tables, and the two prior drafts, and re-derived a sample of results from the raw JSONL rather than trusting the tables.

The prior draft's numbers were sound — the ten tables regenerate byte-identically from the committed records, and every number the draft stated traces to one of them. Three things the audit found that the draft did not contain:

1. **The A4 result is a window-transient artefact.** Reading `atk_P.jsonl` request by request shows the 11 successes are exactly requests 11–21, the interval where the unknown-device penalty (0.35) is the only rule firing and 0.35 < τ_allow = 0.40. The two flanking signals are bookkeeping effects: session continuity self-extinguishes as the adversary's own traffic dilutes the victim's baseline, and the call rate only engages once the shared 60 s window accumulates 30 events. The draft reported the aggregate and diagnosed the threshold placement, but did not connect it to the mechanism or draw the consequence.
2. **The consequence is that the paper's one positive security result does not hold.** An adversary who paces below the rate rule and mimics the victim's self-reported context — capabilities the threat model already grants — should succeed on every request. This was implemented as A7 and measured: 30/30 at the shipped operating point, against 11/30 for the non-adaptive adversary. The remedy the draft had already identified from the threshold sweep was then validated live: τ_allow = 0.30 refuses the adaptive adversary 30/30 at both paces.
3. **An information-free rule still changes outcomes.** The call-rate rule fires on 100% of legitimate traffic (median 1090 req/min against a 30 req/min threshold, 36×) and therefore carries no information — and it is nevertheless what converts every geo-velocity event from a step-up challenge into an outright denial. In the first seconds of a run, before the window fills, the same events produced the only 8 challenges the system ever issued. The draft observed that the challenge band was unused but attributed it to bimodality alone.

Smaller findings, all now stated in the manuscript: the measured data path does not exercise PAR or PKCE (the harness uses a direct grant), so B1 is a faithful comparator for FAPI 2.0's *sender-constraining* provisions and not for the profile as a whole; `htu` is compared including the query string, which is stricter than RFC 9449; the `cnf_jkt_match` field in the records recorded claim *presence* rather than a verified match, which was corrected in the code and provably affects no reported quantity; and each performance cell is a single run, so the reported intervals cover within-run and not between-run variation.

---

## 2. Simulated peer review

**Recommendation: major revision.** The work is a genuine empirical contribution with an unusually honest result and a well-instrumented artefact. It is not currently a paper about a system that works, and it should not be presented as one; presented as what it is — a measurement that locates and diagnoses a failure boundary — it is publishable at this venue after the revisions below.

### 2.1 What is strong

- **The comparator is right.** Evaluating against a FAPI 2.0-correct baseline rather than plain bearer OAuth is the single most important methodological decision in the paper, and it is what makes the result mean anything. Most of the Zero-Trust-for-banking literature does not do this.
- **The negative results are load-bearing and specific.** "The defence does not work" is not a contribution; "the defence collected unforgeable evidence on 100% of adversarial requests and priced it 0.05 below its own decision threshold, so an adversary who slows down succeeds on all of them, and moving the threshold by 0.10 fixes it at zero measured cost" is. The diagnosis is mechanistic and the remedy is validated, not asserted.
- **The adaptive-adversary evaluation.** Very few systems papers in this space measure an adversary who adapts within the stated threat model. That the adaptation costs the adversary nothing and erases the entire benefit is the most useful thing in the paper.
- **The measurement-integrity section.** Documenting the self-declared-attack-tag defect, quantifying its effect (6/6 versus 2/6), and retaining it as an explicitly labelled detection ceiling is exemplary, and the standing audit column in the rule-firing table is the right way to keep it honest.
- **Attribution.** The ablation is genuinely attributive because each flag maps to one rule group, and the threshold sweep separates "signal absent" from "signal mispriced" — a distinction most evaluations cannot make.
- **Reproducibility.** One-command bring-up, pinned images, fixed seeds, raw records as the single source of truth, and a checked consistency between the manuscript's numbers and the committed tables.

### 2.2 Major concerns

**M1. The testbed measures one subject.** All legitimate traffic shares one `sub` and one enrolled device, because the realm provides one identity and because giving each virtual client its own key would make every request trip the new-device rule. This is defensible and it is disclosed, but it drives the paper's most quoted secondary finding: the per-subject call-rate rule saturates *because* twenty concurrent clients share one subject. A reviewer will ask whether the rule would saturate at a realistic per-subject concurrency of one or two clients, and the honest answer is that we do not know. This weakens — though it does not overturn — the §9.5 claim, because A3's adversary shares the victim's subject by definition and would still be indistinguishable on rate at any plausible threshold. **This is the single most important missing experiment (E-1 below).**

**M2. Single-run cells.** Each latency, resource and friction figure comes from one 60-second run and each scaling figure from one 30-second run. The Wilson and bootstrap intervals describe within-run sampling only. For a paper whose headline cost figures are +6.22 ms and 7.4% friction, a reviewer is entitled to between-run variation. Cheap to fix (E-2).

**M3. The baseline is a partial FAPI 2.0.** PAR and PKCE are configured but not exercised by measured traffic; mTLS sender-constraining is not evaluated at all. The paper now says this plainly, and the argument only depends on sender-constraining, but the title and framing invoke "FAPI 2.0" and a reviewer will hold them to it. Either narrow the framing to sender-constraining, or exercise the authorization-code flow (E-3).

**M4. Synthetic geography.** The geo signal is region codes with an assumed 1 000 km separation. The §9.4 conclusion — that a per-request velocity rule degenerates into a "region changed" trip-wire — follows from the rule's *form* and the request cadence, not from the synthetic distances, and the paper says so. But the 97.3% drift-refusal figure is not a real-world false-positive rate and must never be quoted as one. Consider re-running the drift workload with a real geo-IP distance function over a plausible travel trace (E-5).

**M5. The contribution is a measurement, and the system is an integration.** The controller integrates standard mechanisms: DPoP verification, a key registry, additive rules, an external PDP. There is no new primitive, protocol or policy concept, and the paper says so. Whether that is sufficient depends on the venue's tolerance for measurement papers. My judgement is that it is sufficient *here* because the measurement produces transferable findings — the evidence/threshold distinction, the window-erosion failure mode, the uninformative-rule amplification, the cost decomposition — but the framing must lead with those findings and not with the architecture. The current rewrite does this; an earlier framing did not.

**M6. The resource server trusts a header.** The controller-to-resource-server channel is an internal header on a private network, not mutual TLS. An adversary inside the boundary bypasses the entire enforcement layer. This is disclosed in §10.3 and it is a correct modelling of network isolation, but it is a weak link in a paper about a Zero Trust architecture, whose premise is precisely that internal network position should not confer trust. A reviewer will find that ironic and will be right to.

### 2.3 Minor concerns

- A5 does not discriminate between configurations and is retained only for taxonomy completeness. Consider moving it to an appendix, or replacing it with a BOLA variant the enforcement layer could plausibly act on (for example, consent-scope violation checked at the PDP rather than object ownership at the resource server).
- "Challenge" is scored as a refusal for the adversary and as friction for the legitimate user. Both are correct, but a challenge a real user can satisfy and a denial they cannot are not equally costly, and the paper's 7.4% figure conflates nothing here only because zero challenges were issued. Say so where the metric is defined, which the rewrite now does.
- The p99 of 510.8 ms at 40 clients is flagged and not interpreted. Good, but a reviewer may ask for a repeat of that single cell rather than a flag (folded into E-2).
- Figure 2 and Table 2 partly duplicate. Acceptable — the figure carries the threat model, the table the result — but check the final layout.
- Cliff's δ magnitude labels ("large") are conventional; the manuscript cites Cliff and does not over-lean on the label.

### 2.4 Missing experiments

Listed with priority in §4 below.

### 2.5 Missing comparisons

- **No learned-detector comparison.** [6] shows behavioural features discriminate offline in exactly the regime (A3/A6) where this rule set fails. The paper's negative result would be substantially stronger — or substantially qualified — if a simple learned detector were run on the same recorded telemetry. The records needed already exist. (E-4.)
- **No mTLS comparison.** FAPI 2.0 permits mTLS as an alternative to DPoP. The cost decomposition would be more useful to a deployer with both arms measured.
- **No comparison against a commercial API gateway's risk engine.** Out of reach for a synthetic testbed, and correctly not attempted.

### 2.6 Security-analysis concerns

- The security analysis (§10) correctly separates demonstrated, argued and assumed. Two assumptions carry most of the weight: the unforgeability of the device signal (argued, not measured) and the integrity of the internal network (assumed; see M6).
- Enrolment-time trust is out of scope and should be stated as an explicit residual: the first key a subject presents is enrolled unconditionally, so an adversary who reaches a fresh subject first becomes the baseline. §10.4 now states this.
- The paper should not, and does not, claim any formal result.

### 2.7 Novelty concerns

The mechanisms are standard integration. The novelty is in the measurement design (FAPI 2.0 baseline, adaptive adversary, threshold-sweep-as-diagnostic, oracle ceiling as an integrity control) and in the transferable findings. A reviewer hostile to measurement papers will call this engineering; a reviewer who reads §9.2–§9.3 and §11.4 will find four findings that generalise beyond this implementation. The paper must be framed so that the second reviewer's reading is the obvious one.

### 2.8 Writing concerns

The rewrite addresses the ones that applied to the prior draft: version-status notes, change logs, appendices containing instructions to the author, and "[FILL]"-era scaffolding are gone. The abstract has been cut from about 600 words to 261 and a five-bullet highlights list added, both within the venue's conventions.

Remaining watch items. The manuscript runs to roughly 19 000 words including tables, captions, references and appendices — on the long side for the venue, though not out of range for a measurement paper with eleven tables. If it must be cut, §9.10 (scaling) and Appendix B are the least load-bearing, and §2 could lose a further paragraph. §9 is long and the reader must be kept oriented; the RQ tags in the subsection headings do this and should be kept through copy-editing. §11.4's four failure modes risk reading as a list rather than an argument.

---

## 3. What must change before submission?

Direct answers to the ten questions.

**1. Is the current system implementation sufficiently novel and rigorous for a *Computers & Security* submission?**

Rigorous, yes — for what it is: a well-instrumented, reproducible measurement harness with genuine attribution. Novel as a *system*, no. There is no new mechanism, and the paper should not and does not claim one. The submission is viable as a measurement and characterisation paper, not as a systems-contribution paper. If the intent is to publish "a Zero Trust architecture for Open Banking", the answer is no: the architecture is an integration of standard components, and the measurement shows it does not deliver the security property it was built for.

**2. Are the current experimental findings sufficient?**

Sufficient to support the paper's claims as now written, which are deliberately narrow. Not sufficient to withstand M1 and M2 without the two experiments below. The A3/A6 negative result in particular currently rests on a workload whose per-subject concurrency is an artefact of the testbed's single identity.

**3. What additional experiments should I run?**

E-1 and E-2 are required; E-3, E-4, E-5 and E-6 are strongly recommended. See §4.

**4. Does the system itself need modification?**

Yes, three changes, and all three are *required to make the paper's own findings actionable* rather than to make the system look better:

- **Multi-subject support in the realm and the workload** (prerequisite for E-1). This is the change with the largest effect on the paper's credibility.
- **Re-price or re-shape the device signal.** The measurement shows the unforgeable evidence is priced below the decision threshold. Either lower τ_allow to 0.30 as the default (validated) or raise R2's penalty above τ_allow. Ship the recalibrated configuration as the system's operating point and report the shipped one as the finding.
- **Replace the per-request geo-velocity rule.** It contributes the entire usability cost and no independent detection, and at this cadence it is not a velocity test. Move velocity reasoning to session or login granularity, or replace it with a session-scoped context-change signal that fires once per excursion rather than twice.

Two further changes would improve the artefact but do not affect the findings: mutual TLS between controller and resource server (M6), and a colocated or cached PDP (which the cost decomposition indicates removes most of the overhead — worth measuring rather than asserting).

**5. Which findings should be strengthened or re-evaluated?**

- The A3/A6 negative result needs the multi-subject workload (E-1) before it can be stated as strongly as §9.5 currently states it. The manuscript already hedges it to "this rule set at these thresholds on this workload"; E-1 would let the hedge be narrower.
- The friction figures need between-run variation (E-2).
- The recalibration result (τ_allow = 0.30) is validated against A4 and A7 on this workload only. It should be re-validated under E-1, where legitimate traffic may occupy [0.30, 0.40).

**6. Which claims should be removed or weakened?**

See `paper/CLAIMS_CHANGED.md` for the full list with the reason for each. The substantive ones: the claim that continuous enforcement reduces account takeover (weakened to a non-adaptive-adversary measurement and then shown not to survive); the claim that the per-subject device registry is the component to adopt first (retained but now conditional on re-pricing); the implicit claim that B1 represents FAPI 2.0 in full (narrowed to sender-constraining); and any reading of the 3.85% stable-context refusal rate as an independent false-positive rate (it is the return leg of the same excursions).

**7. What additional baseline or comparison is needed?**

A learned detector over the same recorded telemetry (E-4) is the one that matters, because it directly addresses whether the A3/A6 failure is a property of rule-based scoring or of the available signals. An mTLS arm would improve the cost section but changes no conclusion.

**8. What additional security analysis is needed?**

The analytical section is adequate for a measurement paper. Two additions would strengthen it materially and neither requires new measurement: a short adversary-strategy analysis enumerating what each position can suppress and what it must emit (the beginnings of this are in Appendix B), and a partial-deployment argument keyed to the ablation cells — *P − device-binding* is exactly a deployment that verifies proofs but does not bind them, and it measurably reintroduces the new-device adversary.

**9. What figures or tables are missing?**

None are missing for the current claims: twelve figures and eleven tables are built from the data and the code. Two would be added with the new experiments: friction and detection as a function of per-subject concurrency (E-1), and a between-run variation plot for the cost figures (E-2). If E-4 is run, a detector comparison on the A3/A6 population.

**10. Top changes, in order of effect on the manuscript.**

1. **Run the multi-subject workload (E-1).** It is the one experiment that a reviewer can use to reject the paper's secondary findings, and the one whose absence the paper currently has to hedge around.
2. **Repeat each performance and friction cell (E-2).** Cheap, and it converts "one run" into a real interval on the paper's headline cost numbers.
3. **Lead with the findings, not the architecture.** The rewrite does this; keep it. The transferable results are the evidence/threshold distinction, window erosion, uninformative-rule amplification, and the cost decomposition.
4. **Add the learned-detector comparison (E-4)** if time permits, because it converts "our rules fail here" into "this regime is hard, and here is the evidence".
5. **Fix the system's operating point and the geo rule, and report the fix as a result** rather than shipping a configuration the paper itself shows to be broken.

### Is there a fundamental research weakness that writing cannot solve?

Yes, and it should be stated plainly rather than managed.

**The system does not achieve the security property it was designed to provide.** Continuous, context-bound enforcement was added to catch the adversaries sender-constraining cannot. It catches neither device-resident abuse nor volume abuse at any operating point, and its effect on account takeover disappears against an adversary who slows down. No amount of writing changes that.

What writing *can* do — and what this rewrite does — is make the paper about that fact rather than around it. That is a legitimate and useful contribution, because the failure is diagnosed to a mechanism, the mechanism generalises beyond this implementation, and one of the two failures has a validated remedy. But it means the paper cannot be a "we built a Zero Trust system for Open Banking and it works" paper, and any attempt to present it as one will not survive review, because the measurements that contradict it are in the paper's own tables.

There is a second, smaller weakness of the same kind: the contribution is a measurement on a synthetic testbed with one subject and one device. Even with E-1, no result here transfers to a production Open Banking deployment without validation. The paper must claim the measured regime and nothing beyond it.

---

## 4. Additional experiments and system modifications

For each: why it is needed, the research question it answers, what to implement, metrics, baseline, the result that would strengthen the paper, and whether it affects the core contribution.

### A. Essential

**E-1. Multi-subject legitimate workload.**
- *Why.* The per-subject call-rate rule saturates because 20 concurrent clients share one subject (§8.3, §9.5). The paper's second-most-quoted finding depends on a testbed artefact, and a reviewer will say so.
- *Question.* Does the call-rate rule still carry no information at a realistic per-subject concurrency, and does the recalibrated operating point still cost no friction when legitimate traffic comes from many subjects?
- *Implement.* Add N test identities to the realm (N ≥ 50), each with its own protocol-mapper-pinned subject matching a distinct synthetic resource-server user, and one enrolled device each. Extend the load generator to draw a subject per virtual client. Re-run the legitimate workload, the friction measurement and the threshold sweep.
- *Metrics.* Rule firing rate by population; friction by context profile; the threshold sweep curve; the risk distribution.
- *Baseline.* The current single-subject run, reported alongside.
- *Strengthening result.* Either the rate rule still fires on most legitimate requests, which generalises the §9.5 finding beyond the artefact; or it does not, which narrows the finding honestly and makes the threshold sweep more informative. Either outcome improves the paper.
- *Affects the core contribution.* Yes, for the A3/A6 negative result and the friction figures. The A4/A7 result is unaffected, since that adversary's evidence is per-subject device novelty.

**E-2. Repeat each performance, friction and scaling cell.**
- *Why.* Every cost figure comes from a single run; the reported intervals cover within-run sampling only (§8.5, §12).
- *Question.* What is the between-run variation of the paper's headline cost and friction numbers?
- *Implement.* Five independent repetitions of each cell, each against a freshly restarted controller, with the run index recorded. No code changes beyond a loop in the Makefile.
- *Metrics.* Per-cell median and p99 latency, CPU, memory and friction, with between-run interval or standard deviation.
- *Baseline.* Same configurations.
- *Strengthening result.* Tight between-run intervals convert "+6.22 ms in one run" into a defensible cost estimate. It also resolves whether the 510.8 ms p99 outlier at 40 clients is systematic.
- *Affects the core contribution.* No — it affects the confidence in the cost claims, not their direction.

### B. Strongly recommended

**E-3. Exercise the authorization-code flow with PAR and PKCE.**
- *Why.* The measured data path does not exercise them, so the paper's "FAPI 2.0 baseline" is really a sender-constraining baseline (M3, §12).
- *Question.* Does the full profile's authorization flow change the per-request cost or the enforcement outcome?
- *Implement.* A headless browser or a scripted redirect flow in the client simulator, using the existing `zt-client` confidential client rather than the direct-grant harness client.
- *Metrics.* Token-acquisition latency (reported separately from per-request latency), and confirmation that attack outcomes are unchanged.
- *Baseline.* The current direct-grant path.
- *Strengthening result.* It would let the paper claim a full FAPI 2.0 baseline rather than a narrowed one. The expected effect on per-request results is none, which is itself worth showing.
- *Affects the core contribution.* No, but it removes a framing objection.

**E-4. Learned detector on the recorded telemetry.**
- *Why.* [6] shows behavioural features discriminate offline in exactly the regime where this rule set fails; the paper's negative result is currently about rules, not about the regime.
- *Question.* Is the A3/A6 failure a property of rule-based scoring, or of the signals available at this enforcement point?
- *Implement.* Train a simple classifier (logistic regression and a gradient-boosted tree, for interpretability and for a strong baseline) on the per-request telemetry vectors already recorded in `data/raw/`, labelled by the ground-truth attack label the records already carry and that no enforcement decision reads. Evaluate with subject-wise or run-wise splits so the classifier cannot memorise a run.
- *Metrics.* Precision, recall and the ROC/PR curve on A3/A6 against legitimate traffic; and the operating point required to reach a friction rate a deployment could tolerate.
- *Baseline.* The rule set at its shipped and recalibrated operating points.
- *Strengthening result.* If a learned detector separates A3 from legitimate traffic on the same features, the finding becomes "rule-based scoring at a deployable operating point is the limitation" — a sharper and more useful claim. If it does not, the finding becomes "these signals do not contain the information", which is stronger still and directly qualifies [6] at the enforcement layer.
- *Affects the core contribution.* It sharpens the central negative result in either direction.

**E-5. Realistic geography and a travel trace.**
- *Why.* The 97.3% drift-refusal figure comes from synthetic region codes at millisecond cadence (M4).
- *Question.* What is the false-refusal rate of a per-request velocity rule under a plausible mobility model?
- *Implement.* Replace the region-code hop with a coordinate pair and a haversine distance, and drive the workload from a simple mobility trace (stationary periods punctuated by moves).
- *Metrics.* Friction by context profile; refusals per excursion.
- *Strengthening result.* It would let the paper quote a friction number that means something outside the testbed. The structural finding — two refusals per excursion — should survive, and showing that it does would be valuable.
- *Affects the core contribution.* No; it affects how quotable the usability numbers are.

**E-6. Consent-scope enforcement at the policy decision point.**
- *Why.* A5 is refused identically in all three configurations because ownership is enforced downstream, so the taxonomy currently contains no authorization attack that the enforcement layer can act on (§9.1, §12). The synthetic dataset already carries a consent object per user, listing the accounts the consent covers; the policy never reads it.
- *Question.* Does moving an authorization decision into the PDP change the outcome of an attack that object-level ownership cannot catch — specifically, a request within the subject's own objects but outside its consent scope?
- *Implement.* Pass the subject's active consent into the policy input document and add a scope rule to `zt.rego`; add an attack that reads an account the subject owns but whose consent does not cover.
- *Metrics.* Attack success rate by configuration; added policy-stage latency.
- *Baseline.* B1, which has no policy engine and would allow it.
- *Strengthening result.* It would give the taxonomy one authorization attack that discriminates between B1 and P, which the current six do not, and it would exercise the PDP on something other than a risk threshold.
- *Affects the core contribution.* It broadens it: the paper currently measures the contextual layer only, not the policy layer's authorization capability.

### C. Optional

**E-7. Colocated or cached policy decision point.** The cost decomposition asserts that an in-process PDP or a decision cache removes most of the 9.39 ms. Measuring it converts an assertion into a result and gives deployers a number. Low effort, since the rule set is deterministic with a small input space.

**E-8. Mutual TLS between controller and resource server.** Closes the M6 irony and lets the paper state a trust boundary it actually enforces rather than assumes.

**E-9. mTLS-based sender-constraining as a second baseline arm.** Completes the FAPI 2.0 comparison and would show whether the "cryptography is cheap" result holds when the crypto is a TLS handshake rather than a signature check.

**E-10. Adversary strategies beyond A7.** A drifting adversary who moves once and then stays (defeating the geo rule by remaining consistent); an adversary who lowers a subject's legitimate rate before acting; an enrolment-time adversary. Each is a few dozen lines against the existing harness.

We deliberately do not recommend: more attack repetitions (30 per cell already gives intervals narrower than the effects being measured), more concurrency levels (the four measured already establish the fixed-tax shape), or additional statistical testing (the comparisons that matter are deterministic recomputations or have effect sizes reported).

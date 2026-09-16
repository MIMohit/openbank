"""
Standing check that every number in the manuscript still matches the data.

A manuscript and a results pipeline drift apart silently: a table is
regenerated, a figure is rebuilt, and a sentence in the prose keeps the old
value. Nothing fails, and the paper quietly stops being true. This script
re-derives every quantity the manuscript states from data/tables/*.csv and
asserts that the manuscript text contains it, so the drift becomes a failing
check instead of a reviewer's discovery.

Run: make verify-manuscript
Exit status is non-zero if any check fails.
"""
from __future__ import annotations

import pathlib
import sys

import pandas as pd

TBL = pathlib.Path("data/tables")
MANUSCRIPT = pathlib.Path("paper/manuscript.md")


def main() -> int:
    tables = {p.stem: pd.read_csv(p) for p in TBL.glob("*.csv")}
    md = MANUSCRIPT.read_text()
    checks: list[tuple[str, bool]] = []

    def chk(desc: str, cond) -> None:
        checks.append((desc, bool(cond)))

    # ── attack outcomes ──────────────────────────────────────────────────────
    t1 = tables["table1_taxonomy"].set_index("Attack")
    chk("A4 under P is 11 of 30",
        int(t1.at["A4", "P_k"]) == 11 and int(t1.at["A4", "P_n"]) == 30)
    chk("A4 under P rate and interval quoted",
        "0.367 [0.219, 0.545]" in md)
    chk("A3 under P is 30 of 30", int(t1.at["A3", "P_k"]) == 30)

    t1b = tables["table1b_oracle_ceiling"]
    chk("oracle ceiling is 0.000 on every attack",
        all(str(v).startswith("0.000") for v in t1b["P_oracle"]))

    # ── friction on legitimate traffic ───────────────────────────────────────
    t2 = tables["table2_false_challenge"]
    p_all = t2[(t2.Config == "P") & (t2.Context == "all")].iloc[0]
    chk("overall friction 0.0745 quoted",
        abs(float(p_all.friction_rate_num) - 0.0745) < 1e-6
        and "0.0745 [0.064, 0.087]" in md)
    chk("143 refusals and zero challenges",
        int(p_all.denies) == 143 and int(p_all.challenges) == 0
        and "143 refusals" in md)
    drift = t2[(t2.Config == "P") & (t2.Context == "drift")].iloc[0]
    chk("72 of 74 drift requests refused",
        int(drift.denies) == 72 and int(drift.n) == 74 and "72 of 74" in md)
    stable = t2[(t2.Config == "P") & (t2.Context == "stable")].iloc[0]
    chk("71 of 1846 stable requests refused",
        int(stable.denies) == 71 and int(stable.n) == 1846
        and "71 among stable-labelled" in md)

    # ── latency ──────────────────────────────────────────────────────────────
    t3 = tables["table3_latency"].set_index("Config")
    chk("P median 13.64 ms", abs(float(t3.at["P", "p50_ms"]) - 13.641) < 1e-3
        and "13.64" in md)
    chk("P - B1 median +6.22 ms",
        abs((float(t3.at["P", "p50_ms"]) - float(t3.at["B1", "p50_ms"])) - 6.218) < 1e-3
        and "+6.22 ms" in md)
    chk("P - B1 p99 +27.60 ms",
        abs((float(t3.at["P", "p99_ms"]) - float(t3.at["B1", "p99_ms"])) - 27.599) < 1e-2
        and "+27.60 ms" in md)
    chk("B1 - B0 median +0.60 ms",
        abs((float(t3.at["B1", "p50_ms"]) - float(t3.at["B0", "p50_ms"])) - 0.596) < 1e-3
        and "0.60 ms" in md)
    chk("policy stage 9.386 ms",
        abs(float(t3.at["P", "mean_policy_ms"]) - 9.3858) < 1e-3
        and "9.39 ms" in md and "9.386" in md)
    chk("DPoP verification 0.19 ms",
        abs(float(t3.at["P", "mean_dpop_verify_ms"]) - 0.1855) < 1e-3
        and "0.19 ms" in md)
    chk("allow-only mean 17.72 ms",
        abs(float(t3.at["P", "mean_allow_ms"]) - 17.723) < 1e-2 and "17.72 ms" in md)

    # ── resources ────────────────────────────────────────────────────────────
    t4 = tables["table4_resource_overhead"].set_index("Config")
    chk("P CPU +11.51 pp",
        abs(float(t4.at["P", "cpu_delta_vs_B0_pp"]) - 11.514) < 1e-2 and "+11.51" in md)
    chk("P memory +4.99 MiB",
        abs(float(t4.at["P", "mem_delta_vs_B0_mib"]) - 4.99) < 1e-2 and "5.0 MiB" in md)
    chk("B1 CPU +1.56 pp",
        abs(float(t4.at["B1", "cpu_delta_vs_B0_pp"]) - 1.559) < 1e-2 and "+1.56" in md)

    # ── ablation ─────────────────────────────────────────────────────────────
    t5 = tables["table5_ablation"].set_index("Cell")
    chk("P minus device binding A4 0.967",
        abs(float(t5.at["P-minus-device-binding", "A4_num"]) - 0.9667) < 1e-3
        and "0.967" in md)
    chk("P minus velocity A4 0.667",
        abs(float(t5.at["P-minus-velocity", "A4_num"]) - 0.6667) < 1e-3 and "0.667" in md)
    chk("P minus context has zero friction",
        float(t5.at["P-minus-context", "friction_drift_num"]) == 0.0)

    # ── threshold sweep ──────────────────────────────────────────────────────
    t6 = tables["table6_threshold_sensitivity"].set_index("tau_allow")
    chk("tau 0.30 refuses all of A4", float(t6.at[0.30, "A4_blocked"]) == 1.0)
    chk("tau 0.30 friction equals tau 0.40 friction",
        float(t6.at[0.30, "legit_stable_friction"])
        == float(t6.at[0.40, "legit_stable_friction"])
        and float(t6.at[0.30, "legit_drift_friction"])
        == float(t6.at[0.40, "legit_drift_friction"]))
    chk("tau 0.40 refuses 63.3% of A4",
        abs(float(t6.at[0.40, "A4_blocked"]) - 0.6333) < 1e-3 and "63.3%" in md)
    chk("A3 only reachable at tau 0.25, where all legitimate traffic is refused",
        abs(float(t6.at[0.25, "A3_blocked"]) - 0.30) < 1e-6
        and float(t6.at[0.25, "legit_stable_friction"]) == 1.0)

    # ── rule firing ──────────────────────────────────────────────────────────
    t7 = tables["table7_risk_components"].set_index("population")
    chk("unknown-device rule fires on all of A4",
        float(t7.at["attack A4", "device_fp_changed"]) == 1.0)
    chk("call-rate rule fires on all legitimate traffic",
        float(t7.at["legitimate (stable)", "high_call_rate"]) == 1.0)
    chk("A4 mean risk 0.507",
        abs(float(t7.at["attack A4", "mean_risk"]) - 0.5067) < 1e-3 and "0.507" in md)
    chk("A3 mean risk 0.075",
        abs(float(t7.at["attack A3", "mean_risk"]) - 0.075) < 1e-6 and "0.075" in md)
    chk("measurement-integrity audit: oracle rule never fired",
        (t7["attack_context"] == 0.0).all())

    # ── scaling ──────────────────────────────────────────────────────────────
    t8 = tables["table8_scaling"]
    med = {cfg: {int(r.users): float(r.p50_ms)
                 for _, r in t8[t8.Config == cfg].iterrows()}
           for cfg in ("B1", "P")}
    gaps = [round(med["P"][u] - med["B1"][u], 1) for u in (5, 10, 20, 40)]
    chk("P - B1 median gaps 7.8 / 4.9 / 5.8 / 9.6",
        gaps == [7.8, 4.9, 5.8, 9.6] and "+7.8, +4.9, +5.8 and +9.6" in md)
    rps40 = {r.Config: float(r.achieved_rps) for _, r in t8[t8.users == 40].iterrows()}
    spread = (max(rps40.values()) - min(rps40.values())) / max(rps40.values()) * 100
    chk("achieved rate spread 6.1% at 40 clients",
        abs(spread - 6.11) < 0.1 and "6.1%" in md)

    # ── adaptive adversary ───────────────────────────────────────────────────
    t9 = tables["table9_adaptive_adversary"].set_index("Cell")
    chk("adaptive adversary succeeds 30/30 at the shipped threshold, 4.0 s pace",
        float(t9.at["P-adaptive-slow", "A7_success_num"]) == 1.0)
    chk("adaptive adversary 0.900 at 2.5 s pace",
        abs(float(t9.at["P-adaptive", "A7_success_num"]) - 0.9) < 1e-6
        and "0.900 [0.744, 0.965]" in md)
    chk("recalibrated threshold refuses the adaptive adversary at both paces",
        float(t9.at["P-adaptive-tau030", "A7_success_num"]) == 0.0
        and float(t9.at["P-adaptive-slow-tau030", "A7_success_num"]) == 0.0)
    chk("residual rate transient is 10% of the 2.5 s cell",
        abs(float(t9.at["P-adaptive", "high_call_rate"]) - 0.1) < 1e-6
        and "10% of the adaptive" in md)
    chk("adaptive adversary mean risk 0.350 at 4.0 s",
        abs(float(t9.at["P-adaptive-slow", "mean_risk"]) - 0.35) < 1e-6 and "0.350" in md)

    # ── effect sizes ─────────────────────────────────────────────────────────
    te = tables["table_effect_sizes"]
    a4 = te[(te.comparison == "attack success P vs B1") & (te.metric == "A4")].iloc[0]
    chk("A4 risk difference -0.633 with interval",
        abs(float(a4.effect_value) + 0.6333) < 1e-3 and "[−0.806, −0.461]" in md)
    lat = te[te.comparison == "latency P vs B1"].iloc[0]
    chk("Cliff's delta 0.580 for P vs B1",
        abs(float(lat.effect_value) - 0.5804) < 1e-3 and "0.580" in md)
    lat0 = te[te.comparison == "latency B1 vs B0"].iloc[0]
    chk("Cliff's delta 0.115 for B1 vs B0",
        abs(float(lat0.effect_value) - 0.1152) < 1e-3 and "0.115" in md)
    pooled = te[(te.comparison == "attack success P vs B1")
                & (te.metric == "A1-A6 pooled")].iloc[0]
    chk("pooled risk difference -0.106",
        abs(float(pooled.effect_value) + 0.1056) < 1e-3 and "−0.106" in md)

    failed = [d for d, ok in checks if not ok]
    print(f"{len(checks) - len(failed)}/{len(checks)} manuscript claims match the data")
    for d in failed:
        print(f"  MISMATCH: {d}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

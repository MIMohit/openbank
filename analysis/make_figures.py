"""
Analysis pipeline — reads data/raw/ and writes every figure and table the
paper cites to data/figures/ and data/tables/.

Run: make analysis   (or: PYTHONPATH=. analysis/.venv/bin/python3 analysis/make_figures.py)

Inputs
  data/raw/<run_id>.jsonl          one record per controller request. run_id
                                   prefixes name the workload: exp_* (Locust
                                   legitimate traffic), atk_* (primary attack
                                   suite), orc_* (oracle-ceiling suite),
                                   abl_* (ablation cells).
  data/raw/attacks/summary.jsonl          primary attack outcomes
  data/raw/attacks_oracle/summary.jsonl   oracle-ceiling outcomes
  data/raw/attacks_ablation/summary.jsonl ablation outcomes
  data/raw/resources*/<cell>.csv          docker-stats samples per workload

Every number in the paper traces to one of the CSVs written here.
"""
import json
import os
from pathlib import Path
from typing import List, Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from analysis.stats import (
    bootstrap_ci, cliffs_delta, cliffs_delta_magnitude, odds_ratio,
    risk_difference, wilson_ci,
)

RAW_DIR = Path("data/raw")
ATK_DIR = RAW_DIR / "attacks"
ORACLE_DIR = RAW_DIR / "attacks_oracle"
ABL_DIR = RAW_DIR / "attacks_ablation"
RES_DIR = RAW_DIR / "resources"
RES_ABL_DIR = RAW_DIR / "resources_ablation"
FIG_DIR = Path("data/figures")
TBL_DIR = Path("data/tables")

CONFIGS = ["B0", "B1", "P"]
ATTACKS = [f"A{i}" for i in range(1, 7)]
ATTACK_NAMES = {
    "A1": "Network token replay",
    "A2": "Token theft without key",
    "A3": "Device-resident key abuse",
    "A4": "ATO from new device",
    "A5": "BOLA/BFLA",
    "A6": "Velocity/consent abuse",
}
ABLATION_CELLS = ["P", "P-minus-device-binding", "P-minus-context",
                  "P-minus-velocity", "B1"]


# ─── Loading ─────────────────────────────────────────────────────────────────

def _ensure_dirs():
    for d in [FIG_DIR, TBL_DIR]:
        d.mkdir(parents=True, exist_ok=True)


def _load_jsonl(path: Path) -> List[dict]:
    records = []
    if path.is_file():
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return records


def _load_all_raw() -> pd.DataFrame:
    rows = []
    for f in sorted(RAW_DIR.glob("*.jsonl")):
        rows.extend(_load_jsonl(f))
    if not rows:
        return pd.DataFrame()
    df = pd.json_normalize(rows)
    for col, default in [("run_label", ""), ("request.context_profile", ""),
                         ("attack.is_attack", False), ("attack.attack_id", None),
                         ("risk.risk", np.nan)]:
        if col not in df.columns:
            df[col] = default
    df["run_label"] = df["run_label"].fillna(df["config"])
    df["attack.is_attack"] = df["attack.is_attack"].fillna(False).astype(bool)
    df["request.context_profile"] = df["request.context_profile"].fillna("")
    return df


def _load_attack_summary(directory: Path) -> pd.DataFrame:
    """
    Load one attack sweep.

    Only summary.jsonl is read. The per-attack A<id>_<cell>.jsonl files hold
    the same rows, so globbing the directory (as this used to) counted every
    result twice and halved every reported success rate's effective weight.
    """
    rows = _load_jsonl(directory / "summary.jsonl")
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows)


WARMUP_SECONDS = 5.0


def _drop_warmup_window(df: pd.DataFrame, seconds: float = WARMUP_SECONDS) -> pd.DataFrame:
    """
    Drop each run's first `seconds` of traffic.

    §8 states that warm-up is excluded and nothing implemented it. It is not a
    cosmetic exclusion: every workload starts against a freshly restarted
    container, and the cold-start cost is large enough to dominate a short run
    (the 5-user B0 scaling cell reports a 53 ms median over the whole run
    against ~7 ms once the first seconds are dropped), which would make the
    lowest-concurrency cell look like the slowest.
    """
    if df.empty or "ts" not in df.columns:
        return df
    out = df.copy()
    out["_ts"] = pd.to_datetime(out["ts"], format="ISO8601", utc=True, errors="coerce")
    start = out.groupby("run_id")["_ts"].transform("min")
    out = out[out["_ts"] >= start + pd.Timedelta(seconds=seconds)]
    return out.drop(columns=["_ts"])


def _legit(df: pd.DataFrame, run_prefix: str = "", drop_warmup: bool = True) -> pd.DataFrame:
    """
    Legitimate workload requests only.

    Excludes attack traffic, the harness warm-up requests that establish a
    subject's baseline (instrumentation, not workload — counting them would
    dilute every rate reported per context profile), and each run's opening
    warm-up window.
    """
    if df.empty:
        return df
    out = df[(~df["attack.is_attack"]) &
             (df["request.context_profile"].isin(["stable", "drift"]))]
    if run_prefix:
        out = out[out["run_id"].astype(str).str.startswith(run_prefix)]
    if drop_warmup:
        out = _drop_warmup_window(out)
    return out


def _fmt_ci(p: float, lo: float, hi: float) -> str:
    return f"{p:.3f} [{lo:.3f}, {hi:.3f}]"


# ─── Table 1 + Figure: attack outcomes (RQ1) ─────────────────────────────────

def table_taxonomy(atk_df: pd.DataFrame) -> pd.DataFrame:
    """
    Table 1 — attack success rate by configuration, with Wilson 95% CIs.

    The "stopped by B1" / "P adds value" columns are derived from the measured
    rates rather than asserted from the design intent, so the table cannot
    disagree with the figure beside it.
    """
    rows = []
    for aid in ATTACKS:
        row = {"Attack": aid, "Description": ATTACK_NAMES[aid]}
        rates = {}
        for cfg in CONFIGS:
            sub = atk_df[(atk_df["attack_id"] == aid) & (atk_df["config"] == cfg)] \
                if not atk_df.empty else pd.DataFrame()
            if sub.empty:
                row[f"{cfg}_success"] = ""
                row[f"{cfg}_n"] = 0
                continue
            k, n = int(sub["successes"].sum()), int(sub["attempts"].sum())
            p, lo, hi = wilson_ci(k, n)
            rates[cfg] = p
            row[f"{cfg}_success"] = _fmt_ci(p, lo, hi)
            row[f"{cfg}_k"] = k
            row[f"{cfg}_n"] = n
        if "B1" in rates and "P" in rates:
            row["Stopped by B1"] = "Yes" if rates["B1"] <= 0.05 else "No"
            row["P adds value"] = "Yes" if (rates["B1"] - rates["P"]) > 0.05 else "No"
            row["P-B1 success delta"] = round(rates["P"] - rates["B1"], 4)
        rows.append(row)
    df = pd.DataFrame(rows)
    df.to_csv(TBL_DIR / "table1_taxonomy.csv", index=False)
    print("[OK] table1_taxonomy.csv")
    return df


def table_oracle_ceiling(atk_df: pd.DataFrame, orc_df: pd.DataFrame):
    """
    Table 1b — organic detection vs the oracle ceiling.

    The oracle run hands the risk engine a header saying "this request is an
    attack" (rule R7, +0.90). It is not detection; it bounds what the same
    enforcement pipeline would block given a perfect detector, and it is
    reported apart from every primary number precisely so the two cannot be
    confused.
    """
    if orc_df.empty:
        print("[WARN] no oracle-ceiling data; skipping table1b")
        return
    rows = []
    for aid in ATTACKS:
        row = {"Attack": aid, "Description": ATTACK_NAMES[aid]}
        for cfg in ["B1", "P"]:
            org = atk_df[(atk_df["attack_id"] == aid) & (atk_df["config"] == cfg)]
            orc = orc_df[(orc_df["attack_id"] == aid) & (orc_df["config"] == cfg)]
            for label, sub in (("organic", org), ("oracle", orc)):
                if sub.empty:
                    row[f"{cfg}_{label}"] = ""
                    continue
                k, n = int(sub["successes"].sum()), int(sub["attempts"].sum())
                p, lo, hi = wilson_ci(k, n)
                row[f"{cfg}_{label}"] = _fmt_ci(p, lo, hi)
        rows.append(row)
    pd.DataFrame(rows).to_csv(TBL_DIR / "table1b_oracle_ceiling.csv", index=False)
    print("[OK] table1b_oracle_ceiling.csv")


def fig_attack_success(atk_df: pd.DataFrame):
    if atk_df.empty:
        print("[WARN] No attack data for fig_attack_success")
        return
    fig, ax = plt.subplots(figsize=(10, 5))
    width = 0.25
    x = np.arange(len(ATTACKS))
    for i, cfg in enumerate(CONFIGS):
        sub = atk_df[atk_df["config"] == cfg]
        rates, lows, highs = [], [], []
        for atk in ATTACKS:
            row = sub[sub["attack_id"] == atk]
            if row.empty:
                rates.append(0); lows.append(0); highs.append(0)
                continue
            k = int(row["successes"].sum())
            n = int(row["attempts"].sum())
            p, lo, hi = wilson_ci(k, n)
            # max(0, ...) absorbs floating-point noise at the p==0/p==1
            # boundary (e.g. hi computing to 0.9999999999999999 instead of
            # exactly 1.0), which errorbar() rejects as a negative yerr.
            rates.append(p); lows.append(max(0.0, p - lo)); highs.append(max(0.0, hi - p))
        ax.bar(x + i * width, rates, width, label=cfg,
               yerr=[lows, highs], capsize=4, alpha=0.85)
    ax.set_xticks(x + width)
    ax.set_xticklabels([f"{a}\n{ATTACK_NAMES[a].split()[0]}" for a in ATTACKS])
    ax.set_ylabel("Attack success rate")
    ax.set_title("Attack success rate by configuration (Wilson 95% CI, organic detection)")
    ax.legend()
    ax.set_ylim(0, 1.1)
    fig.tight_layout()
    fig.savefig(FIG_DIR / "fig2_attack_success_rate.png", dpi=150)
    plt.close(fig)
    print("[OK] fig2_attack_success_rate.png")


# ─── Table 2: false challenge / false deny on legitimate traffic ─────────────

def table_false_challenge(raw_df: pd.DataFrame):
    """
    Table 2 — CHALLENGE and DENY rates on legitimate traffic, split by whether
    the request's context was stable or drifting.

    The split is only possible because the load generator labels each request
    `x-context-profile: stable|drift` and the controller records the label;
    without it both populations are one undifferentiated blob in the logs.
    """
    legit = _legit(raw_df, run_prefix="exp_")
    if legit.empty:
        print("[WARN] No legitimate-traffic data for table2")
        return
    rows = []
    for cfg in CONFIGS:
        for profile in ["stable", "drift", "all"]:
            sub = legit[legit["run_label"] == cfg]
            if profile != "all":
                sub = sub[sub["request.context_profile"] == profile]
            n = len(sub)
            if n == 0:
                continue
            n_ch = int((sub["decision"] == "CHALLENGE").sum())
            n_dn = int((sub["decision"] == "DENY").sum())
            ch, ch_lo, ch_hi = wilson_ci(n_ch, n)
            dn, dn_lo, dn_hi = wilson_ci(n_dn, n)
            fr, fr_lo, fr_hi = wilson_ci(n_ch + n_dn, n)
            rows.append({
                "Config": cfg,
                "Context": profile,
                "n": n,
                "challenges": n_ch,
                "false_challenge_rate": _fmt_ci(ch, ch_lo, ch_hi),
                "denies": n_dn,
                "false_deny_rate": _fmt_ci(dn, dn_lo, dn_hi),
                "friction_rate": _fmt_ci(fr, fr_lo, fr_hi),
                "challenge_rate_num": round(ch, 4),
                "deny_rate_num": round(dn, 4),
                "friction_rate_num": round(fr, 4),
            })
    pd.DataFrame(rows).to_csv(TBL_DIR / "table2_false_challenge.csv", index=False)
    print("[OK] table2_false_challenge.csv")


# ─── Table 3 + figures: latency (RQ2) ────────────────────────────────────────

STAGES = ["token_verify", "dpop_verify", "telemetry", "risk", "policy", "proxy"]


def table_latency(raw_df: pd.DataFrame):
    legit = _legit(raw_df, run_prefix="exp_")
    if legit.empty or "latency_ms.total" not in legit.columns:
        print("[WARN] No latency data for table")
        return
    rows = []
    for cfg in CONFIGS:
        sub = legit[legit["run_label"] == cfg]
        vals = sub["latency_ms.total"].dropna()
        if vals.empty:
            continue
        est, lo, hi = bootstrap_ci(vals.values, np.mean)
        allow = sub[sub["decision"] == "ALLOW"]["latency_ms.total"].dropna()
        row = {
            "Config": cfg,
            "n": len(vals),
            "p50_ms": round(float(np.percentile(vals, 50)), 3),
            "p95_ms": round(float(np.percentile(vals, 95)), 3),
            "p99_ms": round(float(np.percentile(vals, 99)), 3),
            "mean_ms": round(est, 3),
            "mean_ci_lo": round(lo, 3),
            "mean_ci_hi": round(hi, 3),
            # Denied requests short-circuit before the proxy hop, so a config
            # that denies more looks faster overall; the ALLOW-only column is
            # the like-for-like comparison.
            "n_allow": len(allow),
            "p50_allow_ms": round(float(np.percentile(allow, 50)), 3) if len(allow) else "",
            "p95_allow_ms": round(float(np.percentile(allow, 95)), 3) if len(allow) else "",
            "mean_allow_ms": round(float(allow.mean()), 3) if len(allow) else "",
        }
        for stage in STAGES:
            col = f"latency_ms.{stage}"
            row[f"mean_{stage}_ms"] = round(float(sub[col].mean()), 4) if col in sub else 0.0
        rows.append(row)
    pd.DataFrame(rows).to_csv(TBL_DIR / "table3_latency.csv", index=False)
    print("[OK] table3_latency.csv")


def fig_latency(raw_df: pd.DataFrame):
    legit = _legit(raw_df, run_prefix="exp_")
    if legit.empty or "latency_ms.total" not in legit.columns:
        print("[WARN] No latency data")
        return
    fig, axes = plt.subplots(1, 3, figsize=(16, 5))

    data = [legit[legit["run_label"] == cfg]["latency_ms.total"].dropna().values
            for cfg in CONFIGS]
    ax = axes[0]
    ax.violinplot([d for d in data if len(d)], positions=range(len([d for d in data if len(d)])),
                  showmedians=True)
    ax.set_xticks(range(len(CONFIGS)))
    ax.set_xticklabels(CONFIGS)
    ax.set_ylabel("Total latency (ms)")
    ax.set_title("Latency distribution by config")

    ax = axes[1]
    for cfg, d in zip(CONFIGS, data):
        if len(d) == 0:
            continue
        xs = np.sort(d)
        ys = np.arange(1, len(xs) + 1) / len(xs)
        ax.plot(xs, ys, label=cfg)
    ax.set_xlabel("Total latency (ms)")
    ax.set_ylabel("CDF")
    ax.set_title("Per-request latency CDF")
    ax.set_xscale("log")
    ax.legend()
    ax.grid(alpha=0.3)

    ax2 = axes[2]
    bottoms = np.zeros(len(CONFIGS))
    colors = plt.cm.Set3(np.linspace(0, 1, len(STAGES)))
    for j, stage in enumerate(STAGES):
        col = f"latency_ms.{stage}"
        means = np.array([
            legit[legit["run_label"] == cfg][col].mean() if col in legit.columns else 0.0
            for cfg in CONFIGS
        ])
        means = np.nan_to_num(means)
        ax2.bar(CONFIGS, means, bottom=bottoms, label=stage, color=colors[j])
        bottoms += means
    ax2.set_ylabel("Mean stage latency (ms)")
    ax2.set_title("Stage latency breakdown")
    ax2.legend(fontsize=7)

    fig.tight_layout()
    fig.savefig(FIG_DIR / "fig3_latency.png", dpi=150)
    plt.close(fig)
    print("[OK] fig3_latency.png")


# ─── Table 4: CPU / memory overhead ──────────────────────────────────────────

def _load_resources(directory: Path) -> pd.DataFrame:
    frames = []
    if directory.is_dir():
        for f in sorted(directory.glob("*.csv")):
            try:
                frames.append(pd.read_csv(f))
            except Exception:
                pass
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def table_resources():
    """Table 4 — controller CPU/memory while the legitimate workload runs."""
    res = _load_resources(RES_DIR)
    if res.empty:
        print("[WARN] No resource samples for table4")
        return
    rows = []
    for cfg in CONFIGS:
        sub = res[res["run_label"] == cfg]
        if sub.empty:
            continue
        rows.append({
            "Config": cfg,
            "samples": len(sub),
            "cpu_mean_pct": round(float(sub["cpu_percent"].mean()), 3),
            "cpu_p95_pct": round(float(np.percentile(sub["cpu_percent"], 95)), 3),
            "cpu_peak_pct": round(float(sub["cpu_percent"].max()), 3),
            "mem_mean_mib": round(float(sub["mem_mib"].mean()), 2),
            "mem_peak_mib": round(float(sub["mem_mib"].max()), 2),
            "mem_mean_pct": round(float(sub["mem_percent"].mean()), 3),
        })
    df = pd.DataFrame(rows)
    if not df.empty and "B0" in set(df["Config"]):
        base_cpu = float(df[df["Config"] == "B0"]["cpu_mean_pct"].iloc[0])
        base_mem = float(df[df["Config"] == "B0"]["mem_mean_mib"].iloc[0])
        df["cpu_delta_vs_B0_pp"] = (df["cpu_mean_pct"] - base_cpu).round(3)
        df["mem_delta_vs_B0_mib"] = (df["mem_mean_mib"] - base_mem).round(2)
    df.to_csv(TBL_DIR / "table4_resource_overhead.csv", index=False)
    print("[OK] table4_resource_overhead.csv")


# ─── Table 5: ablation (RQ3) ─────────────────────────────────────────────────

def table_ablation(abl_df: pd.DataFrame, raw_df: pd.DataFrame):
    """
    Table 5 — security and usability per ablation cell.

    Each cell removes one enforcement component and is run through both the
    attack suite and the drifting legitimate workload, so a component that buys
    security can be seen paying for it in friction on the same row.
    """
    if abl_df.empty:
        print("[WARN] No ablation data for table5")
        return
    legit = _legit(raw_df, run_prefix="abl_")
    rows = []
    for cell in ABLATION_CELLS:
        sub = abl_df[abl_df["config"] == cell]
        if sub.empty:
            continue
        row = {"Cell": cell}
        tot_k = tot_n = 0
        for aid in ATTACKS:
            a = sub[sub["attack_id"] == aid]
            if a.empty:
                row[aid] = ""
                continue
            k, n = int(a["successes"].sum()), int(a["attempts"].sum())
            tot_k += k
            tot_n += n
            p, lo, hi = wilson_ci(k, n)
            row[aid] = _fmt_ci(p, lo, hi)
            row[f"{aid}_num"] = round(p, 4)
        if tot_n:
            p, lo, hi = wilson_ci(tot_k, tot_n)
            row["overall_attack_success"] = _fmt_ci(p, lo, hi)
            row["overall_attack_success_num"] = round(p, 4)
        cell_legit = legit[legit["run_label"] == cell] if not legit.empty else pd.DataFrame()
        for profile in ["stable", "drift"]:
            s = cell_legit[cell_legit["request.context_profile"] == profile] \
                if not cell_legit.empty else pd.DataFrame()
            n = len(s)
            if n == 0:
                row[f"friction_{profile}"] = ""
                continue
            k = int(s["decision"].isin(["CHALLENGE", "DENY"]).sum())
            p, lo, hi = wilson_ci(k, n)
            row[f"friction_{profile}"] = _fmt_ci(p, lo, hi)
            row[f"friction_{profile}_num"] = round(p, 4)
            row[f"n_{profile}"] = n
        rows.append(row)
    pd.DataFrame(rows).to_csv(TBL_DIR / "table5_ablation.csv", index=False)
    print("[OK] table5_ablation.csv")


def fig_ablation(abl_df: pd.DataFrame, raw_df: pd.DataFrame):
    if abl_df.empty:
        return
    legit = _legit(raw_df, run_prefix="abl_")
    cells, atk_rates, friction = [], [], []
    for cell in ABLATION_CELLS:
        sub = abl_df[abl_df["config"] == cell]
        if sub.empty:
            continue
        cells.append(cell.replace("P-minus-", "P−"))
        atk_rates.append(int(sub["successes"].sum()) / max(1, int(sub["attempts"].sum())))
        s = legit[legit["run_label"] == cell] if not legit.empty else pd.DataFrame()
        friction.append(
            float(s["decision"].isin(["CHALLENGE", "DENY"]).mean()) if len(s) else 0.0)
    if not cells:
        return
    x = np.arange(len(cells))
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(x - 0.2, atk_rates, 0.4, label="Attack success rate (A1–A6 pooled)")
    ax.bar(x + 0.2, friction, 0.4, label="Legitimate CHALLENGE/DENY rate")
    ax.set_xticks(x)
    ax.set_xticklabels(cells, rotation=15, ha="right")
    ax.set_ylabel("Rate")
    ax.set_title("Ablation: what each enforcement component buys and costs")
    ax.legend()
    fig.tight_layout()
    fig.savefig(FIG_DIR / "fig5_ablation.png", dpi=150)
    plt.close(fig)
    print("[OK] fig5_ablation.png")


# ─── Effect sizes ────────────────────────────────────────────────────────────

def table_effect_sizes(raw_df: pd.DataFrame, atk_df: pd.DataFrame):
    """
    Effect sizes for every P-vs-B1 comparison the paper reports (§8).

    Latency: Cliff's delta (ordinal, non-parametric, no normality assumption).
    Attack success: risk difference with a 95% CI, plus a Haldane-Anscombe
    odds ratio — a rate difference is what a deployer acts on, and an odds
    ratio stays finite when a cell is 0/30 or 30/30, which several are.
    """
    rows = []
    legit = _legit(raw_df, run_prefix="exp_")
    if not legit.empty and "latency_ms.total" in legit.columns:
        for a, b in [("B0", "B1"), ("B1", "P"), ("B0", "P")]:
            xa = legit[legit["run_label"] == a]["latency_ms.total"].dropna().values
            xb = legit[legit["run_label"] == b]["latency_ms.total"].dropna().values
            if len(xa) == 0 or len(xb) == 0:
                continue
            d = cliffs_delta(xb, xa)   # positive => b slower than a
            rows.append({
                "comparison": f"latency {b} vs {a}",
                "metric": "total latency (ms)",
                "n_a": len(xa), "n_b": len(xb),
                "estimate_a": round(float(np.median(xa)), 3),
                "estimate_b": round(float(np.median(xb)), 3),
                "effect_size": "Cliff's delta",
                "effect_value": round(d, 4),
                "effect_magnitude": cliffs_delta_magnitude(d),
                "ci_lo": "", "ci_hi": "", "odds_ratio": "",
            })

    if not atk_df.empty:
        for a, b in [("B0", "B1"), ("B1", "P")]:
            for aid in ATTACKS + ["ALL"]:
                if aid == "ALL":
                    sa = atk_df[atk_df["config"] == a]
                    sb = atk_df[atk_df["config"] == b]
                else:
                    sa = atk_df[(atk_df["config"] == a) & (atk_df["attack_id"] == aid)]
                    sb = atk_df[(atk_df["config"] == b) & (atk_df["attack_id"] == aid)]
                if sa.empty or sb.empty:
                    continue
                ka, na = int(sa["successes"].sum()), int(sa["attempts"].sum())
                kb, nb = int(sb["successes"].sum()), int(sb["attempts"].sum())
                pa, pb = ka / na, kb / nb
                rd, lo, hi = risk_difference(pb, pa, nb, na)
                rows.append({
                    "comparison": f"attack success {b} vs {a}",
                    "metric": aid if aid != "ALL" else "A1-A6 pooled",
                    "n_a": na, "n_b": nb,
                    "estimate_a": round(pa, 4),
                    "estimate_b": round(pb, 4),
                    "effect_size": "risk difference (b - a)",
                    "effect_value": round(rd, 4),
                    "effect_magnitude": "",
                    "ci_lo": round(lo, 4), "ci_hi": round(hi, 4),
                    "odds_ratio": round(odds_ratio(kb, nb, ka, na), 4),
                })

    if not rows:
        print("[WARN] No data for effect sizes")
        return
    pd.DataFrame(rows).to_csv(TBL_DIR / "table_effect_sizes.csv", index=False)
    print("[OK] table_effect_sizes.csv")


# ─── Threshold sensitivity ───────────────────────────────────────────────────

def _hard_blocked(df: pd.DataFrame) -> pd.Series:
    """Requests refused by a credential check, independently of any threshold."""
    cols = {c: df[c] for c in
            ["checks.token_valid", "checks.dpop_valid", "checks.jti_replayed",
             "checks.cnf_jkt_match"] if c in df.columns}
    blocked = pd.Series(False, index=df.index)
    if "checks.token_valid" in cols:
        blocked |= ~cols["checks.token_valid"].fillna(False).astype(bool)
    if "checks.dpop_valid" in cols:
        blocked |= ~cols["checks.dpop_valid"].fillna(False).astype(bool)
    if "checks.jti_replayed" in cols:
        blocked |= cols["checks.jti_replayed"].fillna(False).astype(bool)
    if "checks.cnf_jkt_match" in cols:
        blocked |= ~cols["checks.cnf_jkt_match"].fillna(False).astype(bool)
    return blocked


def table_threshold_sensitivity(raw_df: pd.DataFrame):
    """
    Threshold sweep over the risk scores P actually recorded (§9.4).

    The shipped thresholds are one point on a curve, and reporting only that
    point cannot distinguish "the signal is absent" from "the signal is present
    but priced below the challenge threshold". Recomputing the decision each
    request would have received under other thresholds costs nothing — the risk
    score is in the record — and answers what calibration would be needed to
    catch the attacks P misses, and what it would cost in friction.
    """
    if raw_df.empty or "risk.risk" not in raw_df.columns:
        print("[WARN] No risk scores for threshold sweep")
        return
    p_runs = raw_df[raw_df["run_label"] == "P"]
    attack = p_runs[p_runs["attack.is_attack"] &
                    p_runs["run_id"].astype(str).str.startswith("atk_")]
    legit = _legit(p_runs, run_prefix="exp_")
    if attack.empty or legit.empty:
        print("[WARN] Not enough P-mode data for threshold sweep")
        return

    a_hard = _hard_blocked(attack)
    a_risk = attack["risk.risk"].fillna(0.0).values
    a_ids = attack["attack.attack_id"].values
    l_hard = _hard_blocked(legit)
    l_risk = legit["risk.risk"].fillna(0.0).values
    l_profile = legit["request.context_profile"].values

    rows = []
    for tau in np.round(np.arange(0.05, 1.01, 0.05), 2):
        a_block = a_hard.values | (a_risk >= tau)
        l_block = l_hard.values | (l_risk >= tau)
        row = {
            "tau_allow": tau,
            "attack_requests": len(a_risk),
            "attack_blocked_rate": round(float(a_block.mean()), 4),
            "legit_stable_friction": round(
                float(l_block[l_profile == "stable"].mean()), 4)
            if (l_profile == "stable").any() else "",
            "legit_drift_friction": round(
                float(l_block[l_profile == "drift"].mean()), 4)
            if (l_profile == "drift").any() else "",
            "legit_overall_friction": round(float(l_block.mean()), 4),
        }
        for aid in ATTACKS:
            mask = a_ids == aid
            row[f"{aid}_blocked"] = round(float(a_block[mask].mean()), 4) if mask.any() else ""
        rows.append(row)
    df = pd.DataFrame(rows)
    df.to_csv(TBL_DIR / "table6_threshold_sensitivity.csv", index=False)
    print("[OK] table6_threshold_sensitivity.csv")

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.plot(df["tau_allow"], df["attack_blocked_rate"], "o-", label="Attack requests blocked")
    for col, lab in [("legit_stable_friction", "Legitimate (stable) blocked"),
                     ("legit_drift_friction", "Legitimate (drift) blocked")]:
        vals = pd.to_numeric(df[col], errors="coerce")
        if vals.notna().any():
            ax.plot(df["tau_allow"], vals, "s--", label=lab)
    ax.axvline(0.4, color="grey", ls=":", label=r"shipped $\tau_{allow}=0.4$")
    ax.set_xlabel(r"Challenge threshold $\tau_{allow}$")
    ax.set_ylabel("Fraction of requests not allowed")
    ax.set_title("Threshold sensitivity (P, measured risk scores)")
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIG_DIR / "fig6_threshold_sensitivity.png", dpi=150)
    plt.close(fig)
    print("[OK] fig6_threshold_sensitivity.png")


# ─── Risk-component attribution ──────────────────────────────────────────────

def table_risk_components(raw_df: pd.DataFrame):
    """
    Which risk rules actually fired, per attack and on legitimate traffic.

    This is what lets the discussion say *why* an attack was or was not caught
    rather than only that it was, and it is how the claim "P's A4 blocking is
    device and session evidence, not a self-declared tag" is checked: the
    attack_context column must read 0.0 on every primary row.

    pd.json_normalize flattens `risk.score_components` into one column per rule
    that fired somewhere in the data, so a rule that never fired has no column
    at all; each is read defensively rather than assumed present.
    """
    RULES = ["cnf_jkt_mismatch", "device_fp_changed", "impossible_velocity",
             "high_call_rate", "low_session_continuity", "dpop_failure_elevated",
             "attack_context"]
    if raw_df.empty:
        return
    p_runs = raw_df[raw_df["run_label"] == "P"]
    if p_runs.empty or "risk.risk" not in p_runs.columns:
        return
    rows = []

    def _tally(sub, label):
        if sub.empty:
            return
        row = {"population": label, "n": len(sub)}
        for rule in RULES:
            col = f"risk.score_components.{rule}"
            if col in sub.columns:
                fired = sub[col].notna().sum()
            else:
                fired = 0
            row[rule] = round(float(fired) / len(sub), 4)
        row["mean_risk"] = round(float(sub["risk.risk"].fillna(0).mean()), 4)
        row["mean_risk_scored_only"] = round(
            float(sub["risk.risk"].dropna().mean()), 4) if sub["risk.risk"].notna().any() else ""
        rows.append(row)

    atk = p_runs[p_runs["attack.is_attack"] &
                 p_runs["run_id"].astype(str).str.startswith("atk_")]
    for aid in ATTACKS:
        _tally(atk[atk["attack.attack_id"] == aid], f"attack {aid}")
    legit = _legit(p_runs, run_prefix="exp_")
    for profile in ["stable", "drift"]:
        _tally(legit[legit["request.context_profile"] == profile],
               f"legitimate ({profile})")
    if rows:
        pd.DataFrame(rows).to_csv(TBL_DIR / "table7_risk_components.csv", index=False)
        print("[OK] table7_risk_components.csv")


# ─── Table 8 + figure: latency and throughput vs concurrency (RQ2) ──────────

def table_scaling(raw_df: pd.DataFrame):
    """
    Table 8 — how the enforcement overhead moves as offered load rises.

    RQ2 asks for the overhead "across increasing load" and a single
    concurrency level cannot answer it. Achieved throughput is recomputed from
    the controller's own timestamps rather than scraped from the load
    generator's summary, so it counts the same requests the latency figures do.
    """
    if raw_df.empty:
        return
    scale = raw_df[raw_df["run_id"].astype(str).str.startswith("scale_")]
    legit = _legit(scale)
    if legit.empty:
        print("[WARN] No scaling data for table8")
        return
    legit = legit.copy()
    legit["_ts"] = pd.to_datetime(legit["ts"], format="ISO8601", utc=True, errors="coerce")
    legit["users"] = legit["run_id"].astype(str).str.split("_").str[-1].astype(int)

    rows = []
    for (cfg, users), sub in legit.groupby(["run_label", "users"]):
        vals = sub["latency_ms.total"].dropna()
        if vals.empty:
            continue
        span = (sub["_ts"].max() - sub["_ts"].min()).total_seconds()
        rows.append({
            "Config": cfg,
            "users": int(users),
            "n": len(vals),
            "achieved_rps": round(len(vals) / span, 2) if span > 0 else "",
            "p50_ms": round(float(np.percentile(vals, 50)), 3),
            "p95_ms": round(float(np.percentile(vals, 95)), 3),
            "p99_ms": round(float(np.percentile(vals, 99)), 3),
            "mean_ms": round(float(vals.mean()), 3),
        })
    if not rows:
        return
    df = pd.DataFrame(rows).sort_values(["Config", "users"])
    df.to_csv(TBL_DIR / "table8_scaling.csv", index=False)
    print("[OK] table8_scaling.csv")

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    for cfg in CONFIGS:
        sub = df[df["Config"] == cfg]
        if sub.empty:
            continue
        axes[0].plot(sub["users"], sub["p50_ms"], "o-", label=f"{cfg} p50")
        axes[0].plot(sub["users"], sub["p95_ms"], "s--", alpha=0.6, label=f"{cfg} p95")
        axes[1].plot(sub["users"], pd.to_numeric(sub["achieved_rps"], errors="coerce"),
                     "o-", label=cfg)
    axes[0].set_xlabel("Concurrent users")
    axes[0].set_ylabel("Latency (ms)")
    axes[0].set_title("Latency vs concurrency")
    axes[0].legend(fontsize=7)
    axes[0].grid(alpha=0.3)
    axes[1].set_xlabel("Concurrent users")
    axes[1].set_ylabel("Achieved throughput (req/s)")
    axes[1].set_title("Throughput vs concurrency")
    axes[1].legend()
    axes[1].grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIG_DIR / "fig4_scaling.png", dpi=150)
    plt.close(fig)
    print("[OK] fig4_scaling.png")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    _ensure_dirs()
    raw_df = _load_all_raw()
    atk_df = _load_attack_summary(ATK_DIR)
    orc_df = _load_attack_summary(ORACLE_DIR)
    abl_df = _load_attack_summary(ABL_DIR)

    print(f"Loaded {len(raw_df)} controller records, {len(atk_df)} attack results, "
          f"{len(orc_df)} oracle results, {len(abl_df)} ablation results")

    table_taxonomy(atk_df)
    table_oracle_ceiling(atk_df, orc_df)
    fig_attack_success(atk_df)
    table_false_challenge(raw_df)
    table_latency(raw_df)
    fig_latency(raw_df)
    table_resources()
    table_scaling(raw_df)
    table_ablation(abl_df, raw_df)
    fig_ablation(abl_df, raw_df)
    table_effect_sizes(raw_df, atk_df)
    table_threshold_sensitivity(raw_df)
    table_risk_components(raw_df)

    print("\nAnalysis complete. Outputs in data/figures/ and data/tables/")


if __name__ == "__main__":
    main()

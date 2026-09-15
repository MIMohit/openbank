"""
Analysis pipeline — reads data/raw/*.jsonl and data/raw/attacks/*.jsonl,
computes statistics, and writes §11 figures/tables to data/figures/ and data/tables/.

Run: python analysis/make_figures.py
"""
import json
import os
from pathlib import Path
from typing import List

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from analysis.stats import bootstrap_ci, wilson_ci, cliffs_delta

RAW_DIR = Path("data/raw")
ATK_DIR = Path("data/raw/attacks")
FIG_DIR = Path("data/figures")
TBL_DIR = Path("data/tables")


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
    for f in RAW_DIR.glob("*.jsonl"):
        rows.extend(_load_jsonl(f))
    if not rows:
        return pd.DataFrame()
    return pd.json_normalize(rows)


def _load_attack_summary() -> pd.DataFrame:
    rows = []
    for f in ATK_DIR.glob("*.jsonl"):
        rows.extend(_load_jsonl(f))
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows)


# ─── Figure 1: Attack success rate B0/B1/P ───────────────────────────────────

def fig_attack_success(atk_df: pd.DataFrame):
    if atk_df.empty:
        print("[WARN] No attack data for fig_attack_success")
        return

    configs = ["B0", "B1", "P"]
    attacks = [f"A{i}" for i in range(1, 7)]
    fig, ax = plt.subplots(figsize=(10, 5))
    width = 0.25
    x = np.arange(len(attacks))

    for i, cfg in enumerate(configs):
        sub = atk_df[atk_df["config"] == cfg]
        rates = []
        lows, highs = [], []
        for atk in attacks:
            row = sub[sub["attack_id"] == atk]
            if row.empty:
                rates.append(0); lows.append(0); highs.append(0)
                continue
            k = int(row["successes"].sum())
            n = int(row["attempts"].sum())
            p, lo, hi = wilson_ci(k, n)
            rates.append(p); lows.append(p - lo); highs.append(hi - p)
        ax.bar(x + i * width, rates, width, label=cfg,
               yerr=[lows, highs], capsize=4, alpha=0.8)

    ax.set_xticks(x + width)
    ax.set_xticklabels(attacks)
    ax.set_ylabel("Attack Success Rate")
    ax.set_title("Attack Success Rate by Configuration (Wilson 95% CI)")
    ax.legend()
    ax.set_ylim(0, 1.1)
    fig.tight_layout()
    fig.savefig(FIG_DIR / "fig2_attack_success_rate.png", dpi=150)
    plt.close(fig)
    print("[OK] fig2_attack_success_rate.png")


# ─── Figure 2: Latency distribution ──────────────────────────────────────────

def fig_latency(raw_df: pd.DataFrame):
    if raw_df.empty or "latency_ms.total" not in raw_df.columns:
        print("[WARN] No latency data")
        return

    configs = ["B0", "B1", "P"]
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    # Violin plot
    ax = axes[0]
    data = [
        raw_df[raw_df["config"] == cfg]["latency_ms.total"].dropna().values
        for cfg in configs
    ]
    parts = ax.violinplot(data, positions=range(len(configs)), showmedians=True)
    ax.set_xticks(range(len(configs)))
    ax.set_xticklabels(configs)
    ax.set_ylabel("Total Latency (ms)")
    ax.set_title("Latency Distribution by Config")

    # Stage breakdown stacked bar
    ax2 = axes[1]
    stages = ["token_verify", "dpop_verify", "telemetry", "risk", "policy", "proxy"]
    bottoms = np.zeros(len(configs))
    colors = plt.cm.Set3(np.linspace(0, 1, len(stages)))
    for j, stage in enumerate(stages):
        col = f"latency_ms.{stage}"
        means = []
        for cfg in configs:
            sub = raw_df[raw_df["config"] == cfg]
            if col in sub.columns:
                means.append(sub[col].mean())
            else:
                means.append(0)
        means = np.array(means)
        ax2.bar(configs, means, bottom=bottoms, label=stage, color=colors[j])
        bottoms += means
    ax2.set_ylabel("Mean Stage Latency (ms)")
    ax2.set_title("Stage Latency Breakdown")
    ax2.legend(fontsize=7)

    fig.tight_layout()
    fig.savefig(FIG_DIR / "fig3_latency.png", dpi=150)
    plt.close(fig)
    print("[OK] fig3_latency.png")


# ─── Table 1: Attacker taxonomy ───────────────────────────────────────────────

def table_taxonomy(atk_df: pd.DataFrame):
    attacks = [
        ("A1", "Network token replay", True, False),
        ("A2", "Token theft without key", True, False),
        ("A3", "Device-resident key abuse", False, True),
        ("A4", "ATO from new device", False, True),
        ("A5", "BOLA/BFLA", True, True),
        ("A6", "Velocity abuse", False, True),
    ]
    rows = []
    for aid, desc, b1_stops, p_adds in attacks:
        if not atk_df.empty:
            b1_row = atk_df[(atk_df["attack_id"] == aid) & (atk_df["config"] == "B1")]
            p_row = atk_df[(atk_df["attack_id"] == aid) & (atk_df["config"] == "P")]
            b1_sr = b1_row["success_rate"].mean() if not b1_row.empty else "N/A"
            p_sr = p_row["success_rate"].mean() if not p_row.empty else "N/A"
        else:
            b1_sr = "N/A"; p_sr = "N/A"
        rows.append({
            "Attack": aid,
            "Description": desc,
            "Stopped by B1": "Yes" if b1_stops else "No",
            "P adds value": "Yes" if p_adds else "No",
            "B1 success rate": f"{b1_sr:.2f}" if isinstance(b1_sr, float) else b1_sr,
            "P success rate": f"{p_sr:.2f}" if isinstance(p_sr, float) else p_sr,
        })
    df = pd.DataFrame(rows)
    df.to_csv(TBL_DIR / "table1_taxonomy.csv", index=False)
    print("[OK] table1_taxonomy.csv")


# ─── Table 2: Per-config latency percentiles ─────────────────────────────────

def table_latency(raw_df: pd.DataFrame):
    if raw_df.empty or "latency_ms.total" not in raw_df.columns:
        print("[WARN] No latency data for table")
        return
    rows = []
    for cfg in ["B0", "B1", "P"]:
        sub = raw_df[raw_df["config"] == cfg]["latency_ms.total"].dropna()
        if sub.empty:
            continue
        est, lo, hi = bootstrap_ci(sub.values, np.mean)
        rows.append({
            "Config": cfg,
            "n": len(sub),
            "p50_ms": float(np.percentile(sub, 50)),
            "p95_ms": float(np.percentile(sub, 95)),
            "p99_ms": float(np.percentile(sub, 99)),
            "mean_ms": est,
            "mean_ci_lo": lo,
            "mean_ci_hi": hi,
        })
    pd.DataFrame(rows).to_csv(TBL_DIR / "table3_latency.csv", index=False)
    print("[OK] table3_latency.csv")


def main():
    _ensure_dirs()
    raw_df = _load_all_raw()
    atk_df = _load_attack_summary()

    table_taxonomy(atk_df)
    fig_attack_success(atk_df)
    fig_latency(raw_df)
    table_latency(raw_df)

    print("\nAnalysis complete. Outputs in data/figures/ and data/tables/")


if __name__ == "__main__":
    main()

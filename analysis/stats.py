"""
Statistical utilities.
  - Bootstrap confidence intervals (percentile method)
  - Wilson score intervals for proportions
  - Cliff's delta effect size (ordinal, for latency comparisons)
  - Risk difference and odds ratio (for attack-success proportions)
"""
import numpy as np
from typing import Tuple


# ─── Bootstrap CI ────────────────────────────────────────────────────────────

def bootstrap_ci(
    data: np.ndarray,
    stat_fn=np.mean,
    n_boot: int = 2000,
    ci: float = 0.95,
    seed: int = 42,
) -> Tuple[float, float, float]:
    """
    Percentile bootstrap CI.
    Returns (estimate, lower, upper).
    """
    rng = np.random.default_rng(seed)
    estimates = np.array([
        stat_fn(rng.choice(data, size=len(data), replace=True))
        for _ in range(n_boot)
    ])
    alpha = (1 - ci) / 2
    lower = float(np.percentile(estimates, 100 * alpha))
    upper = float(np.percentile(estimates, 100 * (1 - alpha)))
    return float(stat_fn(data)), lower, upper


# ─── Wilson score interval ────────────────────────────────────────────────────

def wilson_ci(k: int, n: int, ci: float = 0.95) -> Tuple[float, float, float]:
    """
    Wilson score interval for a proportion k/n.
    Returns (proportion, lower, upper).
    """
    from scipy.stats import norm
    if n == 0:
        return 0.0, 0.0, 0.0
    z = norm.ppf((1 + ci) / 2)
    p_hat = k / n
    denom = 1 + z**2 / n
    center = (p_hat + z**2 / (2 * n)) / denom
    margin = (z * np.sqrt(p_hat * (1 - p_hat) / n + z**2 / (4 * n**2))) / denom
    return float(p_hat), float(max(0, center - margin)), float(min(1, center + margin))


# ─── Cliff's delta ────────────────────────────────────────────────────────────

def cliffs_delta(x: np.ndarray, y: np.ndarray) -> float:
    """
    Cliff's delta effect size (non-parametric, ordinal).
    Range [-1, 1]; |d| < 0.147 negligible, < 0.33 small, < 0.474 medium, else large.

    Computed from the Mann-Whitney U statistic rather than by enumerating every
    pair. The identity is delta = 2U/(n_x*n_y) - 1, where U counts pairs with
    x > y and scores ties as 0.5 — exactly the dominance sum in the definition.
    The pairwise form is O(n_x*n_y); a latency comparison here runs to a few
    thousand observations per configuration, i.e. tens of millions of Python-level
    comparisons per cell, which is why the effect size was never actually
    reported. `test_stats.py` checks the two agree on small samples.
    """
    n_x, n_y = len(x), len(y)
    if n_x == 0 or n_y == 0:
        return 0.0
    from scipy.stats import mannwhitneyu
    u_stat = mannwhitneyu(x, y, alternative="two-sided", method="asymptotic").statistic
    return float(2.0 * u_stat / (n_x * n_y) - 1.0)


def cliffs_delta_magnitude(delta: float) -> str:
    """Romano et al.'s conventional thresholds for |delta|."""
    d = abs(delta)
    if d < 0.147:
        return "negligible"
    if d < 0.330:
        return "small"
    if d < 0.474:
        return "medium"
    return "large"


def _cliffs_delta_pairwise(x, y) -> float:
    """Reference O(n*m) definition, kept for the agreement test."""
    n_x, n_y = len(x), len(y)
    if n_x == 0 or n_y == 0:
        return 0.0
    dominance = sum(
        (1 if xi > yi else (-1 if xi < yi else 0))
        for xi in x for yi in y
    )
    return dominance / (n_x * n_y)


# ─── Risk difference / odds ratio ─────────────────────────────────────────────

def risk_difference(p1: float, p2: float, n1: int, n2: int,
                     ci: float = 0.95) -> Tuple[float, float, float]:
    """
    Risk difference (p1 - p2) with 95% CI (Newcombe method approximation).
    """
    from scipy.stats import norm
    if n1 == 0 or n2 == 0:
        return p1 - p2, float("-inf"), float("inf")
    z = norm.ppf((1 + ci) / 2)
    rd = p1 - p2
    se = np.sqrt(p1 * (1 - p1) / n1 + p2 * (1 - p2) / n2)
    return float(rd), float(rd - z * se), float(rd + z * se)


def odds_ratio(k1: int, n1: int, k2: int, n2: int) -> float:
    """Simple odds ratio (Haldane-Anscombe correction)."""
    a = k1 + 0.5
    b = n1 - k1 + 0.5
    c = k2 + 0.5
    d = n2 - k2 + 0.5
    return (a * d) / (b * c)

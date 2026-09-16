"""
Checks on the statistics helpers that feed the reported tables.
"""
import numpy as np
import pytest

from analysis.stats import (
    bootstrap_ci, cliffs_delta, cliffs_delta_magnitude, _cliffs_delta_pairwise,
    odds_ratio, risk_difference, wilson_ci,
)

rng = np.random.default_rng(7)


@pytest.mark.parametrize("seed", range(10))
def test_cliffs_delta_matches_pairwise_definition(seed):
    r = np.random.default_rng(seed)
    x = r.normal(10, 3, size=r.integers(5, 40))
    y = r.normal(11, 3, size=r.integers(5, 40))
    assert cliffs_delta(x, y) == pytest.approx(_cliffs_delta_pairwise(x, y), abs=1e-9)


def test_cliffs_delta_handles_ties():
    x = np.array([1, 2, 2, 3])
    y = np.array([2, 2, 3, 4])
    assert cliffs_delta(x, y) == pytest.approx(_cliffs_delta_pairwise(x, y), abs=1e-9)


def test_cliffs_delta_extremes():
    assert cliffs_delta(np.array([5, 6, 7]), np.array([1, 2, 3])) == pytest.approx(1.0)
    assert cliffs_delta(np.array([1, 2, 3]), np.array([5, 6, 7])) == pytest.approx(-1.0)
    assert cliffs_delta(np.array([]), np.array([1, 2])) == 0.0


def test_cliffs_delta_magnitude_thresholds():
    assert cliffs_delta_magnitude(0.10) == "negligible"
    assert cliffs_delta_magnitude(0.20) == "small"
    assert cliffs_delta_magnitude(0.40) == "medium"
    assert cliffs_delta_magnitude(-0.90) == "large"


def test_wilson_ci_brackets_proportion():
    p, lo, hi = wilson_ci(30, 30)
    assert p == 1.0 and lo < 1.0 and hi <= 1.0
    p, lo, hi = wilson_ci(0, 30)
    assert p == 0.0 and lo >= 0.0 and hi > 0.0
    assert wilson_ci(0, 0) == (0.0, 0.0, 0.0)


def test_risk_difference_sign_and_bracket():
    rd, lo, hi = risk_difference(1.0, 0.0, 30, 30)
    assert rd == pytest.approx(1.0)
    assert lo <= rd <= hi


def test_odds_ratio_haldane_correction_is_finite():
    # 30/30 vs 0/30 would be an infinite OR without the correction.
    assert np.isfinite(odds_ratio(30, 30, 0, 30))
    assert odds_ratio(30, 30, 0, 30) > 1


def test_bootstrap_ci_brackets_mean():
    data = rng.normal(20, 2, size=500)
    est, lo, hi = bootstrap_ci(data, np.mean, n_boot=300)
    assert lo < est < hi

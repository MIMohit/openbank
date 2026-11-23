"""minimise.py — delta-debugging (ddmin) for binding hits.

Two minimisers (CONTRACT §6 "delta-debugging minimiser (ddmin over primitive list and
over request bytes)"):

  1. `ddmin_primitives(primitive_ids, test)`: shrink a hit's primitive set to a minimal
     subset that still reproduces the hit. `test(subset) -> bool` re-runs the case with
     only those primitives and returns True iff it is still a hit.

  2. `ddmin_bytes(raw, test)`: shrink the raw request bytes to a 1-minimal substring that
     still triggers the hit, for the per-byte root-cause the paper shows.

Both implement the classic Zeller & Hildebrand ddmin (1-minimality). `test` is supplied by
the caller (the runner+oracle round-trip), so this module has no I/O and is unit-testable
with a synthetic predicate.
"""
from __future__ import annotations

from typing import Callable, List, Sequence, TypeVar

T = TypeVar("T")


def ddmin(items: Sequence[T], test: Callable[[List[T]], bool]) -> List[T]:
    """Return a 1-minimal sublist of `items` for which `test` is still True.

    Precondition: test(list(items)) is True. If it is not, the input is returned
    unchanged (nothing to minimise against).
    """
    items = list(items)
    if not test(items):
        return items
    n = 2
    while len(items) >= 2:
        chunk = max(1, len(items) // n)
        subsets = [items[i:i + chunk] for i in range(0, len(items), chunk)]
        reduced = False
        # Try removing each complement (ddmin "increase granularity") first.
        for subset in subsets:
            complement = [x for x in items if x not in subset]
            if complement and test(complement):
                items = complement
                n = max(n - 1, 2)
                reduced = True
                break
        if reduced:
            continue
        # Try each subset alone.
        for subset in subsets:
            if subset and len(subset) < len(items) and test(subset):
                items = subset
                n = 2
                reduced = True
                break
        if reduced:
            continue
        if n >= len(items):
            break
        n = min(len(items), n * 2)
    return items


def ddmin_primitives(primitive_ids: Sequence[str],
                     test: Callable[[List[str]], bool]) -> List[str]:
    """Minimise the primitive set of a hit (order preserved by the caller's test)."""
    return ddmin(list(primitive_ids), test)


def ddmin_bytes(raw: bytes, test: Callable[[bytes], bool], *,
                unit: int = 1) -> bytes:
    """Minimise raw request bytes to a 1-minimal substring that still triggers the hit.

    `unit` lets you minimise in larger granules (e.g. token-ish) first; the result is a
    bytes object assembled from the surviving units.
    """
    units: List[bytes] = [raw[i:i + unit] for i in range(0, len(raw), unit)]

    def byte_test(chunks: List[bytes]) -> bool:
        return test(b"".join(chunks))

    survivors = ddmin(units, byte_test)
    return b"".join(survivors)


# ─────────────────────────── offline minimisation over a hit log ────────────────

def minimise_hit_offline(primitive_ids: Sequence[str],
                         reproduces: Callable[[List[str]], bool]) -> dict:
    """Convenience wrapper returning a report dict for a single hit."""
    minimal = ddmin_primitives(primitive_ids, reproduces)
    return {
        "original_primitive_ids": list(primitive_ids),
        "minimal_primitive_ids": minimal,
        "removed": [p for p in primitive_ids if p not in minimal],
        "is_singleton": len(minimal) == 1,
    }

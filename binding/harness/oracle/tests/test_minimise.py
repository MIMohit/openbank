"""ddmin tests (oracle/minimise.py)."""
from oracle.minimise import ddmin, ddmin_primitives, ddmin_bytes, minimise_hit_offline


def test_ddmin_finds_single_culprit():
    # Only 'g1-hdr-xhmo-delete' is needed to reproduce.
    culprit = "g1-hdr-xhmo-delete"
    prims = ["g2-trailing-slash", culprit, "g3-xverified-sub-bob", "g2-dotdot-mixed"]

    def test(subset):
        return culprit in subset

    minimal = ddmin_primitives(prims, test)
    assert minimal == [culprit]


def test_ddmin_pair_culprit():
    need = {"a", "d"}

    def test(subset):
        return need.issubset(set(subset))

    minimal = ddmin(["a", "b", "c", "d", "e"], test)
    assert set(minimal) == need


def test_ddmin_all_needed():
    items = ["x", "y", "z"]

    def test(subset):
        return set(subset) == set(items)

    assert set(ddmin(items, test)) == set(items)


def test_ddmin_bytes_shrinks():
    raw = b"AAAATARGETBBBB"

    def test(b):
        return b"TARGET" in b

    out = ddmin_bytes(raw, test)
    assert b"TARGET" in out
    assert len(out) <= len(raw)


def test_minimise_report():
    rep = minimise_hit_offline(["p1", "p2", "p3"], lambda s: "p2" in s)
    assert rep["minimal_primitive_ids"] == ["p2"]
    assert rep["is_singleton"] is True
    assert set(rep["removed"]) == {"p1", "p3"}

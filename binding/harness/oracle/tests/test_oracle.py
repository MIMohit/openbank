"""Oracle logic tests over synthetic logs (oracle_spec.md §4-§9)."""
from __future__ import annotations

import json
import os

from oracle.correlate import (
    correlate, GroundTruth, load_ground_truth, classify_severity, is_accepted,
    write_outputs,
)
from oracle.tests.synth import (
    runner_rec, verifier_rec, executor_rec, ground_truth_rec, topo,
)


def gt_from(recs):
    gt = GroundTruth()
    for r in recs:
        gt.by_base[r["base_op_id"]] = {"op_id": r["op_id"],
                                       "path_params": r.get("path_params", {}),
                                       "status": r.get("status", 200)}
    return gt


# ─────────────────────────── basic hit: method deviation (G1) ───────────────────

def test_hit_method_deviation_is_s1():
    runner = [runner_rec("c1", "getAccount", "j1",
                         primitive_ids=["g1-hdr-xhmo-delete"])]
    verifier = [verifier_rec("j1", decision="allow")]
    # proof verified for GET, but executor ran DELETE -> deleteAccount
    executor = [executor_rec("j1", "deleteAccount", effective_method="DELETE",
                             raw_method="GET")]
    gt = gt_from([ground_truth_rec("getAccount", "getAccount")])
    res = correlate(runner=runner, verifier=verifier, executor=executor,
                    topo=topo(), ground_truth=gt)
    assert len(res.hits) == 1
    h = res.hits[0]
    assert h["severity"] == "S1"
    assert "method" in h["deviation_kinds"]
    assert h["exec_op_id"] == "deleteAccount"


def test_hit_dispatch_deviation_graphql():
    runner = [runner_rec("c2", "graphql.getProfile", "j2", base_method="POST",
                         base_path="/api/v1/graphql",
                         primitive_ids=["g1-gql-to-deleteProfile"])]
    verifier = [verifier_rec("j2", decision="allow")]
    executor = [executor_rec("j2", "graphql.deleteProfile", raw_method="POST",
                             effective_method="POST", route_template="/api/v1/graphql")]
    gt = gt_from([ground_truth_rec("graphql.getProfile", "graphql.getProfile",
                                   base_method="POST", base_path="/api/v1/graphql")])
    res = correlate(runner=runner, verifier=verifier, executor=executor,
                    topo=topo(), ground_truth=gt)
    assert len(res.hits) == 1
    h = res.hits[0]
    assert "dispatch" in h["deviation_kinds"]
    assert h["severity"] == "S1"  # graphql.deleteProfile


# ─────────────────────────── resource substitution (spec §4 [interpretation]) ───

def test_resource_substitution_same_op_different_id_is_s1():
    runner = [runner_rec("c3", "getAccount", "j3", primitive_ids=["g2-dotdot-mixed"])]
    verifier = [verifier_rec("j3", decision="allow")]
    # same op_id getAccount but a DIFFERENT account id/owner
    executor = [executor_rec("j3", "getAccount", path_params={"id": "acc-bob-1"})]
    gt = gt_from([ground_truth_rec("getAccount", "getAccount",
                                   path_params={"id": "acc-alice-1"})])
    res = correlate(runner=runner, verifier=verifier, executor=executor,
                    topo=topo(), ground_truth=gt)
    assert len(res.hits) == 1
    h = res.hits[0]
    assert "resource" in h["deviation_kinds"]
    assert h["severity"] == "S1"


def test_same_op_same_params_is_not_a_hit():
    runner = [runner_rec("c4", "getAccount", "j4", primitive_ids=["g2-trailing-slash"])]
    verifier = [verifier_rec("j4", decision="allow")]
    executor = [executor_rec("j4", "getAccount", path_params={"id": "acc-alice-1"})]
    gt = gt_from([ground_truth_rec("getAccount", "getAccount",
                                   path_params={"id": "acc-alice-1"})])
    res = correlate(runner=runner, verifier=verifier, executor=executor,
                    topo=topo(), ground_truth=gt)
    assert res.hits == []


# ─────────────────────────── edge cases (spec §6/§7) ─────────────────────────────

def test_not_found_is_not_a_hit():
    runner = [runner_rec("c5", "getAccount", "j5", primitive_ids=["g2-null-byte"])]
    verifier = [verifier_rec("j5", decision="allow")]
    executor = [executor_rec("j5", "NOT_FOUND", status=404)]
    res = correlate(runner=runner, verifier=verifier, executor=executor,
                    topo=topo(), ground_truth=gt_from([ground_truth_rec("getAccount", "getAccount")]))
    assert res.hits == []


def test_denied_is_not_a_hit():
    runner = [runner_rec("c6", "getAccount", "j6", primitive_ids=["g1-hdr-xhmo-delete"])]
    verifier = [verifier_rec("j6", decision="deny", reason="htu_mismatch")]
    executor = [executor_rec("j6", "deleteAccount", effective_method="DELETE",
                             denied=True, status=401)]
    res = correlate(runner=runner, verifier=verifier, executor=executor,
                    topo=topo(), ground_truth=gt_from([ground_truth_rec("getAccount", "getAccount")]))
    assert res.hits == []


def test_status_4xx_not_a_hit():
    runner = [runner_rec("c7", "getAccount", "j7")]
    verifier = [verifier_rec("j7", decision="allow")]
    executor = [executor_rec("j7", "updateAccount", effective_method="PUT", status=422)]
    res = correlate(runner=runner, verifier=verifier, executor=executor,
                    topo=topo(), ground_truth=gt_from([ground_truth_rec("getAccount", "getAccount")]))
    assert res.hits == []


def test_missing_jti_runner_is_reported_not_hit():
    runner = [runner_rec("c8", "getAccount", None)]
    res = correlate(runner=runner, verifier=[], executor=[],
                    topo=topo(), ground_truth=GroundTruth())
    assert res.hits == []
    assert any(o["kind"] == "runner_no_jti" for o in res.other)


def test_uncorrelated_executor_null_jti():
    runner = [runner_rec("c9", "getAccount", "j9")]
    verifier = [verifier_rec("j9", decision="allow")]
    # executor logged a request with no parseable DPoP header
    executor = [executor_rec(None, "deleteAccount", effective_method="DELETE")]
    res = correlate(runner=runner, verifier=verifier, executor=executor,
                    topo=topo(), ground_truth=gt_from([ground_truth_rec("getAccount", "getAccount")]))
    assert res.hits == []  # cannot be joined
    assert any(o["kind"] == "uncorrelated_exec" for o in res.other)


def test_runner_without_executor_is_not_executed():
    runner = [runner_rec("c10", "getAccount", "j10")]
    verifier = [verifier_rec("j10", decision="deny")]
    res = correlate(runner=runner, verifier=verifier, executor=[],
                    topo=topo(), ground_truth=GroundTruth())
    assert res.hits == []
    assert any(o["kind"] == "not_executed" for o in res.other)


def test_allowed_not_executed():
    runner = [runner_rec("c11", "getAccount", "j11")]
    verifier = [verifier_rec("j11", decision="allow")]
    res = correlate(runner=runner, verifier=verifier, executor=[],
                    topo=topo(), ground_truth=GroundTruth())
    assert any(o["kind"] == "allowed_not_executed" for o in res.other)


def test_orphan_verifier():
    runner = [runner_rec("c12", "getAccount", "j12")]
    verifier = [verifier_rec("j12", decision="allow"),
                verifier_rec("j-orphan", decision="allow")]
    executor = [executor_rec("j12", "getAccount", path_params={"id": "acc-alice-1"})]
    gt = gt_from([ground_truth_rec("getAccount", "getAccount",
                                   path_params={"id": "acc-alice-1"})])
    res = correlate(runner=runner, verifier=verifier, executor=executor,
                    topo=topo(), ground_truth=gt)
    assert any(o["kind"] == "orphan_verifier" and o["jti"] == "j-orphan"
               for o in res.other)


def test_verifier_bypass_b0_edge():
    # edge placement, executor ran but no verifier record -> B0, not a binding hit
    runner = [runner_rec("c13", "getAccount", "j13", primitive_ids=["g1-hdr-xhmo-delete"])]
    executor = [executor_rec("j13", "deleteAccount", effective_method="DELETE")]
    res = correlate(runner=runner, verifier=[], executor=executor,
                    topo=topo(placement="edge"),
                    ground_truth=gt_from([ground_truth_rec("getAccount", "getAccount")]))
    assert res.hits == []
    assert any(o["kind"] == "B0_verifier_bypass" for o in res.other)
    assert res.summary["b0"] == 1


def test_nonconformant_excluded():
    runner = [runner_rec("c14", "getAccount", "j14")]
    verifier = [verifier_rec("j14", decision="allow")]
    executor = [executor_rec("j14", "deleteAccount", effective_method="DELETE")]
    # ground truth says getAccount actually resolves to listAccounts -> nonconformant
    gt = gt_from([ground_truth_rec("getAccount", "listAccounts")])
    res = correlate(runner=runner, verifier=verifier, executor=executor,
                    topo=topo(), ground_truth=gt)
    assert res.hits == []
    assert any(o["kind"] == "nonconformant" for o in res.other)


# ─────────────────────────── origin placement ───────────────────────────────────

def test_origin_placement_uses_denied_flag():
    runner = [runner_rec("c15", "getAccount", "j15", primitive_ids=["g1-hdr-xhmo-delete"])]
    # no verifier record; origin placement falls back to executor.denied == False
    executor = [executor_rec("j15", "deleteAccount", effective_method="DELETE",
                             denied=False)]
    res = correlate(runner=runner, verifier=[], executor=executor,
                    topo=topo(placement="origin"),
                    ground_truth=gt_from([ground_truth_rec("getAccount", "getAccount")]))
    assert len(res.hits) == 1
    assert res.hits[0]["severity"] == "S1"


# ─────────────────────────── severity classifier units ─────────────────────────

def test_classify_severity_levels():
    assert classify_severity({"op_id": "health", "effective_method": "GET"}, []) == "S3"
    assert classify_severity({"op_id": "publicFile", "effective_method": "GET"}, []) == "S3"
    assert classify_severity({"op_id": "listAccounts", "effective_method": "GET"}, []) == "S2"
    assert classify_severity({"op_id": "getAccount", "effective_method": "GET"}, []) == "S2"
    assert classify_severity({"op_id": "adminListUsers", "effective_method": "GET"}, []) == "S1"
    assert classify_severity({"op_id": "createTransfer", "effective_method": "POST"}, []) == "S1"
    assert classify_severity({"op_id": "accountAction.close", "effective_method": "POST"}, []) == "S1"
    assert classify_severity({"op_id": "getAccount", "effective_method": "GET"}, ["resource"]) == "S1"
    assert classify_severity({"op_id": "getAccount", "effective_method": "PUT"}, []) == "S1"


# ─────────────────────────── G3 propagation predicate (spec §8) ─────────────────

def test_propagation_identity_header_s1():
    catalogue = {
        "g3-xverified-sub-bob": {
            "transform": [{"fn": "add_header",
                           "args": {"name": "X-Verified-Sub", "value": "bob"}}],
            "class": "G3"},
    }
    runner = [runner_rec("c16", "getAccount", "j16", primitive_ids=["g3-xverified-sub-bob"])]
    verifier = [verifier_rec("j16", decision="allow")]
    # executor reflects the spoofed header in its trust_headers filter
    executor = [executor_rec("j16", "getAccount", path_params={"id": "acc-alice-1"},
                             trust_headers={"x-verified-sub": "bob"})]
    gt = gt_from([ground_truth_rec("getAccount", "getAccount",
                                   path_params={"id": "acc-alice-1"})])
    res = correlate(runner=runner, verifier=verifier, executor=executor,
                    topo=topo(), ground_truth=gt, primitive_catalogue=catalogue)
    # not a binding hit (op unchanged), but a propagation finding
    assert res.hits == []
    assert len(res.propagation) == 1
    assert res.propagation[0]["severity"] == "S1"


def test_propagation_underscore_folding():
    catalogue = {
        "g3-xverified-sub-underscore": {
            "transform": [{"fn": "add_header",
                           "args": {"name": "X_Verified_Sub", "value": "bob"}}],
            "class": "G3"},
    }
    runner = [runner_rec("c17", "getAccount", "j17",
                         primitive_ids=["g3-xverified-sub-underscore"])]
    verifier = [verifier_rec("j17", decision="allow")]
    executor = [executor_rec("j17", "getAccount", path_params={"id": "acc-alice-1"},
                             trust_headers={"x-verified-sub": "bob"})]  # folded to dash
    gt = gt_from([ground_truth_rec("getAccount", "getAccount",
                                   path_params={"id": "acc-alice-1"})])
    res = correlate(runner=runner, verifier=verifier, executor=executor,
                    topo=topo(), ground_truth=gt, primitive_catalogue=catalogue)
    assert len(res.propagation) == 1


# ─────────────────────────── minimisation + signatures (spec §9) ────────────────

def test_minimisation_folds_superset():
    # Two hits: P'={g1} and P={g1,g3} on same op/deviation. P is folded (not minimal).
    runner = [
        runner_rec("ca", "getAccount", "ja", primitive_ids=["g1-hdr-xhmo-delete"]),
        runner_rec("cb", "getAccount", "jb",
                   primitive_ids=["g1-hdr-xhmo-delete", "g3-xverified-sub-bob"]),
    ]
    verifier = [verifier_rec("ja", decision="allow"), verifier_rec("jb", decision="allow")]
    executor = [executor_rec("ja", "deleteAccount", effective_method="DELETE"),
                executor_rec("jb", "deleteAccount", effective_method="DELETE")]
    gt = gt_from([ground_truth_rec("getAccount", "getAccount")])
    res = correlate(runner=runner, verifier=verifier, executor=executor,
                    topo=topo(), ground_truth=gt)
    assert len(res.hits) == 2
    minimal = {h["case_id"]: h["minimal"] for h in res.hits}
    assert minimal["ca"] is True
    assert minimal["cb"] is False
    assert res.summary["signatures"] == 1  # one minimal signature


# ─────────────────────────── determinism (spec §10) ─────────────────────────────

def test_determinism_byte_identical(tmp_path):
    runner = [runner_rec("cz", "getAccount", "jz", primitive_ids=["g1-hdr-xhmo-delete"]),
              runner_rec("cy", "getAccount", "jy", primitive_ids=["g2-dotdot-mixed"])]
    verifier = [verifier_rec("jz", decision="allow"), verifier_rec("jy", decision="allow")]
    executor = [executor_rec("jz", "deleteAccount", effective_method="DELETE"),
                executor_rec("jy", "listAccounts", raw_target="/api/v1/accounts")]
    gt = gt_from([ground_truth_rec("getAccount", "getAccount")])

    def run_once(d):
        res = correlate(runner=runner, verifier=verifier, executor=executor,
                        topo=topo(), ground_truth=gt)
        write_outputs(res, str(d))
        with open(os.path.join(str(d), "hits.jsonl"), "rb") as f:
            return f.read()

    out1 = run_once(tmp_path / "a")
    out2 = run_once(tmp_path / "b")
    assert out1 == out2
    # hits sorted by case_id
    lines = [json.loads(l) for l in out1.decode().splitlines()]
    assert [h["case_id"] for h in lines] == sorted(h["case_id"] for h in lines)

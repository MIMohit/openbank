"""Runner unit tests (no network): auth injection, op_id parse, minter shim."""
import os
import base64

from runner.run_matrix import inject_auth, parse_resp_op_id
from runner.minter_adapter import get_minter
from mutator import compose


def test_inject_auth_replaces_placeholders():
    case = compose.generate(depth=1, only_op="getAccount")[0]
    raw = inject_auth(case.raw_request_b64, "DPoP TESTAT", "TESTPROOF")
    text = raw.decode("latin-1")
    assert "Authorization: DPoP TESTAT" in text
    assert "DPoP: TESTPROOF" in text
    assert "@@AUTHZ@@" not in text and "@@PROOF@@" not in text


def test_parse_resp_op_id():
    assert parse_resp_op_id(b'{"op_id":"deleteAccount","framework":"fastapi"}') == "deleteAccount"
    assert parse_resp_op_id(b"not json") is None
    assert parse_resp_op_id(b'{"other":1}') is None


def test_shim_minter_produces_bound_proof():
    os.environ["W7_FORCE_SHIM"] = "1"
    try:
        m = get_minter()
        assert m.kind == "shim"
        authz, dpop, jti = m.mint("alice", "GET",
                                  "http://api.bench.test/api/v1/accounts/acc-alice-1")
        assert authz.startswith("DPoP ")
        assert len(dpop.split(".")) == 3
        assert jti
        # jti differs each mint
        _, _, jti2 = m.mint("alice", "GET", "http://api.bench.test/api/v1/me")
        assert jti2 != jti
    finally:
        del os.environ["W7_FORCE_SHIM"]


def test_build_groundtruth_joins_on_jti():
    from runner.build_groundtruth import build
    runner_recs = [
        {"case_id": "getAccount:baseline", "base_op_id": "getAccount",
         "base_method": "GET", "base_path": "/api/v1/accounts/acc-alice-1",
         "depth": 0, "primitive_ids": [], "jti": "J1"},
        # a non-baseline record must be ignored by ground truth
        {"case_id": "getAccount:mut", "base_op_id": "getAccount",
         "base_method": "GET", "base_path": "/api/v1/accounts/acc-alice-1",
         "depth": 1, "primitive_ids": ["g2-fragment"], "jti": "J2"},
    ]
    exec_recs = [
        {"jti": "J1", "op_id": "getAccount", "path_params": {"id": "acc-alice-1"}, "status": 200},
        {"jti": "J2", "op_id": "getAccount", "path_params": {"id": "acc-alice-1#frag"}, "status": 200},
    ]
    gt = build(runner_recs, exec_recs)
    assert set(gt) == {"getAccount"}  # only the baseline defines op(pi)
    assert gt["getAccount"]["op_id"] == "getAccount"
    assert gt["getAccount"]["path_params"] == {"id": "acc-alice-1"}
    assert gt["getAccount"]["status"] == 200


def test_build_groundtruth_missing_executor_record():
    from runner.build_groundtruth import build
    runner_recs = [{"case_id": "me:baseline", "base_op_id": "me", "base_method": "GET",
                    "base_path": "/api/v1/me", "depth": 0, "primitive_ids": [], "jti": "JX"}]
    gt = build(runner_recs, [])  # no executor line -> base op absent, no crash
    assert gt == {}

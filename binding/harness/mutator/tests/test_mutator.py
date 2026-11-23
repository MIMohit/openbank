"""Mutator catalogue, transforms, and compose determinism tests."""
import base64

from mutator.base_ops import BASE_OPS_BY_ID, AUTHZ_PLACEHOLDER, PROOF_PLACEHOLDER
from mutator.catalogue import load_catalogue, catalogue_by_id
from mutator import transforms, compose
from rawhttp.model import RawRequest


def test_catalogue_loads_60_plus_unique():
    prims = load_catalogue()
    assert len(prims) >= 60
    ids = [p.id for p in prims]
    assert len(ids) == len(set(ids))  # unique
    # every group represented
    assert {p.group for p in prims} == {"G1", "G2", "G3"}
    # every primitive has the required fields and a resolvable transform
    for p in prims:
        assert p.description and p.source and p.transform
        for step in p.transform:
            assert step["fn"] in transforms.REGISTRY


def test_compatibility_selectors():
    cat = catalogue_by_id(load_catalogue())
    getacc = BASE_OPS_BY_ID["getAccount"]
    action = BASE_OPS_BY_ID["accountAction.freeze"]
    graphql = BASE_OPS_BY_ID["graphql.getProfile"]
    # op-switch only applies to the action op
    assert not cat["g1-op-freeze-to-close"].compatible_with(getacc)
    assert cat["g1-op-freeze-to-close"].compatible_with(action)
    # graphql swap only to graphql
    assert cat["g1-gql-to-deleteProfile"].compatible_with(graphql)
    assert not cat["g1-gql-to-deleteProfile"].compatible_with(getacc)
    # v1->v2 prefix only to v1 ops
    assert cat["g2-prefix-v1-to-v2"].compatible_with(getacc)
    assert not cat["g2-prefix-v1-to-v2"].compatible_with(BASE_OPS_BY_ID["getAccountV2"])


def test_transform_method_override_header():
    req = BASE_OPS_BY_ID["getAccount"].canonical_request()
    out = transforms.apply_steps(req, [{"fn": "add_header",
                                        "args": {"name": "X-HTTP-Method-Override", "value": "DELETE"}}])
    assert out.get_header("X-HTTP-Method-Override") == "DELETE"
    # original untouched (copy semantics)
    assert req.get_header("X-HTTP-Method-Override") is None


def test_transform_dot_segment_insert():
    req = RawRequest(target="/api/v1/accounts/acc-alice-1")
    out = transforms.apply_steps(req, [{"fn": "insert_before_last_segment",
                                        "args": {"token": "..%2f"}}])
    assert out.target == "/api/v1/accounts/..%2facc-alice-1"


def test_transform_set_json_field_fixes_length():
    req = BASE_OPS_BY_ID["graphql.getProfile"].canonical_request()
    out = transforms.apply_steps(req, [{"fn": "set_json_field",
                                        "args": {"field": "operationName", "value": "deleteProfile"}}])
    import json
    body = json.loads(out.body)
    assert body["operationName"] == "deleteProfile"
    assert out.get_header("content-length") == str(len(out.body))


def test_compose_deterministic():
    a = compose.generate(depth=2, seed=99, pairs_per_op=10)
    b = compose.generate(depth=2, seed=99, pairs_per_op=10)
    assert [c.case_id for c in a] == [c.case_id for c in b]
    # raw bytes identical too
    assert [c.raw_request_b64 for c in a] == [c.raw_request_b64 for c in b]


def test_compose_depth1_covers_every_compatible_pair():
    prims = load_catalogue()
    cases = compose.generate(depth=1, only_op="accountAction.freeze")
    depth1 = [c for c in cases if c.depth == 1]
    compat = [p for p in prims if p.compatible_with(BASE_OPS_BY_ID["accountAction.freeze"])]
    assert len(depth1) == len(compat)


def test_cases_contain_auth_placeholders():
    cases = compose.generate(depth=1, only_op="getAccount")
    raw = base64.b64decode(cases[0].raw_request_b64).decode("latin-1")
    assert AUTHZ_PLACEHOLDER in raw and PROOF_PLACEHOLDER in raw

"""W18 A1 supplementary 'swap' set (what htm/htu buy): the leaked proof for base op p is replayed on
  (a) cross-op: the canonical request of every other base op q (method, target, body of q), 17x16 = 272;
  (b) method-only: p's canonical target/body with each other method in {GET,POST,PUT,DELETE,PATCH}.
The A_leak catalogue has no primitive that rewrites the request-line method or the path to another op, so
without this set no-htm/no-htu would only be tested on incidental path edits. Usage like gen_cases.py.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ab_base  # noqa: E402

ab_base.register()
import mutator.base_ops as bo  # noqa: E402
from mutator import compose  # noqa: E402
from rawhttp.model import RawRequest  # noqa: E402


def case(p, raw, tag, client="alice"):
    return compose.Case(case_id=compose._case_id(p.op_id, [tag], client), base_op_id=p.op_id,
                        base_method=p.method, base_path=p.path, primitive_ids=[tag], client=client,
                        raw_request_b64=raw.to_b64(), depth=1, groups=["SWAP"])


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", required=True); a = ap.parse_args()
    out = []
    for p in bo.BASE_OPS:
        out.append(compose.Case(case_id=compose._case_id(p.op_id, ["baseline"], "alice"), base_op_id=p.op_id,
                                base_method=p.method, base_path=p.path, primitive_ids=[], client="alice",
                                raw_request_b64=p.canonical_request().to_b64(), depth=0, groups=[]))
        for q in bo.BASE_OPS:
            if q.op_id != p.op_id:
                out.append(case(p, q.canonical_request(), f"swap-op-{q.op_id}"))
        for m in ("GET", "POST", "PUT", "DELETE", "PATCH"):
            if m != p.method:
                r = p.canonical_request()
                out.append(case(p, RawRequest(method=m, target=r.target, version=r.version, headers=r.headers,
                                              body=r.body), f"swap-method-{m}"))
    with open(a.out, "w") as f:
        for c in out:
            f.write(c.to_json() + "\n")
    print(len(out), "swap cases")


if __name__ == "__main__":
    main()

"""Command-line minter.

  python -m minter.cli keys [--force]
  python -m minter.cli mint --client alice --htm GET --htu http://api.bench.test/api/v1/accounts/acc-alice-1
        [--variant wrong_ath] [--at <token>] [--jti X] [--iat-offset N]
  python -m minter.cli token --client alice
  python -m minter.cli variants

`mint` prints a JSON object: {"Authorization": ..., "DPoP": ..., "jti": ..., "htm": ..., "htu": ...}.
For variant multiple_dpop, "DPoP" is a list of two proofs; for no_dpop / bearer_downgrade it is absent.
Run from binding/harness/ (or put it on PYTHONPATH). Keys dir: $BH_KEYS_DIR or binding/harness/keys.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import keys as K
from .dpop import REQUEST_VARIANTS, VARIANTS, decode_unverified, headers_for
from .tokens import mint_access_token


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="minter.cli", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    kp = sub.add_parser("keys", help="generate keys (once)")
    kp.add_argument("--force", action="store_true")

    mp = sub.add_parser("mint", help="mint Authorization + DPoP headers")
    mp.add_argument("--client", default="alice")
    mp.add_argument("--htm", required=True)
    mp.add_argument("--htu", required=True)
    mp.add_argument("--variant", default="valid", choices=sorted(VARIANTS) + list(REQUEST_VARIANTS))
    mp.add_argument("--at", default=None, help="reuse this access token instead of minting one")
    mp.add_argument("--jti", default=None)
    mp.add_argument("--iat-offset", type=int, default=0)

    tp = sub.add_parser("token", help="mint an access token only")
    tp.add_argument("--client", default="alice")
    tp.add_argument("--lifetime", type=int, default=3600)

    sub.add_parser("variants", help="list proof variants")
    a = ap.parse_args(argv)

    if a.cmd == "keys":
        K.main(["--force"] if a.force else [])
        return 0
    if a.cmd == "variants":
        print(json.dumps({"proof_variants": sorted(VARIANTS), "request_variants": list(REQUEST_VARIANTS)}, indent=2))
        return 0
    if a.cmd == "token":
        print(mint_access_token(a.client, lifetime=a.lifetime))
        return 0

    kw = {}
    if a.jti:
        kw["jti"] = a.jti
    if a.iat_offset:
        kw["iat_offset"] = a.iat_offset
    h = headers_for(a.client, a.htm, a.htu, variant=a.variant, access_token=a.at, **kw)
    out = dict(h)
    first = h.get("DPoP")
    if isinstance(first, list):
        first = first[0]
    if first:
        try:
            _, claims = decode_unverified(first)
            out["jti"] = claims.get("jti")
        except Exception:  # malformed variants
            out["jti"] = None
    else:
        out["jti"] = None
    out.update({"htm": a.htm, "htu": a.htu, "client": a.client, "variant": a.variant})
    json.dump(out, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

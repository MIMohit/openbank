"""Adapter that prefers W3's real minter, falling back to the shim.

W3 (ready) exposes `minter.dpop.headers_for(client, htm, htu, variant=...) -> dict` with
keys "Authorization" and "DPoP", plus `minter.dpop.decode_unverified(proof)` to read the
jti. This adapter normalises either the real minter or the local shim to:

    authz, dpop, jti = get_minter().mint(client, htm, htu)

`authz` is the full Authorization header value ("DPoP <at>"); `dpop` is the proof JWT.
"""
from __future__ import annotations

import os
from typing import Tuple


class MinterAdapter:
    def __init__(self, impl, kind: str):
        self._impl = impl
        self.kind = kind  # "w3" or "shim"

    def mint(self, client: str, htm: str, htu: str,
             variant: str = "valid") -> Tuple[str, str, str]:
        if self.kind == "w3":
            dpop_mod = self._impl
            h = dpop_mod.headers_for(client, htm, htu, variant=variant)
            authz = h["Authorization"]
            dpop = h["DPoP"]
            if isinstance(dpop, list):  # multiple_dpop variant
                dpop = dpop[0]
            _, claims = dpop_mod.decode_unverified(dpop)
            jti = claims.get("jti")
            return authz, dpop, jti
        # shim
        at, dpop, jti = self._impl.mint(client=client, htm=htm, htu=htu)
        return f"DPoP {at}", dpop, jti


def get_minter(prefer: str = "auto") -> MinterAdapter:
    """Return a MinterAdapter. prefer: 'auto' (W3 then shim), 'shim', or 'w3'."""
    if prefer in ("auto", "w3"):
        dpop_mod = _try_import_w3()
        if dpop_mod is not None:
            return MinterAdapter(dpop_mod, "w3")
        if prefer == "w3":
            raise ImportError("W3 minter requested but minter.dpop not importable")
    from runner.minter_shim import get_shim_minter
    return MinterAdapter(get_shim_minter(), "shim")


def _try_import_w3():
    """Return W3's `minter.dpop` module (with headers_for/decode_unverified) or None."""
    if os.environ.get("W7_FORCE_SHIM") == "1":
        return None
    try:
        from minter import dpop  # type: ignore
    except Exception:
        return None
    if hasattr(dpop, "headers_for") and hasattr(dpop, "decode_unverified"):
        return dpop
    return None

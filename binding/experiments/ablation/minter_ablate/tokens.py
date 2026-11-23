"""Access-token minting (CONTRACT section 2): ES256 JWS, typ at+jwt, cnf.jkt-bound."""
from __future__ import annotations

import time
import uuid
from typing import Any

from . import keys as K
from .jose import sign_compact, thumbprint

ISS = "https://as.bench.test"
AUD = "https://api.bench.test"
DEFAULT_SCOPE = "accounts transfers profile"


def mint_access_token(client: str = "alice", *, client_jwk: dict | None = None, as_key: dict | None = None,
                      sub: str | None = None, scope: str = DEFAULT_SCOPE, iss: str = ISS, aud: Any = AUD,
                      iat: int | None = None, lifetime: int = 3600, exp: int | None = None,
                      jti: str | None = None, cnf_jkt: str | None = None, typ: str | None = "at+jwt",
                      alg: str = "ES256", extra_claims: dict | None = None, drop_claims=(),
                      signature: str | None = None) -> str:
    """Mint an access token. Every knob can be overridden for negative tests.

    cnf_jkt defaults to the RFC 7638 thumbprint of the client's DPoP key; pass "" to omit cnf.
    """
    as_key = as_key or K.as_private()
    if cnf_jkt is None:
        cnf_jkt = thumbprint(client_jwk or K.client_key(client))
    now = int(time.time()) if iat is None else iat
    claims: dict[str, Any] = {
        "iss": iss, "aud": aud, "sub": sub or client, "client_id": client, "scope": scope,
        "iat": now, "exp": exp if exp is not None else now + lifetime, "jti": jti or str(uuid.uuid4()),
    }
    if cnf_jkt:
        claims["cnf"] = {"jkt": cnf_jkt}
    claims.update(extra_claims or {})
    for c in drop_claims:
        claims.pop(c, None)
    header = {"alg": alg, "kid": as_key.get("kid")}
    if typ is not None:
        header["typ"] = typ
    return sign_compact(header, claims, key=as_key, alg=alg, signature=signature)

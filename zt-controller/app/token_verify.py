"""
Stage 1: Access-token verification.

Verifies:
  - JWT signature against Keycloak JWKS
  - issuer matches expected realm
  - token not expired
  - required scopes present
  - cnf.jkt present (when DPoP is enforced)

Returns parsed claims on success; raises HTTPException on failure.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

import httpx
from fastapi import HTTPException, status
from jose import jwt, JWTError, jwk
from jose.utils import base64url_decode

from app import config

logger = logging.getLogger(__name__)

_jwks_cache: dict = {}
_jwks_fetched_at: float = 0.0
_JWKS_TTL = 300  # seconds


async def _fetch_jwks(realm: str) -> dict:
    global _jwks_cache, _jwks_fetched_at
    now = time.time()
    if _jwks_cache.get(realm) and now - _jwks_fetched_at < _JWKS_TTL:
        return _jwks_cache[realm]
    url = f"{config.KEYCLOAK_URL}/realms/{realm}/protocol/openid-connect/certs"
    async with httpx.AsyncClient(timeout=5) as client:
        resp = await client.get(url)
        resp.raise_for_status()
    _jwks_cache[realm] = resp.json()
    _jwks_fetched_at = now
    return _jwks_cache[realm]


async def verify_access_token(
    authorization: str,
    realm: str,
    required_scopes: Optional[list[str]] = None,
) -> dict:
    """
    Parse and validate the Bearer access token.
    Returns decoded JWT claims on success.
    Raises HTTPException(401) on any failure.
    """
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization[7:]

    try:
        header = jwt.get_unverified_header(token)
    except JWTError as exc:
        logger.warning({"event": "token_invalid_header", "error": str(exc)})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid token header")

    # Fetch public key from Keycloak JWKS
    try:
        jwks = await _fetch_jwks(realm)
    except Exception as exc:
        logger.error({"event": "jwks_fetch_failed", "error": str(exc)})
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Unable to fetch signing keys")

    # Find the matching key by kid
    kid = header.get("kid")
    key = next(
        (k for k in jwks.get("keys", []) if k.get("kid") == kid),
        None,
    )
    if not key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Token signing key not found")

    issuer = f"{config.KEYCLOAK_URL}/realms/{realm}"
    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=[header.get("alg", "RS256")],
            options={"verify_aud": False},  # audience varies per deployment
            issuer=issuer,
        )
    except JWTError as exc:
        logger.warning({"event": "token_decode_failed", "error": str(exc)})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Token validation failed")

    # Scope check
    if required_scopes:
        token_scopes = set(claims.get("scope", "").split())
        missing = set(required_scopes) - token_scopes
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required scopes: {missing}",
            )

    # cnf.jkt must be present for DPoP-bound tokens
    if config.ENFORCE_DPOP:
        cnf = claims.get("cnf", {})
        if not cnf.get("jkt"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing DPoP key binding (cnf.jkt)",
            )

    return claims

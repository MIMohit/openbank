"""
Authentication guard for the Mock ADR API.

The mock API only accepts requests that come from the ZT Controller (identified
by the internal X-ZT-Validated header).  In B0 pass-through mode the controller
sets a different header; otherwise direct access is refused with 403.

IMPORTANT: This is an internal trust boundary check (network-isolated).
The header is NOT a substitute for real mTLS — it models the network isolation
described in §5 of the spec.  Real mTLS would be added in production.
"""
from fastapi import Header, HTTPException, status


INTERNAL_SECRET = "zt-internal-only"  # never leaves the Docker network


async def require_zt_controller(
    x_zt_validated: str = Header(default=""),
    x_zt_user_id: str = Header(default=""),
) -> str:
    """
    Dependency: verifies the request came through the ZT Controller.
    Returns the authenticated user_id.
    """
    if x_zt_validated != INTERNAL_SECRET:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Direct access to resource server is not permitted.",
        )
    if not x_zt_user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing user identity from controller.",
        )
    return x_zt_user_id

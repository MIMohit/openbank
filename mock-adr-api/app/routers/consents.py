"""Consents endpoints."""
import time
import logging
from fastapi import APIRouter, Depends, HTTPException, status, Header
from app.auth import require_zt_controller
from seed.synthetic_data import get_consent_for_user, get_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/consents", tags=["consents"])


@router.get("")
async def list_consents(
    user_id: str = Depends(require_zt_controller),
    x_request_id: str = Header(default=""),
):
    t0 = time.perf_counter()
    consents = get_consent_for_user(user_id)
    latency = (time.perf_counter() - t0) * 1000
    logger.info({"event": "list_consents", "user_id": user_id,
                 "count": len(consents), "handler_ms": round(latency, 2)})
    return {"data": [
        {"id": c.id, "status": c.status, "scopes": c.scopes,
         "accounts": c.accounts, "expires_at": c.expires_at}
        for c in consents
    ]}


@router.post("")
async def create_consent(
    user_id: str = Depends(require_zt_controller),
    x_request_id: str = Header(default=""),
):
    """Stub — consent creation would persist a new consent object."""
    latency = 0.0
    logger.info({"event": "create_consent_stub", "user_id": user_id,
                 "request_id": x_request_id, "handler_ms": latency})
    return {"data": {"status": "created", "note": "stub — not persisted in testbed"}}

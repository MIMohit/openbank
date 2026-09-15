"""Accounts endpoints with object-level ownership enforcement."""
import time
import logging
from fastapi import APIRouter, Depends, HTTPException, status, Header
from app.auth import require_zt_controller
from seed.synthetic_data import get_user, get_account

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/accounts", tags=["accounts"])


@router.get("")
async def list_accounts(
    user_id: str = Depends(require_zt_controller),
    x_request_id: str = Header(default=""),
):
    t0 = time.perf_counter()
    user = get_user(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    latency = (time.perf_counter() - t0) * 1000
    logger.info({"event": "list_accounts", "user_id": user_id,
                 "count": len(user.accounts), "handler_ms": round(latency, 2)})
    return {"data": [
        {"id": a.id, "type": a.type, "name": a.account_name,
         "balance": a.balance, "currency": a.currency}
        for a in user.accounts
    ]}


@router.get("/{account_id}")
async def get_account_detail(
    account_id: str,
    user_id: str = Depends(require_zt_controller),
    x_request_id: str = Header(default=""),
):
    t0 = time.perf_counter()
    acct = get_account(account_id)
    if not acct:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")
    # Object-level ownership enforcement
    if acct.owner_user_id != user_id:
        logger.warning({
            "event": "bola_attempt", "requester": user_id,
            "account_owner": acct.owner_user_id, "account_id": account_id,
            "request_id": x_request_id,
        })
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    latency = (time.perf_counter() - t0) * 1000
    logger.info({"event": "get_account", "user_id": user_id,
                 "account_id": account_id, "handler_ms": round(latency, 2)})
    return {"data": {
        "id": acct.id, "type": acct.type, "name": acct.account_name,
        "bsb": acct.bsb, "account_number": acct.account_number,
        "balance": acct.balance, "currency": acct.currency,
    }}

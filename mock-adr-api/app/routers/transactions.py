"""Transactions endpoint with object-level ownership enforcement."""
import time
import logging
from fastapi import APIRouter, Depends, HTTPException, status, Header, Query
from app.auth import require_zt_controller
from seed.synthetic_data import get_user, get_account, get_transaction

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/transactions", tags=["transactions"])


@router.get("")
async def list_transactions(
    account_id: str = Query(..., description="Account ID to list transactions for"),
    user_id: str = Depends(require_zt_controller),
    x_request_id: str = Header(default=""),
):
    t0 = time.perf_counter()
    acct = get_account(account_id)
    if not acct:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")
    if acct.owner_user_id != user_id:
        logger.warning({
            "event": "bola_attempt", "requester": user_id,
            "account_owner": acct.owner_user_id, "request_id": x_request_id,
        })
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    latency = (time.perf_counter() - t0) * 1000
    logger.info({"event": "list_transactions", "user_id": user_id,
                 "account_id": account_id, "count": len(acct.transactions),
                 "handler_ms": round(latency, 2)})
    return {"data": [
        {"id": tx.id, "amount": tx.amount, "currency": tx.currency,
         "description": tx.description, "date": tx.date, "type": tx.type}
        for tx in acct.transactions
    ]}


@router.get("/{tx_id}")
async def get_transaction_detail(
    tx_id: str,
    user_id: str = Depends(require_zt_controller),
    x_request_id: str = Header(default=""),
):
    t0 = time.perf_counter()
    tx = get_transaction(tx_id)
    if not tx:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transaction not found")
    if tx.owner_user_id != user_id:
        logger.warning({
            "event": "bola_attempt", "requester": user_id,
            "tx_owner": tx.owner_user_id, "tx_id": tx_id,
        })
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    latency = (time.perf_counter() - t0) * 1000
    logger.info({"event": "get_transaction", "user_id": user_id, "tx_id": tx_id,
                 "handler_ms": round(latency, 2)})
    return {"data": {
        "id": tx.id, "account_id": tx.account_id, "amount": tx.amount,
        "currency": tx.currency, "description": tx.description,
        "date": tx.date, "type": tx.type,
    }}

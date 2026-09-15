"""Users and connections endpoints (Basiq-isomorphic)."""
import time
import logging
from fastapi import APIRouter, Depends, HTTPException, status, Header
from app.auth import require_zt_controller
from seed.synthetic_data import get_users, get_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/users", tags=["users"])


@router.get("")
async def list_users(
    user_id: str = Depends(require_zt_controller),
    x_request_id: str = Header(default=""),
):
    t0 = time.perf_counter()
    users = get_users()
    # Return summary — ownership enforced by returning only the requesting user's data
    user = users.get(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    latency = (time.perf_counter() - t0) * 1000
    logger.info({
        "event": "list_users", "user_id": user_id,
        "request_id": x_request_id, "handler_ms": round(latency, 2),
    })
    return {"data": [{"id": user.id, "name": user.name, "email": user.email}]}


@router.get("/{target_id}")
async def get_user_detail(
    target_id: str,
    user_id: str = Depends(require_zt_controller),
    x_request_id: str = Header(default=""),
):
    t0 = time.perf_counter()
    # Object-level ownership check (BOLA prevention)
    if target_id != user_id:
        logger.warning({
            "event": "bola_attempt", "requester": user_id,
            "target": target_id, "request_id": x_request_id,
        })
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    user = get_user(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    latency = (time.perf_counter() - t0) * 1000
    logger.info({"event": "get_user", "user_id": user_id, "handler_ms": round(latency, 2)})
    return {"data": {"id": user.id, "name": user.name, "email": user.email}}


@router.get("/{target_id}/connections")
async def get_connections(
    target_id: str,
    user_id: str = Depends(require_zt_controller),
    x_request_id: str = Header(default=""),
):
    t0 = time.perf_counter()
    if target_id != user_id:
        logger.warning({"event": "bola_attempt", "requester": user_id, "target": target_id})
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    user = get_user(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    latency = (time.perf_counter() - t0) * 1000
    logger.info({"event": "get_connections", "user_id": user_id, "handler_ms": round(latency, 2)})
    return {"data": [
        {"id": c.id, "institution": c.institution, "status": c.status}
        for c in user.connections
    ]}

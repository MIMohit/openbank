"""
Stage 6: Proxy approved requests to the Mock ADR API.

Only ALLOW decisions reach here.  Sets the internal trust header so the
mock API accepts the request.
"""
import logging

import httpx
from fastapi import HTTPException, Request, status
from fastapi.responses import Response

from app import config

logger = logging.getLogger(__name__)


async def forward(request: Request, user_id: str) -> Response:
    """
    Forward the incoming request to the upstream Mock ADR API.
    Strips any existing authorization headers and injects the internal
    service-to-service trust header.
    """
    upstream_url = config.MOCK_ADR_URL + request.url.path
    if request.url.query:
        upstream_url += "?" + request.url.query

    # Build forwarded headers — strip auth/dpop, inject internal secret
    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("authorization", "dpop", "host",
                              "x-zt-validated", "x-zt-user-id")
    }
    forward_headers["x-zt-validated"] = config.INTERNAL_SECRET
    forward_headers["x-zt-user-id"] = user_id

    body = await request.body()

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.request(
                method=request.method,
                url=upstream_url,
                headers=forward_headers,
                content=body,
            )
    except httpx.RequestError as exc:
        logger.error({"event": "proxy_upstream_error", "error": str(exc)})
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Upstream resource server unavailable",
        )

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers=dict(resp.headers),
        media_type=resp.headers.get("content-type"),
    )

"""
Mock ADR API — synthetic Basiq-isomorphic resource server.

- Network-isolated: only accepts requests from the ZT Controller.
- All data is synthetic; no real banking data.
- Object-level ownership enforced on every account/transaction endpoint.
"""
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from seed.synthetic_data import generate
from app.routers import users, accounts, transactions, consents

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":%(message)s}',
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info('"Generating synthetic data..."')
    generate()
    logger.info('"Synthetic data ready"')
    yield


app = FastAPI(
    title="Mock ADR API",
    description="Synthetic Basiq-isomorphic Open Banking resource server for testbed use.",
    version="1.0.0",
    docs_url="/docs",
    lifespan=lifespan,
)

app.include_router(users.router)
app.include_router(accounts.router)
app.include_router(transactions.router)
app.include_router(consents.router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "mock-adr-api"}


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error('"Unhandled exception: %s"', str(exc))
    # Never expose stack traces or internal details to clients
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )

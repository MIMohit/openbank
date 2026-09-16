"""
Structured per-request JSONL logger.
Appends one record per request to data/raw/<run_id>.jsonl
Schema matches §14 of the spec exactly.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from app import config

logger = logging.getLogger(__name__)
_lock = threading.Lock()


def write_record(record: dict) -> None:
    """Append a single JSON record to the active JSONL log file."""
    run_id = record.get("run_id", "unknown")
    out_dir = Path(config.DATA_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{run_id}.jsonl"
    line = json.dumps(record, default=str) + "\n"
    with _lock:
        with open(out_file, "a") as f:
            f.write(line)


# Semantics of the `checks` block, since two of the four are easy to misread:
#   token_valid      the access token's signature, issuer and expiry verified
#   dpop_valid       a DPoP proof was presented and passed every RFC 9449 check
#   jti_replayed     the proof's jti was already in the replay cache
#   cnf_jkt_present  the access token carries a cnf.jkt confirmation claim
#   cnf_jkt_match    the presented key's thumbprint was *verified* equal to
#                    cnf.jkt. False therefore means "not established", which
#                    covers both a mismatch and a proof that failed earlier for
#                    some other reason; it is not evidence that the key differed.
def build_record(
    run_id: str,
    request_info: dict,
    context: dict,
    checks: dict,
    risk_result: dict,
    decision: str,
    latency_ms: dict,
    attack_info: dict | None = None,
) -> dict:
    """Build the full JSONL record as specified in §14."""
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "config": config.ZT_MODE,
        # run_label separates experiment cells that share a ZT_MODE but differ
        # in ablation flags (e.g. "P" vs "P-minus-velocity").
        "run_label": config.RUN_LABEL,
        "flags": config.as_dict(),
        "request": request_info,
        "context": context,
        "checks": checks,
        "risk": risk_result,
        "decision": decision,
        "latency_ms": latency_ms,
        "attack": attack_info or {"is_attack": False, "attack_id": None, "succeeded": None},
    }

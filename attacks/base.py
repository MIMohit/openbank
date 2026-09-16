"""
Base class and result schema for all attack modules.
"""
import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


ORACLE_HEADER = "x-attack-context"


def attack_headers(attack_id: str, oracle_tag: bool = False) -> dict:
    """
    Instrumentation headers for one attack request.

    `x-attack-id` only labels the controller's JSONL record so the analysis can
    attribute requests to an attack; no enforcement decision reads it.

    `x-attack-context` is different in kind: it tells the risk engine "this
    request is an attack", and rule R7 scores it at 0.90 — nearly the DENY
    threshold on its own. That is an oracle supplied by the adversary, not
    detection, so it is OFF unless the suite is deliberately run with
    `--oracle-tag` to measure the pipeline's detection ceiling. The primary
    measurement in the paper is the organic one, with this header absent.
    """
    headers = {"x-attack-id": attack_id}
    if oracle_tag:
        headers[ORACLE_HEADER] = "true"
    return headers


@dataclass
class AttackResult:
    attack_id: str
    config: str                  # B0 | B1 | P | ablation label
    oracle_tag: bool = False     # was rule R7's oracle header supplied?
    attempts: int = 0
    successes: int = 0
    blocked_at_stage: str = ""
    detected: bool = False
    time_to_detect_ms: float = 0.0
    notes: str = ""
    raw_responses: list = field(default_factory=list)

    def success_rate(self) -> float:
        if self.attempts == 0:
            return 0.0
        return self.successes / self.attempts

    def detection_rate(self) -> float:
        return 1.0 if self.detected else 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["success_rate"] = self.success_rate()
        d["detection_rate"] = self.detection_rate()
        d["ts"] = datetime.now(timezone.utc).isoformat()
        return d


def write_attack_result(result: AttackResult, out_dir: str = "data/raw/attacks") -> None:
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    suffix = "_oracle" if result.oracle_tag else ""
    fname = Path(out_dir) / f"{result.attack_id}_{result.config}{suffix}.jsonl"
    with open(fname, "a") as f:
        f.write(json.dumps(result.to_dict()) + "\n")

"""
Base class and result schema for all attack modules.
"""
import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class AttackResult:
    attack_id: str
    config: str                  # B0 | B1 | P
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
    fname = Path(out_dir) / f"{result.attack_id}_{result.config}.jsonl"
    with open(fname, "a") as f:
        f.write(json.dumps(result.to_dict()) + "\n")

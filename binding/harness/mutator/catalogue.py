"""Load the primitive catalogue YAML and resolve compatibility against base ops."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, List, Optional

import yaml

from .base_ops import BaseOp

PRIMITIVES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "primitives")


@dataclass
class Primitive:
    id: str
    group: str                 # G1 | G2 | G3
    cls: str
    description: str
    source: str
    transform: List[dict]
    applies_to: Optional[dict] = None  # {requires_tags: [...]} or {op_ids: [...]}

    def compatible_with(self, op: BaseOp) -> bool:
        if not self.applies_to:
            return True
        req = self.applies_to.get("requires_tags")
        if req is not None and not set(req).issubset(op.tags):
            return False
        op_ids = self.applies_to.get("op_ids")
        if op_ids is not None and op.op_id not in op_ids:
            return False
        return True


def load_catalogue(files=("g1.yaml", "g2.yaml", "g3.yaml")) -> List[Primitive]:
    prims: List[Primitive] = []
    seen = set()
    for fname in files:
        path = os.path.join(PRIMITIVES_DIR, fname)
        with open(path) as f:
            doc = yaml.safe_load(f)
        group = doc.get("class_group", fname.split(".")[0].upper())
        for entry in doc.get("primitives", []):
            pid = entry["id"]
            if pid in seen:
                raise ValueError(f"duplicate primitive id across catalogue: {pid}")
            seen.add(pid)
            prims.append(Primitive(
                id=pid, group=group, cls=entry["class"],
                description=entry["description"], source=entry["source"],
                transform=entry["transform"], applies_to=entry.get("applies_to"),
            ))
    return prims


def catalogue_by_id(prims: List[Primitive]) -> Dict[str, Primitive]:
    return {p.id: p for p in prims}

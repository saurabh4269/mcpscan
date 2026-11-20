"""Shared scoring helpers for MCPScan crawl and documentation parity with preflight."""
import json
import os
import re

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CFG = json.load(open(os.path.join(_ROOT, "shared", "risk_patterns.json")))

RISKY = {k: re.compile(v) for k, v in _CFG["patterns"].items()}
RISK_PENALTIES = _CFG["penalties"]


def risky_from_text(text: str) -> set[str]:
    found = set()
    for k, rx in RISKY.items():
        if rx.search(text):
            found.add(k)
    return found


def directory_score_penalty(risky: set[str]) -> int:
    return sum(RISK_PENALTIES.get(k, 0) for k in risky)

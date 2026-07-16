"""
mini-siem correlation engine.

Mimics the detection-rule model used by Elastic Security / Splunk ES /
Microsoft Sentinel, all of which have converged on something close to the
open Sigma rule format: declarative YAML rules matched against a stream of
structured log events, with optional time-windowed correlation
(e.g. "5 failed logins then 1 success, same source, within 60s").

This is a STARTING POINT. Real SIEM correlation engines index events for
fast lookback queries and support much richer rule grammars. See README
for extension ideas.
"""

from __future__ import annotations

import json
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional

import yaml


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    detection: Dict[str, Any]      # field-match conditions (Sigma-style "selection")
    condition: str                 # e.g. "selection" or "selection | count() > 5"
    window_seconds: Optional[int] = None
    group_by: Optional[str] = None  # field to correlate on, e.g. "src_ip"
    threshold: Optional[int] = None


def load_rules(path: str) -> List[Rule]:
    with open(path, "r") as f:
        raw_rules = yaml.safe_load(f)

    rules = []
    for r in raw_rules:
        rules.append(
            Rule(
                id=r["id"],
                title=r["title"],
                severity=r.get("severity", "medium"),
                detection=r["detection"],
                condition=r.get("condition", "selection"),
                window_seconds=r.get("window_seconds"),
                group_by=r.get("group_by"),
                threshold=r.get("threshold"),
            )
        )
    return rules


def event_matches_selection(event: Dict[str, Any], selection: Dict[str, Any]) -> bool:
    """A minimal Sigma-style field matcher. Supports plain equality and
    the 'contains' suffix convention Sigma uses, e.g. field|contains: value."""
    for key, expected in selection.items():
        if "|" in key:
            field, op = key.split("|", 1)
        else:
            field, op = key, "eq"

        actual = event.get(field)
        if actual is None:
            return False

        if op == "eq" and actual != expected:
            return False
        if op == "contains" and str(expected) not in str(actual):
            return False
        if op == "gte" and not (isinstance(actual, (int, float)) and actual >= expected):
            return False

    return True


class CorrelationWindow:
    """Tracks matching events per group key within a sliding time window,
    used for threshold-based rules like brute-force detection."""

    def __init__(self, window_seconds: int, threshold: int):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.buckets: Dict[str, Deque[float]] = {}

    def record(self, group_key: str, ts: float) -> bool:
        """Record an event timestamp; return True if threshold is now met."""
        bucket = self.buckets.setdefault(group_key, deque())
        bucket.append(ts)

        cutoff = ts - self.window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        return len(bucket) >= self.threshold


class DetectionEngine:
    def __init__(self, rules: List[Rule]):
        self.rules = rules
        self.windows: Dict[str, CorrelationWindow] = {
            r.id: CorrelationWindow(r.window_seconds or 60, r.threshold or 1)
            for r in rules
            if r.threshold
        }

    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        alerts = []
        ts = event.get("ts", time.time())

        for rule in self.rules:
            if not event_matches_selection(event, rule.detection):
                continue

            if rule.threshold:
                # Correlation rule: only alert once the group hits threshold
                group_key = str(event.get(rule.group_by, "unknown")) if rule.group_by else "global"
                window = self.windows[rule.id]
                if window.record(group_key, ts):
                    alerts.append(self._build_alert(rule, event, group_key))
            else:
                # Simple single-event rule
                alerts.append(self._build_alert(rule, event, None))

        return alerts

    def _build_alert(self, rule: Rule, event: Dict[str, Any], group_key: Optional[str]) -> Dict[str, Any]:
        return {
            "rule_id": rule.id,
            "title": rule.title,
            "severity": rule.severity,
            "group_key": group_key,
            "triggering_event": event,
            "detected_at": time.time(),
        }

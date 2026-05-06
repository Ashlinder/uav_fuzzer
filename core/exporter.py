"""Export findings to JSON or CSV strings (no I/O)."""

from __future__ import annotations

import csv
import io
import json
from typing import Iterable

from .findings import Finding


FIELD_ORDER = ["line_no", "packet_id", "schema", "rule", "severity",
               "field", "value", "message", "mode"]


def to_json(findings: Iterable[Finding], pretty: bool = True) -> str:
    payload = [f.to_dict() for f in findings]
    return json.dumps(payload, indent=2 if pretty else None,
                      ensure_ascii=False)


def to_csv(findings: Iterable[Finding]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=FIELD_ORDER)
    writer.writeheader()
    for f in findings:
        d = f.to_dict()
        writer.writerow({k: d.get(k, "") for k in FIELD_ORDER})
    return buf.getvalue()


def summary(findings: list[Finding]) -> dict:
    """Quick aggregate stats for display in the UI."""
    by_rule: dict[str, int] = {}
    by_severity: dict[str, int] = {"NONE": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0}
    for f in findings:
        by_rule[f.rule] = by_rule.get(f.rule, 0) + 1
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return {
        "total_findings": len(findings),
        "by_rule": dict(sorted(by_rule.items(), key=lambda kv: -kv[1])),
        "by_severity": by_severity,
    }

"""Finding model — one record per detected anomaly."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

# Stable rule identifiers.
RULE_INVALID_HEADER = "INVALID_HEADER"
RULE_INVALID_COMMAND = "INVALID_COMMAND"
RULE_MISSING_PAYLOAD = "MISSING_PAYLOAD"
RULE_UNSAFE_ALTITUDE = "UNSAFE_ALTITUDE"
RULE_INVALID_GPS = "INVALID_GPS_RANGE"
RULE_ABNORMAL_NUMERIC = "ABNORMAL_NUMERIC"
RULE_PARSER_EXCEPTION = "PARSER_EXCEPTION"
RULE_INVALID_SOURCE = "INVALID_SOURCE_SYSTEM"
RULE_ILLEGAL_TRANSITION = "ILLEGAL_STATE_TRANSITION"

# Telemetry-only rules.
RULE_GPS_LOSS = "GPS_LOSS"
RULE_LOW_BATTERY = "LOW_BATTERY"
RULE_CRITICAL_BATTERY = "CRITICAL_BATTERY"
RULE_ABNORMAL_VELOCITY = "ABNORMAL_VELOCITY"
RULE_TAKEOFF_WHILE_DISARMED = "TAKEOFF_WHILE_DISARMED"


@dataclass
class Finding:
    line_no: int
    packet_id: str
    rule: str
    severity: str          # NONE | LOW | MEDIUM | HIGH
    field: str             # which field triggered the finding ("" if N/A)
    value: str             # the offending value as a string
    message: str           # human-readable explanation
    mode: str              # "basic" | "fuzz"
    schema: str = ""       # "command" | "telemetry"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

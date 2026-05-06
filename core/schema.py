"""Schema detection.

Looks at the header of an uploaded text blob and decides which parser to
use. Returns one of: "command", "telemetry", "unknown".
"""

from __future__ import annotations


def detect_schema(text: str) -> str:
    """Return 'command', 'telemetry', or 'unknown'.

    Detection is purely on the header keywords so we don't have to read
    the whole file. If the user pastes data without a header, we default
    to 'command' (the older, positional-friendly format).
    """
    if not text or not text.strip():
        return "unknown"

    # First non-empty line.
    first = ""
    for ln in text.splitlines():
        if ln.strip():
            first = ln.lower()
            break

    if not first:
        return "unknown"

    # Telemetry signature: timestamp_s + nav_state are unique to that file.
    if "timestamp_s" in first and "nav_state" in first:
        return "telemetry"
    # Also accept partial telemetry header (in case someone trims columns).
    if "timestamp_s" in first or "arming_state" in first or "flight_id" in first:
        return "telemetry"

    # Command signature: param1..param7, packet_id.
    if "param1" in first or "packet_id" in first:
        return "command"

    # Header-less paste: assume command schema (positional fallback).
    if "," in first and "timestamp" not in first:
        return "command"

    return "unknown"

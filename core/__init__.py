"""Core fuzzing logic — UI-independent.

The package supports two input schemas (COMMAND and TELEMETRY) with
separate parsers and scanners. A schema detector picks the right pair
automatically; callers may also invoke a specific parser/scanner directly.
"""

from .command_parser import CommandPacket, parse_command_text, COMMAND_FIELDS
from .telemetry_parser import TelemetryRow, parse_telemetry_text, TELEMETRY_FIELDS
from .findings import Finding
from .command_scanner import scan_commands, StateMachine
from .telemetry_scanner import scan_telemetry
from .exporter import to_json, to_csv, summary
from .schema import detect_schema


def parse_and_scan(text: str, mode: str = "basic",
                   state_rules: list[dict] | None = None,
                   schema: str | None = None) -> tuple[str, int, list[Finding]]:
    """Top-level convenience: detect schema, parse, scan.

    Returns (schema, n_records, findings).
    """
    if schema is None:
        schema = detect_schema(text)

    if schema == "telemetry":
        rows = parse_telemetry_text(text)
        findings = scan_telemetry(rows, mode=mode, state_rules=state_rules)
        return schema, len(rows), findings

    if schema == "command":
        packets = parse_command_text(text)
        findings = scan_commands(packets, mode=mode, state_rules=state_rules)
        return schema, len(packets), findings

    return "unknown", 0, []


__all__ = [
    "CommandPacket",
    "TelemetryRow",
    "Finding",
    "parse_command_text",
    "parse_telemetry_text",
    "scan_commands",
    "scan_telemetry",
    "StateMachine",
    "detect_schema",
    "parse_and_scan",
    "to_json",
    "to_csv",
    "summary",
    "COMMAND_FIELDS",
    "TELEMETRY_FIELDS",
]

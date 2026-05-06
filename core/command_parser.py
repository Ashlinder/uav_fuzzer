"""Parser for the COMMAND schema (mavlink_command_samples.csv).

Schema columns (header row required when uploaded as CSV):

  packet_id, msg_type, command, source_system, target_system,
  target_component, param1..param7, [optional: description,
  expected_status, expected_severity, expected_reason]

Also supports a positional, header-less form where each line is the same
fields in the same order.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from typing import Any


COMMAND_FIELDS = [
    "packet_id",
    "msg_type",
    "command",
    "source_system",
    "target_system",
    "target_component",
    "param1",
    "param2",
    "param3",
    "param4",
    "param5",
    "param6",
    "param7",
]


@dataclass
class CommandPacket:
    """One row from the COMMAND schema. Fields kept as raw strings so the
    scanner can detect type errors (e.g. param1='abc' for TAKEOFF) instead
    of crashing during parse."""

    line_no: int
    raw: str
    packet_id: str = ""
    msg_type: str = ""
    command: str = ""
    source_system: str = ""
    target_system: str = ""
    target_component: str = ""
    param1: str = ""
    param2: str = ""
    param3: str = ""
    param4: str = ""
    param5: str = ""
    param6: str = ""
    param7: str = ""
    parse_error: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def get_param(self, idx: int) -> str:
        return getattr(self, f"param{idx}", "")

    def is_param_empty(self, idx: int) -> bool:
        v = self.get_param(idx)
        return v is None or str(v).strip() == ""


def _row_to_packet(line_no: int, raw: str,
                   row: dict[str, Any]) -> CommandPacket:
    pkt = CommandPacket(line_no=line_no, raw=raw)
    extra: dict[str, Any] = {}
    for key, value in row.items():
        if key is None:
            continue
        norm_key = key.strip()
        norm_val = "" if value is None else str(value).strip()
        if norm_key in COMMAND_FIELDS:
            setattr(pkt, norm_key, norm_val)
        else:
            extra[norm_key] = norm_val
    pkt.extra = extra
    return pkt


def parse_command_text(text: str) -> list[CommandPacket]:
    """Parse a COMMAND-schema text blob.

    Auto-detects header vs positional form. If the first non-empty line
    contains commas AND a known field name, treat as CSV with header.
    """
    if not text:
        return []
    lines = [ln for ln in text.splitlines() if ln.strip() != ""]
    if not lines:
        return []

    first = lines[0]
    looks_like_header = "," in first and any(
        f in first.lower() for f in ("msg_type", "packet_id", "command")
    )

    packets: list[CommandPacket] = []

    if looks_like_header:
        reader = csv.DictReader(io.StringIO(text))
        # csv.DictReader rows start at file line 2 (line 1 is the header).
        for offset, row in enumerate(reader, start=2):
            raw_line = ",".join(
                "" if v is None else str(v) for v in row.values()
            )
            packets.append(_row_to_packet(offset, raw_line, row))
        return packets

    # Positional fallback.
    for idx, line in enumerate(lines, start=1):
        try:
            cells = next(csv.reader([line]))
        except Exception as exc:  # pragma: no cover
            packets.append(CommandPacket(line_no=idx, raw=line,
                                         parse_error=f"csv error: {exc}"))
            continue
        row = {fld: cells[i] if i < len(cells) else ""
               for i, fld in enumerate(COMMAND_FIELDS)}
        packets.append(_row_to_packet(idx, line, row))

    return packets

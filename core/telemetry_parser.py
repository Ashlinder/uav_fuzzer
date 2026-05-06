"""Parser for the TELEMETRY schema (telemetry_real_extract.csv).

Schema columns (header row required):

  timestamp_s, flight_id, msg_type, system_id, component_id,
  nav_state, arming_state, mode, command,
  lat, lon, relative_alt_m,
  vx_m_s, vy_m_s, vz_m_s,
  gps_fix_type, satellites_visible,
  battery_remaining_pct, voltage_v,
  roll_deg, pitch_deg, yaw_deg, link_quality_pct,
  result, expected_anomaly, notes

Telemetry rows carry their own state (nav_state, arming_state) so the
fuzz scanner can do context-aware checks without an external FSM.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from typing import Any


TELEMETRY_FIELDS = [
    "timestamp_s",
    "flight_id",
    "msg_type",
    "system_id",
    "component_id",
    "nav_state",
    "arming_state",
    "mode",
    "command",
    "lat",
    "lon",
    "relative_alt_m",
    "vx_m_s",
    "vy_m_s",
    "vz_m_s",
    "gps_fix_type",
    "satellites_visible",
    "battery_remaining_pct",
    "voltage_v",
    "roll_deg",
    "pitch_deg",
    "yaw_deg",
    "link_quality_pct",
    "result",
    "expected_anomaly",
    "notes",
]


@dataclass
class TelemetryRow:
    """One row from the TELEMETRY schema. All fields stored as raw strings;
    the scanner coerces them and reports parse errors as findings."""

    line_no: int
    raw: str
    timestamp_s: str = ""
    flight_id: str = ""
    msg_type: str = ""
    system_id: str = ""
    component_id: str = ""
    nav_state: str = ""
    arming_state: str = ""
    mode: str = ""
    command: str = ""
    lat: str = ""
    lon: str = ""
    relative_alt_m: str = ""
    vx_m_s: str = ""
    vy_m_s: str = ""
    vz_m_s: str = ""
    gps_fix_type: str = ""
    satellites_visible: str = ""
    battery_remaining_pct: str = ""
    voltage_v: str = ""
    roll_deg: str = ""
    pitch_deg: str = ""
    yaw_deg: str = ""
    link_quality_pct: str = ""
    result: str = ""
    expected_anomaly: str = ""
    notes: str = ""
    parse_error: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def packet_id(self) -> str:
        """Synthetic id: timestamp is a unique per-row anchor."""
        return self.timestamp_s or str(self.line_no)


def _row_to_telemetry(line_no: int, raw: str,
                      row: dict[str, Any]) -> TelemetryRow:
    rec = TelemetryRow(line_no=line_no, raw=raw)
    extra: dict[str, Any] = {}
    for key, value in row.items():
        if key is None:
            continue
        norm_key = key.strip()
        norm_val = "" if value is None else str(value).strip()
        if norm_key in TELEMETRY_FIELDS:
            setattr(rec, norm_key, norm_val)
        else:
            extra[norm_key] = norm_val
    rec.extra = extra
    return rec


def parse_telemetry_text(text: str) -> list[TelemetryRow]:
    """Parse a TELEMETRY-schema text blob. Header row is required."""
    if not text:
        return []
    lines = [ln for ln in text.splitlines() if ln.strip() != ""]
    if not lines:
        return []

    first = lines[0].lower()
    if not ("timestamp_s" in first or "nav_state" in first):
        # Not a recognisable telemetry header. Surface a single parse-error
        # row so the scanner emits a clear message.
        return [TelemetryRow(
            line_no=1, raw=lines[0],
            parse_error=("Telemetry parser expects a header row containing "
                         "timestamp_s/nav_state columns."),
        )]

    reader = csv.DictReader(io.StringIO(text))
    rows: list[TelemetryRow] = []
    for offset, row in enumerate(reader, start=2):
        raw_line = ",".join(
            "" if v is None else str(v) for v in row.values()
        )
        rows.append(_row_to_telemetry(offset, raw_line, row))
    return rows

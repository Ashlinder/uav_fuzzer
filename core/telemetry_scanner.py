"""Detection engine for the TELEMETRY schema.

Telemetry rows carry their own state context (nav_state, arming_state,
gps_fix_type, battery_remaining_pct), so most checks here are
context-aware by construction.

Two scan modes:
  * basic — field validation: header, command, GPS range, altitude bounds.
  * fuzz  — basic + abnormal velocity, GPS-loss detection, low-battery
            warnings, takeoff-while-disarmed, optional FSM replay.
"""

from __future__ import annotations

from typing import Iterable

from .constants import (
    ALT_MAX_M,
    ALT_MIN_M,
    BATTERY_CRITICAL_PCT,
    BATTERY_LOW_PCT,
    GPS_FIX_NONE,
    LAT_MAX,
    LAT_MIN,
    LON_MAX,
    LON_MIN,
    MIN_SATELLITES_FOR_NAV,
    VALID_COMMANDS,
    VALID_MSG_TYPES,
    VELOCITY_ABS_MAX,
)
from .findings import (
    Finding,
    RULE_ABNORMAL_NUMERIC,
    RULE_ABNORMAL_VELOCITY,
    RULE_CRITICAL_BATTERY,
    RULE_GPS_LOSS,
    RULE_ILLEGAL_TRANSITION,
    RULE_INVALID_COMMAND,
    RULE_INVALID_GPS,
    RULE_INVALID_HEADER,
    RULE_LOW_BATTERY,
    RULE_PARSER_EXCEPTION,
    RULE_TAKEOFF_WHILE_DISARMED,
    RULE_UNSAFE_ALTITUDE,
)
from .telemetry_parser import TelemetryRow
from .command_scanner import StateMachine  # reuse FSM


# ---------- helpers ----------------------------------------------------------

def _try_float(s: str) -> tuple[bool, float | None]:
    if s is None or str(s).strip() == "":
        return True, None
    try:
        return True, float(s)
    except (TypeError, ValueError):
        return False, None


def _mk(row: TelemetryRow, rule: str, severity: str, field: str,
        value: str, message: str, mode: str) -> Finding:
    return Finding(
        line_no=row.line_no,
        packet_id=row.packet_id,
        rule=rule,
        severity=severity,
        field=field,
        value=str(value),
        message=message,
        mode=mode,
        schema="telemetry",
    )


# ---------- per-rule checks --------------------------------------------------

def check_invalid_header(row: TelemetryRow, mode: str) -> list[Finding]:
    if not row.msg_type:
        return [_mk(row, RULE_INVALID_HEADER, "MEDIUM", "msg_type", "",
                    "msg_type is empty", mode)]
    if row.msg_type not in VALID_MSG_TYPES:
        return [_mk(row, RULE_INVALID_HEADER, "MEDIUM", "msg_type",
                    row.msg_type,
                    f"Unknown msg_type '{row.msg_type}'", mode)]
    return []


def check_invalid_command(row: TelemetryRow, mode: str) -> list[Finding]:
    if not row.command or row.command == "NONE":
        return []
    if row.command not in VALID_COMMANDS:
        return [_mk(row, RULE_INVALID_COMMAND, "MEDIUM", "command",
                    row.command,
                    f"Unknown command '{row.command}'", mode)]
    return []


def check_invalid_gps(row: TelemetryRow, mode: str) -> list[Finding]:
    out: list[Finding] = []
    for fld, raw, lo, hi, name in (
        ("lat", row.lat, LAT_MIN, LAT_MAX, "latitude"),
        ("lon", row.lon, LON_MIN, LON_MAX, "longitude"),
    ):
        ok, val = _try_float(raw)
        if not ok:
            out.append(_mk(row, RULE_PARSER_EXCEPTION, "MEDIUM", fld, raw,
                           f"{name} '{raw}' is not numeric", mode))
            continue
        if val is None:
            continue
        if not (lo <= val <= hi):
            out.append(_mk(row, RULE_INVALID_GPS, "HIGH", fld, raw,
                           f"{name} {val} outside [{lo},{hi}]", mode))
    return out


def check_unsafe_altitude(row: TelemetryRow, mode: str) -> list[Finding]:
    """Altitude is meaningful only when airborne. Skip when LANDED/IDLE."""
    state = (row.nav_state or "").upper()
    if state in {"IDLE", "LANDED", ""}:
        return []
    ok, val = _try_float(row.relative_alt_m)
    if not ok:
        return [_mk(row, RULE_PARSER_EXCEPTION, "MEDIUM",
                    "relative_alt_m", row.relative_alt_m,
                    f"relative_alt_m '{row.relative_alt_m}' is not numeric",
                    mode)]
    if val is None:
        return []
    if val < ALT_MIN_M:
        return [_mk(row, RULE_UNSAFE_ALTITUDE, "HIGH", "relative_alt_m",
                    row.relative_alt_m,
                    f"Negative altitude {val}m while in state {state}",
                    mode)]
    if val > ALT_MAX_M:
        return [_mk(row, RULE_UNSAFE_ALTITUDE, "HIGH", "relative_alt_m",
                    row.relative_alt_m,
                    f"Altitude {val}m exceeds safe ceiling {ALT_MAX_M}m",
                    mode)]
    return []


def check_abnormal_velocity(row: TelemetryRow, mode: str) -> list[Finding]:
    out: list[Finding] = []
    for fld in ("vx_m_s", "vy_m_s", "vz_m_s"):
        raw = getattr(row, fld)
        ok, val = _try_float(raw)
        if not ok:
            out.append(_mk(row, RULE_PARSER_EXCEPTION, "MEDIUM", fld, raw,
                           f"{fld} '{raw}' is not numeric", mode))
            continue
        if val is None:
            continue
        if abs(val) > VELOCITY_ABS_MAX:
            out.append(_mk(row, RULE_ABNORMAL_VELOCITY, "HIGH", fld, raw,
                           f"{fld}={val} m/s exceeds {VELOCITY_ABS_MAX} m/s",
                           mode))
    return out


def check_gps_loss(row: TelemetryRow, mode: str) -> list[Finding]:
    """Flag GPS loss while navigating."""
    state = (row.nav_state or "").upper()
    ok, fix = _try_float(row.gps_fix_type)
    if not ok or fix is None:
        return []
    ok2, sats = _try_float(row.satellites_visible)
    sats_val = sats if ok2 and sats is not None else None

    if state in {"NAVIGATE", "TAKEOFF", "HOVER", "RETURN_HOME"}:
        if int(fix) == GPS_FIX_NONE:
            return [_mk(row, RULE_GPS_LOSS, "HIGH", "gps_fix_type",
                        row.gps_fix_type,
                        f"GPS fix lost (fix_type=0) while in {state}", mode)]
        if sats_val is not None and sats_val < MIN_SATELLITES_FOR_NAV:
            return [_mk(row, RULE_GPS_LOSS, "MEDIUM", "satellites_visible",
                        row.satellites_visible,
                        f"Only {int(sats_val)} satellites visible "
                        f"(< {MIN_SATELLITES_FOR_NAV}) while in {state}",
                        mode)]
    return []


def check_battery(row: TelemetryRow, mode: str) -> list[Finding]:
    ok, pct = _try_float(row.battery_remaining_pct)
    if not ok or pct is None:
        return []
    if pct <= BATTERY_CRITICAL_PCT:
        return [_mk(row, RULE_CRITICAL_BATTERY, "HIGH",
                    "battery_remaining_pct", row.battery_remaining_pct,
                    f"Critical battery {pct}% (<= {BATTERY_CRITICAL_PCT}%)",
                    mode)]
    if pct <= BATTERY_LOW_PCT:
        return [_mk(row, RULE_LOW_BATTERY, "MEDIUM",
                    "battery_remaining_pct", row.battery_remaining_pct,
                    f"Low battery {pct}% (<= {BATTERY_LOW_PCT}%)", mode)]
    return []


def check_takeoff_while_disarmed(row: TelemetryRow, mode: str) -> list[Finding]:
    if row.command != "TAKEOFF":
        return []
    if (row.arming_state or "").upper() == "DISARMED":
        return [_mk(row, RULE_TAKEOFF_WHILE_DISARMED, "HIGH", "arming_state",
                    row.arming_state,
                    "TAKEOFF command issued while arming_state=DISARMED",
                    mode)]
    return []


def check_state_transition(row: TelemetryRow, fsm: StateMachine | None,
                           mode: str) -> list[Finding]:
    """Replay the row's command through the FSM (fuzz mode, optional)."""
    if fsm is None:
        return []
    event = row.command if row.command and row.command != "NONE" else ""
    if not event:
        return []
    allowed, why, prev = fsm.step(event)
    if allowed:
        return []
    return [_mk(row, RULE_ILLEGAL_TRANSITION, "HIGH", "command",
                event,
                f"Illegal transition from {prev} on {event}: {why}", mode)]


# ---------- public API ------------------------------------------------------

BASIC_CHECKS = (
    check_invalid_header,
    check_invalid_command,
    check_invalid_gps,
    check_unsafe_altitude,
)

FUZZ_EXTRA_CHECKS = (
    check_abnormal_velocity,
    check_gps_loss,
    check_battery,
    check_takeoff_while_disarmed,
)


def scan_telemetry(rows: Iterable[TelemetryRow], mode: str = "basic",
                   state_rules: list[dict[str, str]] | None = None
                   ) -> list[Finding]:
    """Run all detection rules over a TelemetryRow stream."""
    if mode not in ("basic", "fuzz"):
        raise ValueError(f"unknown mode {mode!r}")

    fsm = StateMachine(state_rules) if (mode == "fuzz" and state_rules) else None
    findings: list[Finding] = []

    for row in rows:
        if row.parse_error:
            findings.append(_mk(row, RULE_PARSER_EXCEPTION, "MEDIUM", "",
                                row.raw, row.parse_error, mode))
            continue
        for check in BASIC_CHECKS:
            findings.extend(check(row, mode))
        if mode == "fuzz":
            for check in FUZZ_EXTRA_CHECKS:
                findings.extend(check(row, mode))
            findings.extend(check_state_transition(row, fsm, mode))

    return findings

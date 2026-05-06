"""Detection engine for the COMMAND schema.

Two scan modes:
  * basic — per-packet, stateless field validation.
  * fuzz  — basic + numeric-anomaly check + state-machine replay.

Each rule is a small function returning list[Finding] so they're easy
to test, add, or disable individually.
"""

from __future__ import annotations

from typing import Iterable

from .command_parser import CommandPacket
from .constants import (
    ALT_MAX_M,
    ALT_MIN_M,
    LAT_MAX,
    LAT_MIN,
    LON_MAX,
    LON_MIN,
    NUMERIC_ABS_MAX,
    REQUIRED_COMMAND_PARAMS,
    SOURCE_SYSTEM_MAX,
    SOURCE_SYSTEM_MIN,
    VALID_COMMANDS,
    VALID_MSG_TYPES,
)
from .findings import (
    Finding,
    RULE_ABNORMAL_NUMERIC,
    RULE_ILLEGAL_TRANSITION,
    RULE_INVALID_COMMAND,
    RULE_INVALID_GPS,
    RULE_INVALID_HEADER,
    RULE_INVALID_SOURCE,
    RULE_MISSING_PAYLOAD,
    RULE_PARSER_EXCEPTION,
    RULE_UNSAFE_ALTITUDE,
)


# ---------- helpers ----------------------------------------------------------

def _try_float(s: str) -> tuple[bool, float | None]:
    """Best-effort float coercion. Empty -> (True, None) meaning 'no value'."""
    if s is None or str(s).strip() == "":
        return True, None
    try:
        return True, float(s)
    except (TypeError, ValueError):
        return False, None


def _mk(pkt: CommandPacket, rule: str, severity: str, field: str,
        value: str, message: str, mode: str) -> Finding:
    return Finding(
        line_no=pkt.line_no,
        packet_id=pkt.packet_id or str(pkt.line_no),
        rule=rule,
        severity=severity,
        field=field,
        value=str(value),
        message=message,
        mode=mode,
        schema="command",
    )


# ---------- per-rule checks --------------------------------------------------

def check_invalid_header(pkt: CommandPacket, mode: str) -> list[Finding]:
    if not pkt.msg_type:
        return [_mk(pkt, RULE_INVALID_HEADER, "MEDIUM", "msg_type", "",
                    "msg_type is empty", mode)]
    if pkt.msg_type not in VALID_MSG_TYPES:
        return [_mk(pkt, RULE_INVALID_HEADER, "MEDIUM", "msg_type",
                    pkt.msg_type,
                    f"Unknown msg_type '{pkt.msg_type}' (not in whitelist)",
                    mode)]
    return []


def check_invalid_command(pkt: CommandPacket, mode: str) -> list[Finding]:
    if not pkt.command:
        if pkt.msg_type == "COMMAND_LONG":
            return [_mk(pkt, RULE_INVALID_COMMAND, "MEDIUM", "command", "",
                        "COMMAND_LONG with empty command", mode)]
        return []
    if pkt.command not in VALID_COMMANDS:
        return [_mk(pkt, RULE_INVALID_COMMAND, "MEDIUM", "command",
                    pkt.command,
                    f"Unknown command '{pkt.command}'", mode)]
    return []


def check_missing_payload(pkt: CommandPacket, mode: str) -> list[Finding]:
    cmd = pkt.command or "NONE"
    required = REQUIRED_COMMAND_PARAMS.get(cmd, [])
    out: list[Finding] = []
    for idx in required:
        if pkt.is_param_empty(idx):
            out.append(_mk(pkt, RULE_MISSING_PAYLOAD, "MEDIUM",
                           f"param{idx}", "",
                           f"{cmd} requires param{idx} but it is empty",
                           mode))
    return out


def check_invalid_source(pkt: CommandPacket, mode: str) -> list[Finding]:
    ok, val = _try_float(pkt.source_system)
    if not ok:
        return [_mk(pkt, RULE_PARSER_EXCEPTION, "LOW", "source_system",
                    pkt.source_system,
                    "source_system is not numeric", mode)]
    if val is None:
        return []
    if not (SOURCE_SYSTEM_MIN <= val <= SOURCE_SYSTEM_MAX):
        return [_mk(pkt, RULE_INVALID_SOURCE, "LOW", "source_system",
                    pkt.source_system,
                    f"source_system {val} outside expected "
                    f"[{SOURCE_SYSTEM_MIN},{SOURCE_SYSTEM_MAX}]", mode)]
    return []


def check_unsafe_altitude(pkt: CommandPacket, mode: str) -> list[Finding]:
    """Altitude is param1 for TAKEOFF, param7 for GLOBAL_POSITION_INT."""
    out: list[Finding] = []
    candidates: list[tuple[str, str]] = []
    if pkt.command == "TAKEOFF":
        candidates.append(("param1", pkt.param1))
    if pkt.msg_type == "GLOBAL_POSITION_INT":
        candidates.append(("param7", pkt.param7))

    for fld, raw in candidates:
        ok, val = _try_float(raw)
        if not ok:
            out.append(_mk(pkt, RULE_PARSER_EXCEPTION, "MEDIUM", fld, raw,
                           f"Altitude field {fld}='{raw}' is not numeric",
                           mode))
            continue
        if val is None:
            continue
        if val < ALT_MIN_M:
            out.append(_mk(pkt, RULE_UNSAFE_ALTITUDE, "HIGH", fld, raw,
                           f"Negative altitude {val}m", mode))
        elif val > ALT_MAX_M:
            out.append(_mk(pkt, RULE_UNSAFE_ALTITUDE, "HIGH", fld, raw,
                           f"Altitude {val}m exceeds safe ceiling "
                           f"{ALT_MAX_M}m", mode))
    return out


def check_invalid_gps(pkt: CommandPacket, mode: str) -> list[Finding]:
    """GPS lat/lon live in param5/param6 for GLOBAL_POSITION_INT."""
    if pkt.msg_type != "GLOBAL_POSITION_INT":
        return []
    out: list[Finding] = []
    for fld, raw, lo, hi, name in (
        ("param5", pkt.param5, LAT_MIN, LAT_MAX, "latitude"),
        ("param6", pkt.param6, LON_MIN, LON_MAX, "longitude"),
    ):
        ok, val = _try_float(raw)
        if not ok:
            out.append(_mk(pkt, RULE_PARSER_EXCEPTION, "MEDIUM", fld, raw,
                           f"{name} '{raw}' is not numeric", mode))
            continue
        if val is None:
            continue
        if not (lo <= val <= hi):
            out.append(_mk(pkt, RULE_INVALID_GPS, "HIGH", fld, raw,
                           f"{name} {val} outside [{lo},{hi}]", mode))
    return out


def check_abnormal_numeric(pkt: CommandPacket, mode: str) -> list[Finding]:
    """Catch absurd magnitudes in any numeric param. Skips fields already
    covered by GPS/altitude checks to avoid double-flagging."""
    out: list[Finding] = []
    skip_fields: set[str] = set()
    if pkt.command == "TAKEOFF":
        skip_fields.add("param1")
    if pkt.msg_type == "GLOBAL_POSITION_INT":
        skip_fields.update({"param5", "param6", "param7"})

    for idx in range(1, 8):
        fld = f"param{idx}"
        if fld in skip_fields:
            continue
        raw = pkt.get_param(idx)
        if raw is None or str(raw).strip() == "":
            continue
        ok, val = _try_float(raw)
        if not ok:
            out.append(_mk(pkt, RULE_PARSER_EXCEPTION, "MEDIUM", fld, raw,
                           f"{fld}='{raw}' is not numeric", mode))
            continue
        if val is None:
            continue
        if abs(val) > NUMERIC_ABS_MAX:
            out.append(_mk(pkt, RULE_ABNORMAL_NUMERIC, "HIGH", fld, raw,
                           f"{fld}={val} exceeds magnitude "
                           f"{NUMERIC_ABS_MAX:g}", mode))
    return out


# ---------- state-machine replay (fuzz mode only) ---------------------------

class StateMachine:
    """FSM driven by state_transition_rules.csv."""

    def __init__(self, rules: list[dict[str, str]] | None = None):
        self.rules: dict[tuple[str, str], tuple[str, bool, str, str]] = {}
        self.state = "IDLE"
        if rules:
            self.load(rules)

    def load(self, rules: list[dict[str, str]]) -> None:
        for r in rules:
            key = (
                str(r.get("current_state", "")).strip().upper(),
                str(r.get("event_or_command", "")).strip().upper(),
            )
            self.rules[key] = (
                str(r.get("next_state", "")).strip().upper(),
                str(r.get("allowed", "NO")).strip().upper() == "YES",
                str(r.get("severity_if_violated", "MEDIUM")).strip().upper() or "MEDIUM",
                str(r.get("rationale", "")).strip(),
            )

    def step(self, event: str) -> tuple[bool, str | None, str]:
        prev = self.state
        event = (event or "").upper()
        key = (self.state, event)
        if key not in self.rules:
            return True, None, prev
        next_state, allowed, severity, rationale = self.rules[key]
        if allowed:
            self.state = next_state
            return True, None, prev
        return False, f"{rationale} (severity={severity})", prev


def check_state_transition(pkt: CommandPacket, fsm: StateMachine | None,
                           mode: str) -> list[Finding]:
    if fsm is None:
        return []
    event = pkt.command if pkt.command and pkt.command != "NONE" else pkt.msg_type
    if not event:
        return []
    allowed, why, prev = fsm.step(event)
    if allowed:
        return []
    return [_mk(pkt, RULE_ILLEGAL_TRANSITION, "HIGH", "command",
                event,
                f"Illegal transition from {prev} on {event}: {why}",
                mode)]


# ---------- public API ------------------------------------------------------

BASIC_CHECKS = (
    check_invalid_header,
    check_invalid_command,
    check_missing_payload,
    check_invalid_source,
    check_unsafe_altitude,
    check_invalid_gps,
)

FUZZ_EXTRA_CHECKS = (
    check_abnormal_numeric,
)


def scan_commands(packets: Iterable[CommandPacket], mode: str = "basic",
                  state_rules: list[dict[str, str]] | None = None
                  ) -> list[Finding]:
    """Run all detection rules over a CommandPacket stream."""
    if mode not in ("basic", "fuzz"):
        raise ValueError(f"unknown mode {mode!r}")

    fsm = StateMachine(state_rules) if (mode == "fuzz" and state_rules) else None
    findings: list[Finding] = []

    for pkt in packets:
        if pkt.parse_error:
            findings.append(_mk(pkt, RULE_PARSER_EXCEPTION, "MEDIUM", "",
                                pkt.raw, pkt.parse_error, mode))
            continue
        for check in BASIC_CHECKS:
            findings.extend(check(pkt, mode))
        if mode == "fuzz":
            for check in FUZZ_EXTRA_CHECKS:
                findings.extend(check(pkt, mode))
            findings.extend(check_state_transition(pkt, fsm, mode))

    return findings

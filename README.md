# Mini UAV Protocol Fuzzing Platform

A small web-based platform that ingests UAV-like command packets, runs
field-level + state-machine validation, and exports consolidated findings
as JSON or CSV.

Built for the SIT 2-hour hands-on assignment. Inspired by protocol-aware
fuzzing of MAVLink-style command streams.

## Quick start

```bash
pip install -r requirements.txt
streamlit run app.py
```

Then open <http://localhost:8501>.

## Project layout

```
uav_fuzzer/
├── app.py                  # Streamlit UI (thin)
├── core/                   # Pure-Python detection engine
│   ├── __init__.py         # public re-exports
│   ├── constants.py        # whitelists, ranges, thresholds
│   ├── parser.py           # text/CSV → Packet objects
│   ├── findings.py         # Finding dataclass + rule IDs
│   ├── scanner.py          # detection rules + FSM replay
│   └── exporter.py         # JSON / CSV / summary
├── sample_data/
│   ├── mavlink_command_samples.csv
│   ├── telemetry_real_extract.csv
│   └── state_transition_rules.csv
├── requirements.txt
└── README.md
```

UI and logic are deliberately decoupled: nothing in `core/` imports
Streamlit, so the same engine can drive a CLI, a FastAPI service, or
unit tests.

## Scan modes

| Mode  | What it does |
|-------|--------------|
| basic | Stateless per-packet checks: header, command, required payload, GPS range, altitude bounds, source-system range, checksum advisory. |
| fuzz  | All basic checks **plus** abnormal numeric magnitudes (>1e5) on every param, **plus** state-machine replay against `state_transition_rules.csv`. Flags illegal transitions like `IDLE → TAKEOFF` or `HOVER → DISARM`. |

## Detection rules

| Rule ID                    | Severity | Trigger |
|----------------------------|----------|---------|
| `INVALID_HEADER`           | MEDIUM   | `msg_type` empty or not in whitelist |
| `INVALID_COMMAND`          | MEDIUM   | `command` not in whitelist (or empty for COMMAND_LONG) |
| `MISSING_PAYLOAD`          | MEDIUM   | required param empty for the given command |
| `UNSAFE_ALTITUDE`          | HIGH     | TAKEOFF param1 or GPI param7 outside `[0, 500]` m |
| `INVALID_GPS_RANGE`        | HIGH     | latitude ∉ [-90, 90] or longitude ∉ [-180, 180] |
| `ABNORMAL_NUMERIC` *(fuzz)*| HIGH     | any param magnitude > 1e5 |
| `PARSER_EXCEPTION`         | MEDIUM   | numeric coercion failure on a populated field |
| `INVALID_SOURCE_SYSTEM`    | LOW      | source_system outside `[1, 255]` |
| `MISSING_CHECKSUM`         | LOW/MED  | checksum/CRC column absent or invalid hex |
| `ILLEGAL_STATE_TRANSITION` *(fuzz)* | HIGH | FSM disallows current_state + event |

## Input format

Either:

* a CSV with a header row matching `mavlink_command_samples.csv` columns, or
* a positional comma-separated stream where each line follows
  `packet_id, msg_type, command, source_system, target_system,
  target_component, param1, ..., param7`.

Auto-detected by the parser.

## Output format

JSON array of objects, or CSV with the same columns:

```json
[
  {
    "line_no": 10,
    "packet_id": "9",
    "rule": "UNSAFE_ALTITUDE",
    "severity": "HIGH",
    "field": "param1",
    "value": "-10",
    "message": "Negative altitude -10.0m",
    "mode": "basic"
  }
]
```

## Validation against ground truth

The bundled `mavlink_command_samples.csv` contains an `expected_status`
column. Running fuzz mode flags **10 of the 11** purely-syntactic anomalies
(rows 9–14, 17–20 + 11 in fuzz mode). The two remaining samples — rows 15
and 16, "LAND while GPS unavailable" and "DISARM during hover" — are
labelled `WARN` in the dataset and are explicitly noted as needing
`state/context validation`. They are caught by the fuzz-mode FSM replay
when state context is present (e.g. on `telemetry_real_extract.csv`).

## Assumptions and limitations

* The simplified format does not ship a checksum column, so
  `MISSING_CHECKSUM` is emitted as a global advisory only. The detector
  will validate hex if a `checksum`/`crc` column is added.
* Altitude ceiling (500 m) and source-system range (1–255) are heuristics
  for the dataset, not real MAVLink limits.
* Param semantics differ per command (param1 is altitude for TAKEOFF but
  x-delta for MOVE). Skip-rules in `check_abnormal_numeric` prevent
  double-flagging fields already inspected by altitude/GPS checks.
* The FSM is a strict whitelist — unmodelled transitions pass silently
  rather than being flagged, to avoid false positives on the larger
  telemetry log which uses additional events not in the rule table.

## Extending

To add a rule:

1. Define a `check_*` function in `core/scanner.py` returning
   `list[Finding]`.
2. Add it to `BASIC_CHECKS` or `FUZZ_EXTRA_CHECKS`.
3. Optionally export a new `RULE_*` constant from `core/findings.py`.

That's it — no UI changes required.

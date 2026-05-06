"""Protocol-level constants for both supported schemas.

Two input schemas are supported:

  * COMMAND     -- mavlink_command_samples.csv format. Per-packet command/
                   position records with param1..param7.
  * TELEMETRY   -- telemetry_real_extract.csv format. Time-ordered flight
                   log with explicit lat/lon/altitude and state columns.

Each schema has its own parser and its own detection-rule set; this
module just holds shared whitelists and physical thresholds.
"""

# ---- shared protocol whitelists --------------------------------------------

VALID_MSG_TYPES = {
    "HEARTBEAT",
    "COMMAND_LONG",
    "GLOBAL_POSITION_INT",
    "LOCAL_POSITION",
    "GPS_RAW_INT",
}

VALID_COMMANDS = {
    "NONE",
    "ARM",
    "DISARM",
    "TAKEOFF",
    "LAND",
    "RTL",
    "MOVE",
    "GPS_LOSS",  # appears as an event in telemetry
}

# Required params for each command in the COMMAND schema (1-based indices).
REQUIRED_COMMAND_PARAMS = {
    "ARM": [1],
    "DISARM": [1],
    "TAKEOFF": [1],            # param1 = altitude
    "MOVE": [1, 2, 3],         # x, y, z deltas
    "RTL": [1],
    "LAND": [],
    "NONE": [],
}

# ---- physical / range thresholds -------------------------------------------

ALT_MIN_M = 0.0
ALT_MAX_M = 500.0

LAT_MIN, LAT_MAX = -90.0, 90.0
LON_MIN, LON_MAX = -180.0, 180.0

NUMERIC_ABS_MAX = 1.0e5

VELOCITY_ABS_MAX = 100.0  # m/s — telemetry sanity bound

SOURCE_SYSTEM_MIN = 1
SOURCE_SYSTEM_MAX = 255

# Battery thresholds for telemetry warnings.
BATTERY_LOW_PCT = 20.0
BATTERY_CRITICAL_PCT = 10.0

# GPS quality.
MIN_SATELLITES_FOR_NAV = 6
GPS_FIX_NONE = 0  # gps_fix_type==0 means no fix

# ---- ordering --------------------------------------------------------------

SEVERITY_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}

"""Mini UAV Protocol Fuzzing Platform — Streamlit UI.

Run with:  streamlit run app.py

This file is UI-only. All parsing/detection/export lives in `core/`.
The app supports two input schemas:

  * COMMAND   — mavlink_command_samples.csv
  * TELEMETRY — telemetry_real_extract.csv

Schema is auto-detected from the file's header. The user can override
the choice from the sidebar if needed.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path

import pandas as pd
import streamlit as st

from core import (
    detect_schema,
    parse_command_text,
    parse_telemetry_text,
    scan_commands,
    scan_telemetry,
    summary,
    to_csv,
    to_json,
)


# ---------- page config ------------------------------------------------------

st.set_page_config(
    page_title="UAV Fuzzing Platform",
    page_icon="🛰",
    layout="wide",
)

st.markdown(
    """
    <style>
      .block-container { padding-top: 2rem; max-width: 1200px; }
      h1, h2, h3 {
        font-family: 'JetBrains Mono', 'Menlo', monospace;
        letter-spacing: -0.02em;
      }
      div[data-testid="stMetricValue"] { font-family: 'JetBrains Mono', monospace; }
      .stTextArea textarea { font-family: 'JetBrains Mono', monospace; font-size: 13px; }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------- helpers ----------------------------------------------------------

SAMPLE_DIR = Path(__file__).parent / "sample_data"

SAMPLE_FILES = {
    "(none)": None,
    "Command samples (mavlink_command_samples.csv)": "mavlink_command_samples.csv",
    "Telemetry log (telemetry_real_extract.csv)":   "telemetry_real_extract.csv",
}


def load_state_rules(uploaded_file) -> list[dict] | None:
    if uploaded_file is None:
        default = SAMPLE_DIR / "state_transition_rules.csv"
        if default.exists():
            with default.open() as fh:
                return list(csv.DictReader(fh))
        return None
    text = uploaded_file.getvalue().decode("utf-8", errors="replace")
    return list(csv.DictReader(io.StringIO(text)))


def load_sample(name: str) -> str:
    path = SAMPLE_DIR / name
    return path.read_text() if path.exists() else ""


def run_scan(text: str, schema_choice: str, mode: str,
             state_rules: list[dict] | None):
    """Dispatch to the right parser+scanner based on schema."""
    if schema_choice == "auto":
        schema = detect_schema(text)
    else:
        schema = schema_choice

    if schema == "telemetry":
        rows = parse_telemetry_text(text)
        findings = scan_telemetry(rows, mode=mode, state_rules=state_rules)
        return schema, len(rows), findings

    if schema == "command":
        packets = parse_command_text(text)
        findings = scan_commands(packets, mode=mode, state_rules=state_rules)
        return schema, len(packets), findings

    return "unknown", 0, []


# ---------- sidebar ----------------------------------------------------------

st.sidebar.title("⚙ Configuration")

mode = st.sidebar.radio(
    "Scan mode",
    options=["basic", "fuzz"],
    format_func=lambda m: {
        "basic": "Basic validation",
        "fuzz":  "Fuzz / anomaly scan",
    }[m],
    help=("Basic = stateless field checks. "
          "Fuzz = basic + numeric/velocity anomalies + context-aware checks "
          "+ optional state-machine replay."),
)

st.sidebar.markdown("---")
st.sidebar.subheader("Input schema")
schema_override = st.sidebar.radio(
    "Schema",
    options=["auto", "command", "telemetry"],
    format_func=lambda s: {
        "auto":      "Auto-detect",
        "command":   "Command (mavlink_command_samples)",
        "telemetry": "Telemetry (telemetry_real_extract)",
    }[s],
    help="Auto-detect reads the header row. Override if detection misfires.",
)

st.sidebar.markdown("---")
st.sidebar.subheader("State machine (fuzz mode)")
state_file = st.sidebar.file_uploader(
    "state_transition_rules.csv",
    type=["csv"],
    help="Optional. Used to replay commands through an FSM in fuzz mode. "
         "Falls back to bundled default if not supplied.",
)

st.sidebar.markdown("---")
st.sidebar.subheader("Sample data")
sample_choice = st.sidebar.selectbox(
    "Load a bundled sample",
    options=list(SAMPLE_FILES.keys()),
)


# ---------- main -------------------------------------------------------------

st.title("Mini UAV Protocol Fuzzing Platform")
st.caption(
    "Upload or paste UAV-like command packets or telemetry rows, run a "
    "fuzzing/anomaly scan, and export consolidated findings."
)

uploaded = st.file_uploader(
    "Upload packets (.txt or .csv)",
    type=["txt", "csv"],
    help="Either a command-samples CSV or a telemetry CSV. "
         "Schema is auto-detected from the header row.",
)

# Decide source text (upload > sample > manual paste).
default_text = ""
sample_filename = SAMPLE_FILES.get(sample_choice)
if uploaded is not None:
    default_text = uploaded.getvalue().decode("utf-8", errors="replace")
elif sample_filename is not None:
    default_text = load_sample(sample_filename)
    st.info(f"Loaded sample: **{sample_filename}**")

text = st.text_area(
    "Or paste packet/telemetry data here",
    value=default_text,
    height=240,
    placeholder=("# Either of these headers will work:\n"
                 "packet_id,msg_type,command,source_system,...\n"
                 "timestamp_s,flight_id,msg_type,system_id,...,nav_state,..."),
)

# Schema preview before scan.
if text.strip():
    detected = detect_schema(text)
    label = {"command": "COMMAND", "telemetry": "TELEMETRY",
             "unknown": "UNKNOWN"}[detected]
    st.caption(f"Detected schema: **{label}**")

run = st.button("▶ Run scan", type="primary")


# ---------- run scan ---------------------------------------------------------

if run:
    if not text.strip():
        st.warning("No input provided. Upload a file, paste data, "
                   "or pick a sample.")
        st.stop()

    state_rules = load_state_rules(state_file) if mode == "fuzz" else None

    with st.spinner("Parsing and scanning…"):
        schema, n_records, findings = run_scan(
            text, schema_override, mode, state_rules,
        )

    if schema == "unknown":
        st.error("Could not detect schema. Use the sidebar to choose "
                 "'command' or 'telemetry' explicitly.")
        st.stop()
    if n_records == 0:
        st.error("No records could be parsed from the input.")
        st.stop()

    st.success(f"Scanned **{n_records}** record(s) using the **{schema}** "
               f"schema in **{mode}** mode.")

    stats = summary(findings)

    # ---- summary metrics ----
    st.subheader("Summary")
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Records",  n_records)
    m2.metric("Findings", stats["total_findings"])
    m3.metric("HIGH",     stats["by_severity"].get("HIGH", 0))
    m4.metric("MEDIUM",   stats["by_severity"].get("MEDIUM", 0))
    m5.metric("LOW",      stats["by_severity"].get("LOW", 0))

    if stats["by_rule"]:
        st.markdown("**Findings by rule**")
        rule_df = pd.DataFrame(
            [{"rule": k, "count": v} for k, v in stats["by_rule"].items()]
        )
        st.dataframe(rule_df, hide_index=True, use_container_width=True)

    # ---- findings table ----
    st.subheader("Findings")
    if not findings:
        st.success("✅ No anomalies detected.")
    else:
        df = pd.DataFrame([f.to_dict() for f in findings])
        sev_options = ["HIGH", "MEDIUM", "LOW", "NONE"]
        chosen = st.multiselect(
            "Filter severity", sev_options,
            default=["HIGH", "MEDIUM", "LOW"],
        )
        view = df[df["severity"].isin(chosen)] if chosen else df
        st.dataframe(view, hide_index=True, use_container_width=True)

    # ---- export ----
    st.subheader("Export")
    json_blob = to_json(findings)
    csv_blob = to_csv(findings)
    e1, e2 = st.columns(2)
    e1.download_button(
        "⬇ Download JSON", data=json_blob,
        file_name=f"findings_{schema}.json", mime="application/json",
        use_container_width=True,
    )
    e2.download_button(
        "⬇ Download CSV", data=csv_blob,
        file_name=f"findings_{schema}.csv", mime="text/csv",
        use_container_width=True,
    )

    with st.expander("Preview JSON"):
        preview = json_blob[:5000] + ("…" if len(json_blob) > 5000 else "")
        st.code(preview, language="json")

else:
    st.info("Configure scan mode in the sidebar, then click **Run scan**.")


# ---------- footer -----------------------------------------------------------

st.markdown("---")
st.caption(
    "**Command schema rules:** invalid header · invalid command · missing "
    "payload · unsafe altitude · invalid GPS range · abnormal numeric · "
    "parser exceptions · invalid source system · (fuzz) illegal state "
    "transition. \n\n"
    "**Telemetry schema rules:** invalid header · invalid command · "
    "invalid GPS range · unsafe altitude (state-aware) · (fuzz) abnormal "
    "velocity · GPS loss during nav · low/critical battery · "
    "takeoff while disarmed · (fuzz) illegal state transition."
)

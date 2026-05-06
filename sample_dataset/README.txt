# UAV Interview Dataset

This folder contains three CSV files for a 2-hour Research Engineer hands-on assignment.

Files:
1. telemetry_real_extract.csv
   - PX4/ArduPilot/MAVLink-inspired telemetry extract.
   - Contains normal flight rows, warnings, and labelled anomaly examples.

2. mavlink_command_samples.csv
   - MAVLink-like command and position messages.
   - Includes accepted, rejected, warning, and unsafe samples.

3. state_transition_rules.csv
   - Simple finite-state transition rules for UAV command/state reasoning.

Candidate task:
Build a small dashboard/platform to upload these CSV files, scan for anomalies, classify severity,
show findings, and export a report.

Note:
This is a curated educational dataset inspired by open-source UAV concepts. It is not operational drone data.

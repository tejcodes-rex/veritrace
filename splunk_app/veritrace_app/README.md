# Veritrace app for Splunk

This app is the native bridge between Splunk and the Veritrace autonomous SOC
analyst. It ships:

- **A trigger alert** (`Veritrace - Brute force authentication success`) that runs
  on a schedule and, when it fires, hands the alert to Veritrace through a custom
  alert action.
- **A custom alert action** (`Send to Veritrace`) that posts the firing alert to
  the Veritrace backend, which starts an autonomous investigation over the MCP
  Server.
- **A reasoning ledger dashboard** that searches the `veritrace_ledger` and
  `veritrace_detections` indexes, so every step the agent took is visible,
  auditable and replayable inside Splunk.
- **A proposed correlation detection** (disabled by default) that Veritrace
  writes after an investigation. An analyst enables it once approved, which is
  the detection-as-code loop.

## Requirements

- Splunk Enterprise 9.x or 10.x, or Splunk Cloud Platform.
- Three indexes: `security`, `veritrace_ledger`, `veritrace_detections`.
- A running Veritrace backend reachable from Splunk (default
  `http://localhost:8400`). Set the URL on the alert action.

## Install

Copy `veritrace_app` into `$SPLUNK_HOME/etc/apps/` and restart Splunk, or install
the packaged `veritrace_app.tar.gz` from the Splunk app management screen.

## Configure the alert action

Open the trigger alert, edit the `Send to Veritrace` action, and set the
Veritrace API URL for your environment.

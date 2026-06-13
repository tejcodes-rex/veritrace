#!/usr/bin/env bash
# Package the Veritrace Splunk app into an installable tarball.
set -euo pipefail
cd "$(dirname "$0")/.."
tar -czf veritrace_app.tar.gz -C splunk_app veritrace_app
echo "Wrote veritrace_app.tar.gz"

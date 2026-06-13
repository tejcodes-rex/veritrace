#!/usr/bin/env bash
# Veritrace one-command launcher (macOS / Linux).
# Brings up Splunk, the MCP server, the agent backend and the console.
set -euo pipefail
[ -f .env ] || { cp .env.example .env; echo "Created .env from .env.example"; }
docker compose up --build

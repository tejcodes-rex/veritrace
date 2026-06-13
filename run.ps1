# Veritrace one-command launcher (Windows PowerShell).
# Brings up Splunk, the MCP server, the agent backend and the console.
$ErrorActionPreference = "Stop"
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example"
}
docker compose up --build

# Package the Veritrace Splunk app into an installable tarball.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
tar -czf veritrace_app.tar.gz -C splunk_app veritrace_app
Write-Host "Wrote veritrace_app.tar.gz"

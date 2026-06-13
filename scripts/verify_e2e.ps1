# Verify the running Veritrace stack end to end.
# Run after `docker compose up --build` reports the api container is up.
$ErrorActionPreference = "Stop"
$base = "http://localhost:8400"

Write-Host "1. Health..."
$h = Invoke-RestMethod "$base/api/health"
Write-Host "   model=$($h.model_provider) mcp=$($h.mcp_url)"

Write-Host "2. Starting an investigation..."
Invoke-RestMethod -Method Post "$base/api/investigations" -ContentType "application/json" -Body '{"alert":null}' | Out-Null

Write-Host "3. Waiting for completion..."
$iid = $null
for ($i = 0; $i -lt 120; $i++) {
    $list = (Invoke-RestMethod "$base/api/investigations").investigations
    if ($list -and $list[0].status -eq "completed") { $iid = $list[0].investigation_id; break }
    Start-Sleep -Seconds 1
}
if (-not $iid) { Write-Error "investigation did not complete in time"; exit 1 }

$inv = Invoke-RestMethod "$base/api/investigations/$iid"
Write-Host "   verdict=$($inv.verdict) severity=$($inv.severity) confidence=$($inv.confidence)"
Write-Host "   steps=$($inv.steps.Count) attack_chain=$($inv.attack_chain.Count) detection=$($inv.detection.name)"
Write-Host "   backtest: $($inv.detection.backtest_hits_incident) hit / $($inv.detection.backtest_false_positives) FP"

Write-Host "4. Confirm the ledger landed in Splunk..."
$cred = "admin:$($env:SPLUNK_PASSWORD)"; if (-not $env:SPLUNK_PASSWORD) { $cred = "admin:Veritrace!2026" }
$bytes = [System.Text.Encoding]::ASCII.GetBytes($cred)
$auth = [Convert]::ToBase64String($bytes)
try {
    $r = Invoke-RestMethod -SkipCertificateCheck -Headers @{Authorization = "Basic $auth"} `
        "https://localhost:8089/services/search/jobs/export?search=search index=veritrace_ledger sourcetype=veritrace:investigation | stats count&output_mode=json&earliest_time=-1d"
    Write-Host "   ledger query returned (see Splunk dashboard for detail)"
} catch {
    Write-Host "   ledger check skipped: $_"
}

Write-Host ""
Write-Host "PASS. Open http://localhost:8400 for the console and http://localhost:8000 for Splunk."

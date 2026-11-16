# simulate.ps1 - writes simulated Cowrie attack events into the shared log volume.
param([int]$Events = 3000, [double]$Hours = 24, [switch]$Live)
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Test-Path (Join-Path $root '.env'))) { Write-Host 'Run start.bat first (it creates .env and starts the stack).' -ForegroundColor Red; exit 1 }

if ($Live) {
    Write-Host 'Live simulation running - open the Kibana dashboard. Press Ctrl+C to stop.' -ForegroundColor Cyan
    docker compose --profile tools run --rm tools python simulate_attacks.py --live --rate 4
} else {
    docker compose --profile tools run --rm tools python simulate_attacks.py --events $Events --hours $Hours
    if ($LASTEXITCODE -eq 0) {
        Write-Host ''
        Write-Host 'Done. Filebeat -> Logstash -> Elasticsearch takes ~10-30 seconds. Refresh the Kibana dashboard (time range: Last 24 hours).' -ForegroundColor Green
    }
}
exit $LASTEXITCODE

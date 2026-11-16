# report.ps1 - generate the threat-intelligence report now and open it.
param([double]$Hours = 24, [switch]$ExcludeSimulated, [switch]$NoOpen)
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Test-Path (Join-Path $root '.env'))) { Write-Host 'Run start.bat first.' -ForegroundColor Red; exit 1 }
$extra = @()
if ($ExcludeSimulated) { $extra += '--exclude-simulated' }

docker compose --profile tools run --rm tools python generate_report.py --hours $Hours --out /reports @extra
if ($LASTEXITCODE -ne 0) { Write-Host 'Report generation failed - is the stack running (status.bat) and does it contain data (simulate.bat)?' -ForegroundColor Red; exit 1 }

$latest = Join-Path $root 'reports\latest.html'
Write-Host ''
Write-Host "Reports are in: $(Join-Path $root 'reports')" -ForegroundColor Green
if ((-not $NoOpen) -and (Test-Path $latest)) { Start-Process $latest }
exit 0

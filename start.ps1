# start.ps1 - one-command launcher for the Threat Intelligence Dashboard (Windows).
param([switch]$NoBrowser)
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Fail([string]$msg) {
    Write-Host ''
    Write-Host "ERROR: $msg" -ForegroundColor Red
    exit 1
}
function Test-Cmd([string]$cmdline) {
    & cmd.exe /c "$cmdline >nul 2>&1"
    return ($LASTEXITCODE -eq 0)
}

Write-Host '=== Threat Intelligence Dashboard ===' -ForegroundColor Cyan

# ---- 1. prerequisites -------------------------------------------------------
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Fail ("Docker was not found.`nInstall Docker Desktop (https://www.docker.com/products/docker-desktop/), reboot, start it, then run start.bat again.`nSee HOW_TO_RUN.txt section 2.")
}
if (-not (Test-Cmd 'docker info')) {
    Fail ("Docker is installed but its engine is not running.`nStart 'Docker Desktop', wait until it says 'Engine running', then run start.bat again.")
}
if (-not (Test-Cmd 'docker compose version')) {
    Fail ("'docker compose' (v2) is not available. Update Docker Desktop to a current version.")
}
try {
    $ramGb = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
    if ($ramGb -lt 8) { Write-Host "WARNING: only $ramGb GB RAM detected. The ELK stack needs ~5 GB; 8 GB+ recommended (see HOW_TO_RUN.txt, Troubleshooting)." -ForegroundColor Yellow }
} catch { }
try {
    $listeners = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() | ForEach-Object { $_.Port }
    foreach ($p in 2222, 2223, 5601, 9200) {
        if ($listeners -contains $p) { Write-Host "WARNING: TCP port $p is already in use on this PC - change it in .env (COWRIE_*_PORT) or stop the other program." -ForegroundColor Yellow }
    }
} catch { }

# ---- 2. configuration -------------------------------------------------------
& "$PSScriptRoot\setup.ps1"
if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) { Fail 'setup failed' }
if (-not (Test-Path (Join-Path $root 'reports'))) { New-Item -ItemType Directory -Path (Join-Path $root 'reports') | Out-Null }

# ---- 3. build + start -------------------------------------------------------
Write-Host '[start] Pulling images and starting containers (first run downloads several GB, please wait)...' -ForegroundColor Cyan
docker compose up -d --build
if ($LASTEXITCODE -ne 0) {
    Fail ("docker compose failed (see messages above). Common causes: no internet access to docker.elastic.co / Docker Hub, or not enough memory given to Docker Desktop.")
}

# ---- 4. wait for Kibana -----------------------------------------------------
Write-Host '[start] Waiting for Kibana (this can take 2-4 minutes on first start)...'
$ready = $false
$deadline = (Get-Date).AddMinutes(12)
while ((Get-Date) -lt $deadline) {
    try {
        $r = Invoke-WebRequest -Uri 'http://localhost:5601/api/status' -UseBasicParsing -TimeoutSec 5
        if ($r.Content -match '"level":"available"') { $ready = $true; break }
    } catch { }
    Start-Sleep -Seconds 5
    Write-Host '.' -NoNewline
}
Write-Host ''
if (-not $ready) {
    Write-Host 'Kibana did not become ready in 12 minutes. Run status.bat and logs.bat to investigate (HOW_TO_RUN.txt, Troubleshooting).' -ForegroundColor Yellow
    exit 1
}

# ---- 5. dashboard import status ---------------------------------------------
$initDeadline = (Get-Date).AddMinutes(3)
$initState = ''
while ((Get-Date) -lt $initDeadline) {
    $initState = (docker inspect -f '{{.State.Status}}:{{.State.ExitCode}}' ti-kibana-init 2>$null)
    if ($initState -like 'exited:*') { break }
    Start-Sleep -Seconds 3
}
if ($initState -eq 'exited:0') { Write-Host '[start] Dashboard imported: "Threat Intelligence - SOC Overview"' -ForegroundColor Green }
else { Write-Host "[start] Dashboard import state: $initState  (run: docker compose logs kibana-init)" -ForegroundColor Yellow }

$elasticPw = ''
foreach ($line in [System.IO.File]::ReadAllLines((Join-Path $root '.env'))) {
    if ($line -match '^ELASTIC_PASSWORD=(.+)$') { $elasticPw = $Matches[1].Trim() }
}
Write-Host ''
Write-Host '=============================================================' -ForegroundColor Green
Write-Host ' Kibana    : http://localhost:5601' -ForegroundColor Green
Write-Host ' Login     : elastic / (password is in the .env file: ELASTIC_PASSWORD)' -ForegroundColor Green
Write-Host ' Dashboard : Analytics > Dashboards > "Threat Intelligence - SOC Overview"' -ForegroundColor Green
Write-Host ' Honeypot  : SSH localhost:2222   Telnet localhost:2223' -ForegroundColor Green
Write-Host ' Next      : run simulate.bat to load demo attacks, then report.bat' -ForegroundColor Green
Write-Host '=============================================================' -ForegroundColor Green
if (-not $NoBrowser) { Start-Process 'http://localhost:5601' }
exit 0

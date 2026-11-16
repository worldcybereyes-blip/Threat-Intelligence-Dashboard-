# status.ps1 - quick health check: containers, indexed event count, newest event.
# Compatible with Windows PowerShell 5.1.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host '=== Containers ===' -ForegroundColor Cyan
docker compose ps -a

$envPath = Join-Path $root '.env'
if (-not (Test-Path $envPath)) { Write-Host 'No .env yet - run start.bat first.' -ForegroundColor Yellow; exit 0 }

$pw = ''
foreach ($line in [System.IO.File]::ReadAllLines($envPath)) {
    if ($line -match '^ELASTIC_PASSWORD=(.+)$') { $pw = $Matches[1].Trim() }
}
if (-not $pw) { Write-Host 'ELASTIC_PASSWORD is empty in .env' -ForegroundColor Yellow; exit 0 }

$token = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("elastic:$pw"))
$headers = @{ Authorization = "Basic $token" }

Write-Host ''
Write-Host '=== Elasticsearch ===' -ForegroundColor Cyan
try {
    $health = Invoke-RestMethod -Uri 'http://localhost:9200/_cluster/health' -Headers $headers -TimeoutSec 10
    Write-Host ("Cluster status : " + $health.status)
    $count = Invoke-RestMethod -Uri 'http://localhost:9200/honeypot-cowrie-*/_count' -Headers $headers -TimeoutSec 10
    Write-Host ("Indexed events : " + $count.count)
    $body = '{"size":1,"sort":[{"@timestamp":"desc"}],"_source":["@timestamp","source.ip","event.action"]}'
    $latest = Invoke-RestMethod -Uri 'http://localhost:9200/honeypot-cowrie-*/_search' -Headers $headers -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 10
    if ($latest.hits.hits.Count -gt 0) {
        $src = $latest.hits.hits[0]._source
        Write-Host ("Newest event   : " + $src.'@timestamp' + "  " + $src.event.action)
    } else {
        Write-Host 'Newest event   : (none yet - run simulate.bat or wait for attackers)'
    }
} catch {
    Write-Host ("Elasticsearch is not reachable yet: " + $_.Exception.Message) -ForegroundColor Yellow
    Write-Host 'If the stack was just started, wait 1-2 minutes and run status.bat again.'
}
exit 0

# setup.ps1 - creates .env with cryptographically random secrets and renders the
# ElastAlert2 config. Idempotent: existing values are never overwritten.
# Compatible with Windows PowerShell 5.1 (built into Windows 10/11 and Server 2016+).
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function New-Secret([int]$Length) {
    $chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    $bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $bytes) { [void]$sb.Append($chars[$b % $chars.Length]) }
    return $sb.ToString()
}

# name -> length (Kibana encryption keys must be >= 32 characters)
$secrets = @{
    'ELASTIC_PASSWORD'         = 24
    'KIBANA_SYSTEM_PASSWORD'   = 24
    'LOGSTASH_WRITER_PASSWORD' = 24
    'TI_READER_PASSWORD'       = 24
    'ELASTALERT_PASSWORD'      = 24
    'KIBANA_SECURITY_KEY'      = 40
    'KIBANA_ENCRYPTION_KEY'    = 40
    'KIBANA_REPORTING_KEY'     = 40
}

$envPath = Join-Path $root '.env'
$examplePath = Join-Path $root '.env.example'
if (Test-Path $envPath) { $source = $envPath; $created = $false } else { $source = $examplePath; $created = $true }

$lines = [System.IO.File]::ReadAllLines($source)
$out = New-Object System.Collections.Generic.List[string]
$filled = 0
foreach ($line in $lines) {
    $newLine = $line
    if ($line -match '^([A-Z_]+)=(.*)$') {
        $name = $Matches[1]
        $value = $Matches[2].Trim()
        if ($secrets.ContainsKey($name) -and $value -eq '') {
            $newLine = $name + '=' + (New-Secret $secrets[$name])
            $filled++
        }
    }
    $out.Add($newLine)
}
if ($created -or $filled -gt 0) {
    [System.IO.File]::WriteAllText($envPath, (($out -join "`n") + "`n"), $utf8NoBom)
    Write-Host "[setup] .env written ($filled secrets generated). Keep this file private." -ForegroundColor Green
} else {
    Write-Host "[setup] .env already complete - left unchanged."
}

# Read ELASTALERT_PASSWORD back from .env and render the ElastAlert2 config.
$alertPw = $null
foreach ($line in [System.IO.File]::ReadAllLines($envPath)) {
    if ($line -match '^ELASTALERT_PASSWORD=(.+)$') { $alertPw = $Matches[1].Trim() }
}
if (-not $alertPw) { throw 'ELASTALERT_PASSWORD missing from .env' }
$template = [System.IO.File]::ReadAllText((Join-Path $root 'elastalert\config.yaml.template'))
$rendered = $template.Replace('__ES_PASSWORD__', $alertPw).Replace("`r`n", "`n")
[System.IO.File]::WriteAllText((Join-Path $root 'elastalert\config.yaml'), $rendered, $utf8NoBom)
Write-Host "[setup] elastalert\config.yaml rendered."

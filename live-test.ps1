# live-test.ps1 - proves the honeypot captures a REAL connection.
# Opens a TCP connection to the Cowrie SSH port, reads the banner and sends a client banner.
# (Interactive login test: run  ssh -p 2222 root@localhost  and type any password.)
param([int]$Port = 2222)
$ErrorActionPreference = 'Continue'
try {
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect('127.0.0.1', $Port)
    $stream = $client.GetStream()
    $stream.ReadTimeout = 5000
    $buf = New-Object byte[] 256
    $n = $stream.Read($buf, 0, 256)
    $banner = [System.Text.Encoding]::ASCII.GetString($buf, 0, $n).Trim()
    Write-Host "Honeypot banner received: $banner" -ForegroundColor Green
    $hello = [System.Text.Encoding]::ASCII.GetBytes("SSH-2.0-TI-LiveTest_1.0`r`n")
    $stream.Write($hello, 0, $hello.Length)
    Start-Sleep -Seconds 1
    $client.Close()
    Write-Host 'Sent a client banner and closed. In ~15 s look in Kibana Discover for event.action : "cowrie.client.version".'
    Write-Host 'NOTE: on Docker Desktop, connections from this PC appear with a private Docker gateway IP (172.x / 192.168.65.x),'
    Write-Host '      so GeoIP/threat-intel is skipped (ti.verdict = not_applicable). Internet attackers show their real public IP.'
} catch {
    Write-Host "Could not connect to localhost:$Port - is the stack running (start.bat / status.bat)?  $_" -ForegroundColor Red
    exit 1
}

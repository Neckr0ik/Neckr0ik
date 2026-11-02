# Health check (lo ejecuta una tarea programada cada 5 min). Repara lo que pueda, en orden:
#  1) Internet (si falla: reconecta la Wi-Fi conocida)
#  2) Docker Desktop (si no responde: lo arranca)
#  3) Graphiti local /health (si falla: docker compose up -d, luego restart)
#  4) URL publica (opcional, PUBLIC_HEALTH_URL en .env) via tunel (si falla: reinicia cloudflared)
#  5) Si todo OK, avisa a un monitor externo (opcional, HEALTHCHECKS_PING_URL en .env)
#     -> si el PC se apaga o pierde internet, ese servicio te manda un email.
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$log = Join-Path $PSScriptRoot 'healthcheck.log'
function Log($m) { "$(Get-Date -Format s)  $m" | Add-Content $log }
if ((Test-Path $log) -and (Get-Item $log).Length -gt 1MB) { Move-Item $log "$log.old" -Force }

$envMap = @{}
if (Test-Path '.env') {
    Get-Content '.env' | Where-Object { $_ -match '^\s*[^#].*=' } | ForEach-Object { $k, $v = $_ -split '=', 2; $envMap[$k.Trim()] = $v.Trim() }
}
function Http-Ok($url) { try { return (Invoke-WebRequest -UseBasicParsing $url -TimeoutSec 10).StatusCode -lt 500 } catch { return $false } }
$profileArgs = @(); if ($envMap['CLOUDFLARE_TUNNEL_TOKEN']) { $profileArgs = @('--profile', 'tunnel') }

# 1) Internet
if (-not (Test-Connection 1.1.1.1 -Count 2 -Quiet)) {
    Log "SIN INTERNET -> reconectando Wi-Fi"
    $ssid = (netsh wlan show profiles | Select-String ':\s+(.+)$' | Select-Object -First 1).Matches.Groups[1].Value
    netsh wlan disconnect | Out-Null; Start-Sleep 3
    if ($ssid) { netsh wlan connect name="$ssid" | Out-Null }
    Start-Sleep 20
    if (-not (Test-Connection 1.1.1.1 -Count 2 -Quiet)) {
        Log "Sigue sin internet -> reiniciando adaptador de red"
        Get-NetAdapter -Physical | Where-Object { $_.Status -ne 'Disabled' } | Restart-NetAdapter -Confirm:$false
        Start-Sleep 30
    }
}

# 2) Docker
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Log "Docker no responde -> iniciando Docker Desktop"
    Start-Process "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe"
    for ($i = 0; $i -lt 24; $i++) { Start-Sleep 5; docker info *> $null; if ($LASTEXITCODE -eq 0) { break } }
}

# 3) Graphiti local
if (-not (Http-Ok 'http://127.0.0.1:8000/health')) {
    Log "Graphiti caido -> docker compose up -d"
    docker compose @profileArgs up -d *> $null
    Start-Sleep 30
    if (-not (Http-Ok 'http://127.0.0.1:8000/health')) {
        Log "Sigue caido -> restart"
        docker compose @profileArgs restart *> $null
        Start-Sleep 30
    }
}
$localOk = Http-Ok 'http://127.0.0.1:8000/health'

# 4) Publico (por el tunel)
$publicOk = $true
if ($envMap['PUBLIC_HEALTH_URL']) {
    $publicOk = Http-Ok $envMap['PUBLIC_HEALTH_URL']
    if (-not $publicOk) {
        Log "URL publica no responde -> reiniciando cloudflared"
        docker compose @profileArgs restart cloudflared *> $null
        Start-Sleep 20
        $publicOk = Http-Ok $envMap['PUBLIC_HEALTH_URL']
    }
}

# 5) Monitor externo
if ($localOk -and $publicOk) {
    if ($envMap['HEALTHCHECKS_PING_URL']) { try { Invoke-WebRequest -UseBasicParsing $envMap['HEALTHCHECKS_PING_URL'] -TimeoutSec 10 | Out-Null } catch {} }
} else {
    Log "FALLO: local=$localOk publico=$publicOk"
    if ($envMap['HEALTHCHECKS_PING_URL']) { try { Invoke-WebRequest -UseBasicParsing ($envMap['HEALTHCHECKS_PING_URL'] + '/fail') -TimeoutSec 10 | Out-Null } catch {} }
}

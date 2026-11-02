# Paso 1: crea .env, arranca Graphiti (+ tunel si hay token) y muestra la URL del connector.
# Uso: abre PowerShell en esta carpeta y ejecuta:  powershell -ExecutionPolicy Bypass -File .\windows\1-instalar-graphiti.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "Docker no esta instalado. Instalando Docker Desktop con winget..." -ForegroundColor Yellow
    winget install -e --id Docker.DockerDesktop --accept-package-agreements --accept-source-agreements
    Write-Host "Reinicia Windows, abre Docker Desktop una vez (acepta terminos) y vuelve a ejecutar este script." -ForegroundColor Yellow
    exit 1
}

$envFile = Join-Path $root '.env'
if (-not (Test-Path $envFile)) {
    $content = Get-Content (Join-Path $root '.env.example') -Raw
    $sb = New-Object byte[] 24
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($sb)
    $secret = -join ($sb | ForEach-Object { $_.ToString('x2') })   # 48 hex = 192 bits, CSPRNG
    $anth = Read-Host "Pega tu ANTHROPIC_API_KEY (console.anthropic.com)"
    $goog = Read-Host "Pega tu GOOGLE_API_KEY (aistudio.google.com)"
    $mode = Read-Host "Salida publica: escribe 'tailscale' (recomendado) o 'tunnel' (Cloudflare)"
    if ($mode -ne 'tunnel') { $mode = 'tailscale' }
    $tsk = ''; $tok = ''
    if ($mode -eq 'tailscale') { $tsk = Read-Host "Pega tu TS_AUTHKEY (login.tailscale.com -> Settings -> Keys)" }
    else { $tok = Read-Host "Pega tu CLOUDFLARE_TUNNEL_TOKEN" }
    $content = $content -replace '(?m)^ANTHROPIC_API_KEY=.*', "ANTHROPIC_API_KEY=$anth"
    $content = $content -replace '(?m)^GOOGLE_API_KEY=.*', "GOOGLE_API_KEY=$goog"
    $content = $content -replace '(?m)^MCP_SECRET_PATH=.*', "MCP_SECRET_PATH=$secret"
    $content = $content -replace '(?m)^CLOUDFLARE_TUNNEL_TOKEN=.*', "CLOUDFLARE_TUNNEL_TOKEN=$tok"
    $content = $content -replace '(?m)^TS_AUTHKEY=.*', "TS_AUTHKEY=$tsk"
    $content = $content -replace '(?m)^EXPOSE_MODE=.*', "EXPOSE_MODE=$mode"
    Set-Content -Path $envFile -Value $content -Encoding ascii
    Write-Host ".env creado." -ForegroundColor Green
}

# Asegura secretos del visor (tambien para .env creados con versiones anteriores)
function New-Hex([int]$bytes) {
    $b = New-Object byte[] $bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    return -join ($b | ForEach-Object { $_.ToString('x2') })
}
$raw = Get-Content $envFile -Raw
foreach ($pair in @(@('NEXTAUTH_SECRET', 32), @('ENCRYPTION_KEY', 32))) {
    $name = $pair[0]
    if ($raw -notmatch "(?m)^$name=\S+") {
        $val = New-Hex $pair[1]
        if ($raw -match "(?m)^$name=") { $raw = $raw -replace "(?m)^$name=.*", "$name=$val" }
        else { $raw = $raw.TrimEnd() + "`r`n$name=$val`r`n" }
        Write-Host "$name generado." -ForegroundColor Green
    }
}
Set-Content -Path $envFile -Value $raw -Encoding ascii

$envMap = @{}
Get-Content $envFile | Where-Object { $_ -match '^\s*[^#].*=' } | ForEach-Object {
    $k, $v = $_ -split '=', 2; $envMap[$k.Trim()] = $v.Trim()
}

$profileArgs = @()
if ($envMap['EXPOSE_MODE'] -eq 'tunnel' -and $envMap['CLOUDFLARE_TUNNEL_TOKEN']) { $profileArgs = @('--profile', 'tunnel') }
elseif ($envMap['EXPOSE_MODE'] -eq 'tailscale' -and $envMap['TS_AUTHKEY']) { $profileArgs = @('--profile', 'tailscale') }
docker compose @profileArgs up -d

Write-Host "Esperando a Graphiti..."
for ($i = 0; $i -lt 30; $i++) {
    try { if ((Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/health -TimeoutSec 3).StatusCode -eq 200) { break } } catch {}
    Start-Sleep 3
}

Write-Host ""
Write-Host "Graphiti local:   http://127.0.0.1:8000/mcp" -ForegroundColor Green
Write-Host "Ver el grafo:     http://127.0.0.1:3000" -ForegroundColor Green
$publicHost = 'graphiti.TU-DOMINIO.com'
if ($envMap['EXPOSE_MODE'] -eq 'tailscale') {
    Start-Sleep 10
    $dns = ''
    try { $dns = (docker compose exec -T tailscale tailscale status --json | ConvertFrom-Json).Self.DNSName.TrimEnd('.') } catch {}
    if ($dns) { $publicHost = $dns } else { $publicHost = 'graphiti.TU-TAILNET.ts.net' }
}
Write-Host "URL para el connector de claude.ai:" -ForegroundColor Cyan
Write-Host ("   https://" + $publicHost + "/" + $envMap['MCP_SECRET_PATH'] + "/mcp") -ForegroundColor Cyan
Write-Host "Guardala como una contrasena." -ForegroundColor Yellow

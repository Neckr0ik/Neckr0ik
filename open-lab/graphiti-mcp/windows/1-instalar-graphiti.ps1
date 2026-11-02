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
    $secret = -join ((48..57) + (97..122) | Get-Random -Count 40 | ForEach-Object { [char]$_ })
    $anth = Read-Host "Pega tu ANTHROPIC_API_KEY (console.anthropic.com)"
    $goog = Read-Host "Pega tu GOOGLE_API_KEY (aistudio.google.com)"
    $tok  = Read-Host "Pega tu CLOUDFLARE_TUNNEL_TOKEN (Enter para omitir por ahora)"
    $content = $content -replace '(?m)^ANTHROPIC_API_KEY=.*', "ANTHROPIC_API_KEY=$anth"
    $content = $content -replace '(?m)^GOOGLE_API_KEY=.*', "GOOGLE_API_KEY=$goog"
    $content = $content -replace '(?m)^MCP_SECRET_PATH=.*', "MCP_SECRET_PATH=$secret"
    $content = $content -replace '(?m)^CLOUDFLARE_TUNNEL_TOKEN=.*', "CLOUDFLARE_TUNNEL_TOKEN=$tok"
    Set-Content -Path $envFile -Value $content -Encoding ascii
    Write-Host ".env creado." -ForegroundColor Green
}

$envMap = @{}
Get-Content $envFile | Where-Object { $_ -match '^\s*[^#].*=' } | ForEach-Object {
    $k, $v = $_ -split '=', 2; $envMap[$k.Trim()] = $v.Trim()
}

if ($envMap['CLOUDFLARE_TUNNEL_TOKEN']) {
    docker compose --profile tunnel up -d
} else {
    docker compose up -d
}

Write-Host "Esperando a Graphiti..."
for ($i = 0; $i -lt 30; $i++) {
    try { if ((Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/health -TimeoutSec 3).StatusCode -eq 200) { break } } catch {}
    Start-Sleep 3
}

Write-Host ""
Write-Host "Graphiti local:   http://127.0.0.1:8000/mcp" -ForegroundColor Green
Write-Host "Ver el grafo:     http://127.0.0.1:3000" -ForegroundColor Green
Write-Host "URL para el connector de claude.ai (cambia el dominio por el tuyo):" -ForegroundColor Cyan
Write-Host ("   https://graphiti.TU-DOMINIO.com/" + $envMap['MCP_SECRET_PATH'] + "/mcp") -ForegroundColor Cyan
Write-Host "Guardala como una contrasena." -ForegroundColor Yellow

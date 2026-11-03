# Instala y publica Firecrawl MCP: Firecrawl self-hosted + MCP HTTP + Caddy + Tailscale Funnel.
# Se puede volver a ejecutar sin riesgo: solo crea lo que falta y pide solo las keys que faltan.
#
# Uso (PowerShell en open-lab\firecrawl-mcp):
#   powershell -ExecutionPolicy Bypass -File .\windows\1-instalar-firecrawl.ps1
# Opciones:
#   -NuevaKey        vuelve a pedir TS_AUTHKEY aunque ya exista (p. ej. si caduco)
#   -NuevoSecreto    genera una ruta secreta nueva (la URL anterior deja de funcionar)
#   -FirecrawlDir    carpeta del Firecrawl self-hosted (por defecto: $HOME\firecrawl)
param(
    [switch]$NuevaKey,
    [switch]$NuevoSecreto,
    [string]$FirecrawlDir = (Join-Path $HOME 'firecrawl')
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Write-Step([string]$msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }

# En PowerShell 5.1, con ErrorActionPreference=Stop, cualquier linea que un programa (docker, git,
# claude) escriba en stderr se vuelve un error que corta el script, aunque el programa termine bien.
# Los programas externos se ejecutan con esta funcion y se revisa $LASTEXITCODE.
function Invoke-Native([scriptblock]$cmd) {
    $ErrorActionPreference = 'Continue'
    & $cmd
}

function New-Hex([int]$bytes) {
    $b = New-Object byte[] $bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    return -join ($b | ForEach-Object { $_.ToString('x2') })   # CSPRNG
}

function Read-Secret([string]$prompt) {
    # Lo que escribes no se muestra en pantalla ni queda en el historial de la consola.
    $sec = Read-Host $prompt -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try { return ([Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)).Trim() }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Get-EnvValue([string]$raw, [string]$name) {
    if ($raw -match "(?m)^$name=(.*)$") { return $Matches[1].Trim() } else { return '' }
}

function Set-EnvValue([string]$raw, [string]$name, [string]$value) {
    if ($raw -match "(?m)^$name=") {
        # Se reemplaza con un MatchEvaluator y no con un texto: un '$' dentro de la key se
        # interpretaria como referencia de grupo ($1, $&) y corromperia el valor.
        $line = "$name=$value"
        return [regex]::Replace($raw, "(?m)^$name=.*$", { param($m) $line }.GetNewClosure())
    }
    return $raw.TrimEnd() + "`r`n$name=$value`r`n"
}

function Wait-Http([string]$url, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        try { if ((Invoke-WebRequest -UseBasicParsing $url -TimeoutSec 5).StatusCode -eq 200) { return $true } } catch {}
        Start-Sleep 3
    }
    return $false
}

# --- 1. Docker ----------------------------------------------------------------
Write-Step 'Docker'
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host 'Docker no esta instalado. Instalando Docker Desktop con winget...' -ForegroundColor Yellow
    winget install -e --id Docker.DockerDesktop --accept-package-agreements --accept-source-agreements
    Write-Host 'Reinicia Windows, abre Docker Desktop una vez (acepta terminos) y vuelve a ejecutar este script.' -ForegroundColor Yellow
    exit 1
}
Invoke-Native { docker info --format '{{.ServerVersion}}' *> $null }
if ($LASTEXITCODE -ne 0) {
    Write-Host 'Docker Desktop no esta corriendo. Abrelo, espera a que diga "Engine running" y vuelve a ejecutar.' -ForegroundColor Yellow
    exit 1
}
Write-Host 'OK' -ForegroundColor Green

# --- 2. Firecrawl self-hosted ---------------------------------------------------
Write-Step "Firecrawl self-hosted en $FirecrawlDir"
if (-not (Test-Path (Join-Path $FirecrawlDir 'docker-compose.yaml'))) {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        winget install -e --id Git.Git --accept-package-agreements --accept-source-agreements
        $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
    }
    Invoke-Native { git clone --depth 1 https://github.com/firecrawl/firecrawl.git $FirecrawlDir }
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo clonar Firecrawl.' }
}
$fcEnv = Join-Path $FirecrawlDir '.env'
if (-not (Test-Path $fcEnv)) {
    Copy-Item (Join-Path $root 'firecrawl\firecrawl.env') $fcEnv
    Write-Host '.env de Firecrawl creado.' -ForegroundColor Green
}
# El override siempre se actualiza desde el repo: es el que cierra el puerto 3002 a la red local.
Copy-Item (Join-Path $root 'firecrawl\docker-compose.override.yaml') (Join-Path $FirecrawlDir 'docker-compose.override.yaml') -Force

Push-Location $FirecrawlDir
try {
    Write-Host 'docker compose up -d --build (la primera vez tarda 10-20 min)...'
    # Firecrawl avisa de decenas de variables opcionales vacias (OPENAI_API_KEY, SUPABASE_*...): se ocultan.
    Invoke-Native { docker compose up -d --build 2>&1 | Where-Object { "$_" -notmatch 'level=warning' } | ForEach-Object { "$_" } }
    if ($LASTEXITCODE -ne 0) { throw 'Firecrawl no arranco. Revisa: docker compose logs api' }
    $fcProject = (Invoke-Native { docker compose config --format json 2>$null } | Out-String | ConvertFrom-Json).name
} finally { Pop-Location }
if (-not (Wait-Http 'http://127.0.0.1:3002/' 180)) { throw 'La API de Firecrawl no responde en 127.0.0.1:3002.' }
Write-Host 'Firecrawl API OK en http://127.0.0.1:3002 (solo este PC)' -ForegroundColor Green

# --- 3. .env del MCP: ruta secreta y key de Tailscale -----------------------------
Write-Step 'Keys (.env)'
$envFile = Join-Path $root '.env'
if (-not (Test-Path $envFile)) { Copy-Item (Join-Path $root '.env.example') $envFile }
$raw = Get-Content $envFile -Raw
# Quita marcas de instrucciones que hayan quedado en el .env
$raw = [regex]::Replace($raw, '(?m)^# TODO\(human\).*\r?\n', '')

$secret = Get-EnvValue $raw 'MCP_SECRET_PATH'
if ($NuevoSecreto -or -not $secret -or $secret -like 'cambia-esto*') {
    $raw = Set-EnvValue $raw 'MCP_SECRET_PATH' (New-Hex 24)   # 48 hex = 192 bits
    Write-Host 'MCP_SECRET_PATH generada.' -ForegroundColor Green
}

$tsk = Get-EnvValue $raw 'TS_AUTHKEY'
if ($NuevaKey -or -not $tsk) {
    Write-Host 'Necesito una auth key de Tailscale: login.tailscale.com -> Settings -> Keys -> Generate auth key'
    Write-Host '  Reusable: SI   Ephemeral: NO   Tags: ninguno (con tag, la regla de Funnel autogroup:member no lo cubre)' -ForegroundColor Yellow
    do {
        $tsk = Read-Secret 'Pega tu TS_AUTHKEY (no se mostrara)'
        $ok = $tsk -match '^tskey-(auth|client)-\S+$'
        if (-not $ok) { Write-Host 'Eso no parece una key de Tailscale (empieza con tskey-auth-). Intenta de nuevo.' -ForegroundColor Red }
    } until ($ok)
    $raw = Set-EnvValue $raw 'TS_AUTHKEY' $tsk
    Write-Host 'TS_AUTHKEY guardada.' -ForegroundColor Green
}
if (-not (Get-EnvValue $raw 'TS_HOSTNAME')) { $raw = Set-EnvValue $raw 'TS_HOSTNAME' 'firecrawl' }
if ($fcProject -and $fcProject -ne 'firecrawl') { $raw = Set-EnvValue $raw 'FIRECRAWL_NETWORK' "${fcProject}_backend" }
Set-Content -Path $envFile -Value $raw.TrimEnd() -Encoding ascii

$envMap = @{}
Get-Content $envFile | Where-Object { $_ -match '^\s*[^#].*=' } | ForEach-Object {
    $k, $v = $_ -split '=', 2; $envMap[$k.Trim()] = $v.Trim()
}

# --- 4. MCP + Caddy + Tailscale ------------------------------------------------------
Write-Step 'firecrawl-mcp + Caddy + Tailscale'
Invoke-Native { docker compose up -d --build 2>&1 | ForEach-Object { "$_" } }
if ($LASTEXITCODE -ne 0) { throw 'docker compose up fallo. Revisa: docker compose logs' }
if (-not (Wait-Http 'http://127.0.0.1:3010/health' 90)) { throw 'firecrawl-mcp no responde en 127.0.0.1:3010.' }
Write-Host 'MCP local OK: http://127.0.0.1:3010/mcp' -ForegroundColor Green

# --- 5. Claude Code en este PC ---------------------------------------------------
if (Get-Command claude -ErrorAction SilentlyContinue) {
    Write-Step 'Registrando el MCP en Claude Code (scope user)'
    Invoke-Native {
        claude mcp remove firecrawl -s user *> $null   # falla si no existia: no importa
        claude mcp add --scope user --transport http firecrawl http://127.0.0.1:3010/mcp
    }
}

# --- 6. URL publica -------------------------------------------------------------
Write-Step 'Tailscale Funnel'
$dns = ''
for ($i = 0; $i -lt 20 -and -not $dns; $i++) {
    try { $dns = (Invoke-Native { docker compose exec -T tailscale tailscale status --json 2>$null } | Out-String | ConvertFrom-Json).Self.DNSName.TrimEnd('.') } catch {}
    if (-not $dns) { Start-Sleep 3 }
}
if (-not $dns) {
    Write-Host 'Tailscale no se conecto. Mira: docker compose logs tailscale' -ForegroundColor Red
    Write-Host 'Si la key caduco o era Ephemeral, ejecuta de nuevo con -NuevaKey.' -ForegroundColor Yellow
    exit 1
}
$base = "https://$dns/$($envMap['MCP_SECRET_PATH'])"
Write-Host 'Comprobando la URL publica (el primer certificado HTTPS puede tardar 1-2 min)...'
if (Wait-Http "$base/health" 150) { Write-Host 'URL publica OK' -ForegroundColor Green }
else {
    Write-Host 'La URL publica todavia no responde. Revisa en login.tailscale.com/admin:' -ForegroundColor Yellow
    Write-Host '  DNS -> MagicDNS y HTTPS Certificates activados; Access controls -> nodeAttrs con "funnel".' -ForegroundColor Yellow
}

Write-Host ''
Write-Host 'URL para el connector de claude.ai (Settings -> Connectors -> Add custom connector):' -ForegroundColor Cyan
Write-Host "   $base/mcp" -ForegroundColor Cyan
Write-Host 'Pegala sin barra final. Guardala como una contrasena: quien la tenga puede usar tu Firecrawl.' -ForegroundColor Yellow

# Paso 2 (ejecutar UNA vez como Administrador): deja el PC listo para estar siempre disponible.
#  - Sin suspension/hibernacion, tapa cerrada = no hacer nada
#  - Wi-Fi: conexion automatica y sin ahorro de energia en el adaptador
#  - Windows Update sin reinicios automaticos con sesion abierta
#  - Docker Desktop al iniciar sesion
#  - Health check cada 5 minutos (y al arrancar)
#  - Autologin con Sysinternals Autologon (tu escribes la contrasena en su ventana; se guarda cifrada)
# Uso: PowerShell como Administrador ->  powershell -ExecutionPolicy Bypass -File .\windows\2-configurar-pc-servidor.ps1
$ErrorActionPreference = 'Continue'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Ejecuta este script como Administrador." -ForegroundColor Red; exit 1
}
$root = Split-Path -Parent $PSScriptRoot
$user = "$env:USERDOMAIN\$env:USERNAME"

Write-Host "[1/6] Energia: nunca suspender" -ForegroundColor Cyan
powercfg /change standby-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
powercfg /change monitor-timeout-ac 10
powercfg /hibernate off
# Tapa cerrada (portatiles) = no hacer nada, enchufado
powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0
powercfg /setactive SCHEME_CURRENT

Write-Host "[2/6] Wi-Fi: autoconexion y sin ahorro de energia" -ForegroundColor Cyan
$ssid = (netsh wlan show interfaces | Select-String '^\s+SSID\s+:\s+(.+)$' | Select-Object -First 1).Matches.Groups[1].Value
if ($ssid) {
    netsh wlan set profileparameter name="$ssid" connectionmode=auto | Out-Null
    Write-Host "   Red '$ssid' en conexion automatica."
} else { Write-Host "   No hay Wi-Fi conectada ahora (si usas cable, mejor aun)." }
Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | ForEach-Object {
    try { Disable-NetAdapterPowerManagement -Name $_.Name -NoRestart -ErrorAction Stop } catch {}
}

Write-Host "[3/6] Windows Update: sin reinicio automatico con sesion iniciada" -ForegroundColor Cyan
$wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
New-Item -Path $wu -Force | Out-Null
Set-ItemProperty -Path $wu -Name NoAutoRebootWithLoggedOnUsers -Value 1 -Type DWord

Write-Host "[4/6] Docker Desktop al iniciar sesion" -ForegroundColor Cyan
$dockerExe = "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe"
if (Test-Path $dockerExe) {
    $a = New-ScheduledTaskAction -Execute $dockerExe
    $t = New-ScheduledTaskTrigger -AtLogOn -User $user
    Register-ScheduledTask -TaskName 'Graphiti - Docker Desktop' -Action $a -Trigger $t -RunLevel Limited -User $user -Force | Out-Null
} else { Write-Host "   No encontre Docker Desktop; instalalo primero." -ForegroundColor Yellow }

Write-Host "[5/6] Health check cada 5 minutos" -ForegroundColor Cyan
$hc = Join-Path $PSScriptRoot 'healthcheck.ps1'
$a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$hc`"" -WorkingDirectory $root
$t1 = New-ScheduledTaskTrigger -AtLogOn -User $user
$t2 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 4)
Register-ScheduledTask -TaskName 'Graphiti - Health check' -Action $a -Trigger $t1,$t2 -Settings $s -RunLevel Highest -User $user -Force | Out-Null

Write-Host "[6/6] Autologin (Sysinternals Autologon)" -ForegroundColor Cyan
$tools = Join-Path $root 'windows\tools'
New-Item -ItemType Directory -Force -Path $tools | Out-Null
$zip = Join-Path $tools 'Autologon.zip'
Invoke-WebRequest -UseBasicParsing 'https://download.sysinternals.com/files/AutoLogon.zip' -OutFile $zip
Expand-Archive -Path $zip -DestinationPath $tools -Force
Write-Host "   Se abrira Autologon: escribe tu contrasena de Windows y pulsa 'Enable'." -ForegroundColor Yellow
Write-Host "   (Si tu cuenta usa PIN/Windows Hello, Autologon necesita la contrasena de la cuenta Microsoft.)" -ForegroundColor Yellow
Start-Process (Join-Path $tools 'Autologon64.exe') -ArgumentList '/accepteula' -Wait

Write-Host ""
Write-Host "Listo. Reinicia el PC para comprobar: debe entrar solo, abrir Docker y levantar Graphiti." -ForegroundColor Green
Write-Host "Registro del health check: $root\windows\healthcheck.log"

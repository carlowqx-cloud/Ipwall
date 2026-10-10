param(
    [string]$WhitelistPath = "C:\xampp\htdocs\ipwall\whitelist.txt",
    [string]$InboundWhitelistPath = "",
    [string]$StateDir = "C:\ProgramData\IPWhitelistFirewall"
)

$ErrorActionPreference = "Stop"
$WG = "IPWhitelistFirewall"
$CG = "IPWhitelistControl"
$ApplyErrorLog = Join-Path $StateDir "apply-errors.log"

function Write-ApplyError([string]$Message) {
    try {
        New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
        Add-Content -LiteralPath $ApplyErrorLog -Encoding UTF8 -Value ("[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"),$Message)
    } catch {}
}

function Is-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Is-Admin)) { throw "Se requieren permisos de Administrador/SYSTEM." }

function Normalize-WhitelistEntry([string]$Raw) {
    $value = $Raw.Trim()
    if ([string]::IsNullOrWhiteSpace($value)) { throw "Entrada vacia." }
    $parts = @($value.Split('/'))
    if ($parts.Count -gt 2) { throw "CIDR invalido: $value" }

    # IPAddress.TryParse por si solo admite IPv4 abreviadas, por eso exigimos
    # cuatro octetos decimales si la direccion no contiene ':'.
    $address = $parts[0]
    if ($address.Contains(':')) {
        if ($address.Contains('%')) { throw "IPv6 con zona no admitido: $value" }
    } elseif ($address -notmatch '^(\d{1,3}\.){3}\d{1,3}$') {
        throw "IPv4 invalida: $value"
    }
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($address, [ref]$parsed)) {
        throw "Direccion IP invalida: $value"
    }
    $ipBytes = $parsed.GetAddressBytes()
    $totalBits = $ipBytes.Length * 8
    if ($totalBits -ne 32 -and $totalBits -ne 128) { throw "IP invalida: $value" }
    $prefix = $totalBits
    if ($parts.Count -eq 2) {
        if ($parts[1] -cnotmatch '^[0-9]{1,3}$') { throw "Prefijo CIDR invalido: $value" }
        $prefix = [int]$parts[1]
        $minimum = $(if ($totalBits -eq 32) { 16 } else { 64 })
        if ($prefix -lt $minimum -or $prefix -gt $totalBits) {
            throw "Prefijo CIDR demasiado amplio/invalido: $value (IPv4 /16-/32, IPv6 /64-/128)"
        }
    }
    $networkBytes = [byte[]]$ipBytes.Clone()
    for ($j=0; $j -lt $ipBytes.Length; $j++) {
        $remain = $prefix - ($j * 8)
        if ($remain -ge 8) {
            $networkBytes[$j] = $ipBytes[$j]
        } elseif ($remain -le 0) {
            $networkBytes[$j] = 0
        } else {
            $mask = (255 -shl (8 - $remain)) -band 255
            $networkBytes[$j] = [byte]($ipBytes[$j] -band $mask)
        }
    }
    $network = [System.Net.IPAddress]::new($networkBytes)
    if ($prefix -eq $totalBits) { return $network.ToString() }
    return "$($network.ToString())/$prefix"
}

if ([string]::IsNullOrWhiteSpace($InboundWhitelistPath)) {
    $InboundWhitelistPath = Join-Path (Split-Path -Parent $WhitelistPath) 'whitelist-inbound.txt'
}
foreach ($path in @($WhitelistPath, $InboundWhitelistPath)) {
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -ItemType File -Path $path -Force | Out-Null
    }
}

# Validar AMBAS listas completas antes de tocar las reglas de Windows.
# Se aceptan lineas vacias y comentarios que empiecen por # o ; para mantener
# compatibilidad con whitelists editadas a mano.
function Read-IPWallWhitelist([string]$Path) {
    $result = @()
    $lineNo = 0
    foreach ($rawLine in @(Get-Content -LiteralPath $Path -ErrorAction Stop)) {
        $lineNo++
        $line = ([string]$rawLine).Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#') -or $line.StartsWith(';')) { continue }
        try {
            $entry = Normalize-WhitelistEntry $line
        } catch {
            throw ("{0}, linea {1}: {2}" -f (Split-Path -Leaf $Path),$lineNo,$_.Exception.Message)
        }
        if ($result -notcontains $entry) { $result += $entry }
    }
    return @($result)
}

$outboundAddresses = @(Read-IPWallWhitelist $WhitelistPath)
$inboundAddresses = @(Read-IPWallWhitelist $InboundWhitelistPath)

$StrictScript = Join-Path (Split-Path -Parent $WhitelistPath) 'strict-firewall.ps1'
if (-not (Test-Path -LiteralPath $StrictScript)) { throw "Falta strict-firewall.ps1." }
try {
    . $StrictScript
    Install-IPWallStrictRuleSet -OutboundAddresses @($outboundAddresses) -InboundAddresses @($inboundAddresses)
} catch {
    $detail = "No se pudo aplicar el modo hermetico allowlist-only; se conservaron las reglas anteriores cuando fue posible. $($_.Exception.Message)"
    Write-ApplyError $detail
    throw $detail
}

# Puente de control SYSTEM. También funciona con el agente 4.0 que ya estaba
# cargado en memoria: ese agente ejecuta ESTE archivo cada vez que cambia la
# whitelist. index.php escribe una orden y agrega una línea vacía inocua para
# forzar un nuevo hash; aquí se crea un trabajador SYSTEM independiente.
function Start-IPWallSystemControlIfRequested {
    $projectDir = Split-Path -Parent $WhitelistPath
    $runtimeDir = Join-Path $projectDir 'runtime'
    New-Item -ItemType Directory -Path $runtimeDir -Force | Out-Null
    try { (Get-Item -LiteralPath $runtimeDir -Force).Attributes = ((Get-Item -LiteralPath $runtimeDir -Force).Attributes -bor [IO.FileAttributes]::Hidden) } catch {}

    # v4.4 usa runtime\. El fallback en la raiz conserva el puente de
    # actualizacion cuando un agente/broker 4.0-4.3 aun sigue cargado.
    $requestPath = Join-Path $runtimeDir 'system-control.request.json'
    $statusPath = Join-Path $runtimeDir 'control-status.json'
    if (-not (Test-Path -LiteralPath $requestPath)) {
        $legacyRequest = Join-Path $projectDir 'system-control.request.json'
        if (-not (Test-Path -LiteralPath $legacyRequest)) { return }
        $requestPath = $legacyRequest
        $statusPath = Join-Path $projectDir 'control-status.json'
    }

    try {
        $workerPath = Join-Path $projectDir 'ipwall-system-worker.ps1'
        if (-not (Test-Path -LiteralPath $workerPath)) { throw "Falta ipwall-system-worker.ps1." }

        $request = Get-Content -LiteralPath $requestPath -Raw -ErrorAction Stop | ConvertFrom-Json
        $requestId = [string]$request.id
        $requestAction = [string]$request.action
        if ($requestId -notmatch '^[a-f0-9]{16,64}$') { throw "ID de orden SYSTEM inválido." }
        if ($requestAction -notin @('install','restore')) { throw "Acción SYSTEM inválida." }

        $taskName = 'IPWallControlWorker-' + $requestId.Substring(0,[Math]::Min(16,$requestId.Length))
        $args = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $workerPath + '" -ProjectDir "' + $projectDir + '" -RequestId "' + $requestId + '" -TaskName "' + $taskName + '"'
        $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($null -eq $existing) {
            $taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $args
            $trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(10))
            $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::FromMinutes(15))
            Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        }
        Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    } catch {
        try {
            $obj = [ordered]@{
                action = 'control'
                state = 'error'
                message = ('No se pudo iniciar el trabajador SYSTEM: ' + $_.Exception.Message)
                updated_unix = [int64](((Get-Date).ToUniversalTime() - [datetime]::SpecifyKind([datetime]'1970-01-01 00:00:00',[DateTimeKind]::Utc)).TotalSeconds)
            }
            [System.IO.File]::WriteAllText($statusPath,($obj | ConvertTo-Json -Compress),[System.Text.UTF8Encoding]::new($false))
        } catch {}
    }
}

Start-IPWallSystemControlIfRequested


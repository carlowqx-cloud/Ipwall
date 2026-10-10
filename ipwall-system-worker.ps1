param(
    [Parameter(Mandatory=$true)][string]$ProjectDir,
    [Parameter(Mandatory=$true)][string]$RequestId,
    [Parameter(Mandatory=$true)][string]$TaskName
)

$ErrorActionPreference = "Stop"
$ProjectDir = [IO.Path]::GetFullPath($ProjectDir)
$RuntimeDir = Join-Path $ProjectDir "runtime"
New-Item -ItemType Directory -Path $RuntimeDir -Force | Out-Null
try { (Get-Item -LiteralPath $RuntimeDir -Force).Attributes = ((Get-Item -LiteralPath $RuntimeDir -Force).Attributes -bor [IO.FileAttributes]::Hidden) } catch {}
$RuntimeRequestPath = Join-Path $RuntimeDir "system-control.request.json"
$LegacyRequestPath = Join-Path $ProjectDir "system-control.request.json"
if (Test-Path -LiteralPath $RuntimeRequestPath) {
    $RequestPath = $RuntimeRequestPath
    $StatusPath = Join-Path $RuntimeDir "control-status.json"
    $ProcessingPath = Join-Path $RuntimeDir ("system-control.processing." + $RequestId + ".json")
} elseif (Test-Path -LiteralPath $LegacyRequestPath) {
    # Puente para una orden creada por un broker/agente 4.0-4.3 que ya estaba
    # cargado antes de copiar los archivos v4.4.
    $RequestPath = $LegacyRequestPath
    $StatusPath = Join-Path $ProjectDir "control-status.json"
    $ProcessingPath = Join-Path $ProjectDir ("system-control.processing." + $RequestId + ".json")
} else {
    $RequestPath = $RuntimeRequestPath
    $StatusPath = Join-Path $RuntimeDir "control-status.json"
    $ProcessingPath = Join-Path $RuntimeDir ("system-control.processing." + $RequestId + ".json")
}

function Get-UnixTime {
    $epoch = [datetime]::SpecifyKind([datetime]'1970-01-01 00:00:00',[DateTimeKind]::Utc)
    return [int64](((Get-Date).ToUniversalTime() - $epoch).TotalSeconds)
}

function Write-ControlStatus([string]$Action,[string]$State,[string]$Message) {
    try {
        $obj = [ordered]@{
            action = $Action
            state = $State
            message = $Message
            updated_unix = [int64](Get-UnixTime)
        }
        $json = $obj | ConvertTo-Json -Compress
        $tmp = "$StatusPath.tmp.$PID"
        [System.IO.File]::WriteAllText($tmp,$json,[System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $tmp -Destination $StatusPath -Force
    } catch {}
}

function Test-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Remove-SelfTask {
    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
}

$action = "control"
try {
    if (-not (Test-Administrator)) { throw "El trabajador de control no se está ejecutando como Administrador/SYSTEM." }
    if (-not (Test-Path -LiteralPath $RequestPath)) { Remove-SelfTask; exit 0 }

    $request = Get-Content -LiteralPath $RequestPath -Raw -ErrorAction Stop | ConvertFrom-Json
    if ([string]$request.id -ne $RequestId) { Remove-SelfTask; exit 0 }
    $action = [string]$request.action
    if ($action -notin @('install','restore')) { throw "Acción de control inválida: $action" }

    # Reclamar la orden antes de ejecutar. install.ps1 llama de nuevo a
    # apply-whitelist.ps1; al no existir ya runtime\system-control.request.json no se
    # crea un segundo trabajador recursivo.
    Move-Item -LiteralPath $RequestPath -Destination $ProcessingPath -Force
    Start-Sleep -Milliseconds 900

    if ($action -eq 'install') {
        Write-ControlStatus 'install' 'running' 'Actualizando/instalando IPWall como SYSTEM...'
        $script = Join-Path $ProjectDir 'install.ps1'
        if (-not (Test-Path -LiteralPath $script)) { throw "No existe install.ps1 en $ProjectDir" }
        & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File $script -ProjectDir $ProjectDir -ResultFile $StatusPath
        if ($LASTEXITCODE -ne 0) {
            $detail = ''
            try {
                if (Test-Path -LiteralPath $StatusPath) {
                    $lastStatus = Get-Content -LiteralPath $StatusPath -Raw | ConvertFrom-Json
                    if ([string]$lastStatus.state -eq 'error') { $detail = [string]$lastStatus.message }
                }
            } catch {}
            if ([string]::IsNullOrWhiteSpace($detail)) { $detail = "install.ps1 terminó con código $LASTEXITCODE." }
            throw $detail
        }
    } else {
        Write-ControlStatus 'restore' 'running' 'Restaurando el firewall original como SYSTEM...'
        $script = Join-Path $ProjectDir 'restore-firewall.ps1'
        if (-not (Test-Path -LiteralPath $script)) { throw "No existe restore-firewall.ps1 en $ProjectDir" }
        & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File $script -ProjectDir $ProjectDir -ResultFile $StatusPath
        if ($LASTEXITCODE -ne 0) { throw "restore-firewall.ps1 terminó con código $LASTEXITCODE." }
    }

    Remove-Item -LiteralPath $ProcessingPath -Force -ErrorAction SilentlyContinue
    Remove-SelfTask
    exit 0
} catch {
    Write-ControlStatus $action 'error' $_.Exception.Message
    Remove-Item -LiteralPath $ProcessingPath -Force -ErrorAction SilentlyContinue
    Remove-SelfTask
    exit 1
}

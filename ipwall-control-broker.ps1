param(
    [string]$ProjectDir = "C:\xampp\htdocs\ipwall",
    [int]$IntervalSeconds = 1
)

$ErrorActionPreference = "Continue"
$ProjectDir = [IO.Path]::GetFullPath($ProjectDir)
$RuntimeDir = Join-Path $ProjectDir 'runtime'
New-Item -ItemType Directory -Path $RuntimeDir -Force | Out-Null
try { (Get-Item -LiteralPath $RuntimeDir -Force).Attributes = ((Get-Item -LiteralPath $RuntimeDir -Force).Attributes -bor [IO.FileAttributes]::Hidden) } catch {}
$RequestPath = Join-Path $RuntimeDir 'system-control.request.json'
$StatusPath = Join-Path $RuntimeDir 'control-broker-status.json'
$WorkerPath = Join-Path $ProjectDir 'ipwall-system-worker.ps1'
$lastScheduledId = ''

function Get-UnixTime {
    $epoch = [datetime]::SpecifyKind([datetime]'1970-01-01 00:00:00',[DateTimeKind]::Utc)
    return [int64](((Get-Date).ToUniversalTime() - $epoch).TotalSeconds)
}

function Save-BrokerStatus([string]$LastError,[string]$ScheduledId) {
    try {
        $obj = [ordered]@{
            broker_version = '4.6.1'
            heartbeat = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            heartbeat_unix = [int64](Get-UnixTime)
            last_scheduled_id = $ScheduledId
            last_error = $LastError
        }
        $json = $obj | ConvertTo-Json -Compress
        # Heartbeat de alta frecuencia: escribir el mismo archivo directamente.
        # Crear/renombrar un .tmp cada segundo provoca eventos de alta/baja que
        # hacen saltar la lista del Explorador de Windows.
        [System.IO.File]::WriteAllText($StatusPath,$json,[System.Text.UTF8Encoding]::new($false))
    } catch {}
}

function Start-ControlWorker([string]$RequestId) {
    if (-not (Test-Path -LiteralPath $WorkerPath)) { throw 'Falta ipwall-system-worker.ps1.' }
    if ($RequestId -notmatch '^[a-f0-9]{16,64}$') { throw 'ID de orden SYSTEM inválido.' }

    $taskName = 'IPWallControlWorker-' + $RequestId.Substring(0,[Math]::Min(16,$RequestId.Length))
    $args = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $WorkerPath + '" -ProjectDir "' + $ProjectDir + '" -RequestId "' + $RequestId + '" -TaskName "' + $taskName + '"'
    $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($null -eq $existing) {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $args
        $trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(10))
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::FromMinutes(15))
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    }
    Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
}

while ($true) {
    $err = ''
    try {
        if (Test-Path -LiteralPath $RequestPath) {
            $request = Get-Content -LiteralPath $RequestPath -Raw -ErrorAction Stop | ConvertFrom-Json
            $requestId = [string]$request.id
            $requestAction = [string]$request.action
            if ($requestAction -notin @('install','restore')) { throw "Acción SYSTEM inválida: $requestAction" }
            if ($requestId -ne $lastScheduledId) {
                Start-ControlWorker $requestId
                $lastScheduledId = $requestId
            }
        } else {
            $lastScheduledId = ''
        }
    } catch {
        $err = $_.Exception.Message
    }
    Save-BrokerStatus $err $lastScheduledId
    Start-Sleep -Seconds ([Math]::Max(1,$IntervalSeconds))
}

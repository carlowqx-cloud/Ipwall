param(
    [ValidateSet("install","restore")]
    [string]$Action,
    [string]$ProjectDir = "C:\xampp\htdocs\ipwall",
    [string]$ResultFile = ""
)

$ErrorActionPreference = "Stop"
$RuntimeDir = Join-Path $ProjectDir "runtime"
New-Item -ItemType Directory -Path $RuntimeDir -Force | Out-Null
try { (Get-Item -LiteralPath $RuntimeDir -Force).Attributes = ((Get-Item -LiteralPath $RuntimeDir -Force).Attributes -bor [IO.FileAttributes]::Hidden) } catch {}
if ([string]::IsNullOrWhiteSpace($ResultFile)) {
    $ResultFile = Join-Path $RuntimeDir "control-status.json"
}

function Get-UnixTime {
    $epoch = [datetime]::SpecifyKind([datetime]'1970-01-01 00:00:00',[DateTimeKind]::Utc)
    return [int64](((Get-Date).ToUniversalTime() - $epoch).TotalSeconds)
}

function Write-ControlStatus([string]$State,[string]$Message) {
    try {
        $dir = Split-Path -Parent $ResultFile
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        $obj = [ordered]@{
            action = $Action
            state = $State
            message = $Message
            updated_unix = [int64](Get-UnixTime)
        }
        $json = $obj | ConvertTo-Json -Compress
        $tmp = "$ResultFile.tmp.$PID"
        [System.IO.File]::WriteAllText($tmp,$json,[System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $tmp -Destination $ResultFile -Force
    } catch {}
}

function Test-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

try {
    $ProjectDir = [IO.Path]::GetFullPath($ProjectDir)
    $ResultFile = [IO.Path]::GetFullPath($ResultFile)
    $self = [IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)

    if (-not (Test-Administrator)) {
        Write-ControlStatus "awaiting_uac" "Windows solicita permiso de administrador para continuar."

        $quotedSelf = '"' + $self + '"'
        $quotedProject = '"' + $ProjectDir + '"'
        $quotedResult = '"' + $ResultFile + '"'
        $args = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File $quotedSelf -Action $Action -ProjectDir $quotedProject -ResultFile $quotedResult"

        try {
            Start-Process -FilePath "powershell.exe" -Verb RunAs -WindowStyle Hidden -ArgumentList $args | Out-Null
        } catch {
            Write-ControlStatus "error" ("No se concedió la elevación de administrador: " + $_.Exception.Message)
            exit 1
        }
        exit 0
    }

    Write-ControlStatus "running" ($(if($Action -eq 'install'){'Instalando IPWall...'}else{'Restaurando el firewall...'}))

    if ($Action -eq "install") {
        $script = Join-Path $ProjectDir "install.ps1"
        if (-not (Test-Path -LiteralPath $script)) { throw "No existe install.ps1 en $ProjectDir" }
        & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File $script -ProjectDir $ProjectDir -ResultFile $ResultFile
    } else {
        $script = Join-Path $ProjectDir "restore-firewall.ps1"
        if (-not (Test-Path -LiteralPath $script)) { throw "No existe restore-firewall.ps1 en $ProjectDir" }
        & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File $script -ProjectDir $ProjectDir -ResultFile $ResultFile
    }

    if ($LASTEXITCODE -ne 0) {
        $detail = ''
        try {
            if (Test-Path -LiteralPath $ResultFile) {
                $last = Get-Content -LiteralPath $ResultFile -Raw | ConvertFrom-Json
                if ([string]$last.state -eq 'error') { $detail = [string]$last.message }
            }
        } catch {}
        if ([string]::IsNullOrWhiteSpace($detail)) { $detail = "La operacion termino con codigo $LASTEXITCODE." }
        throw $detail
    }
    exit 0
} catch {
    Write-ControlStatus "error" $_.Exception.Message
    exit 1
}

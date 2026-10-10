param(
    [string]$ProjectDir="C:\xampp\htdocs\ipwall",
    [string]$ResultFile="",
    [switch]$FromAgent
)

$ErrorActionPreference="Stop"
$RuntimeDir=Join-Path $ProjectDir "runtime"
New-Item -ItemType Directory -Path $RuntimeDir -Force | Out-Null
try { (Get-Item -LiteralPath $RuntimeDir -Force).Attributes = ((Get-Item -LiteralPath $RuntimeDir -Force).Attributes -bor [IO.FileAttributes]::Hidden) } catch {}
if ([string]::IsNullOrWhiteSpace($ResultFile)) { $ResultFile = Join-Path $RuntimeDir "control-status.json" }

function Get-ControlUnixTime {
    $epoch=[datetime]::SpecifyKind([datetime]'1970-01-01 00:00:00',[DateTimeKind]::Utc)
    return [int64](((Get-Date).ToUniversalTime()-$epoch).TotalSeconds)
}
function Write-ControlStatus([string]$State,[string]$Message) {
    try {
        $obj=[ordered]@{action='restore';state=$State;message=$Message;updated_unix=[int64](Get-ControlUnixTime)}
        $json=$obj|ConvertTo-Json -Compress
        $tmp="$ResultFile.tmp.$PID"
        [System.IO.File]::WriteAllText($tmp,$json,[System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $tmp -Destination $ResultFile -Force
        $runtimeResult=Join-Path $RuntimeDir 'control-status.json'
        if(-not [string]::Equals([IO.Path]::GetFullPath($ResultFile),[IO.Path]::GetFullPath($runtimeResult),[StringComparison]::OrdinalIgnoreCase)){
            [System.IO.File]::WriteAllText($runtimeResult,$json,[System.Text.UTF8Encoding]::new($false))
        }
    } catch {}
}
trap {
    Write-ControlStatus 'error' $_.Exception.Message
    exit 1
}

$id=[Security.Principal.WindowsIdentity]::GetCurrent()
$p=New-Object Security.Principal.WindowsPrincipal($id)
if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw "Se requieren privilegios de Administrador."}

Write-ControlStatus 'running' 'Restaurando la configuración original del firewall...'

$TaskName="IPWhitelistFirewall"
$StateDir="C:\ProgramData\IPWhitelistFirewall"
$Backup=Join-Path $StateDir "firewall-before-whitelist.wfw"
$DnsLogName="Microsoft-Windows-DNS-Client/Operational"
$DnsLogMarker=Join-Path $StateDir "dns-operational-enabled-by-ipwall.txt"
$WfpAuditMarker=Join-Path $StateDir "wfp-connection-audit-configured.txt"
$WfpPacketAuditMarker=Join-Path $StateDir "wfp-packet-audit-configured.txt"
$AuditBackup=Join-Path $StateDir "audit-before-ipwall.csv"
$WfpCursor=Join-Path $StateDir "wfp-browser-last-record-id.txt"
$AgentStatus=Join-Path $RuntimeDir "agent-status.json"
$RestoreFlag=Join-Path $RuntimeDir "restore-firewall.flag"
$DisabledMarker=Join-Path $StateDir "restored-disabled.marker"

# Si la restauración viene del propio agente SYSTEM, no detenerlo al inicio:
# el hijo necesita terminar la importación. La tarea se elimina al final.
if(-not $FromAgent){
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
}

if(-not(Test-Path -LiteralPath $Backup)){throw "No existe el respaldo original: $Backup"}

# Impedir que el agente vuelva a aplicar reglas aunque la definición de la tarea
# tarde en desaparecer mientras su instancia SYSTEM actual termina.
"restored" | Set-Content -LiteralPath $DisabledMarker -Encoding ASCII
Disable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null

& netsh.exe advfirewall import $Backup | Out-Null
if($LASTEXITCODE -ne 0){throw "No se pudo restaurar el firewall desde $Backup"}

# Solo desactivar el log DNS si IPWall fue quien lo activó originalmente.
if(Test-Path -LiteralPath $DnsLogMarker){
    try {
        & wevtutil.exe sl $DnsLogName /e:false
        if($LASTEXITCODE -eq 0){Remove-Item -LiteralPath $DnsLogMarker -Force -ErrorAction SilentlyContinue}
    } catch {}
}

# Restaurar la directiva de auditoría que existía antes de IPWall.
if(Test-Path -LiteralPath $AuditBackup){
    try {
        & auditpol.exe /restore /file:$AuditBackup | Out-Null
        if($LASTEXITCODE -eq 0){
            Remove-Item -LiteralPath $WfpAuditMarker,$WfpPacketAuditMarker -Force -ErrorAction SilentlyContinue
        }
    } catch {}
}

Remove-Item -LiteralPath $WfpCursor -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $RestoreFlag -Force -ErrorAction SilentlyContinue

# Marcar el agente como inactivo antes de retirar la tarea para que el panel no
# enseñe un heartbeat antiguo como si IPWall siguiera activo.
try {
    $offline=[ordered]@{agent_version='4.6.1';heartbeat='';heartbeat_unix=0;restored=$true;last_error=''} | ConvertTo-Json -Compress
    [System.IO.File]::WriteAllText($AgentStatus,$offline,[System.Text.UTF8Encoding]::new($false))
} catch {}

# Quitar la persistencia al final. Si la llamada viene del agente, este proceso
# hijo termina primero y el bucle padre sale inmediatamente después.
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
if(-not $FromAgent){
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
}

Write-ControlStatus 'success' 'Firewall original restaurado. IPWall quedó desactivado.'
Remove-Item -LiteralPath (Join-Path $ProjectDir 'control-status.json') -Force -ErrorAction SilentlyContinue
Write-Host "Firewall y auditoría restaurados. IPWall desactivado."
exit 0

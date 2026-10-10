param(
    [string]$ProjectDir="C:\xampp\htdocs\ipwall",
    [string]$ResultFile=""
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
        $obj=[ordered]@{action='install';state=$State;message=$Message;updated_unix=[int64](Get-ControlUnixTime)}
        $json=$obj|ConvertTo-Json -Compress
        $tmp="$ResultFile.tmp.$PID"
        [System.IO.File]::WriteAllText($tmp,$json,[System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $tmp -Destination $ResultFile -Force

        # Si la actualizacion fue lanzada por un broker 4.0-4.3, ResultFile
        # puede ser la ruta legacy de la raiz. Reflejar el estado tambien en
        # runtime para que al arrancar 4.4 el panel conserve el resultado.
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
Write-ControlStatus 'running' 'Preparando respaldo y reglas de Windows Firewall...'


$id=[Security.Principal.WindowsIdentity]::GetCurrent()
$p=New-Object Security.Principal.WindowsPrincipal($id)
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Abre PowerShell como Administrador."
}

$StateDir="C:\ProgramData\IPWhitelistFirewall"
$Backup=Join-Path $StateDir "firewall-before-whitelist.wfw"
$TaskName="IPWhitelistFirewall"
$BrokerTaskName="IPWallControlBroker"
$DnsLogName="Microsoft-Windows-DNS-Client/Operational"
$DnsLogMarker=Join-Path $StateDir "dns-operational-enabled-by-ipwall.txt"
$WfpAuditGuid="{0CCE9226-69AE-11D9-BED3-505054503030}"
$WfpPacketAuditGuid="{0CCE9225-69AE-11D9-BED3-505054503030}"
$WfpAuditMarker=Join-Path $StateDir "wfp-connection-audit-configured.txt"
$WfpPacketAuditMarker=Join-Path $StateDir "wfp-packet-audit-configured.txt"
$AuditBackup=Join-Path $StateDir "audit-before-ipwall.csv"
$WfpCursor=Join-Path $StateDir "wfp-browser-last-record-id.txt"
$DisabledMarker=Join-Path $StateDir "restored-disabled.marker"

$Whitelist=Join-Path $ProjectDir "whitelist.txt"
$InboundWhitelist=Join-Path $ProjectDir "whitelist-inbound.txt"
$Requests=Join-Path $RuntimeDir "requests.json"
$Status=Join-Path $RuntimeDir "agent-status.json"
$Apply=Join-Path $ProjectDir "apply-whitelist.ps1"
$StrictFirewall=Join-Path $ProjectDir "strict-firewall.ps1"
$NetLib=Join-Path $ProjectDir "ipwall-net.php"
$Agent=Join-Path $ProjectDir "agent.ps1"
$Control=Join-Path $ProjectDir "ipwall-control.ps1"
$SystemWorker=Join-Path $ProjectDir "ipwall-system-worker.ps1"
$ControlBroker=Join-Path $ProjectDir "ipwall-control-broker.ps1"
$BrokerStatus=Join-Path $RuntimeDir "control-broker-status.json"
$LegacyRequests=Join-Path $ProjectDir "requests.json"
$LegacyStatus=Join-Path $ProjectDir "agent-status.json"
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$isUpgrade = ($null -ne $existingTask) -or (Test-Path -LiteralPath $LegacyStatus) -or (Test-Path -LiteralPath $WfpCursor)

New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
Remove-Item -LiteralPath $DisabledMarker -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path "$env:SystemRoot\System32\LogFiles\Firewall" -Force | Out-Null

foreach($f in @($Apply,$StrictFirewall,$Agent,$NetLib,$Control,$SystemWorker,$ControlBroker)) {
    if(-not(Test-Path -LiteralPath $f)){throw "Falta: $f"}
}
# Conservar datos existentes y migrar el historial legacy antes de tocar tareas.
if(-not(Test-Path -LiteralPath $Whitelist)){ [System.IO.File]::WriteAllText($Whitelist,'',[System.Text.Encoding]::ASCII) }
if(-not(Test-Path -LiteralPath $InboundWhitelist)){ [System.IO.File]::WriteAllText($InboundWhitelist,'',[System.Text.Encoding]::ASCII) }
$runtimeRequestsUseful=$false
if(Test-Path -LiteralPath $Requests){
    try { $rr=Get-Content -LiteralPath $Requests -Raw | ConvertFrom-Json; if(@($rr).Count -gt 0){$runtimeRequestsUseful=$true} } catch {}
}
if((Test-Path -LiteralPath $LegacyRequests) -and -not $runtimeRequestsUseful){
    try {
        $lr=Get-Content -LiteralPath $LegacyRequests -Raw | ConvertFrom-Json
        if(@($lr).Count -gt 0){ Copy-Item -LiteralPath $LegacyRequests -Destination $Requests -Force; $runtimeRequestsUseful=$true }
    } catch {}
}
if(-not(Test-Path -LiteralPath $Requests)){ [System.IO.File]::WriteAllText($Requests,'[]',[System.Text.Encoding]::ASCII) }
if(-not(Test-Path -LiteralPath $Status)){ [System.IO.File]::WriteAllText($Status,'{}',[System.Text.Encoding]::ASCII) }
if(-not(Test-Path -LiteralPath $BrokerStatus)){ [System.IO.File]::WriteAllText($BrokerStatus,'{}',[System.Text.Encoding]::ASCII) }

if(-not(Test-Path -LiteralPath $Backup)){
    & netsh.exe advfirewall export $Backup | Out-Null
    if($LASTEXITCODE -ne 0){throw "No se pudo crear el respaldo del firewall."}
}

# Activar el historial operativo del cliente DNS. IPWall recuerda si fue quien
# lo activó para poder devolverlo a su estado anterior al restaurar.
try {
    $dnsLog = Get-WinEvent -ListLog $DnsLogName -ErrorAction Stop
    if(-not $dnsLog.IsEnabled){
        & wevtutil.exe sl $DnsLogName /e:true
        if($LASTEXITCODE -eq 0){
            "enabled-by-ipwall" | Set-Content -LiteralPath $DnsLogMarker -Encoding ASCII
        }
    }
} catch {
    Write-Warning "No se pudo activar DNS Client/Operational. IPWall seguirá usando caché DNS y PTR."
}

# Guardar la directiva de auditoria antes del primer cambio y activar
# bloqueos de conexion 5157 y de paquetes 5152. Ambos contienen ejecutable,
# direccion e IP y permiten evitar trafico de procesos ajenos al navegador.
# 5152 puede generar muchos eventos; se filtran al leerlos.
try {
    Remove-Item -LiteralPath $WfpAuditMarker,$WfpPacketAuditMarker -Force -ErrorAction SilentlyContinue
    if(-not(Test-Path -LiteralPath $AuditBackup)){
        & auditpol.exe /backup /file:$AuditBackup | Out-Null
        if($LASTEXITCODE -ne 0){Remove-Item -LiteralPath $AuditBackup -Force -ErrorAction SilentlyContinue}
    }

    & auditpol.exe /set /subcategory:$WfpAuditGuid /failure:enable | Out-Null
    if($LASTEXITCODE -eq 0){
        "configured" | Set-Content -LiteralPath $WfpAuditMarker -Encoding ASCII
    } else {
        Write-Warning "No se pudo activar la auditoria WFP 5157."
    }
    & auditpol.exe /set /subcategory:$WfpPacketAuditGuid /failure:enable | Out-Null
    if($LASTEXITCODE -eq 0){
        "configured" | Set-Content -LiteralPath $WfpPacketAuditMarker -Encoding ASCII
    } else {
        Write-Warning "No se pudo activar la auditoria WFP 5152."
    }
} catch {
    Write-Warning "No se pudo activar la auditoria WFP: $($_.Exception.Message)"
}

Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

$dns=@(
    Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
    ForEach-Object {$_.ServerAddresses} |
    Where-Object {$_ -and $_ -ne "0.0.0.0" -and $_ -ne "::"} |
    Select-Object -Unique
)

$dns | Set-Content -LiteralPath (Join-Path $StateDir "dns-servers.txt") -Encoding ASCII

# Strict mode has no hidden DNS firewall exception. DNS servers are recorded
# only so the panel/README can tell the operator what IPs may need to be added
# explicitly to whitelist.txt. apply-whitelist.ps1 removes legacy DNS rules.

# Primera instalación: empezar a observar desde "ahora". En actualizaciones NO
# borrar requests.json ni adelantar el cursor: hacerlo en 4.4 vaciaba el panel y
# descartaba intentos bloqueados que el usuario aun necesitaba autorizar.
if(-not $isUpgrade -and -not(Test-Path -LiteralPath $WfpCursor)){
    try {
        $lastSecurity = @(Get-WinEvent -LogName 'Security' -MaxEvents 1 -ErrorAction SilentlyContinue)
        if($lastSecurity.Count -gt 0){
            [string]$lastSecurity[0].RecordId | Set-Content -LiteralPath $WfpCursor -Encoding ASCII
        }
    } catch {}
}
"{}" | Set-Content -LiteralPath $Status -Encoding ASCII

try {
    # Ejecutarlo en el mismo PowerShell conserva la excepcion real. En v4.5 el
    # proceso hijo solo devolvia codigo 1 y el panel ocultaba la causa.
    & $Apply -WhitelistPath $Whitelist -InboundWhitelistPath $InboundWhitelist -StateDir $StateDir
} catch {
    throw ("apply-whitelist.ps1: " + $_.Exception.Message)
}

# Confirmar la barrera hermetica directamente antes de declarar que el agente
# fallo. Las reglas Allow ordinarias de terceros no son fuga frente a nuestros
# Block explicitos; solo un Allow-Bypass o perfiles/rules ausentes invalidan.
. $StrictFirewall
$preflight = Test-IPWallStrictIntegrity
if(-not [bool]$preflight.Hermetic){
    throw ("La política hermética no quedó efectiva. ProfilesOk={0}; BlockIn={1}; BlockOut={2}; AllowBypass={3}; ForeignLocal={4}" -f $preflight.ProfilesOk,$preflight.StrictInboundRules,$preflight.StrictOutboundRules,$preflight.AllowBypassRules,$preflight.ForeignEnabledLocalRules)
}

$action=New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Agent`" -ProjectDir `"$ProjectDir`""
$trigger=New-ScheduledTaskTrigger -AtStartup
$principal=New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

# Broker SYSTEM persistente: permanece activo incluso después de restaurar el
# firewall, para que el botón Instalar pueda volver a activar IPWall sin que PHP
# necesite exec/popen ni abrir PowerShell.
Stop-ScheduledTask -TaskName $BrokerTaskName -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $BrokerTaskName -Confirm:$false -ErrorAction SilentlyContinue
"{}" | Set-Content -LiteralPath $BrokerStatus -Encoding ASCII
$brokerAction=New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ControlBroker`" -ProjectDir `"$ProjectDir`""
$brokerTrigger=New-ScheduledTaskTrigger -AtStartup
$brokerPrincipal=New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$brokerSettings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName $BrokerTaskName -Action $brokerAction -Trigger $brokerTrigger -Principal $brokerPrincipal -Settings $brokerSettings -Force | Out-Null
Start-ScheduledTask -TaskName $BrokerTaskName

$agentConfirmed=$false
for($i=0;$i -lt 45;$i++){
    Start-Sleep -Seconds 1
    try {
        if(Test-Path -LiteralPath $Status){
            $s=Get-Content -LiteralPath $Status -Raw | ConvertFrom-Json
            $now=[int64](Get-ControlUnixTime)
            $strictConfirmed = ($null -ne $s.PSObject.Properties['strict_hermetic'] -and [bool]$s.strict_hermetic)
            $wfpReady = ($null -ne $s.PSObject.Properties['wfp_security_log_available'] -and [bool]$s.wfp_security_log_available -and
                         $null -ne $s.PSObject.Properties['wfp_audit_configured'] -and [bool]$s.wfp_audit_configured)
            if([string]$s.agent_version -eq '4.6.1' -and [int64]$s.heartbeat_unix -ge ($now-15) -and $strictConfirmed -and $wfpReady){
                $agentConfirmed=$true
                break
            }
        }
    } catch {}
}
if(-not $agentConfirmed){
    $detail = ''
    try {
        if(Test-Path -LiteralPath $Status){
            $lastAgent = Get-Content -LiteralPath $Status -Raw | ConvertFrom-Json
            $detail = (" strict_error={0}; wfp_error={1}; last_error={2}" -f [string]$lastAgent.strict_error,[string]$lastAgent.wfp_read_error,[string]$lastAgent.last_error)
        }
    } catch {}
    throw ("El agente 4.6.1 no confirmo modo hermetico + captura WFP 5157 dentro de 45 s." + $detail + " Revisa C:\ProgramData\IPWhitelistFirewall\agent-errors.log y apply-errors.log.")
}

$brokerConfirmed=$false
for($i=0;$i -lt 20;$i++){
    Start-Sleep -Seconds 1
    try {
        if(Test-Path -LiteralPath $BrokerStatus){
            $b=Get-Content -LiteralPath $BrokerStatus -Raw | ConvertFrom-Json
            $now=[int64](Get-ControlUnixTime)
            if([string]$b.broker_version -eq '4.6.1' -and [int64]$b.heartbeat_unix -ge ($now-15)){
                $brokerConfirmed=$true
                break
            }
        }
    } catch {}
}
if(-not $brokerConfirmed){throw "IPWall instaló el agente, pero el broker SYSTEM 4.6.1 no confirmó su inicio."}

# Limpiar runtime legado de la raiz. Desde v4.4 los archivos que cambian de
# forma continua viven en runtime\ para que el Explorador no reordene ni
# cancele ediciones de scripts/whitelists.
$legacyVolatile=@('requests.json','agent-status.json','control-broker-status.json','clear-requests.flag','restore-firewall.flag','system-control.request.json')
foreach($legacyName in $legacyVolatile){
    Remove-Item -LiteralPath (Join-Path $ProjectDir $legacyName) -Force -ErrorAction SilentlyContinue
}
Get-ChildItem -LiteralPath $ProjectDir -Filter '*.tmp.*' -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

Write-ControlStatus 'success' 'IPWall 4.6.1 instalado; runtime estable, historial preservado y allowlist-only hermetico activo.'
$legacyControlStatus=Join-Path $ProjectDir 'control-status.json'
$runtimeControlStatus=Join-Path $RuntimeDir 'control-status.json'
if(-not [string]::Equals([IO.Path]::GetFullPath($legacyControlStatus),[IO.Path]::GetFullPath($runtimeControlStatus),[StringComparison]::OrdinalIgnoreCase)){
    Remove-Item -LiteralPath $legacyControlStatus -Force -ErrorAction SilentlyContinue
}
Write-Host ""
Write-Host "IPWall v4.6.1 estricto instalado: solo las IP/CIDR de las whitelists pueden pasar."
Write-Host "Panel: http://localhost/ipwall/"
Write-Host "Tarea: $TaskName"
Write-Host "Respaldo: $Backup"
Write-Host ""
Write-Host "Estado de tarea:"
Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName,State
exit 0

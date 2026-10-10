param([string]$ProjectDir="C:\xampp\htdocs\ipwall")

$ErrorActionPreference="Stop"
$TaskName="IPWhitelistFirewall"
$BrokerTaskName="IPWallControlBroker"
$StateDir="C:\ProgramData\IPWhitelistFirewall"
$RuntimeDir=Join-Path $ProjectDir "runtime"
$Agent=Join-Path $ProjectDir "agent.ps1"
$ControlBroker=Join-Path $ProjectDir "ipwall-control-broker.ps1"
$InboundWhitelist=Join-Path $ProjectDir "whitelist-inbound.txt"
$AuditBackup=Join-Path $StateDir "audit-before-ipwall.csv"
$WfpAuditGuid="{0CCE9226-69AE-11D9-BED3-505054503030}"
$WfpPacketAuditGuid="{0CCE9225-69AE-11D9-BED3-505054503030}"
$WfpAuditMarker=Join-Path $StateDir "wfp-connection-audit-configured.txt"
$WfpPacketAuditMarker=Join-Path $StateDir "wfp-packet-audit-configured.txt"
$WfpCursor=Join-Path $StateDir "wfp-browser-last-record-id.txt"

$id=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($id)
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw "Ejecuta este script desde PowerShell como Administrador."
}

if(-not(Test-Path -LiteralPath $ProjectDir)){throw "No existe el proyecto: $ProjectDir"}
$task=Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if($null -eq $task){
    throw "La tarea IPWhitelistFirewall no existe. Para instalar desde cero, copia la carpeta ipwall a C:\xampp\htdocs\ipwall y ejecuta install.ps1."
}

$SourceDir=$PSScriptRoot
$files=@('agent.ps1','index.php','ipwall-net.php','install.ps1','diagnose.ps1','restore-firewall.ps1','ipwall-control.ps1','ipwall-system-worker.ps1','ipwall-control-broker.ps1','apply-whitelist.ps1','strict-firewall.ps1','README.md','upgrade.ps1')
foreach($file in $files){
    if(-not(Test-Path -LiteralPath (Join-Path $SourceDir $file))){throw "El ZIP no contiene $file"}
}

Write-Host "Deteniendo agente y broker anteriores..."
Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Stop-ScheduledTask -TaskName $BrokerTaskName -ErrorAction SilentlyContinue
for($i=0;$i -lt 20;$i++){
    $state=(Get-ScheduledTask -TaskName $TaskName).State
    if($state -ne 'Running'){break}
    Start-Sleep -Milliseconds 300
}
if((Get-ScheduledTask -TaskName $TaskName).State -eq 'Running'){
    throw "La tarea todavia se ejecuta; no se copiaron archivos."
}

New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
$BackupDir=Join-Path $StateDir ("upgrade-backup-"+(Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
foreach($file in @($files)+@('whitelist.txt','whitelist-inbound.txt','requests.json','agent-status.json','control-broker-status.json','control-status.json')){
    $dst=Join-Path $ProjectDir $file
    if(Test-Path -LiteralPath $dst){Copy-Item -LiteralPath $dst -Destination (Join-Path $BackupDir $file) -Force}
}

# Solo se actualiza codigo: se conservan ambos ficheros de permisos.
# Los permisos heredados de whitelist.txt siguen siendo SALIENTES.
if(-not(Test-Path -LiteralPath $InboundWhitelist)){
    New-Item -ItemType File -Path $InboundWhitelist -Force | Out-Null
}
foreach($file in $files){
    $src=Join-Path $SourceDir $file
    $dst=Join-Path $ProjectDir $file
    if(-not [string]::Equals([IO.Path]::GetFullPath($src),[IO.Path]::GetFullPath($dst),[StringComparison]::OrdinalIgnoreCase)){
        Copy-Item -LiteralPath $src -Destination $dst -Force
    }
}

# Conservar la auditoria previa a IPWall para una restauracion completa.
if(-not(Test-Path -LiteralPath $AuditBackup)){
    & auditpol.exe /backup /file:$AuditBackup | Out-Null
    if($LASTEXITCODE -ne 0){throw "No se pudo respaldar la auditoria antes de cambiarla."}
}

Remove-Item -LiteralPath $WfpAuditMarker,$WfpPacketAuditMarker -Force -ErrorAction SilentlyContinue
& auditpol.exe /set /subcategory:$WfpAuditGuid /failure:enable | Out-Null
if($LASTEXITCODE -ne 0){throw "Error al activar la auditoria 5157."}
"configured" | Set-Content -LiteralPath $WfpAuditMarker -Encoding ASCII
& auditpol.exe /set /subcategory:$WfpPacketAuditGuid /failure:enable | Out-Null
if($LASTEXITCODE -ne 0){throw "Error al activar la auditoria 5152."}
"configured" | Set-Content -LiteralPath $WfpPacketAuditMarker -Encoding ASCII

# Actualizacion sin borrar el historial: el usuario lo limpia cuando quiera.
# Desde v4.4 todos los archivos que cambian continuamente viven dentro de
# runtime\ para que el Explorador de Windows no cambie la lista de archivos.
New-Item -ItemType Directory -Path $RuntimeDir -Force | Out-Null
try { (Get-Item -LiteralPath $RuntimeDir -Force).Attributes = ((Get-Item -LiteralPath $RuntimeDir -Force).Attributes -bor [IO.FileAttributes]::Hidden) } catch {}
if(-not(Test-Path -LiteralPath $WfpCursor)){
    $last=@(Get-WinEvent -LogName 'Security' -MaxEvents 1 -ErrorAction SilentlyContinue)
    if($last.Count -gt 0){
        [string]$last[0].RecordId | Set-Content -LiteralPath $WfpCursor -Encoding ASCII
    }
}
$runtimeRequests=Join-Path $RuntimeDir 'requests.json'
$legacyRequests=Join-Path $ProjectDir 'requests.json'
if(-not(Test-Path -LiteralPath $runtimeRequests)){
    if(Test-Path -LiteralPath $legacyRequests){ Copy-Item -LiteralPath $legacyRequests -Destination $runtimeRequests -Force }
    else { "[]" | Set-Content -LiteralPath $runtimeRequests -Encoding ASCII }
}
"{}" | Set-Content -LiteralPath (Join-Path $RuntimeDir 'agent-status.json') -Encoding ASCII
"{}" | Set-Content -LiteralPath (Join-Path $RuntimeDir 'control-broker-status.json') -Encoding ASCII

# Borrar solo runtime legado de la raiz; las whitelists y el codigo no se tocan.
foreach($legacyName in @('requests.json','agent-status.json','control-broker-status.json','control-status.json','clear-requests.flag','restore-firewall.flag','system-control.request.json')){
    Remove-Item -LiteralPath (Join-Path $ProjectDir $legacyName) -Force -ErrorAction SilentlyContinue
}
Get-ChildItem -LiteralPath $ProjectDir -Filter '*.tmp.*' -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

# El nuevo agente aplica el modo allowlist-only estricto: crea bloques explicitos
# para el complemento de ambas listas y deshabilita reglas locales ajenas.
# Mantener la tarea SYSTEM existente hasta que la nueva politica quede aplicada.
$action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Agent`" -ProjectDir `"$ProjectDir`""
Set-ScheduledTask -TaskName $TaskName -Action $action | Out-Null
Start-ScheduledTask -TaskName $TaskName

Stop-ScheduledTask -TaskName $BrokerTaskName -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $BrokerTaskName -Confirm:$false -ErrorAction SilentlyContinue
$brokerAction=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ControlBroker`" -ProjectDir `"$ProjectDir`""
$brokerTrigger=New-ScheduledTaskTrigger -AtStartup
$brokerPrincipal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$brokerSettings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName $BrokerTaskName -Action $brokerAction -Trigger $brokerTrigger -Principal $brokerPrincipal -Settings $brokerSettings -Force | Out-Null
Start-ScheduledTask -TaskName $BrokerTaskName
Start-Sleep -Seconds 3

Write-Host ""
Write-Host "IPWall 4.6.1 actualizado: runtime separado y modo hermetico allowlist-only."
Write-Host "Permisos salientes anteriores conservados; entrantes en whitelist-inbound.txt."
Write-Host "Respaldo de archivos: $BackupDir"
Write-Host "Panel: http://localhost/ipwall/"
Write-Host "Puedes limpiar las solicitudes con el boton Limpiar datos en la parte superior del panel."
Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName,State

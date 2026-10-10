param([string]$ProjectDir="C:\xampp\htdocs\ipwall")

$TaskName="IPWhitelistFirewall"
$DnsLog="Microsoft-Windows-DNS-Client/Operational"
$WfpConnectionGuid="{0CCE9226-69AE-11D9-BED3-505054503030}"
$WfpPacketGuid="{0CCE9225-69AE-11D9-BED3-505054503030}"
$BrowserExe=@('brave.exe','chrome.exe','chromium.exe','msedge.exe','firefox.exe','opera.exe','opera_gx.exe','vivaldi.exe','waterfox.exe','librewolf.exe','iexplore.exe','zen.exe','floorp.exe','palemoon.exe','seamonkey.exe','duckduckgo.exe','arc.exe')

Write-Host "=== AGENTE Y VERSION ==="
Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Select-Object TaskName,State
Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue | Select-Object LastRunTime,LastTaskResult
$RuntimeDir=Join-Path $ProjectDir 'runtime'
$Status=Join-Path $RuntimeDir 'agent-status.json'
if(-not(Test-Path -LiteralPath $Status)){ $Status=Join-Path $ProjectDir 'agent-status.json' }
if(Test-Path -LiteralPath $Status){Get-Content -LiteralPath $Status}

Write-Host "`n=== FIREWALL ==="
Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogBlocked

Write-Host "`n=== MODO HERMETICO ALLOWLIST-ONLY ==="
$StrictScript=Join-Path $ProjectDir 'strict-firewall.ps1'
if(Test-Path -LiteralPath $StrictScript){
    try {
        . $StrictScript
        $strict=Test-IPWallStrictIntegrity
        $strict | Format-List
        if(-not $strict.Hermetic){
            Write-Warning "El modo hermetico NO esta confirmado. Revisa AllowBypassRules, perfiles y reglas estrictas."
        }
    } catch {
        Write-Warning ("No se pudo auditar el modo hermetico: " + $_.Exception.Message)
    }
} else {
    Write-Warning "Falta strict-firewall.ps1."
}

Write-Host "`n=== AUDITORIA DE CONEXIONES 5157 ==="
& auditpol.exe /get /subcategory:$WfpConnectionGuid
Write-Host "`n=== AUDITORIA DE PAQUETES 5152 ==="
& auditpol.exe /get /subcategory:$WfpPacketGuid

Write-Host "`n=== TRAFICO ENTRANTE Y SALIENTE BLOQUEADO EN SECURITY (ULTIMOS 10 MINUTOS) ==="
$all=0
$incoming=0
$outgoing=0
$fromBrowsers=0
$rows=New-Object 'System.Collections.Generic.List[object]'
try {
    $events=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=@(5152,5157);StartTime=(Get-Date).AddMinutes(-10)} -MaxEvents 1500 -ErrorAction Stop)
    $all=$events.Count
    foreach($ev in $events){
        try {
            $xml=[xml]$ev.ToXml()
            $d=@{}
            foreach($node in @($xml.Event.EventData.Data)){
                if($node.Name){$d[[string]$node.Name]=[string]$node.InnerText}
            }
            $raw=([string]$d['Direction']).Trim()
            if(@('%%14593','14593','Outbound','Saliente') -contains $raw){
                $traffic='Salida'; $outgoing++
                $remoteIp=[string]$d['DestAddress']
                $remotePort=[string]$d['DestPort']
            } elseif(@('%%14592','14592','Inbound','Entrante') -contains $raw){
                $traffic='Entrada'; $incoming++
                $remoteIp=[string]$d['SourceAddress']
                $remotePort=[string]$d['SourcePort']
            } else {continue}
            $app=[string]$d['Application']
            $parts=@($app -split '[\\/]')
            $exe=([string]$parts[$parts.Count-1]).ToLowerInvariant()
            if($BrowserExe -notcontains $exe){continue}
            $fromBrowsers++
            if($rows.Count -lt 15){
                $rows.Add([pscustomobject]@{
                    Hora=$ev.TimeCreated
                    Evento=$ev.Id
                    Direccion=$traffic
                    Navegador=$exe
                    IpRemota=$remoteIp
                    PuertoRemoto=$remotePort
                    Protocolo=[string]$d['Protocol']
                })
            }
        } catch {}
    }
} catch {
    if([string]$_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound'){
        Write-Warning ("No fue posible leer Security: " + $_.Exception.Message)
    }
}
Write-Host "Eventos WFP: $all | Entrantes: $incoming | Salientes: $outgoing | Atribuidos a navegadores: $fromBrowsers"
if($rows.Count -gt 0){
    $rows | Format-Table -AutoSize
} else {
    Write-Host "No se encontraron bloqueos con ejecutable de navegador en la muestra."
    Write-Host "Prueba: abre en Brave una web externa nueva, espera unos segundos y repite el diagnostico."
}

Write-Host "`n=== DNS ==="
try { Get-WinEvent -ListLog $DnsLog -ErrorAction Stop | Select-Object LogName,IsEnabled,RecordCount }
catch { Write-Host "DNS Client Operational no disponible: $($_.Exception.Message)" }

Write-Host "`n=== ULTIMOS ERRORES DE APPLY-WHITELIST ==="
$ApplyErrorLog=Join-Path "C:\ProgramData\IPWhitelistFirewall" "apply-errors.log"
if(Test-Path -LiteralPath $ApplyErrorLog){ Get-Content -LiteralPath $ApplyErrorLog -Tail 20 }
else { Write-Host "Sin apply-errors.log." }

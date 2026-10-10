param(
    [string]$ProjectDir = "C:\xampp\htdocs\ipwall",
    [int]$IntervalSeconds = 2
)

$ErrorActionPreference = "Continue"
$AgentVersion = "4.6.1"

$WhitelistPath = Join-Path $ProjectDir "whitelist.txt"
$InboundWhitelistPath = Join-Path $ProjectDir "whitelist-inbound.txt"
$RuntimeDir = Join-Path $ProjectDir "runtime"
New-Item -ItemType Directory -Path $RuntimeDir -Force | Out-Null
try { (Get-Item -LiteralPath $RuntimeDir -Force).Attributes = ((Get-Item -LiteralPath $RuntimeDir -Force).Attributes -bor [IO.FileAttributes]::Hidden) } catch {}
$RequestsPath = Join-Path $RuntimeDir "requests.json"
$StatusPath = Join-Path $RuntimeDir "agent-status.json"
$ClearFlag = Join-Path $RuntimeDir "clear-requests.flag"
$RestoreFlag = Join-Path $RuntimeDir "restore-firewall.flag"
$ControlStatusPath = Join-Path $RuntimeDir "control-status.json"
$RestoreScript = Join-Path $ProjectDir "restore-firewall.ps1"
$ApplyScript = Join-Path $ProjectDir "apply-whitelist.ps1"
$StrictFirewallScript = Join-Path $ProjectDir "strict-firewall.ps1"
$FirewallLog = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
$ErrorLog = "C:\ProgramData\IPWhitelistFirewall\agent-errors.log"
$DnsEventLogName = "Microsoft-Windows-DNS-Client/Operational"
$SecurityLogName = "Security"
$StateDir = "C:\ProgramData\IPWhitelistFirewall"
$WfpAuditConfiguredMarker = Join-Path $StateDir "wfp-connection-audit-configured.txt"
$WfpPacketAuditMarker = Join-Path $StateDir "wfp-packet-audit-configured.txt"
$WfpAuditGuid = "{0CCE9226-69AE-11D9-BED3-505054503030}"
$WfpPacketAuditGuid = "{0CCE9225-69AE-11D9-BED3-505054503030}"
$WfpCursorPath = Join-Path $StateDir "wfp-browser-last-record-id.txt"
$DisabledMarker = Join-Path $StateDir "restored-disabled.marker"

$requests = @{}
$lastWhitelistHash = ""
$reverseDnsCache = @{}
$script:dnsHistory = @{}
$script:lastDnsRecordId = 0
$script:dnsEventLogAvailable = $false
$script:dnsEventsThisCycle = 0
$script:lastWfpRecordId = 0
$script:wfpEventLogAvailable = $false
$script:wfpEventsThisCycle = 0
$script:browserEventsThisCycle = 0
$script:wfp5152EventsThisCycle = 0
$script:wfp5157EventsThisCycle = 0
$script:browserEventsSinceStart = 0
$script:wfpReadError = ""
$script:wfpParseFailures = 0
$script:lastWfpParseError = ""
$script:strictHermetic = $false
$script:strictProfilesOk = $false
$script:strictInboundRules = 0
$script:strictOutboundRules = 0
$script:strictAllowBypassRules = 0
$script:strictForeignLocalRules = 0
$script:strictDisabledThisCycle = 0
$script:strictError = ""

function Ensure-IPWallWfpAudit {
    try {
        & auditpol.exe /set /subcategory:$WfpAuditGuid /failure:enable | Out-Null
        if ($LASTEXITCODE -eq 0) {
            "configured" | Set-Content -LiteralPath $WfpAuditConfiguredMarker -Encoding ASCII
        }
        & auditpol.exe /set /subcategory:$WfpPacketAuditGuid /failure:enable | Out-Null
        if ($LASTEXITCODE -eq 0) {
            "configured" | Set-Content -LiteralPath $WfpPacketAuditMarker -Encoding ASCII
        }
    } catch {}
}

Ensure-IPWallWfpAudit

try {
    if (-not (Test-Path -LiteralPath $StrictFirewallScript)) { throw "Falta strict-firewall.ps1." }
    . $StrictFirewallScript
} catch {
    $script:strictError = $_.Exception.Message
}

# Una restauración completa deja esta marca antes de retirar la tarea. Incluso
# si Windows no permite borrar una tarea que aún está terminando, el agente no
# volverá a aplicar reglas en el siguiente arranque.
if (Test-Path -LiteralPath $DisabledMarker) { exit 0 }

function Get-UnixTime([datetime]$Value = (Get-Date)) {
    $epoch = [datetime]::SpecifyKind([datetime]'1970-01-01 00:00:00',[DateTimeKind]::Utc)
    return [int64](($Value.ToUniversalTime() - $epoch).TotalSeconds)
}

function Normalize-Domain([string]$Name) {
    if ([string]::IsNullOrWhiteSpace($Name)) { return "" }
    $n = $Name.Trim().TrimEnd('.').ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($n)) { return "" }
    if ($n -match '\s') { return "" }
    if ($n.EndsWith('.in-addr.arpa') -or $n.EndsWith('.ip6.arpa')) { return "" }

    $parsedIp = $null
    if ([System.Net.IPAddress]::TryParse($n,[ref]$parsedIp)) { return "" }
    return $n
}

function Normalize-Ip([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return "" }
    $v = $Value.Trim()
    if ($v -match '^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$') { $v = $matches[1] }

    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($v,[ref]$parsed)) { return "" }
    try {
        if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 -and $parsed.IsIPv4MappedToIPv6) {
            return $parsed.MapToIPv4().ToString()
        }
    } catch {}
    return $parsed.ToString()
}

function Save-Json([string]$Path,$Object) {
    $json = ConvertTo-Json $Object -Depth 8
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path,$json,$enc)
}

function Normalize-Protocol([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return "" }
    $v = $Value.Trim().ToUpperInvariant()
    if ($v -eq "6") { return "TCP" }
    if ($v -eq "17") { return "UDP" }
    if ($v -eq "1") { return "ICMP" }
    if ($v -eq "58") { return "ICMPV6" }
    return $v
}

function Convert-ProcessIdValue([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return 0 }
    $v = $Value.Trim()
    try {
        if ($v.StartsWith("0x",[System.StringComparison]::OrdinalIgnoreCase)) {
            return [int64]::Parse($v.Substring(2),[System.Globalization.NumberStyles]::HexNumber)
        }
        $n = 0L
        if ([int64]::TryParse($v,[ref]$n)) { return $n }
    } catch {}
    return 0
}

function Get-ExecutableName([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return "" }
    $clean = $Path.Trim().Trim('"')
    if ($clean -eq "System") { return "System" }
    $parts = @($clean -split '[\\/]')
    if ($parts.Count -gt 0) { return [string]$parts[$parts.Count - 1] }
    return $clean
}

function Get-ApplicationDisplayName([string]$Path,[string]$Exe) {
    $p = ([string]$Path).ToLowerInvariant()
    $e = ([string]$Exe).ToLowerInvariant()

    if ($p -match 'tor browser') { return "Tor Browser" }
    switch ($e) {
        "brave.exe" { return "Brave Browser" }
        "chromium.exe" { return "Chromium" }
        "chrome.exe" { return "Google Chrome" }
        "msedge.exe" { return "Microsoft Edge" }
        "firefox.exe" { return "Mozilla Firefox" }
        "opera.exe" { return "Opera" }
        "vivaldi.exe" { return "Vivaldi" }
        "opera_gx.exe" { return "Opera GX" }
        "zen.exe" { return "Zen Browser" }
        "floorp.exe" { return "Floorp" }
        "palemoon.exe" { return "Pale Moon" }
        "seamonkey.exe" { return "SeaMonkey" }
        "duckduckgo.exe" { return "DuckDuckGo Browser" }
        "arc.exe" { return "Arc Browser" }
        "waterfox.exe" { return "Waterfox" }
        "librewolf.exe" { return "LibreWolf" }
        "iexplore.exe" { return "Internet Explorer" }
        "msedgewebview2.exe" { return "Microsoft Edge WebView2" }
        "steamwebhelper.exe" { return "Steam WebHelper" }
        "discord.exe" { return "Discord" }
        "spotify.exe" { return "Spotify" }
        "system" { return "Sistema Windows" }
    }

    if (-not [string]::IsNullOrWhiteSpace($Exe)) { return $Exe }
    if (-not [string]::IsNullOrWhiteSpace($Path)) { return $Path }
    return "Aplicacion desconocida"
}

# Solo procesos de navegadores completos. NO incluir WebView2 ni helpers:
# msedgewebview2.exe, steamwebhelper.exe y otros son componentes de apps.
function Test-BrowserExecutable([string]$Exe) {
    if ([string]::IsNullOrWhiteSpace($Exe)) { return $false }
    $name = $Exe.Trim().ToLowerInvariant()
    return (@(
        "brave.exe", "chrome.exe", "chromium.exe", "msedge.exe", "firefox.exe",
        "opera.exe", "opera_gx.exe", "vivaldi.exe", "waterfox.exe",
        "librewolf.exe", "iexplore.exe", "zen.exe", "floorp.exe",
        "palemoon.exe", "seamonkey.exe", "duckduckgo.exe", "arc.exe"
    ) -contains $name)
}

# Fuente AUTORITATIVA: eventos 5152/5157 indican proceso e IP que
# intento alcanzar. No se infiere la app por coincidencia de IP/puerto/tiempo:
# una IP compartida por Windows y Chrome nunca atribuye trafico de Windows
# al navegador.
function Add-BrowserAttempt {
    param(
        [string]$Ip,
        [string]$Port,
        [string]$Protocol,
        [string]$ApplicationPath,
        [int64]$ProcessId,
        [datetime]$SeenTime,
        [int]$EventId,
        [ValidateSet('Inbound','Outbound')][string]$Direction
    )

    $exe = Get-ExecutableName $ApplicationPath
    if (-not (Test-BrowserExecutable $exe)) { return $false }

    $cleanIp = Normalize-Ip $Ip
    if ([string]::IsNullOrWhiteSpace($cleanIp)) { return $false }
    $cleanProto = Normalize-Protocol $Protocol
    if ([string]::IsNullOrWhiteSpace($cleanProto)) { return $false }

    $seenUnix = Get-UnixTime $SeenTime
    $seen = $SeenTime.ToString("yyyy-MM-dd HH:mm:ss")
    $appName = Get-ApplicationDisplayName $ApplicationPath $exe
    # Separar incluso dos navegadores basados en firefox.exe con rutas distintas.
    $key = "$Direction|$cleanIp|$Port|$cleanProto|$($ApplicationPath.ToLowerInvariant())"

    if ($requests.ContainsKey($key)) {
        $item = $requests[$key]
        if ($seenUnix -gt [int64]$item["last_seen_unix"]) {
            $item["last_seen_unix"] = $seenUnix
            $item["last_seen"] = $seen
            $item["process_id"] = $ProcessId
            $item["application_path"] = $ApplicationPath
            $item["application_source"] = $(if ($EventId -eq 5152) { "WFP 5152 (directo)" } else { "WFP 5157 (directo)" })
            $item["wfp_event_id"] = $EventId
        }
        $item["count"] = [int]$item["count"] + 1
    } else {
        $requests[$key] = [ordered]@{
            browser_verified=$true
            direction=$Direction
            domain=""
            domain_source=""
            domain_confidence=0
            domain_candidates=@()
            reverse_dns=""
            provider_hint=""
            application=$appName
            application_exe=$exe
            application_path=$ApplicationPath
            process_id=$ProcessId
            application_source=$(if ($EventId -eq 5152) { "WFP 5152 (directo)" } else { "WFP 5157 (directo)" })
            wfp_event_id=$EventId
            application_confidence=100
            application_candidates=@()
            ip=$cleanIp
            port=$Port
            protocol=$cleanProto
            first_seen=$seen
            last_seen=$seen
            first_seen_unix=$seenUnix
            last_seen_unix=$seenUnix
            count=1
        }
    }
    return $true
}

function Update-BrowserRequestsFromWfpEvents {
    $script:wfpEventsThisCycle = 0
    $script:wfp5152EventsThisCycle = 0
    $script:wfp5157EventsThisCycle = 0
    $script:browserEventsThisCycle = 0
    $script:wfpReadError = ""
    $script:wfpParseFailures = 0
    $script:lastWfpParseError = ""
    try {
        $log = Get-WinEvent -ListLog $SecurityLogName -ErrorAction Stop
        $script:wfpEventLogAvailable = [bool]$log.IsEnabled
        if (-not $script:wfpEventLogAvailable) {
            $script:wfpReadError = "El registro Security esta desactivado."
            return
        }

        # 5157 = conexion bloqueada; 5152 = paquete bloqueado.
        # Ambos contienen la ruta del ejecutable. El log de firewall de texto
        # no se usa porque no identifica de modo fiable el proceso.
        $events = @()
        try {
            if ($script:lastWfpRecordId -gt 0) {
                $xpath = "*[System[((EventID=5152) or (EventID=5157)) and (EventRecordID > $($script:lastWfpRecordId))]]"
                $events = @(Get-WinEvent -LogName $SecurityLogName -FilterXPath $xpath -MaxEvents 650 -Oldest -ErrorAction Stop)
            } else {
                $events = @(Get-WinEvent -FilterHashtable @{LogName=$SecurityLogName;Id=@(5152,5157);StartTime=(Get-Date).AddMinutes(-3)} -MaxEvents 650 -Oldest -ErrorAction Stop)
            }
        } catch {
            # No encontrar eventos es normal; otros errores se muestran.
            if ([string]$_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') { return }
            throw
        }
        if ($events.Count -eq 0) { return }

        foreach ($ev in @($events | Sort-Object RecordId)) {
            # Adelantar el cursor aunque la entrada sea de Windows. Si hay
            # gran volumen, el siguiente ciclo continua desde este registro.
            if ([int64]$ev.RecordId -gt $script:lastWfpRecordId) {
                $script:lastWfpRecordId = [int64]$ev.RecordId
            }
            try {
                $xml = [xml]$ev.ToXml()
                $data = @{}
                foreach ($node in @($xml.Event.EventData.Data)) {
                    $name = [string]$node.Name
                    if (-not [string]::IsNullOrWhiteSpace($name)) {
                        $data[$name] = [string]$node.InnerText
                    }
                }
                if (-not $data.ContainsKey("Direction") -or -not $data.ContainsKey("Application")) { continue }
                $rawDirection = ([string]$data["Direction"]).Trim()
                if (@("%%14593","14593","Outbound","Saliente") -contains $rawDirection) {
                    $direction = 'Outbound'
                    $remoteIpField = 'DestAddress'
                    $remotePortField = 'DestPort'
                } elseif (@("%%14592","14592","Inbound","Entrante") -contains $rawDirection) {
                    $direction = 'Inbound'
                    $remoteIpField = 'SourceAddress'
                    $remotePortField = 'SourcePort'
                } else { continue }
                if (-not $data.ContainsKey($remoteIpField)) { continue }
                $script:wfpEventsThisCycle++
                if ($ev.Id -eq 5152) { $script:wfp5152EventsThisCycle++ }
                if ($ev.Id -eq 5157) { $script:wfp5157EventsThisCycle++ }

                $appPath = [string]$data["Application"]
                if (-not (Test-BrowserExecutable (Get-ExecutableName $appPath))) { continue }

                $ip = Normalize-Ip ([string]$data[$remoteIpField])
                if ([string]::IsNullOrWhiteSpace($ip)) { continue }
                $port = $(if ($data.ContainsKey($remotePortField)) { [string]$data[$remotePortField] } else { "" })
                $proto = $(if ($data.ContainsKey("Protocol")) { [string]$data["Protocol"] } else { "" })
                $eventProcessId = $(if ($data.ContainsKey("ProcessID")) { Convert-ProcessIdValue ([string]$data["ProcessID"]) } else { 0 })

                if (Add-BrowserAttempt -Ip $ip -Port $port -Protocol $proto -ApplicationPath $appPath -ProcessId $eventProcessId -SeenTime $ev.TimeCreated -EventId ([int]$ev.Id) -Direction $direction) {
                    $script:browserEventsThisCycle++
                    $script:browserEventsSinceStart++
                }
            } catch {
                $script:wfpParseFailures++
                $script:lastWfpParseError = $_.Exception.Message
            }
        }
    } catch {
        $script:wfpEventLogAvailable = $false
        $script:wfpReadError = $_.Exception.Message
    }
}

# La accion 'Limpiar datos' debe dejar descartados los eventos previos.
function Mark-CurrentWfpEvents-AsProcessed {
    try {
        $last = @(Get-WinEvent -LogName $SecurityLogName -MaxEvents 1 -ErrorAction SilentlyContinue)
        if ($last.Count -gt 0 -and [int64]$last[0].RecordId -gt $script:lastWfpRecordId) {
            $script:lastWfpRecordId = [int64]$last[0].RecordId
        }
    } catch {}
}

function Load-Requests {
    $map = @{}
    try {
        if (Test-Path -LiteralPath $RequestsPath) {
            $raw = [System.IO.File]::ReadAllText($RequestsPath)
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                $arr = $raw | ConvertFrom-Json
                foreach ($x in @($arr)) {
                    # Migracion: ignorar intentos antiguos basados en logs DROP
                    # y cualquier fila sin procedencia directa del navegador.
                    $isVerified = ($null -ne $x.PSObject.Properties["browser_verified"] -and $x.browser_verified -eq $true)
                    $exe = [string]$x.application_exe
                    $isDirect = (@("WFP 5157 (directo)", "WFP 5152 (directo)") -contains [string]$x.application_source)
                    if ($isVerified -and $isDirect -and (Test-BrowserExecutable $exe) -and $null -ne $x.ip -and [string]$x.ip -ne "") {
                        $appPathKey = ([string]$x.application_path).ToLowerInvariant()
                        # Migracion: solicitudes previas sin direccion eran salientes.
                        $storedDirection = $(if ([string]$x.direction -eq 'Inbound') { 'Inbound' } else { 'Outbound' })
                        $key = "$storedDirection|$($x.ip)|$($x.port)|$($x.protocol)|$appPathKey"
                        $candidates = @()
                        if ($null -ne $x.PSObject.Properties["domain_candidates"]) {
                            foreach ($candidate in @($x.domain_candidates)) {
                                if (-not [string]::IsNullOrWhiteSpace([string]$candidate)) {
                                    $candidates += [string]$candidate
                                }
                            }
                        }
                        $appCandidates = @()
                        if ($null -ne $x.PSObject.Properties["application_candidates"]) {
                            foreach ($candidate in @($x.application_candidates)) {
                                if (-not [string]::IsNullOrWhiteSpace([string]$candidate)) {
                                    $appCandidates += [string]$candidate
                                }
                            }
                        }
                        $map[$key] = [ordered]@{
                            browser_verified=$true
                            direction=$storedDirection
                            domain=[string]$x.domain
                            domain_source=$(if ($null -ne $x.PSObject.Properties["domain_source"]) { [string]$x.domain_source } else { "" })
                            domain_confidence=$(if ($null -ne $x.PSObject.Properties["domain_confidence"]) { [int]$x.domain_confidence } else { 0 })
                            domain_candidates=$candidates
                            reverse_dns=$(if ($null -ne $x.PSObject.Properties["reverse_dns"]) { [string]$x.reverse_dns } else { "" })
                            provider_hint=$(if ($null -ne $x.PSObject.Properties["provider_hint"]) { [string]$x.provider_hint } else { "" })
                            application=$(if ($null -ne $x.PSObject.Properties["application"]) { [string]$x.application } else { "" })
                            application_exe=$(if ($null -ne $x.PSObject.Properties["application_exe"]) { [string]$x.application_exe } else { "" })
                            application_path=$(if ($null -ne $x.PSObject.Properties["application_path"]) { [string]$x.application_path } else { "" })
                            process_id=$(if ($null -ne $x.PSObject.Properties["process_id"]) { [int64]$x.process_id } else { 0 })
                            application_source=$(if ($null -ne $x.PSObject.Properties["application_source"]) { [string]$x.application_source } else { "" })
                            wfp_event_id=$(if ($null -ne $x.PSObject.Properties["wfp_event_id"]) { [int]$x.wfp_event_id } else { 5157 })
                            application_confidence=$(if ($null -ne $x.PSObject.Properties["application_confidence"]) { [int]$x.application_confidence } else { 0 })
                            application_candidates=$appCandidates
                            ip=[string]$x.ip
                            port=[string]$x.port
                            protocol=[string]$x.protocol
                            first_seen=[string]$x.first_seen
                            last_seen=[string]$x.last_seen
                            first_seen_unix=$(if ($null -ne $x.PSObject.Properties["first_seen_unix"]) { [int64]$x.first_seen_unix } else { 0 })
                            last_seen_unix=$(if ($null -ne $x.PSObject.Properties["last_seen_unix"]) { [int64]$x.last_seen_unix } else { 0 })
                            count=[int]$x.count
                        }
                    }
                }
            }
        }
    } catch {}
    return $map
}

function Add-DnsObservation {
    param(
        [string]$Ip,
        [string]$Domain,
        [int]$Score,
        [string]$Source,
        [int64]$SeenUnix = 0
    )

    $cleanIp = Normalize-Ip $Ip
    $cleanDomain = Normalize-Domain $Domain
    if ([string]::IsNullOrWhiteSpace($cleanIp) -or [string]::IsNullOrWhiteSpace($cleanDomain)) { return }
    if ($SeenUnix -le 0) { $SeenUnix = Get-UnixTime }

    if (-not $script:dnsHistory.ContainsKey($cleanIp)) {
        $script:dnsHistory[$cleanIp] = @{}
    }
    $perIp = $script:dnsHistory[$cleanIp]

    if ($perIp.ContainsKey($cleanDomain)) {
        $obs = $perIp[$cleanDomain]
        if ($SeenUnix -gt [int64]$obs["last_seen_unix"]) { $obs["last_seen_unix"] = $SeenUnix }
        if ($Score -gt [int]$obs["score"]) {
            $obs["score"] = $Score
            $obs["source"] = $Source
        }
    } else {
        $perIp[$cleanDomain] = [ordered]@{
            score=$Score
            source=$Source
            last_seen_unix=$SeenUnix
        }
    }
}

function Prune-DnsHistory([int]$MaxAgeSeconds = 1200) {
    $now = Get-UnixTime
    foreach ($ip in @($script:dnsHistory.Keys)) {
        $perIp = $script:dnsHistory[$ip]
        foreach ($name in @($perIp.Keys)) {
            $last = [int64]$perIp[$name]["last_seen_unix"]
            if ($last -le 0 -or ($now - $last) -gt $MaxAgeSeconds) {
                $perIp.Remove($name)
            }
        }
        if ($perIp.Count -eq 0) {
            $script:dnsHistory.Remove($ip)
        }
    }
}

function Parse-DnsResultIps([string]$Results) {
    $out = @()
    if ([string]::IsNullOrWhiteSpace($Results)) { return $out }

    foreach ($piece in @($Results -split ';')) {
        $token = $piece.Trim()
        if ([string]::IsNullOrWhiteSpace($token)) { continue }
        $token = $token -replace '^type:\s*\d+\s+', ''
        $ip = Normalize-Ip $token
        if (-not [string]::IsNullOrWhiteSpace($ip) -and $out -notcontains $ip) {
            $out += $ip
        }
    }
    return $out
}

function Update-DnsHistoryFromEvents {
    $script:dnsEventsThisCycle = 0
    try {
        $logInfo = Get-WinEvent -ListLog $DnsEventLogName -ErrorAction Stop
        $script:dnsEventLogAvailable = [bool]$logInfo.IsEnabled
        if (-not $script:dnsEventLogAvailable) { return }

        $events = @()
        if ($script:lastDnsRecordId -gt 0) {
            $xpath = "*[System[(EventID=3008) and (EventRecordID > $($script:lastDnsRecordId))]]"
            $events = @(Get-WinEvent -LogName $DnsEventLogName -FilterXPath $xpath -MaxEvents 250 -ErrorAction SilentlyContinue)
        } else {
            $events = @(Get-WinEvent -FilterHashtable @{LogName=$DnsEventLogName; Id=3008; StartTime=(Get-Date).AddMinutes(-10)} -MaxEvents 300 -ErrorAction SilentlyContinue)
        }

        if ($events.Count -eq 0) { return }
        $events = @($events | Sort-Object RecordId)

        foreach ($ev in $events) {
            if ([int64]$ev.RecordId -gt $script:lastDnsRecordId) {
                $script:lastDnsRecordId = [int64]$ev.RecordId
            }

            try {
                $xml = [xml]$ev.ToXml()
                $data = @{}
                foreach ($node in @($xml.Event.EventData.Data)) {
                    $fieldName = [string]$node.Name
                    if (-not [string]::IsNullOrWhiteSpace($fieldName)) {
                        $data[$fieldName] = [string]$node.InnerText
                    }
                }

                if (-not $data.ContainsKey("QueryStatus") -or [string]$data["QueryStatus"] -ne "0") { continue }
                $queryName = Normalize-Domain ([string]$data["QueryName"])
                if ([string]::IsNullOrWhiteSpace($queryName)) { continue }
                if (-not $data.ContainsKey("QueryResults")) { continue }

                $ips = @(Parse-DnsResultIps ([string]$data["QueryResults"]))
                if ($ips.Count -eq 0) { continue }
                $seenUnix = Get-UnixTime $ev.TimeCreated

                foreach ($ip in $ips) {
                    Add-DnsObservation -Ip $ip -Domain $queryName -Score 100 -Source "DNS reciente" -SeenUnix $seenUnix
                }
                $script:dnsEventsThisCycle++
            } catch {}
        }
    } catch {
        $script:dnsEventLogAvailable = $false
    }
}

function Update-DnsHistoryFromCache {
    try {
        $records = @(Get-DnsClientCache -ErrorAction SilentlyContinue)
        if ($records.Count -eq 0) { return }

        $ipOwners = @{}
        $targetToAliases = @{}

        foreach ($r in $records) {
            $owner = ""
            if ($null -ne $r.Entry) { $owner = Normalize-Domain ([string]$r.Entry) }
            if ([string]::IsNullOrWhiteSpace($owner) -and $null -ne $r.RecordName) {
                $owner = Normalize-Domain ([string]$r.RecordName)
            }
            if ([string]::IsNullOrWhiteSpace($owner)) { continue }

            $data = ""
            if ($null -ne $r.Data) { $data = [string]$r.Data }
            if ([string]::IsNullOrWhiteSpace($data)) { continue }

            $ip = Normalize-Ip $data
            if (-not [string]::IsNullOrWhiteSpace($ip)) {
                if (-not $ipOwners.ContainsKey($ip)) { $ipOwners[$ip] = @() }
                if (@($ipOwners[$ip]) -notcontains $owner) {
                    $ipOwners[$ip] = @($ipOwners[$ip]) + $owner
                }
                continue
            }

            $target = Normalize-Domain $data
            if (-not [string]::IsNullOrWhiteSpace($target) -and $target -ne $owner) {
                if (-not $targetToAliases.ContainsKey($target)) { $targetToAliases[$target] = @() }
                if (@($targetToAliases[$target]) -notcontains $owner) {
                    $targetToAliases[$target] = @($targetToAliases[$target]) + $owner
                }
            }
        }

        $now = Get-UnixTime
        foreach ($ip in @($ipOwners.Keys)) {
            foreach ($owner in @($ipOwners[$ip])) {
                Add-DnsObservation -Ip $ip -Domain $owner -Score 82 -Source "Caché DNS" -SeenUnix $now

                $frontier = @($owner)
                $seenNames = @{}
                $seenNames[$owner] = 1
                for ($depth = 1; $depth -le 4; $depth++) {
                    $next = @()
                    foreach ($target in $frontier) {
                        if (-not $targetToAliases.ContainsKey($target)) { continue }
                        foreach ($alias in @($targetToAliases[$target])) {
                            if ($seenNames.ContainsKey($alias)) { continue }
                            $seenNames[$alias] = 1
                            $score = [Math]::Max(84, 96 - (($depth - 1) * 3))
                            Add-DnsObservation -Ip $ip -Domain $alias -Score $score -Source "CNAME" -SeenUnix $now
                            $next += $alias
                        }
                    }
                    if ($next.Count -eq 0) { break }
                    $frontier = $next
                }
            }
        }
    } catch {}
}

function Get-DomainCandidates {
    param(
        [string]$Ip,
        [int64]$ReferenceUnix = 0,
        [int]$Limit = 6
    )

    $cleanIp = Normalize-Ip $Ip
    if ([string]::IsNullOrWhiteSpace($cleanIp) -or -not $script:dnsHistory.ContainsKey($cleanIp)) { return @() }
    if ($ReferenceUnix -le 0) { $ReferenceUnix = Get-UnixTime }

    $items = @()
    foreach ($name in @($script:dnsHistory[$cleanIp].Keys)) {
        $obs = $script:dnsHistory[$cleanIp][$name]
        $last = [int64]$obs["last_seen_unix"]
        $delta = [Math]::Abs($ReferenceUnix - $last)
        if ($delta -gt 1200) { continue }

        $score = [int]$obs["score"]
        if ($delta -gt 600) { $score -= 25 }
        elseif ($delta -gt 180) { $score -= 15 }
        elseif ($delta -gt 60) { $score -= 7 }
        elseif ($delta -gt 20) { $score -= 2 }
        $score = [Math]::Max(1,[Math]::Min(100,$score))

        $items += [pscustomobject]@{
            name=$name
            score=$score
            source=[string]$obs["source"]
            delta=[int64]$delta
        }
    }

    if ($items.Count -eq 0) { return @() }
    return @($items | Sort-Object @{Expression='score';Descending=$true}, @{Expression='delta';Ascending=$true}, @{Expression='name';Ascending=$true} | Select-Object -First $Limit)
}

function Enrich-Domains {
    $matched = 0
    foreach ($key in @($requests.Keys)) {
        $item = $requests[$key]
        $ip = [string]$item["ip"]
        $reference = [int64]$item["last_seen_unix"]
        $candidates = @(Get-DomainCandidates -Ip $ip -ReferenceUnix $reference -Limit 6)
        if ($candidates.Count -eq 0) { continue }

        $names = @()
        foreach ($candidate in $candidates) {
            if ($names -notcontains [string]$candidate.name) { $names += [string]$candidate.name }
        }
        $item["domain_candidates"] = $names

        $best = $candidates[0]
        $currentConfidence = 0
        try { $currentConfidence = [int]$item["domain_confidence"] } catch {}
        $currentDomain = [string]$item["domain"]

        if ([string]::IsNullOrWhiteSpace($currentDomain) -or [int]$best.score -ge $currentConfidence) {
            $item["domain"] = [string]$best.name
            $item["domain_source"] = [string]$best.source
            $item["domain_confidence"] = [int]$best.score
        }
        $matched++
    }
    return $matched
}

function Get-ReverseDns([string]$Ip) {
    if ([string]::IsNullOrWhiteSpace($Ip)) { return "" }
    if ($reverseDnsCache.ContainsKey($Ip)) { return [string]$reverseDnsCache[$Ip] }

    $name = ""
    try {
        $cmd = Get-Command Resolve-DnsName -ErrorAction SilentlyContinue
        if ($null -ne $cmd) {
            $answers = @(Resolve-DnsName -Name $Ip -Type PTR -DnsOnly -QuickTimeout -ErrorAction Stop)
            foreach ($answer in $answers) {
                if ($null -ne $answer.PSObject.Properties["NameHost"]) {
                    $candidate = [string]$answer.NameHost
                    if (-not [string]::IsNullOrWhiteSpace($candidate)) {
                        $name = $candidate.TrimEnd(".")
                        break
                    }
                }
            }
        } else {
            $entry = [System.Net.Dns]::GetHostEntry($Ip)
            if ($null -ne $entry -and -not [string]::IsNullOrWhiteSpace([string]$entry.HostName)) {
                $name = ([string]$entry.HostName).TrimEnd(".")
                if ($name -eq $Ip) { $name = "" }
            }
        }
    } catch {
        $name = ""
    }

    $reverseDnsCache[$Ip] = $name
    return $name
}

function Get-ProviderHint([string]$HostName) {
    if ([string]::IsNullOrWhiteSpace($HostName)) { return "" }
    $n = $HostName.ToLowerInvariant()
    if ($n -match 'cloudflare|\.cloudflare\.net$') { return "Cloudflare" }
    if ($n -match 'cloudfront\.net$|amazonaws\.com$|\.aws$') { return "Amazon Web Services" }
    if ($n -match 'googleusercontent\.com$|1e100\.net$|\.google\.com$') { return "Google" }
    if ($n -match 'azure|microsoft|windows\.net$|cloudapp\.') { return "Microsoft / Azure" }
    if ($n -match 'akamai|akamaiedge|edgekey\.net$') { return "Akamai" }
    if ($n -match 'fastly\.net$|fastlylb\.net$') { return "Fastly" }
    if ($n -match 'cdn77|cdn77\.org$') { return "CDN77" }
    return ""
}

function Enrich-ReverseDns([int]$MaxLookups = 3) {
    $targets = @()

    foreach ($key in @($requests.Keys)) {
        $item = $requests[$key]
        $ip = [string]$item["ip"]
        $current = [string]$item["reverse_dns"]

        if ([string]::IsNullOrWhiteSpace($ip)) { continue }
        if (-not [string]::IsNullOrWhiteSpace($current)) {
            if ([string]::IsNullOrWhiteSpace([string]$item["provider_hint"])) {
                $item["provider_hint"] = Get-ProviderHint $current
            }
            continue
        }
        if ($reverseDnsCache.ContainsKey($ip)) { continue }
        if ($targets -contains $ip) { continue }

        $targets += $ip
        if ($targets.Count -ge $MaxLookups) { break }
    }

    foreach ($ip in $targets) {
        $name = Get-ReverseDns $ip
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $provider = Get-ProviderHint $name

        foreach ($key in @($requests.Keys)) {
            if ([string]$requests[$key]["ip"] -eq $ip) {
                $requests[$key]["reverse_dns"] = $name
                if (-not [string]::IsNullOrWhiteSpace($provider)) {
                    $requests[$key]["provider_hint"] = $provider
                }
            }
        }
    }
}

function Write-Status([string]$err,[int]$domainMatches) {
    $obj = [ordered]@{
        agent_version=$AgentVersion
        heartbeat=(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        heartbeat_unix=[int64](Get-UnixTime)
        firewall_log_exists=(Test-Path -LiteralPath $FirewallLog)
        dns_event_log_available=$script:dnsEventLogAvailable
        dns_events_last_cycle=$script:dnsEventsThisCycle
        domain_matches_last_cycle=$domainMatches
        wfp_security_log_available=$script:wfpEventLogAvailable
        wfp_audit_configured=(Test-Path -LiteralPath $WfpAuditConfiguredMarker)
        wfp_packet_audit_configured=(Test-Path -LiteralPath $WfpPacketAuditMarker)
        wfp_events_last_cycle=$script:wfpEventsThisCycle
        wfp_5152_events_last_cycle=$script:wfp5152EventsThisCycle
        wfp_5157_events_last_cycle=$script:wfp5157EventsThisCycle
        wfp_last_record_id=$script:lastWfpRecordId
        wfp_read_error=$script:wfpReadError
        wfp_parse_errors_last_cycle=$script:wfpParseFailures
        wfp_last_parse_error=$script:lastWfpParseError
        browser_events_last_cycle=$script:browserEventsThisCycle
        browser_events_since_start=$script:browserEventsSinceStart
        browser_destinations_total=$requests.Count
        strict_mode='allowlist-only'
        strict_hermetic=$script:strictHermetic
        strict_profiles_ok=$script:strictProfilesOk
        strict_block_rules_inbound=$script:strictInboundRules
        strict_block_rules_outbound=$script:strictOutboundRules
        strict_allow_bypass_rules=$script:strictAllowBypassRules
        strict_foreign_local_rules=$script:strictForeignLocalRules
        strict_disabled_rules_last_cycle=$script:strictDisabledThisCycle
        strict_error=$script:strictError
        last_error=$err
    }
    try { Save-Json $StatusPath $obj } catch {}
}

# No reimportar bloqueos anteriores al reiniciar el agente o al usar Limpiar.
try {
    if (Test-Path -LiteralPath $WfpCursorPath) {
        $storedCursor = [int64]::Parse(([System.IO.File]::ReadAllText($WfpCursorPath)).Trim())
        if ($storedCursor -ge 0) { $script:lastWfpRecordId = $storedCursor }
    }
    if ($script:lastWfpRecordId -gt 0) {
        $newestSecurity = @(Get-WinEvent -LogName $SecurityLogName -MaxEvents 1 -ErrorAction SilentlyContinue)
        if ($newestSecurity.Count -gt 0 -and [int64]$newestSecurity[0].RecordId -lt $script:lastWfpRecordId) {
            $script:lastWfpRecordId = 0
        }
    }
} catch { $script:lastWfpRecordId = 0 }

$requests = Load-Requests
$lastError = ""

# Publicar estado inmediatamente. En 4.4 el primer heartbeat se escribia solo
# despues de un ciclo completo de WFP/DNS; en equipos con registros grandes el
# instalador agotaba su espera y mostraba ERROR aunque el agente ya estuviera vivo.
try {
    if (Get-Command Test-IPWallStrictIntegrity -ErrorAction SilentlyContinue) {
        $strictBoot = Test-IPWallStrictIntegrity
        $script:strictHermetic = [bool]$strictBoot.Hermetic
        $script:strictProfilesOk = [bool]$strictBoot.ProfilesOk
        $script:strictInboundRules = [int]$strictBoot.StrictInboundRules
        $script:strictOutboundRules = [int]$strictBoot.StrictOutboundRules
        $script:strictAllowBypassRules = [int]$strictBoot.AllowBypassRules
        $script:strictForeignLocalRules = [int]$strictBoot.ForeignEnabledLocalRules
        $script:strictDisabledThisCycle = [int]$strictBoot.DisabledThisCycle
        $script:strictError = ''
    }
} catch {
    $script:strictHermetic = $false
    $script:strictError = $_.Exception.Message
}
Write-Status $lastError 0

while ($true) {
    $domainMatches = 0
    try {
        # Restauración solicitada desde index.php. El agente ya corre como SYSTEM,
        # por lo que no hace falta abrir PowerShell ni pedir una segunda elevación.
        if (Test-Path -LiteralPath $RestoreFlag) {
            Remove-Item -LiteralPath $RestoreFlag -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path -LiteralPath $RestoreScript)) {
                throw "No existe restore-firewall.ps1 en el proyecto."
            }
            & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File $RestoreScript -ProjectDir $ProjectDir -ResultFile $ControlStatusPath -FromAgent
            if ($LASTEXITCODE -ne 0) {
                throw "La restauración solicitada desde el panel falló con código $LASTEXITCODE."
            }
            exit 0
        }

        if (Test-Path -LiteralPath $ClearFlag) {
            $requests = @{}
            $script:dnsHistory = @{}
            $script:browserEventsSinceStart = 0
            Mark-CurrentWfpEvents-AsProcessed
            Save-Json $RequestsPath @()
            Remove-Item -LiteralPath $ClearFlag -Force -ErrorAction SilentlyContinue
        }

        if (-not (Test-Path -LiteralPath $InboundWhitelistPath)) {
            [System.IO.File]::WriteAllText($InboundWhitelistPath, '', [System.Text.Encoding]::ASCII)
        }
        if ((Test-Path -LiteralPath $WhitelistPath) -and (Test-Path -LiteralPath $InboundWhitelistPath)) {
            $hash = (Get-FileHash -LiteralPath $WhitelistPath -Algorithm SHA256).Hash + '|' + (Get-FileHash -LiteralPath $InboundWhitelistPath -Algorithm SHA256).Hash
            if ($hash -ne $lastWhitelistHash) {
                try {
                    & $ApplyScript -WhitelistPath $WhitelistPath -InboundWhitelistPath $InboundWhitelistPath -StateDir $StateDir
                    $lastWhitelistHash = $hash
                } catch {
                    throw ("No se pudo aplicar la whitelist: " + $_.Exception.Message)
                }
            }
        }

        # Guardia continua: mantiene perfiles en Block, deshabilita reglas locales
        # ajenas y verifica que no haya reglas Allow-Bypass capaces de saltarse
        # los bloques explicitos del complemento de la whitelist.
        if (Get-Command Test-IPWallStrictIntegrity -ErrorAction SilentlyContinue) {
            try {
                $strict = Test-IPWallStrictIntegrity
                $script:strictHermetic = [bool]$strict.Hermetic
                $script:strictProfilesOk = [bool]$strict.ProfilesOk
                $script:strictInboundRules = [int]$strict.StrictInboundRules
                $script:strictOutboundRules = [int]$strict.StrictOutboundRules
                $script:strictAllowBypassRules = [int]$strict.AllowBypassRules
                $script:strictForeignLocalRules = [int]$strict.ForeignEnabledLocalRules
                $script:strictDisabledThisCycle = [int]$strict.DisabledThisCycle
                $script:strictError = ''
            } catch {
                $script:strictHermetic = $false
                $script:strictError = $_.Exception.Message
            }
        } else {
            $script:strictHermetic = $false
            if ([string]::IsNullOrWhiteSpace($script:strictError)) { $script:strictError = 'No se cargo strict-firewall.ps1.' }
        }

        # Detectar y PUBLICAR primero. En 4.4 la IP no se escribia hasta
        # terminar DNS/cache/PTR; un lookup lento hacia parecer que el panel no
        # actualizaba. Ahora WFP -> requests.json ocurre antes del enriquecido.
        Update-BrowserRequestsFromWfpEvents
        $items = @($requests.Values | Sort-Object last_seen_unix -Descending | Select-Object -First 500)
        Save-Json $RequestsPath $items
        try {
            [System.IO.File]::WriteAllText($WfpCursorPath, [string]$script:lastWfpRecordId, [System.Text.Encoding]::ASCII)
        } catch {}
        # Mantener heartbeat fresco antes de cualquier lookup DNS potencialmente lento.
        Write-Status $lastError 0

        # DNS solo enriquece el nombre. NUNCA determina si una IP entra en
        # la lista; eso depende exclusivamente del proceso WFP del navegador.
        Update-DnsHistoryFromEvents
        Update-DnsHistoryFromCache
        Prune-DnsHistory -MaxAgeSeconds 1200
        $domainMatches = Enrich-Domains
        Enrich-ReverseDns -MaxLookups 3

        # Segunda publicacion: misma IP, ahora con dominio/PTR si hubo respuesta.
        $items = @($requests.Values | Sort-Object last_seen_unix -Descending | Select-Object -First 500)
        Save-Json $RequestsPath $items
        $lastError = ""
    } catch {
        $lastError = $_.Exception.Message
        try {
            Add-Content -LiteralPath $ErrorLog -Value ("[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"),$lastError)
        } catch {}
    }

    Write-Status $lastError $domainMatches
    Start-Sleep -Seconds $IntervalSeconds
}

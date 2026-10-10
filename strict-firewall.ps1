$script:IPWallAllowGroup = "IPWhitelistFirewall"
$script:IPWallStrictBlockGroup = "IPWallStrictBlock"
$script:IPWallLegacyControlGroup = "IPWhitelistControl"

function Assert-IPWallFirewallPlatform {
    try { Import-Module NetSecurity -ErrorAction Stop } catch {
        throw "No se pudo cargar el modulo NetSecurity: $($_.Exception.Message)"
    }

    foreach ($serviceName in @('BFE','MpsSvc')) {
        try {
            $svc = Get-Service -Name $serviceName -ErrorAction Stop
            if ($svc.Status -ne 'Running') {
                Start-Service -Name $serviceName -ErrorAction Stop
                $svc.WaitForStatus('Running',[TimeSpan]::FromSeconds(12))
            }
        } catch {
            throw "El servicio requerido $serviceName no esta disponible/activo: $($_.Exception.Message)"
        }
    }
}

try { Add-Type -AssemblyName System.Numerics -ErrorAction SilentlyContinue } catch {}

function ConvertTo-IPWallBigInteger([System.Net.IPAddress]$Ip) {
    [System.Numerics.BigInteger]$value = [System.Numerics.BigInteger]::Zero
    foreach ($b in $Ip.GetAddressBytes()) {
        $value = ($value * 256) + [int]$b
    }
    return $value
}

function ConvertFrom-IPWallBigInteger([System.Numerics.BigInteger]$Value,[int]$ByteCount) {
    if ($Value -lt 0) { throw "Negative IP integer." }
    $bytes = New-Object byte[] $ByteCount
    [System.Numerics.BigInteger]$v = $Value
    [System.Numerics.BigInteger]$base = 256
    for ($i = $ByteCount - 1; $i -ge 0; $i--) {
        $bytes[$i] = [byte][int]($v % $base)
        $v = [System.Numerics.BigInteger]::Divide($v,$base)
    }
    return [System.Net.IPAddress]::new($bytes)
}

function Get-IPWallEntryInterval([string]$Entry) {
    $parts = @($Entry.Split('/'))
    $ip = [System.Net.IPAddress]::Parse($parts[0])
    $bits = $ip.GetAddressBytes().Length * 8
    $prefix = $(if ($parts.Count -eq 2) { [int]$parts[1] } else { $bits })
    [System.Numerics.BigInteger]$start = ConvertTo-IPWallBigInteger $ip
    $hostBits = $bits - $prefix
    [System.Numerics.BigInteger]$size = [System.Numerics.BigInteger]::Pow(([System.Numerics.BigInteger]2),$hostBits)
    [pscustomobject]@{
        Bits = $bits
        Start = $start
        End = $start + $size - 1
    }
}

function Merge-IPWallIntervals([object[]]$Intervals) {
    if ($null -eq $Intervals -or $Intervals.Count -eq 0) { return @() }
    $sorted = @($Intervals | Sort-Object -Property @{Expression={$_.Start}})
    $merged = New-Object System.Collections.ArrayList
    foreach ($item in $sorted) {
        if ($merged.Count -eq 0) {
            [void]$merged.Add([pscustomobject]@{Start=$item.Start;End=$item.End})
            continue
        }
        $last = $merged[$merged.Count-1]
        if ($item.Start -le ($last.End + 1)) {
            if ($item.End -gt $last.End) { $last.End = $item.End }
        } else {
            [void]$merged.Add([pscustomobject]@{Start=$item.Start;End=$item.End})
        }
    }
    return @($merged)
}

function Format-IPWallRange([System.Numerics.BigInteger]$Start,[System.Numerics.BigInteger]$End,[int]$Bits) {
    $bytes = $Bits / 8
    $a = (ConvertFrom-IPWallBigInteger $Start $bytes).ToString()
    $b = (ConvertFrom-IPWallBigInteger $End $bytes).ToString()
    if ($Start -eq $End) { return $a }
    return "$a-$b"
}

function Get-IPWallComplementForFamily([AllowEmptyCollection()][string[]]$Entries,[int]$Bits) {
    $intervals = @()
    foreach ($entry in @($Entries)) {
        if ([string]::IsNullOrWhiteSpace($entry)) { continue }
        $iv = Get-IPWallEntryInterval $entry
        if ($iv.Bits -eq $Bits) { $intervals += $iv }
    }

    if ($intervals.Count -eq 0) {
        # Algunas compilaciones de NetSecurity rechazan /0, especialmente ::/0,
        # aunque aceptan prefijos IPv6 normales. Dos /1 son exactamente el mismo
        # espacio completo y mantienen el bloqueo explicito sin huecos.
        if ($Bits -eq 32) { return @('0.0.0.0/1','128.0.0.0/1') }
        return @('::/1','8000::/1')
    }

    $merged = @(Merge-IPWallIntervals $intervals)
    [System.Numerics.BigInteger]$max = [System.Numerics.BigInteger]::Pow(([System.Numerics.BigInteger]2),$Bits) - 1
    [System.Numerics.BigInteger]$cursor = [System.Numerics.BigInteger]::Zero
    $ranges = New-Object System.Collections.ArrayList

    foreach ($iv in $merged) {
        if ($iv.Start -gt $cursor) {
            [void]$ranges.Add((Format-IPWallRange $cursor ($iv.Start - 1) $Bits))
        }
        if ($iv.End -ge $max) {
            $cursor = $max + 1
            break
        }
        if (($iv.End + 1) -gt $cursor) { $cursor = $iv.End + 1 }
    }
    if ($cursor -le $max) {
        [void]$ranges.Add((Format-IPWallRange $cursor $max $Bits))
    }
    return @($ranges)
}

function Get-IPWallComplementRanges([AllowEmptyCollection()][string[]]$Entries) {
    $all = @()
    $all += @(Get-IPWallComplementForFamily -Entries $Entries -Bits 32)
    $all += @(Get-IPWallComplementForFamily -Entries $Entries -Bits 128)
    return @($all)
}

function Set-IPWallStrictProfiles {
    New-Item -ItemType Directory -Path "$env:SystemRoot\System32\LogFiles\Firewall" -Force | Out-Null
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
    Set-NetFirewallProfile -Profile Domain,Private,Public `
        -DefaultInboundAction Block `
        -DefaultOutboundAction Block `
        -LogBlocked True `
        -LogAllowed False `
        -LogFileName "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" `
        -LogMaxSizeKilobytes 32767
}

function Disable-IPWallForeignPersistentRules {
    $disabled = 0
    $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Where-Object {
        $_.Enabled -eq 'True' -and
        $_.Group -ne $script:IPWallAllowGroup -and
        $_.Group -ne $script:IPWallStrictBlockGroup
    })
    foreach ($rule in $rules) {
        try {
            Disable-NetFirewallRule -InputObject $rule -ErrorAction Stop | Out-Null
            $disabled++
        } catch {}
    }
    return $disabled
}

function Remove-IPWallLegacyControlFirewallRules {
    Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction SilentlyContinue |
        Where-Object { $_.Group -eq $script:IPWallLegacyControlGroup } |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
}

function New-IPWallChunkedRules {
    param(
        [Parameter(Mandatory=$true)][string]$Generation,
        [Parameter(Mandatory=$true)][ValidateSet('Inbound','Outbound')][string]$Direction,
        [Parameter(Mandatory=$true)][ValidateSet('Allow','Block')][string]$Action,
        [Parameter(Mandatory=$true)][string]$Group,
        [Parameter(Mandatory=$true)][string[]]$RemoteAddresses,
        [Parameter(Mandatory=$true)][string]$NamePrefix
    )

    # Capa de compatibilidad adicional: nunca entregar /0 directamente a
    # New-NetFirewallRule. Si otra ruta vuelve a producirlo, expandirlo en dos
    # /1 equivalentes antes de hablar con NetSecurity.
    $expandedAddresses = New-Object System.Collections.ArrayList
    foreach ($rawAddress in @($RemoteAddresses)) {
        $address = ([string]$rawAddress).Trim()
        if ([string]::IsNullOrWhiteSpace($address)) { continue }
        if ($address -eq '0.0.0.0/0') {
            [void]$expandedAddresses.Add('0.0.0.0/1')
            [void]$expandedAddresses.Add('128.0.0.0/1')
        } elseif ($address -eq '::/0') {
            [void]$expandedAddresses.Add('::/1')
            [void]$expandedAddresses.Add('8000::/1')
        } else {
            [void]$expandedAddresses.Add($address)
        }
    }
    $addresses = @($expandedAddresses | Select-Object -Unique)
    if ($addresses.Count -eq 0) { return @() }

    # Separar IPv4/IPv6 evita diferencias del proveedor NetSecurity de algunas
    # versiones de Windows cuando una sola regla mezcla ambas familias.
    $families = @(
        [pscustomobject]@{Name='v4'; Items=@($addresses | Where-Object { ([string]$_).IndexOf(':') -lt 0 })},
        [pscustomobject]@{Name='v6'; Items=@($addresses | Where-Object { ([string]$_).IndexOf(':') -ge 0 })}
    )

    $created = @()
    $number = 0
    # 40 es deliberadamente conservador. NetSecurity admite arrays, pero el
    # tamano serializado de rangos IPv6 varia entre versiones de Windows.
    $chunkSize = 40

    foreach ($family in $families) {
        $items = @($family.Items)
        if ($items.Count -eq 0) { continue }
        for ($i=0; $i -lt $items.Count; $i += $chunkSize) {
            $end = [Math]::Min($i+$chunkSize-1,$items.Count-1)
            $chunk = @($items[$i..$end])
            $number++
            $dirShort = $(if ($Direction -eq 'Inbound') {'In'} else {'Out'})
            $name = ("IPWall-{0}-{1}-{2}-{3}-{4:D4}" -f $NamePrefix,$Generation,$dirShort,$family.Name,$number)
            $display = ("IPWall-{0}-{1}-{2}-{3:D4}" -f $NamePrefix,$dirShort,$family.Name,$number)
            try {
                $rule = New-NetFirewallRule `
                    -PolicyStore PersistentStore `
                    -Name $name `
                    -DisplayName $display `
                    -Group $Group `
                    -Direction $Direction `
                    -Action $Action `
                    -Enabled True `
                    -Profile Any `
                    -RemoteAddress $chunk `
                    -ErrorAction Stop
                $created += $rule
            } catch {
                $sample = ($chunk | Select-Object -First 3) -join ', '
                throw ("No se pudo crear regla {0}/{1} {2} ({3}, {4} direcciones; muestra: {5}): {6}" -f $Direction,$Action,$display,$family.Name,$chunk.Count,$sample,$_.Exception.Message)
            }
        }
    }
    return @($created)
}

function Install-IPWallStrictRuleSet {
    param(
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][string[]]$OutboundAddresses,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][string[]]$InboundAddresses
    )

    Assert-IPWallFirewallPlatform
    Set-IPWallStrictProfiles
    Remove-IPWallLegacyControlFirewallRules
    [void](Disable-IPWallForeignPersistentRules)

    $oldRules = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Where-Object {
        $_.Group -eq $script:IPWallAllowGroup -or $_.Group -eq $script:IPWallStrictBlockGroup
    })
    $newRules = @()
    $generation = [guid]::NewGuid().ToString('N')

    try {
        # Create explicit deny-complements first. Block rules take precedence over
        # allow rules, so removing an IP from a whitelist becomes fail-closed
        # before any old allow rule is removed.
        $inDeny = @(Get-IPWallComplementRanges -Entries $InboundAddresses)
        $outDeny = @(Get-IPWallComplementRanges -Entries $OutboundAddresses)
        $newRules += @(New-IPWallChunkedRules -Generation $generation -Direction Inbound -Action Block -Group $script:IPWallStrictBlockGroup -RemoteAddresses $inDeny -NamePrefix 'Deny')
        $newRules += @(New-IPWallChunkedRules -Generation $generation -Direction Outbound -Action Block -Group $script:IPWallStrictBlockGroup -RemoteAddresses $outDeny -NamePrefix 'Deny')

        if ($InboundAddresses.Count -gt 0) {
            $newRules += @(New-IPWallChunkedRules -Generation $generation -Direction Inbound -Action Allow -Group $script:IPWallAllowGroup -RemoteAddresses $InboundAddresses -NamePrefix 'Allow')
        }
        if ($OutboundAddresses.Count -gt 0) {
            $newRules += @(New-IPWallChunkedRules -Generation $generation -Direction Outbound -Action Allow -Group $script:IPWallAllowGroup -RemoteAddresses $OutboundAddresses -NamePrefix 'Allow')
        }
    } catch {
        foreach ($rule in $newRules) {
            Remove-NetFirewallRule -InputObject $rule -ErrorAction SilentlyContinue
        }
        throw
    }

    foreach ($rule in $oldRules) {
        Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop
    }

    [void](Disable-IPWallForeignPersistentRules)
}

function Test-IPWallStrictIntegrity {
    Assert-IPWallFirewallPlatform
    $disabled = Disable-IPWallForeignPersistentRules
    Set-IPWallStrictProfiles
    Remove-IPWallLegacyControlFirewallRules

    $profiles = @(Get-NetFirewallProfile -Profile Domain,Private,Public -ErrorAction SilentlyContinue)
    $profilesOk = ($profiles.Count -eq 3)
    foreach ($profile in $profiles) {
        if ([string]$profile.Enabled -ne 'True' -or [string]$profile.DefaultInboundAction -ne 'Block' -or [string]$profile.DefaultOutboundAction -ne 'Block') {
            $profilesOk = $false
        }
    }

    $strictRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object {
        $_.Enabled -eq 'True' -and $_.Action -eq 'Block' -and $_.Group -eq $script:IPWallStrictBlockGroup
    })
    $strictIn = @($strictRules | Where-Object {$_.Direction -eq 'Inbound'}).Count
    $strictOut = @($strictRules | Where-Object {$_.Direction -eq 'Outbound'}).Count

    # Allow-bypass rules can override an explicit block. Query the security
    # filter directly because OverrideBlockRules belongs to that filter.
    $bypass = @()
    try {
        $bypass = @(Get-NetFirewallSecurityFilter -PolicyStore ActiveStore -OverrideBlockRules $true -ErrorAction SilentlyContinue |
            Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {
                $_.Enabled -eq 'True' -and
                $_.Action -eq 'Allow' -and
                $_.Group -ne $script:IPWallAllowGroup
            })
    } catch { $bypass = @() }

    $foreignEnabledLocal = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Where-Object {
        $_.Enabled -eq 'True' -and
        $_.Group -ne $script:IPWallAllowGroup -and
        $_.Group -ne $script:IPWallStrictBlockGroup
    }).Count

    # Las reglas Allow normales ajenas no abren un hueco: un Block explicito
    # coincidente tiene precedencia. Se siguen deshabilitando por higiene, pero
    # no convierten por si solas el estado en falso negativo. Un Allow-Bypass si.
    $hermetic = ($profilesOk -and $strictIn -gt 0 -and $strictOut -gt 0 -and $bypass.Count -eq 0)
    [pscustomobject]@{
        Hermetic = $hermetic
        ProfilesOk = $profilesOk
        StrictInboundRules = $strictIn
        StrictOutboundRules = $strictOut
        AllowBypassRules = $bypass.Count
        ForeignEnabledLocalRules = $foreignEnabledLocal
        DisabledThisCycle = $disabled
    }
}

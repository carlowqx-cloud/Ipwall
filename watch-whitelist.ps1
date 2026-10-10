param(
    [string]$WhitelistPath = "C:\xampp\htdocs\ipwall\whitelist.txt",
    [string]$InboundWhitelistPath = "C:\xampp\htdocs\ipwall\whitelist-inbound.txt",
    [string]$ApplyScript = "C:\xampp\htdocs\ipwall\apply-whitelist.ps1",
    [int]$IntervalSeconds = 1
)

$ErrorActionPreference = "Continue"
$lastHash = ""

while ($true) {
    try {
        if (-not (Test-Path -LiteralPath $InboundWhitelistPath)) {
            [System.IO.File]::WriteAllText($InboundWhitelistPath,'',[System.Text.Encoding]::ASCII)
        }
        if ((Test-Path -LiteralPath $WhitelistPath) -and (Test-Path -LiteralPath $InboundWhitelistPath)) {
            $hash = (Get-FileHash -LiteralPath $WhitelistPath -Algorithm SHA256).Hash + '|' + (Get-FileHash -LiteralPath $InboundWhitelistPath -Algorithm SHA256).Hash
            if ($hash -ne $lastHash) {
                & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ApplyScript -WhitelistPath $WhitelistPath -InboundWhitelistPath $InboundWhitelistPath
                if ($LASTEXITCODE -eq 0) { $lastHash = $hash }
            }
        }
    } catch {
        $stateDir = "C:\ProgramData\IPWhitelistFirewall"
        New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
        Add-Content -LiteralPath (Join-Path $stateDir "watcher-errors.log") -Value ("[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_.Exception.Message)
    }
    Start-Sleep -Seconds ([Math]::Max(1,$IntervalSeconds))
}

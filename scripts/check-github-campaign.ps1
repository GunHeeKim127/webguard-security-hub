# Read-only snapshot of selected Dr.Web Trojan.Loader.3261 indicators.
# No downloads, scans/remediation, registry changes, process termination or secret collection.
$ErrorActionPreference = 'Stop'
$result = [ordered]@{
    schemaVersion = 1
    observedAt = [DateTimeOffset]::Now.ToString('o')
    source = 'https://github.com/DoctorWebLtd/malware-iocs/blob/master/Trojan.Loader.3261/README.adoc'
    indicatorSnapshot = '2026-11-09'
    scope = 'Selected paths, Defender status/history, current connections and DNS cache only. Not an infection-free verdict.'
}
$paths = @(
    @{ id = 'campaign-photos-directory'; path = 'C:\ProgramData\Windows.Microsoft.Photos' },
    @{ id = 'campaign-public-script-t'; path = 'C:\Users\Public\Pictures\t.ps1' },
    @{ id = 'campaign-public-script-l'; path = 'C:\Users\Public\Pictures\L.ps1' }
)
$result.paths = @($paths | ForEach-Object {
    try { [pscustomobject]@{ id = $_.id; status = 'observed'; exists = Test-Path -LiteralPath $_.path -ErrorAction Stop } }
    catch { [pscustomobject]@{ id = $_.id; status = 'unavailable' } }
})
try {
    $status = Get-MpComputerStatus
    $result.defender = @{status='observed';antivirusEnabled=$status.AntivirusEnabled;realTimeProtectionEnabled=$status.RealTimeProtectionEnabled;behaviorMonitorEnabled=$status.BehaviorMonitorEnabled;signatureUpdated=$status.AntivirusSignatureLastUpdated;quickScanEnd=$status.QuickScanEndTime;fullScanEnd=$status.FullScanEndTime}
} catch { $result.defender = @{status='unavailable'} }
try {
    $detections = @(Get-MpThreatDetection)
    $result.detections = @{status='observed';count=$detections.Count;unsuccessfulActionCount=@($detections | Where-Object { $_.ActionSuccess -eq $false }).Count}
} catch { $result.detections = @{status='unavailable'} }
try {
    $matches = @(Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -in @('130.12.182.172','130.12.182.209') })
    $result.connections = @{status='observed';matchingCount=$matches.Count}
} catch { $result.connections = @{status='unavailable'} }
try {
    $matches = @(Get-DnsClientCache | Where-Object { $_.Entry -match '(^|\.)(muckanthropic\.com|muckduck\.duckdns\.org|muckcoding\.com|muckdeveloper\.com)$' })
    $result.dnsCache = @{status='observed';matchingCount=$matches.Count}
} catch { $result.dnsCache = @{status='unavailable'} }
$result | ConvertTo-Json -Depth 5

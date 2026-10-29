param([Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference = 'Stop'
$targetPath = [System.IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $targetPath) { throw 'Output already exists; choose another path.' }
$export = @{ schemaVersion=1; firewall=@{domain=$null;private=$null;public=$null}; defender=@{antivirus=$null;realtime=$null}; rdp=@{enabled=$null;nla=$null} }
try {
 foreach ($profile in (Get-NetFirewallProfile -PolicyStore ActiveStore)) {
  $key = $profile.Name.ToLowerInvariant()
  if ($export.firewall.ContainsKey($key)) {
   if ([string]$profile.Enabled -eq 'True') { $export.firewall[$key] = $true }
   elseif ([string]$profile.Enabled -eq 'False') { $export.firewall[$key] = $false }
  }
 }
} catch { Write-Warning 'Firewall state unavailable; recording null, not false.' }
try {
 if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
  $status = Get-MpComputerStatus
 } else {
  $status = Get-CimInstance -Namespace 'root/Microsoft/Windows/Defender' -ClassName MSFT_MpComputerStatus
 }
 # Missing provider values remain unknown; never coerce null into a false verdict.
 if ($status.AntivirusEnabled -is [bool]) { $export.defender.antivirus = $status.AntivirusEnabled }
 if ($status.RealTimeProtectionEnabled -is [bool]) { $export.defender.realtime = $status.RealTimeProtectionEnabled }
} catch { Write-Warning 'Defender state unavailable; third-party providers are not inspected.' }
try {
 $setting = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections
 if ($setting.fDenyTSConnections -in @(0,1)) { $export.rdp.enabled = ($setting.fDenyTSConnections -eq 0) }
 $rdp = Get-CimInstance -Namespace 'root/cimv2/terminalservices' -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'"
 if ($null -ne $rdp.UserAuthenticationRequired -and $rdp.UserAuthenticationRequired -in @(0,1)) { $export.rdp.nla = ($rdp.UserAuthenticationRequired -eq 1) }
} catch { Write-Warning 'RDP effective state unavailable; recording unknown fields as null.' }
$parent = Split-Path -Parent $targetPath
if (!(Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$json = $export | ConvertTo-Json -Depth 4
$bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json)
$stream = [System.IO.File]::Open($targetPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
Write-Host 'Read-only snapshot exported. No device settings were changed.'

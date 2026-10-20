<#
Installation with networking blocked (SRS FR-20.20), dot-sourced by
scripts/msi-smoke.ps1 and scripts/desktop-msi-smoke.ps1 on a Windows
runner:

  . ./scripts/msi-offline.ps1
  $block = Enable-InstallerNetworkBlock      # firewall rules and audit on
  Test-InstallerNetworkBlock                 # msiexec cannot connect
  $t0 = Get-Date
  ... msiexec /i ... /qn ...
  Assert-NoInstallerConnection $t0 'install' # no connection, allowed or blocked
  Disable-InstallerNetworkBlock $block

Windows Installer runs as two processes of the same program, the
msiexec.exe client and the Windows Installer service (msiexec.exe /V),
which runs the custom actions. Windows Firewall outbound block rules for
both msiexec.exe programs (System32 and SysWOW64) keep them off the
network, and the Windows Filtering Platform connection audit (Security log
events 5156, connection allowed, and 5157, connection blocked) records
every connection that they, a program started from the Windows Installer
directory (where custom actions run), or the WebView2 bootstrapper
try. The temporary directories are not watched as a whole: the
runner's own agents run from there and talk to GitHub throughout. The
control test makes msiexec fetch a package from an https URL with the
block on and requires a blocked connection in the audit and no allowed
one, so a block or an audit that does not work fails the test. The rules
are removed and the firewall profiles and the audit setting restored
afterwards. Changes the runner's firewall and audit policy, so it runs
only in CI.
#>

# Filtering Platform Connection (the subcategory's GUID, which does not
# depend on the display language).
$script:WfpConnectionAudit = '{0CCE9226-69AE-11D9-BED3-505054503030}'
$script:BlockRule = 'smcp-smoke: no network for Windows Installer (FR-20.20)'
# Programs whose connections count as the installation's.
$script:InstallerPrograms = '\\msiexec\.exe$|\\windows\\installer\\|webview2setup'

function Get-InstallerPrograms {
  @(
    (Join-Path $env:SystemRoot 'System32\msiexec.exe'),
    (Join-Path $env:SystemRoot 'SysWOW64\msiexec.exe')
  ) | Where-Object { Test-Path -LiteralPath $_ }
}

function Enable-InstallerNetworkBlock {
  $state = [ordered]@{
    Profiles = @(Get-NetFirewallProfile | Select-Object Name, Enabled)
    Audit    = (& auditpol.exe /get /subcategory:$script:WfpConnectionAudit /r | Where-Object { $_ } | ConvertFrom-Csv | Select-Object -First 1).'Inclusion Setting'
  }
  Set-NetFirewallProfile -All -Enabled True
  foreach ($p in Get-InstallerPrograms) {
    New-NetFirewallRule -DisplayName $script:BlockRule -Direction Outbound -Action Block -Program $p -Profile Any | Out-Null
  }
  & auditpol.exe /set /subcategory:$script:WfpConnectionAudit /success:enable /failure:enable | Out-Null
  if ($LASTEXITCODE) { throw "auditpol exited $LASTEXITCODE" }
  Write-Host "network blocked for: $((Get-InstallerPrograms) -join ', ')"
  return $state
}

# Get-InstallerConnections <since>: the Security log's 5156 (allowed) and
# 5157 (blocked) events since then of the installer programs.
function Get-InstallerConnections([datetime]$since) {
  Start-Sleep -Seconds 2
  $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5156, 5157; StartTime = $since } -ErrorAction SilentlyContinue |
      Where-Object { [string]$_.Properties[1].Value -match $script:InstallerPrograms })
  [pscustomobject]@{
    Allowed = @($ev | Where-Object Id -EQ 5156).Count
    Blocked = @($ev | Where-Object Id -EQ 5157).Count
    Events  = $ev
  }
}

# Test-InstallerNetworkBlock: msiexec, told to fetch a package over https,
# is blocked, and the audit records it.
function Test-InstallerNetworkBlock {
  $t0 = Get-Date
  $log = Join-Path ([IO.Path]::GetTempPath()) 'smcp-offline-control.log'
  # A release download URL with no such asset: with networking the fetch
  # gets 404, so nothing is installed either way.
  $url = 'https://github.com/ethan03805/Secure-MCP-Gateway/releases/download/v0.0.0-none/none.msi'
  $p = Start-Process msiexec.exe -ArgumentList @('/i', $url, '/qn', '/norestart', '/l*v', "`"$log`"") -Wait -PassThru
  $c = Get-InstallerConnections $t0
  Write-Host "control: msiexec /i $url exited $($p.ExitCode); connections allowed $($c.Allowed), blocked $($c.Blocked)"
  if ($p.ExitCode -eq 0) { throw 'control: msiexec installed a package from the network' }
  if ($c.Allowed -ne 0) { throw 'control: msiexec reached the network through the block' }
  if ($c.Blocked -lt 1) { throw 'control: no blocked connection of msiexec was recorded; the block or the audit does not work' }
}

# Assert-NoInstallerConnection <since> <what>: no connection of the
# installer programs, allowed or blocked, since then (FR-20.20: no network
# request during installation).
function Assert-NoInstallerConnection([datetime]$since, [string]$what) {
  $c = Get-InstallerConnections $since
  if ($c.Allowed -ne 0 -or $c.Blocked -ne 0) {
    $c.Events | Select-Object -First 10 | ForEach-Object { Write-Host "  $($_.Id): $($_.Properties[1].Value) -> $($_.Properties[5].Value):$($_.Properties[6].Value)" }
    throw "$what`: Windows Installer tried $($c.Allowed + $c.Blocked) network connection(s)"
  }
  Write-Host "$what`: no network connection of Windows Installer (audit events 5156 and 5157)"
}

function Disable-InstallerNetworkBlock($state) {
  Get-NetFirewallRule -DisplayName $script:BlockRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  if ($state) {
    foreach ($p in $state.Profiles) { Set-NetFirewallProfile -Name $p.Name -Enabled $p.Enabled }
    $success = if ($state.Audit -match 'Success') { 'enable' } else { 'disable' }
    $failure = if ($state.Audit -match 'Failure') { 'enable' } else { 'disable' }
    & auditpol.exe /set /subcategory:$script:WfpConnectionAudit /success:$success /failure:$failure | Out-Null
  }
}

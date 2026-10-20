<#
Installs, exercises and removes the Windows Installer package of the CLI
and Gateway (packaging/installers/windows/smcp.wxs) on a Windows runner,
as the installers workflow does for the .deb, .rpm and .pkg (FR-20.24):

  1. msiexec /i /qn installs into %ProgramFiles%\smcp-gateway with no
     network access needed;
  2. the binaries report the version, the directory is on the machine PATH,
     the package marker says msi, and the installing user's group Users
     cannot write the binaries (SR-4.11-2);
  3. msiexec /x /qn removes every file and the PATH entry.

Usage: pwsh -File scripts/msi-smoke.ps1 -Msi build\installers\smcp_1.3.0_windows_amd64.msi -Version 1.3.0
#>
param(
  [Parameter(Mandatory = $true)][string]$Msi,
  [Parameter(Mandatory = $true)][string]$Version
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
function Fail([string]$m) { Write-Host "::error::$m"; throw $m }

$Msi = (Resolve-Path $Msi).Path
$dir = Join-Path $env:ProgramFiles 'smcp-gateway'
$log = Join-Path ([IO.Path]::GetTempPath()) 'smcp-msi-install.log'

Write-Host '== install'
$p = Start-Process msiexec.exe -ArgumentList @('/i', "`"$Msi`"", '/qn', '/norestart', '/l*v', "`"$log`"") -Wait -PassThru
if ($p.ExitCode -ne 0) { Get-Content $log -Tail 60; Fail "msiexec /i exited $($p.ExitCode)" }

foreach ($b in 'smcpd', 'smcpctl', 'smcp-refserver', 'smcp-session', 'smcp-stdio', 'smcp-connect') {
  if (-not (Test-Path (Join-Path $dir "$b.exe"))) { Fail "$b.exe not installed" }
}
$v = & (Join-Path $dir 'smcpd.exe') --version
if ($v -ne "smcpd $Version") { Fail "smcpd --version printed '$v'" }
if ((Get-Content (Join-Path $dir 'package-format')).Trim() -ne 'msi') { Fail 'package marker is not msi' }
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if (-not ($machinePath -split ';' | Where-Object { $_.TrimEnd('\') -ieq $dir })) { Fail "$dir is not on the machine PATH" }

Write-Host '== binaries not writable by Users (SR-4.11-2)'
$acl = Get-Acl (Join-Path $dir 'smcpd.exe')
foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
  $sid = $r.IdentityReference.Value
  $write = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, Delete, ChangePermissions, TakeOwnership'
  if ($r.AccessControlType -eq 'Allow' -and ($r.FileSystemRights -band $write) -and $sid -notin @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')) {
    Fail "smcpd.exe is writable by $sid"
  }
}

Write-Host '== smcpctl version'
$sv = & (Join-Path $dir 'smcpctl.exe') version --short
if ($sv -ne $Version) { Fail "smcpctl version --short printed '$sv'" }

Write-Host '== remove'
$p = Start-Process msiexec.exe -ArgumentList @('/x', "`"$Msi`"", '/qn', '/norestart') -Wait -PassThru
if ($p.ExitCode -ne 0) { Fail "msiexec /x exited $($p.ExitCode)" }
if (Test-Path (Join-Path $dir 'smcpd.exe')) { Fail 'files left after removal' }
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($machinePath -split ';' | Where-Object { $_.TrimEnd('\') -ieq $dir }) { Fail 'PATH entry left after removal' }
Write-Host 'msi smoke test passed'

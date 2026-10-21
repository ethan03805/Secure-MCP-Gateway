<#
Installs, exercises and removes the Windows Installer package of the CLI
and Gateway (packaging/installers/windows/smcp.wxs) on a Windows runner,
as the installers workflow does for the .deb, .rpm and .pkg (FR-20.24):

  1. a Gateway state made by smcpctl bootstrap with the Windows binaries
     of the same build (-BinDir) stands for an existing installation;
  2. msiexec /i /qn installs into %ProgramFiles%\smcp-gateway with
     Windows Installer's network access blocked and no connection tried
     (FR-20.20, scripts/msi-offline.ps1);
  3. the binaries report the version, the directory is on the machine PATH,
     the package marker says msi, no service, task, configuration or state
     was created, the existing state is byte-for-byte unchanged (FR-20.21),
     and every installed file grants write access to SYSTEM, Administrators
     and TrustedInstaller only (SR-4.11-2);
  4. smcpctl install --machine from the installed binaries registers the
     machine-mode service, which writes its journal, and a backup is
     taken; msiexec /x /qn then stops and removes that service and every
     installed file and the PATH entry, and keeps the configuration,
     journal, keys and backup (FR-20.22);
  5. a fresh installation of the package verifies the kept journal with
     the kept key (smcpctl journal verify), and is removed again.

Usage: pwsh -File scripts/msi-smoke.ps1 -Msi build\installers\smcp_1.3.0_windows_amd64.msi -Version 1.3.0 -BinDir build\win\amd64
#>
param(
  [Parameter(Mandatory = $true)][string]$Msi,
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][string]$BinDir,
  [int]$Port = 18643,
  [int]$AdminPort = 18644
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
function Fail([string]$m) { Write-Host "::error::msi-smoke: $m"; throw $m }
function Step([string]$m) { Write-Host "== $m" }
. (Join-Path $PSScriptRoot 'msi-offline.ps1')
. (Join-Path $PSScriptRoot 'msi-checks.ps1')

$Msi = (Resolve-Path $Msi).Path
$BinDir = (Resolve-Path $BinDir).Path
$dir = Join-Path $env:ProgramFiles 'smcp-gateway'
$machine = Join-Path $env:ProgramData 'smcp-gateway'
$work = Join-Path ([IO.Path]::GetTempPath()) ("smcp-msi-smoke-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$log = Join-Path $work 'install.log'
$block = $null

function Msiexec([string[]]$arguments, [string]$what) {
  Write-Host "msiexec $($arguments -join ' ')"
  $p = Start-Process msiexec.exe -ArgumentList $arguments -PassThru
  if (-not $p.WaitForExit(600000)) { if (Test-Path $log) { Get-Content $log -Tail 60 }; Fail "msiexec $what did not finish within 10 minutes" }
  if ($p.ExitCode -ne 0) { if (Test-Path $log) { Get-Content $log -Tail 60 }; Fail "msiexec $what exited $($p.ExitCode)" }
}

try {
  # Password files readable by this account only (the Windows counterpart
  # of mode 0600 that smcpctl checks).
  $secrets = Join-Path $work 'secrets'
  New-Item -ItemType Directory -Path $secrets | Out-Null
  & icacls.exe $secrets /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
  Set-Content -LiteralPath (Join-Path $secrets 'admin.pw') -Value 'msi-smoke-admin-password-1' -NoNewline
  Set-Content -LiteralPath (Join-Path $secrets 'approver.pw') -Value 'msi-smoke-approver-password-1' -NoNewline
  Set-Content -LiteralPath (Join-Path $secrets 'backup.pass') -Value 'msi-smoke-backup-passphrase-1' -NoNewline

  Step '1. an existing installation (FR-20.21)'
  $prev = Join-Path $work 'existing'
  & (Join-Path $BinDir 'smcpctl.exe') bootstrap --dir $prev --bootstrap-token --approver-password-file (Join-Path $secrets 'approver.pw') `
    --port 18743 --admin-port 18744 | Out-Null
  if ($LASTEXITCODE -ne 0) { Fail "smcpctl bootstrap exited $LASTEXITCODE" }
  $existing = Get-Digests $prev

  Step '2. install with Windows Installer kept off the network (FR-20.20)'
  $block = Enable-InstallerNetworkBlock
  Test-InstallerNetworkBlock
  $t0 = Get-Date
  Msiexec @('/i', "`"$Msi`"", '/qn', '/norestart', '/l*v', "`"$log`"") 'install'
  Assert-NoInstallerConnection $t0 'install'
  Disable-InstallerNetworkBlock $block
  $block = $null

  Step '3. files, version, PATH, nothing else created'
  foreach ($b in 'smcpd', 'smcpctl', 'smcp-refserver', 'smcp-session', 'smcp-stdio', 'smcp-connect') {
    if (-not (Test-Path (Join-Path $dir "$b.exe"))) { Fail "$b.exe not installed" }
  }
  $v = & (Join-Path $dir 'smcpd.exe') --version
  if ($v -ne "smcpd $Version") { Fail "smcpd --version printed '$v'" }
  $sv = & (Join-Path $dir 'smcpctl.exe') version --short
  if ($sv -ne $Version) { Fail "smcpctl version --short printed '$sv'" }
  if ((Get-Content (Join-Path $dir 'package-format')).Trim() -ne 'msi') { Fail 'package marker is not msi' }
  $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
  if (-not ($machinePath -split ';' | Where-Object { $_.TrimEnd('\') -ieq $dir })) { Fail "$dir is not on the machine PATH" }
  if (Get-Service smcpd -ErrorAction SilentlyContinue) { Fail 'the package registered the smcpd service' }
  schtasks /query /tn smcp-gateway 2>$null | Out-Null
  if ($LASTEXITCODE -eq 0) { Fail 'the package registered the smcp-gateway task' }
  foreach ($c in (Join-Path $env:LOCALAPPDATA 'smcp-gateway'), $machine) {
    if (Test-Path $c) { Fail "the package created $c" }
  }
  Compare-Digests $existing (Get-Digests $prev) 'the existing installation'

  Step '3b. installed files: write access for Administrators only, none for a standard user (SR-4.11-2)'
  Assert-AdminsOnlyWrite $dir
  Assert-UserCannotWrite $dir

  Step '4. machine-mode service, journal and backup, then remove the package (FR-20.22)'
  $smcpctl = Join-Path $dir 'smcpctl.exe'
  & $smcpctl install --machine --admin-password-file (Join-Path $secrets 'admin.pw') --approver-password-file (Join-Path $secrets 'approver.pw') `
    --port $Port --admin-port $AdminPort --notify off --health-timeout 120s
  if ($LASTEXITCODE -ne 0) { Fail "smcpctl install --machine exited $LASTEXITCODE" }
  $cfg = Join-Path $machine 'config\smcp.toml'
  if ((Get-Service smcpd).Status -ne 'Running') { Fail 'the smcpd service is not running' }
  $out = & $smcpctl backup --config $cfg --passphrase-file (Join-Path $secrets 'backup.pass') 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) { Write-Host $out; Fail "smcpctl backup exited $LASTEXITCODE" }
  if ($out -notmatch 'backup written: (.+)') { Write-Host $out; Fail 'no backup path' }
  $backup = $Matches[1].Trim()
  $journal = Join-Path $machine 'state\journal'
  $key = Join-Path $machine 'state\keys\evidence-genesis.pub'
  $kept = @($cfg, $journal, $key, $backup)
  foreach ($k in $kept) { if (-not (Test-Path -LiteralPath $k)) { Fail "$k missing before removal" } }
  $segments = @(Get-ChildItem -LiteralPath $journal -Filter '*.jsonl').Count
  Msiexec @('/x', "`"$Msi`"", '/qn', '/norestart', '/l*v', "`"$log`"") 'remove'
  if (Get-Service smcpd -ErrorAction SilentlyContinue) { Fail 'the smcpd service is still registered after removal' }
  if (Get-Process smcpd -ErrorAction SilentlyContinue) { Fail 'smcpd still runs after removal' }
  if (Test-Path (Join-Path $dir 'smcpd.exe')) { Fail 'files left after removal' }
  $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
  if ($machinePath -split ';' | Where-Object { $_.TrimEnd('\') -ieq $dir }) { Fail 'PATH entry left after removal' }
  foreach ($k in $kept) { if (-not (Test-Path -LiteralPath $k)) { Fail "$k was not kept" } }
  Write-Host "service stopped and removed; kept: configuration, $segments journal segment(s), evidence key, backup"
  Compare-Digests $existing (Get-Digests $prev) 'the existing installation'

  Step '5. a fresh installation verifies the kept journal'
  Msiexec @('/i', "`"$Msi`"", '/qn', '/norestart') 'reinstall'
  & $smcpctl journal verify --dir $journal --key $key
  if ($LASTEXITCODE -ne 0) { Fail "smcpctl journal verify exited $LASTEXITCODE" }
  Msiexec @('/x', "`"$Msi`"", '/qn', '/norestart') 'remove'
  if (Test-Path (Join-Path $dir 'smcpd.exe')) { Fail 'files left after the second removal' }
  Write-Host 'msi smoke test passed'
}
finally {
  if ($block) { Disable-InstallerNetworkBlock $block }
  Remove-Item -Recurse -Force $machine -ErrorAction SilentlyContinue
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

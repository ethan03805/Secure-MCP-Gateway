<#
Windows machine-mode installation smoke test (SRS FR-21.6, FR-21.5,
FR-21.10, SR-4.1-3 in part, SR-4-2), run elevated by the windows job of
.github/workflows/ci.yml:

  1. smcpctl install --machine: the service smcpd under NT SERVICE\smcpd
     with automatic (delayed) start, an unrestricted service SID and
     restart on the first and second failure (sc.exe qc, qsidtype,
     qfailure); %ProgramData%\smcp-gateway with the CP-46 DACLs; the
     local groups smcp-harness and smcp-operators;
  2. the keys are DPAPI blobs made by the service; health is degraded
     with the label "not enforced, windows-machine";
  3. the smcpd process is killed and the Service Control Manager restarts it;
  4. smcpctl uninstall stops the service in order (journal stop record)
     and deletes it.

Usage: pwsh -File scripts/windows-machine-smoke.ps1 -BinDir build\win\bin
#>
param(
  [Parameter(Mandatory = $true)][string]$BinDir,
  [int]$Port = 18543,
  [int]$AdminPort = 18544
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
function Step([string]$m) { Write-Host "== $m" }
function Fail([string]$m) { Write-Host "::error::$m"; throw $m }

$BinDir = (Resolve-Path $BinDir).Path
$work = Join-Path ([IO.Path]::GetTempPath()) ("smcp-machine-" + [Guid]::NewGuid().ToString('N'))
$secrets = Join-Path $work 'secrets'
New-Item -ItemType Directory -Path $secrets | Out-Null
& icacls.exe $secrets /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
Set-Content -LiteralPath (Join-Path $secrets 'admin.pw') -Value 'admin-password-123' -NoNewline
Set-Content -LiteralPath (Join-Path $secrets 'approver.pw') -Value 'approver-password-123' -NoNewline

Step 'smcpctl install --machine'
& (Join-Path $BinDir 'smcpctl.exe') install --machine --admin-password-file (Join-Path $secrets 'admin.pw') --approver-password-file (Join-Path $secrets 'approver.pw') `
  --port $Port --admin-port $AdminPort --notify off --health-timeout 120s
if ($LASTEXITCODE -ne 0) { Fail "smcpctl install --machine exited $LASTEXITCODE" }
$base = Join-Path $env:ProgramData 'smcp-gateway'
$cfg = Join-Path $base 'config\smcp.toml'
$smcpctl = Join-Path $env:ProgramFiles 'smcp-gateway\smcpctl.exe'

Step 'service definition (FR-21.6)'
$qc = & sc.exe qc smcpd | Out-String
Write-Host $qc
if ($qc -notmatch 'NT SERVICE\\smcpd') { Fail 'service does not run as NT SERVICE\smcpd' }
if ($qc -notmatch 'AUTO_START\s+\(DELAYED\)') { Fail 'service is not automatic (delayed) start' }
$sid = & sc.exe qsidtype smcpd | Out-String
if ($sid -notmatch 'UNRESTRICTED') { Fail "service SID type: $sid" }
$qf = & sc.exe qfailure smcpd | Out-String
Write-Host $qf
if (([regex]::Matches($qf, 'RESTART')).Count -lt 2) { Fail 'recovery actions do not restart twice' }

Step 'CP-46 machine-mode DACLs (FR-21.5)'
$svc = (New-Object Security.Principal.NTAccount('NT SERVICE\smcpd')).Translate([Security.Principal.SecurityIdentifier]).Value
foreach ($d in 'state', 'log') {
  $acl = Get-Acl -LiteralPath (Join-Path $base $d)
  if (-not $acl.AreAccessRulesProtected) { Fail "$d inherits its DACL" }
  foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($r.AccessControlType -eq 'Allow' -and @('S-1-5-18', 'S-1-5-32-544', $svc) -notcontains $r.IdentityReference.Value) { Fail "$d grants $($r.IdentityReference.Value)" }
  }
}
foreach ($g in 'smcp-harness', 'smcp-operators') {
  if (-not (Get-LocalGroup -Name $g -ErrorAction SilentlyContinue)) { Fail "local group $g missing" }
}

Step 'keys made by the service as DPAPI blobs (FR-21.10)'
$dpapi = [byte[]](0x01, 0x00, 0x00, 0x00, 0xd0, 0x8c, 0x9d, 0xdf, 0x01, 0x15, 0xd1, 0x11, 0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb)
foreach ($k in 'tls\ca.key', 'keys\evidence.key', 'keys\admin.token') {
  $b = [IO.File]::ReadAllBytes((Join-Path $base "state\$k"))
  for ($i = 0; $i -lt $dpapi.Length; $i++) { if ($b[$i] -ne $dpapi[$i]) { Fail "$k is not a DPAPI blob" } }
}

Step 'health and label (SR-4-2)'
$health = & $smcpctl health --config $cfg 2>&1 | Out-String
Write-Host $health
if ($health -notmatch 'degraded' -or $health -notmatch 'not enforced, windows-machine') { Fail 'health or label wrong' }

Step 'restart after a failure (FR-21.6)'
$p = Get-CimInstance Win32_Service -Filter "Name = 'smcpd'"
Stop-Process -Id $p.ProcessId -Force
$deadline = (Get-Date).AddSeconds(120)
do {
  Start-Sleep -Seconds 2
  $q = Get-CimInstance Win32_Service -Filter "Name = 'smcpd'"
  & $smcpctl health --config $cfg *> $null
  $up = ($LASTEXITCODE -eq 0)
} until (($q.State -eq 'Running' -and $q.ProcessId -ne $p.ProcessId -and $up) -or (Get-Date) -gt $deadline)
if (-not $up) { Fail 'the service was not restarted after its process was killed' }
Write-Host "restarted: pid $($p.ProcessId) -> $($q.ProcessId)"

Step 'smcpctl uninstall (orderly service stop, FR-21.7)'
& $smcpctl uninstall --config $cfg --bin-dir (Join-Path $work 'no-binaries')
if ($LASTEXITCODE -ne 0) { Fail "smcpctl uninstall exited $LASTEXITCODE" }
if (Get-Service -Name smcpd -ErrorAction SilentlyContinue) { Fail 'service still registered' }
$journal = Join-Path $base 'state\journal'
$last = Get-ChildItem -LiteralPath $journal -Filter '*.jsonl' | Sort-Object Name | Select-Object -Last 1
if (-not $last -or (Get-Content -LiteralPath $last.FullName -Raw) -notmatch '"outcome":"stopped"') { Fail 'the journal has no stop record' }
Write-Host 'windows machine-mode smoke test passed'
exit 0

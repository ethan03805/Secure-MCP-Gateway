<#
Windows per-user installation smoke test (SRS FR-21.5, FR-21.6, FR-21.7,
FR-21.10), run by the windows job of .github/workflows/ci.yml on a
windows-latest runner:

  1. smcpctl install in a fresh %LOCALAPPDATA%: CP-46 directories with
     protected DACLs, DPAPI keys, the Task Scheduler task (or the Run-key
     fallback), smcpd -supervise started and healthy ("degraded",
     unconfined, label "not enforced");
  2. smcpctl doctor reports the state directory protected;
  3. the smcpd child of the supervisor is killed and comes back;
  4. smcpctl uninstall stops smcpd through the stop event (the evidence
     journal records the stop), removes the task and keeps the journal.

Usage: pwsh -File scripts/windows-install-smoke.ps1 -BinDir build\win\bin
#>
param(
  [Parameter(Mandatory = $true)][string]$BinDir,
  [int]$Port = 18443,
  [int]$AdminPort = 18444
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Step([string]$m) { Write-Host "== $m" }
function Fail([string]$m) { Write-Host "::error::$m"; throw $m }

$BinDir = (Resolve-Path $BinDir).Path
$smcpctl = Join-Path $BinDir 'smcpctl.exe'
$work = Join-Path ([IO.Path]::GetTempPath()) ("smcp-smoke-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$env:LOCALAPPDATA = Join-Path $work 'LocalAppData'
New-Item -ItemType Directory -Path $env:LOCALAPPDATA | Out-Null

# Password files readable by this account only (the Windows counterpart of
# mode 0600 that smcpctl checks).
$secrets = Join-Path $work 'secrets'
New-Item -ItemType Directory -Path $secrets | Out-Null
& icacls.exe $secrets /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
Set-Content -LiteralPath (Join-Path $secrets 'admin.pw') -Value 'admin-password-123' -NoNewline
Set-Content -LiteralPath (Join-Path $secrets 'approver.pw') -Value 'approver-password-123' -NoNewline

Step 'smcpctl install'
& $smcpctl install --admin-password-file (Join-Path $secrets 'admin.pw') --approver-password-file (Join-Path $secrets 'approver.pw') `
  --port $Port --admin-port $AdminPort --notify off --health-timeout 90s
if ($LASTEXITCODE -ne 0) { Fail "smcpctl install exited $LASTEXITCODE" }
$base = Join-Path $env:LOCALAPPDATA 'smcp-gateway'
$cfg = Join-Path $base 'config\smcp.toml'
if (-not (Test-Path $cfg)) { Fail "no configuration at $cfg" }

Step 'CP-46 directories: inheritance disabled, this user, SYSTEM and Administrators only (FR-21.5)'
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowed = @($me, 'S-1-5-18', 'S-1-5-32-544')
foreach ($d in 'config', 'state', 'log', 'exports') {
  $acl = Get-Acl -LiteralPath (Join-Path $base $d)
  if (-not $acl.AreAccessRulesProtected) { Fail "$d inherits its DACL" }
  foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($r.AccessControlType -eq 'Allow' -and $allowed -notcontains $r.IdentityReference.Value) { Fail "$d grants $($r.IdentityReference.Value)" }
  }
}

Step 'private keys are DPAPI blobs (FR-21.10)'
$dpapi = [byte[]](0x01, 0x00, 0x00, 0x00, 0xd0, 0x8c, 0x9d, 0xdf, 0x01, 0x15, 0xd1, 0x11, 0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb)
foreach ($k in 'tls\ca.key', 'tls\server.key', 'keys\evidence.key', 'keys\admin.token') {
  $b = [IO.File]::ReadAllBytes((Join-Path $base "state\$k"))
  for ($i = 0; $i -lt $dpapi.Length; $i++) { if ($b[$i] -ne $dpapi[$i]) { Fail "$k is not a DPAPI blob" } }
}

Step 'start definition (FR-21.6)'
$task = & schtasks.exe /query /tn smcp-gateway /xml 2>$null | Out-String
if ($LASTEXITCODE -eq 0) {
  if ($task -notmatch [regex]::Escape("<UserId>$me</UserId>")) { Fail 'task trigger is not limited to this user' }
  Write-Host 'Task Scheduler task registered'
} else {
  $run = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'smcp-gateway' -ErrorAction SilentlyContinue
  if (-not $run) { Fail 'neither the task nor the Run-key fallback is registered' }
  Write-Host 'Run-key fallback registered'
}

Step 'health and label'
$health = & $smcpctl health --config $cfg 2>&1 | Out-String
Write-Host $health
if ($health -notmatch 'degraded' -or $health -notmatch 'not enforced') { Fail 'health is not degraded / not enforced' }

Step 'smcpctl doctor (state protection)'
$doc = & $smcpctl doctor --config $cfg 2>&1 | Out-String
Write-Host $doc
if ($doc -notmatch 'protected DACL') { Fail 'doctor did not report the state directory protected' }

Step 'restart after a failure (FR-21.6)'
$procs = Get-CimInstance Win32_Process -Filter "Name = 'smcpd.exe'"
$sup = $procs | Where-Object { $_.CommandLine -match '-supervise' } | Select-Object -First 1
if (-not $sup) { Fail 'no supervisor process' }
$child = $procs | Where-Object { $_.ParentProcessId -eq $sup.ProcessId } | Select-Object -First 1
if (-not $child) { Fail 'no supervised smcpd' }
Stop-Process -Id $child.ProcessId -Force
$deadline = (Get-Date).AddSeconds(90)
do {
  Start-Sleep -Seconds 1
  $next = Get-CimInstance Win32_Process -Filter "Name = 'smcpd.exe'" | Where-Object { $_.ParentProcessId -eq $sup.ProcessId -and $_.ProcessId -ne $child.ProcessId }
  & $smcpctl health --config $cfg *> $null
  $up = ($LASTEXITCODE -eq 0)
} until (($next -and $up) -or (Get-Date) -gt $deadline)
if (-not ($next -and $up)) { Fail 'smcpd was not restarted after it was killed' }
Write-Host "restarted: pid $($child.ProcessId) -> $(@($next)[0].ProcessId)"

Step 'smcpctl uninstall (orderly stop through the stop event, FR-21.7)'
& $smcpctl uninstall --config $cfg --bin-dir (Join-Path $work 'no-binaries')
if ($LASTEXITCODE -ne 0) { Fail "smcpctl uninstall exited $LASTEXITCODE" }
Start-Sleep -Seconds 2
if (Get-CimInstance Win32_Process -Filter "Name = 'smcpd.exe'") { Fail 'smcpd still runs after uninstall' }
& schtasks.exe /query /tn smcp-gateway *> $null
if ($LASTEXITCODE -eq 0) { Fail 'task still registered after uninstall' }
if (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'smcp-gateway' -ErrorAction SilentlyContinue) { Fail 'Run value still present' }
$journal = Join-Path $base 'state\journal'
if (-not (Get-ChildItem -LiteralPath $journal -Filter '*.jsonl' -ErrorAction SilentlyContinue)) { Fail 'journal not kept' }
$last = Get-ChildItem -LiteralPath $journal -Filter '*.jsonl' | Sort-Object Name | Select-Object -Last 1
if ((Get-Content -LiteralPath $last.FullName -Raw) -notmatch '"outcome":"stopped"') { Fail 'the journal has no stop record' }
Write-Host 'windows install smoke test passed'
exit 0

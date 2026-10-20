<#
Installs, starts and removes the smcp-desktop Windows Installer package
(packaging/installers/desktop/build-msi.ps1) on a Windows runner (E-35;
SRS FR-20.20, FR-20.1, FR-20.28, SR-2.8-5, FR-20.21, FR-20.22):

  1. msiexec /i /qn installs per machine into
     "%ProgramFiles%\Secure MCP Gateway"; the WebView2 bootstrapper is not
     run, because the runner has the WebView2 runtime (no download);
  2. smcp-desktop --commands finds the six commands beside it, each
     reporting the expected version; the package marker says msi; no
     service, task or Gateway configuration was created;
  3. the URL scheme smcp is registered for smcp-desktop.exe;
  4. the application starts and its console window checks the admin
     listener's certificate (SR-2.8-5): against a test listener (openssl
     s_server) whose certificate comes from the CA in Settings the page is
     accepted; with a certificate from another CA it is refused; with that
     other CA in the machine's trusted root store (so WebView2 raises no
     certificate error) it is still refused by the committed-load check;
  5. a second start with the link smcp://approvals reaches the running
     copy, which opens the Approvals view (FR-20.14, FR-20.28);
  6. msiexec /x /qn removes the files and the scheme.

The application's log is its standard error. Changes the runner's machine
root store and the user's application settings, so it runs only in CI.

Usage: pwsh -File scripts/desktop-msi-smoke.ps1 -Msi build\desktop\smcp-desktop_1.3.0_windows_amd64.msi -Version 1.3.0
#>
param(
  [Parameter(Mandatory = $true)][string]$Msi,
  [Parameter(Mandatory = $true)][string]$Version
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
function Fail([string]$m) { Write-Host "::error::desktop-msi-smoke: $m"; throw $m }
function Step([string]$m) { Write-Host "== $m" }

$Msi = (Resolve-Path $Msi).Path
$dir = Join-Path $env:ProgramFiles 'Secure MCP Gateway'
$app = Join-Path $dir 'smcp-desktop.exe'
$work = Join-Path ([IO.Path]::GetTempPath()) ("smcp-desktop-smoke-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$log = Join-Path $work 'install.log'
$procs = [Collections.Generic.List[Diagnostics.Process]]::new()
$rootThumb = $null

function Stop-All {
  foreach ($p in $procs) { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
  Get-Process smcp-desktop -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  $procs.Clear()
  Start-Sleep -Seconds 1
}

try {
  Step 'install'
  $p = Start-Process msiexec.exe -ArgumentList @('/i', "`"$Msi`"", '/qn', '/norestart', '/l*v', "`"$log`"") -Wait -PassThru
  if ($p.ExitCode -ne 0) { Get-Content $log -Tail 80; Fail "msiexec /i exited $($p.ExitCode)" }
  if (-not (Test-Path $app)) { Fail "$app not installed" }
  # The bootstrapper runs only without a WebView2 runtime (FR-20.20).
  $wv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $wv) { Fail 'the runner has no WebView2 runtime registration' }
  Write-Host "WebView2 runtime $($wv.pv)"
  $text = Get-Content $log -Raw
  if ($text -match 'Doing action: InvokeBootstrapper') { Fail 'the WebView2 bootstrapper ran on a host that has the runtime' }

  Step 'files, commands and marker'
  $cmdOut = Join-Path $work 'commands.txt'
  $p = Start-Process $app -ArgumentList '--commands' -Wait -PassThru -RedirectStandardOutput $cmdOut -RedirectStandardError (Join-Path $work 'commands.err')
  Get-Content $cmdOut
  if ($p.ExitCode -ne 0) { Fail "smcp-desktop --commands exited $($p.ExitCode)" }
  $n = @(Get-Content $cmdOut | Where-Object { ($_ -split "`t")[2] -eq $Version -and ($_ -split "`t")[1].Replace('\\?\', '').StartsWith($dir, [StringComparison]::OrdinalIgnoreCase) }).Count
  if ($n -ne 6) { Fail "$n of 6 commands beside the application report version $Version" }
  if ((Get-Content (Join-Path $dir 'package-format')).Trim() -ne 'msi') { Fail 'package marker is not msi' }

  Step 'no service, task or configuration (FR-20.21)'
  if (Get-Service smcpd -ErrorAction SilentlyContinue) { Fail 'the package registered the smcpd service' }
  schtasks /query /tn smcp-gateway 2>$null | Out-Null
  if ($LASTEXITCODE -eq 0) { Fail 'the package registered the smcp-gateway task' }
  foreach ($c in (Join-Path $env:LOCALAPPDATA 'smcp-gateway'), (Join-Path $env:ProgramData 'smcp-gateway')) {
    if (Test-Path $c) { Fail "the package created $c" }
  }

  Step 'URL scheme smcp (FR-20.28)'
  $cmd = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Classes\smcp\shell\open\command').'(default)'
  Write-Host "smcp: $cmd"
  # Windows Installer may write the 8.3 short form of the path.
  if ($cmd -notmatch '^"([^"]+)" "%1"$') { Fail "unexpected smcp command: $cmd" }
  # The short form keeps its spelling in .NET, so compare the files.
  $reg = $Matches[1]
  if (-not (Test-Path -LiteralPath $reg) -or (Get-FileHash -LiteralPath $reg).Hash -ne (Get-FileHash -LiteralPath $app).Hash -or
      (Split-Path -Leaf $reg) -notmatch '^(smcp-desktop|SMCP-D~\d+)\.exe$') { Fail "smcp is not registered for $app`: $cmd" }
  if ($null -eq (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Classes\smcp' -Name 'URL Protocol' -ErrorAction SilentlyContinue)) { Fail 'smcp has no URL Protocol value' }

  Step 'test certificates (openssl)'
  $openssl = (Get-Command openssl -ErrorAction SilentlyContinue).Source
  if (-not $openssl) { $openssl = Join-Path $env:ProgramFiles 'Git\usr\bin\openssl.exe' }
  if (-not (Test-Path $openssl)) { Fail 'openssl not found' }
  $ext = Join-Path $work 'leaf.ext'
  Set-Content -Path $ext -Value "basicConstraints=critical,CA:FALSE`nkeyUsage=critical,digitalSignature`nextendedKeyUsage=serverAuth`nsubjectAltName=IP:127.0.0.1,DNS:localhost" -Encoding ascii
  $caExt = Join-Path $work 'ca.ext'
  Set-Content -Path $caExt -Value "[v3]`nbasicConstraints=critical,CA:TRUE`nkeyUsage=critical,keyCertSign,cRLSign`nsubjectKeyIdentifier=hash" -Encoding ascii
  foreach ($name in 'gateway', 'other') {
    & $openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj "/CN=smoke $name CA" `
      -config $caExt -extensions v3 -keyout (Join-Path $work "$name-ca.key") -out (Join-Path $work "$name-ca.crt") 2>&1 | Out-Null
    if ($LASTEXITCODE) { Fail "openssl CA $name exited $LASTEXITCODE" }
    & $openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj '/CN=127.0.0.1' `
      -keyout (Join-Path $work "$name.key") -out (Join-Path $work "$name.csr") 2>&1 | Out-Null
    if ($LASTEXITCODE) { Fail "openssl CSR $name exited $LASTEXITCODE" }
    & $openssl x509 -req -in (Join-Path $work "$name.csr") -CA (Join-Path $work "$name-ca.crt") -CAkey (Join-Path $work "$name-ca.key") `
      -CAcreateserial -days 30 -extfile $ext -out (Join-Path $work "$name.crt") 2>&1 | Out-Null
    if ($LASTEXITCODE) { Fail "openssl sign $name exited $LASTEXITCODE" }
  }

  function Free-Port {
    $l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $l.Start(); $port = $l.LocalEndpoint.Port; $l.Stop(); return $port
  }

  # Settings: the test listener, the Gateway test CA, nothing else that
  # reaches out (notifications, update checks off).
  $cfgDir = Join-Path $env:APPDATA 'com.smcp.desktop'
  New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
  Set-Content -Path (Join-Path $cfgDir 'introduction') -Value 'skipped' -NoNewline -Encoding ascii

  # run_case <certificate name> <expected log pattern> <case name>
  function Run-Case([string]$cert, [string]$want, [string]$case) {
    Step "console window: $case"
    $port = Free-Port
    $settings = [ordered]@{
      admin_url = "https://127.0.0.1:$port"; metrics_address = "127.0.0.1:$(Free-Port)"
      ca_file = (Join-Path $work 'gateway-ca.crt'); notifications = $false; start_at_login = $false; update_checks = $false
    }
    $settings | ConvertTo-Json | Set-Content -Path (Join-Path $cfgDir 'settings.json') -Encoding ascii
    $srvLog = Join-Path $work "server-$case.log"
    $chain = Join-Path $work "$cert-chain.crt"
    Get-Content (Join-Path $work "$cert.crt"), (Join-Path $work "$cert-ca.crt") | Set-Content $chain -Encoding ascii
    $srv = Start-Process $openssl -ArgumentList @('s_server', '-accept', "127.0.0.1:$port", '-cert', "`"$chain`"", '-key', "`"$(Join-Path $work "$cert.key")`"", '-www', '-quiet') `
      -PassThru -RedirectStandardOutput $srvLog -RedirectStandardError "$srvLog.err" -WindowStyle Hidden
    $procs.Add($srv)
    Start-Sleep -Seconds 2
    $appLog = Join-Path $work "app-$case.log"
    $a = Start-Process $app -ArgumentList 'smcp://console' -PassThru -RedirectStandardOutput "$appLog.out" -RedirectStandardError $appLog
    $procs.Add($a)
    $deadline = (Get-Date).AddSeconds(90)
    $seen = $false
    while ((Get-Date) -lt $deadline) {
      Start-Sleep -Seconds 2
      if ($a.HasExited) { break }
      $t = Get-Content $appLog -Raw -ErrorAction SilentlyContinue
      if ($t -and $t -match $want) { $seen = $true; break }
    }
    Get-Content $appLog -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  app: $_" }
    if (-not $seen) { Stop-All; Fail "$case`: no log line matching '$want'" }
    if ($want -match 'accepted') {
      $t = Get-Content $appLog -Raw
      if ($t -match 'console refused') { Stop-All; Fail "$case`: the console was refused" }
      # A second start with a link reaches this copy (FR-20.14, FR-20.28).
      Step 'second start with smcp://approvals'
      Start-Process 'smcp://approvals'
      $deadline = (Get-Date).AddSeconds(30)
      $ok = $false
      while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 2
        if ((Get-Content $appLog -Raw) -match [regex]::Escape("console: https://127.0.0.1:$port/approvals")) { $ok = $true; break }
      }
      Get-Content $appLog | Select-Object -Last 5 | ForEach-Object { Write-Host "  app: $_" }
      if (-not $ok) { Stop-All; Fail 'the link did not open the Approvals view in the running copy' }
      if (@(Get-Process smcp-desktop -ErrorAction SilentlyContinue).Count -ne 1) { Stop-All; Fail 'a second copy of the application kept running' }
    }
    Stop-All
  }

  Run-Case 'gateway' 'console certificate accepted' 'Gateway CA'
  Run-Case 'other' 'console refused: .*does not chain to the Gateway CA' 'another CA'

  Step 'another CA trusted by Windows (committed-load check)'
  $imported = Import-Certificate -FilePath (Join-Path $work 'other-ca.crt') -CertStoreLocation Cert:\LocalMachine\Root
  $rootThumb = $imported.Thumbprint
  Run-Case 'other' 'console refused: .*does not chain to the Gateway CA' 'another CA in the Windows root store'

  Step 'remove'
  $p = Start-Process msiexec.exe -ArgumentList @('/x', "`"$Msi`"", '/qn', '/norestart') -Wait -PassThru
  if ($p.ExitCode -ne 0) { Fail "msiexec /x exited $($p.ExitCode)" }
  if (Test-Path $app) { Fail 'files left after removal' }
  if (Test-Path 'Registry::HKEY_LOCAL_MACHINE\Software\Classes\smcp') { Fail 'the smcp scheme is still registered after removal' }
  Write-Host 'desktop msi smoke test passed'
}
finally {
  Stop-All
  if ($rootThumb) { Remove-Item -Path "Cert:\LocalMachine\Root\$rootThumb" -ErrorAction SilentlyContinue }
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

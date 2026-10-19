<#
Install the Secure MCP Gateway binaries on Windows from a GitHub release.

  irm https://raw.githubusercontent.com/ethan03805/Secure-MCP-Gateway/main/install.ps1 | iex
  powershell -ExecutionPolicy Bypass -File install.ps1 -Version v1.3.0

The script downloads the zip archive for this machine's architecture
(amd64 or arm64), the checksum file and its minisign signature, verifies
the signature and its trusted comment with the release public key embedded
below (SRS FR-21.4), verifies the archive's SHA-256 against the checksum
file, and, when cosign is installed, the checksum file's Sigstore bundle.
If any check fails, or no signature verifier is available, it installs
nothing. It installs to %LOCALAPPDATA%\Programs\smcp-gateway unless -Dir
is given, and never asks for elevation.

The signature is checked with minisign.exe when it is on PATH, otherwise
with OpenSSL 3 (the one in Git for Windows is found by its usual path).
Windows PowerShell 5.1 and PowerShell 7 are supported.

With `irm | iex` the options come from environment variables:
SMCP_VERSION, SMCP_INSTALL_DIR, SMCP_BASE_URL, SMCP_FROM, SMCP_PUBKEY and
SMCP_NO_COSIGN=1.

Options:
  -Version <tag>   release tag to install (default: the latest release)
  -Dir <path>      installation directory
                   (default: %LOCALAPPDATA%\Programs\smcp-gateway)
  -Repo <o/r>      GitHub repository (default: ethan03805/Secure-MCP-Gateway)
  -BaseUrl <url>   download base URL, for a mirror: https, or http on
                   127.0.0.1 or localhost only
  -From <dir>      install from release files already downloaded to <dir>
                   (the zip, the checksum file and its .minisig)
  -PubKey <key>    minisign public key, for a fork (default: the key below)
  -NoCosign        skip the cosign check even when cosign is installed
  -Help            show this help
#>
[CmdletBinding()]
param(
  [string]$Version = $env:SMCP_VERSION,
  [string]$Dir = $env:SMCP_INSTALL_DIR,
  [string]$Repo = 'ethan03805/Secure-MCP-Gateway',
  [string]$BaseUrl = $env:SMCP_BASE_URL,
  [string]$From = $env:SMCP_FROM,
  [string]$PubKey = $env:SMCP_PUBKEY,
  [switch]$NoCosign,
  [switch]$Help
)

# Everything runs in a child scope, so that `irm | iex`, which runs the
# script in the caller's session, leaves the caller's strict mode, error
# preference and variables as they were.
& {
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Release signing public key (minisign, key ID 064FAC0C64ACCED0). The same
# key is published in SECURITY.md and embedded in install.sh.
$ReleaseKey = 'RWTQzqxkDKxPBk0ZPk07i/mcrUVaevLmrm8zRkQLqGrs14RwtUhG30Dq'
$Project = 'smcp'
$Binaries = @('smcpd', 'smcpctl', 'smcp-session', 'smcp-stdio', 'smcp-connect', 'smcp-refserver')

function Say([string]$Message) { Write-Host "install.ps1: $Message" }

# Fail stops the script with a message. It throws instead of calling exit,
# so `irm | iex` does not close the caller's PowerShell window.
function Fail([string]$Message) { throw "install.ps1: $Message" }

function Invoke-Native([string]$Exe, [string[]]$Arguments) {
  # Windows PowerShell 5.1 turns native stderr into terminating errors when
  # $ErrorActionPreference is Stop; the exit code is what counts here.
  $old = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $out = & $Exe @Arguments 2>&1 | Out-String
    return [pscustomobject]@{ Code = $LASTEXITCODE; Out = $out }
  } finally {
    $ErrorActionPreference = $old
  }
}

function Find-Command([string]$Name) {
  $c = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($c) { return $c.Path }
  return $null
}

# Find-OpenSSL3 returns an OpenSSL 3 (or 4) executable: one on PATH, or the
# one Git for Windows installs.
function Find-OpenSSL3 {
  $candidates = @()
  $onPath = Find-Command 'openssl'
  if ($onPath) { $candidates += $onPath }
  if ($env:ProgramFiles) {
    foreach ($sub in @('Git\usr\bin\openssl.exe', 'Git\mingw64\bin\openssl.exe', 'Git\clangarm64\bin\openssl.exe')) {
      $candidates += (Join-Path $env:ProgramFiles $sub)
    }
  }
  foreach ($o in $candidates) {
    if (-not (Test-Path -LiteralPath $o -PathType Leaf)) { continue }
    $r = Invoke-Native $o @('version')
    if ($r.Code -eq 0 -and ($r.Out -match '^OpenSSL [34]')) { return $o }
  }
  return $null
}

function Test-SameBytes([byte[]]$A, [byte[]]$B) {
  if ($A.Length -ne $B.Length) { return $false }
  for ($i = 0; $i -lt $A.Length; $i++) { if ($A[$i] -ne $B[$i]) { return $false } }
  return $true
}

function Get-Slice([byte[]]$B, [int]$Offset, [int]$Count) {
  $out = New-Object byte[] $Count
  [Array]::Copy($B, $Offset, $out, 0, $Count)
  return ,$out
}

# Test-SignatureOpenSSL verifies a minisign signature (legacy "Ed" or
# prehashed "ED", BLAKE2b-512) and its signed trusted comment with OpenSSL 3.
function Test-SignatureOpenSSL([string]$OpenSSL, [string]$File, [string]$SigFile, [string]$Work) {
  New-Item -ItemType Directory -Force -Path $Work | Out-Null
  try { $pk = [Convert]::FromBase64String($PubKey) } catch { Say 'malformed public key'; return $false }
  if ($pk.Length -ne 42 -or $pk[0] -ne 0x45 -or $pk[1] -ne 0x64) { Say 'the public key is not a minisign Ed25519 key'; return $false }
  $lines = [IO.File]::ReadAllLines($SigFile)
  if ($lines.Length -lt 4) { Say 'malformed signature file'; return $false }
  try { $sig = [Convert]::FromBase64String($lines[1].Trim()) } catch { Say 'malformed signature'; return $false }
  if ($sig.Length -ne 74) { Say 'malformed signature'; return $false }
  if (-not (Test-SameBytes (Get-Slice $pk 2 8) (Get-Slice $sig 2 8))) { Say 'the signature was made with a different key'; return $false }
  # SubjectPublicKeyInfo DER prefix of an Ed25519 key, then the 32-byte key.
  $der = [byte[]](0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00) + (Get-Slice $pk 10 32)
  $derFile = Join-Path $Work 'pk.der'
  $pemFile = Join-Path $Work 'pk.pem'
  [IO.File]::WriteAllBytes($derFile, [byte[]]$der)
  if ((Invoke-Native $OpenSSL @('pkey', '-pubin', '-inform', 'DER', '-in', $derFile, '-out', $pemFile)).Code -ne 0) { return $false }
  $rawFile = Join-Path $Work 'sig.raw'
  [IO.File]::WriteAllBytes($rawFile, (Get-Slice $sig 10 64))
  $msgFile = Join-Path $Work 'msg'
  $alg = [Text.Encoding]::ASCII.GetString($sig, 0, 2)
  if ($alg -ceq 'ED') {
    if ((Invoke-Native $OpenSSL @('dgst', '-blake2b512', '-binary', '-out', $msgFile, $File)).Code -ne 0) { return $false }
  } elseif ($alg -ceq 'Ed') {
    Copy-Item -LiteralPath $File -Destination $msgFile
  } else {
    Say 'unknown signature algorithm'
    return $false
  }
  if ((Invoke-Native $OpenSSL @('pkeyutl', '-verify', '-pubin', '-inkey', $pemFile, '-rawin', '-in', $msgFile, '-sigfile', $rawFile)).Code -ne 0) { return $false }
  $tc = $lines[2].TrimEnd("`r")
  if (-not $tc.StartsWith('trusted comment: ')) { Say 'the signature has no trusted comment'; return $false }
  try { $global = [Convert]::FromBase64String($lines[3].Trim()) } catch { return $false }
  $globalRaw = Join-Path $Work 'global.raw'
  $globalMsg = Join-Path $Work 'global.msg'
  [IO.File]::WriteAllBytes($globalRaw, $global)
  $comment = [Text.Encoding]::UTF8.GetBytes($tc.Substring('trusted comment: '.Length))
  [IO.File]::WriteAllBytes($globalMsg, [byte[]]((Get-Slice $sig 10 64) + $comment))
  return ((Invoke-Native $OpenSSL @('pkeyutl', '-verify', '-pubin', '-inkey', $pemFile, '-rawin', '-in', $globalMsg, '-sigfile', $globalRaw)).Code -eq 0)
}

if ($Help) {
  Write-Host @'
usage: install.ps1 [-Version <tag>] [-Dir <path>] [-Repo <owner/name>]
                   [-BaseUrl <url>] [-From <dir>] [-PubKey <key>] [-NoCosign]

Downloads a Secure MCP Gateway release for this architecture, verifies the
minisign signature of its checksum file with the embedded release key,
verifies the archive's SHA-256, checks the Sigstore bundle when cosign is
installed, and installs smcpd, smcpctl and the harness adapters smcp-stdio,
smcp-session and smcp-connect. Signature checks need minisign.exe or
OpenSSL 3 (Git for Windows includes it). With `irm | iex`, set the options
as SMCP_VERSION, SMCP_INSTALL_DIR, SMCP_BASE_URL, SMCP_FROM, SMCP_PUBKEY
and SMCP_NO_COSIGN=1.
'@
  return
}
if (-not $PubKey) { $PubKey = $ReleaseKey }
if (-not $NoCosign -and $env:SMCP_NO_COSIGN -eq '1') { $NoCosign = $true }
if (-not $Dir) {
  if (-not $env:LOCALAPPDATA) { Fail 'LOCALAPPDATA is not set; pass -Dir' }
  $Dir = Join-Path $env:LOCALAPPDATA 'Programs\smcp-gateway'
}

if ($PSVersionTable.PSVersion.Major -lt 5) { Fail "PowerShell $($PSVersionTable.PSVersion) is too old; Windows PowerShell 5.1 or PowerShell 7 is required" }
if ([Environment]::OSVersion.Platform -ne 'Win32NT') { Fail 'this script installs the Windows build; on Linux and macOS use install.sh' }

# PROCESSOR_ARCHITEW6432 is set in a 32-bit process on a 64-bit host.
$hostArch = $env:PROCESSOR_ARCHITEW6432
if (-not $hostArch) { $hostArch = $env:PROCESSOR_ARCHITECTURE }
switch ($hostArch) {
  'AMD64' { $GoArch = 'amd64' }
  'ARM64' { $GoArch = 'arm64' }
  default { Fail "unsupported architecture: $hostArch (supported: AMD64, ARM64)" }
}

# Windows PowerShell 5.1 does not offer TLS 1.2 by default on every host.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

function Get-File([string]$Url, [string]$Out) {
  Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Out
}

if ($BaseUrl) {
  $u = [Uri]$BaseUrl
  $loopback = ($u.Scheme -eq 'http') -and ($u.Host -eq '127.0.0.1' -or $u.Host -eq 'localhost')
  if ($u.Scheme -ne 'https' -and -not $loopback) { Fail "base URL $BaseUrl is not https (plain http is accepted for 127.0.0.1 and localhost only)" }
}

if (-not $Version) {
  if ($From -or $BaseUrl) { Fail 'pass -Version with -From or -BaseUrl' }
  try {
    $rel = Invoke-RestMethod -UseBasicParsing -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ 'User-Agent' = 'smcp-install.ps1' }
    $Version = [string]$rel.tag_name
  } catch {
    Fail "could not resolve the latest release of $Repo; pass -Version ($($_.Exception.Message))"
  }
  if ($Version -notmatch '^v[0-9]') { Fail "could not determine the latest release (got '$Version'); pass -Version" }
}
if (-not $Version.StartsWith('v')) { $Version = "v$Version" }
$Num = $Version.Substring(1)

$Archive = "${Project}_${Num}_windows_${GoArch}.zip"
$Sums = "${Project}_${Num}_checksums.txt"
if (-not $BaseUrl) { $BaseUrl = "https://github.com/$Repo/releases/download/$Version" }
$BaseUrl = $BaseUrl.TrimEnd('/')

$Tmp = Join-Path ([IO.Path]::GetTempPath()) ("smcp-install-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
  $verifier = $null
  foreach ($f in @($Archive, $Sums, "$Sums.minisig")) {
    $dst = Join-Path $Tmp $f
    if ($From) {
      $src = Join-Path $From $f
      if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { Fail "$src is missing; nothing was installed" }
      Copy-Item -LiteralPath $src -Destination $dst
    } else {
      if ($f -eq $Archive) { Say "downloading $Archive ($Version)" }
      try { Get-File "$BaseUrl/$f" $dst } catch { Fail "download failed: $BaseUrl/$f; nothing was installed" }
    }
  }
  $sumsFile = Join-Path $Tmp $Sums
  $sigFile = Join-Path $Tmp "$Sums.minisig"

  # 1. The checksum file's minisign signature and trusted comment, with the
  #    embedded key.
  $ok = $false
  $minisign = Find-Command 'minisign'
  if ($minisign) {
    $verifier = 'minisign'
    $ok = ((Invoke-Native $minisign @('-V', '-q', '-P', $PubKey, '-m', $sumsFile, '-x', $sigFile)).Code -eq 0)
  } else {
    $openssl = Find-OpenSSL3
    if (-not $openssl) {
      Fail 'cannot verify the release signature: install minisign (winget install jedisct1.minisign) or Git for Windows, which includes OpenSSL 3, then run install.ps1 again. Nothing was installed.'
    }
    $verifier = $openssl
    $ok = Test-SignatureOpenSSL $openssl $sumsFile $sigFile (Join-Path $Tmp 'sigcheck')
  }
  if (-not $ok) { Fail "the minisign signature of $Sums does not verify with the release key; nothing was installed" }
  $sigLines = [IO.File]::ReadAllLines($sigFile)
  if ($sigLines.Length -lt 3 -or -not $sigLines[2].Contains("file:$Sums")) {
    Fail "the signed trusted comment in $Sums.minisig does not name $Sums; nothing was installed"
  }
  Say "signature verified ($Sums, with $verifier)"

  # 2. The Sigstore bundle of the checksum file, when cosign is installed.
  $cosign = Find-Command 'cosign'
  if ($NoCosign) {
    Say 'cosign check skipped (-NoCosign)'
  } elseif ($cosign) {
    $bundle = Join-Path $Tmp "$Sums.sigstore.json"
    if ($From) {
      $src = Join-Path $From "$Sums.sigstore.json"
      if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { Fail "cosign is installed but $src is missing; pass -NoCosign to rely on the minisign signature alone" }
      Copy-Item -LiteralPath $src -Destination $bundle
    } else {
      try { Get-File "$BaseUrl/$Sums.sigstore.json" $bundle } catch {
        Fail "download failed: $BaseUrl/$Sums.sigstore.json (cosign is installed but the release has no Sigstore bundle; pass -NoCosign to rely on the minisign signature alone)"
      }
    }
    $r = Invoke-Native $cosign @('verify-blob', '--bundle', $bundle,
      '--certificate-identity-regexp', "^https://github.com/$Repo/.github/workflows/release.yml@",
      '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com', $sumsFile)
    if ($r.Code -ne 0) { Fail "cosign could not verify $Sums.sigstore.json against the $Repo release workflow; nothing was installed" }
    Say "Sigstore bundle verified (cosign, $Repo release workflow)"
  } else {
    Say 'cosign is not installed; the Sigstore bundle was not checked (the minisign signature was)'
  }

  # 3. The archive's SHA-256 against the verified checksum file.
  $want = $null
  foreach ($line in [IO.File]::ReadAllLines($sumsFile)) {
    if ($line -match '^([0-9a-f]{64}) [ *](.+)$' -and $Matches[2] -eq $Archive) { $want = $Matches[1] }
  }
  if (-not $want) { Fail "$Archive is not listed in $Sums; nothing was installed" }
  $got = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $Tmp $Archive)).Hash.ToLowerInvariant()
  if ($got -ne $want) { Fail "checksum mismatch for ${Archive}: expected $want, got $got; nothing was installed" }
  Say "checksum verified ($got)"

  $x = Join-Path $Tmp 'x'
  Expand-Archive -LiteralPath (Join-Path $Tmp $Archive) -DestinationPath $x

  try { New-Item -ItemType Directory -Force -Path $Dir | Out-Null } catch { Fail "cannot create ${Dir}: $($_.Exception.Message)" }
  $installed = @()
  foreach ($b in $Binaries) {
    $src = Join-Path $x "$b.exe"
    if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { continue }
    $dst = Join-Path $Dir "$b.exe"
    $part = "$dst.part"
    Copy-Item -LiteralPath $src -Destination $part -Force
    try {
      Move-Item -LiteralPath $part -Destination $dst -Force
    } catch {
      Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
      Fail "cannot replace ${dst} (is it running? stop the Gateway first): $($_.Exception.Message)"
    }
    # The files were verified above; remove their Mark of the Web (FR-21.22).
    Unblock-File -LiteralPath $dst
    $installed += $b
  }
  if ($installed.Count -eq 0) { Fail 'the archive contains no binaries' }
  Say "installed $($installed -join ' ') to $Dir"
} finally {
  Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Say 'note: the Windows binaries have no Authenticode signature yet. SmartScreen may warn when they first run, and Smart App Control blocks them when it is on. This script verified them with minisign and SHA-256; docs/install.md shows how to check them by hand.'
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not ($userPath -split ';' | Where-Object { $_.TrimEnd('\') -ieq $Dir.TrimEnd('\') })) {
  Say "$Dir is not on your PATH; add it with:"
  Say "  [Environment]::SetEnvironmentVariable('Path', `"$Dir;`" + [Environment]::GetEnvironmentVariable('Path', 'User'), 'User')"
}
Say 'next: smcpctl install   (per-user Gateway; see docs/install.md)'
}

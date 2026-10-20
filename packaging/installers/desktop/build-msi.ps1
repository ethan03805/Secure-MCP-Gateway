<#
Builds the Windows Installer package of the Desktop Application,
smcp-desktop (E-35; SRS FR-20.20, FR-20.1), with the Tauri bundler's WiX
Toolset target, on the Windows runner of the package's architecture:

  pwsh packaging/installers/desktop/build-msi.ps1 -Version 1.3.0 -Arch x64 `
    -BinDir build\win\amd64 -OutDir build\desktop

  <OutDir>\smcp-desktop_<version>_windows_<amd64|arm64>.msi
      Per machine into "%ProgramFiles%\Secure MCP Gateway": smcp-desktop.exe
      and, beside it, smcpd, smcpctl, smcp-session, smcp-stdio, smcp-connect
      and smcp-refserver from -BinDir, with the marker package-format
      ("msi") that tells smcpctl uninstall and upgrade the binaries belong
      to a package; on removal (not on an upgrade) the package first runs
      `smcpctl uninstall --package-removal` (package-removal.wxs,
      FR-20.22). A Start menu shortcut whose application user model ID
      is the application's identifier (the approval toasts use it), the
      URL scheme smcp (FR-20.28) under HKLM\Software\Classes, and the
      WebView2 Evergreen bootstrapper, which the package runs only when no
      WebView2 runtime is installed (tauri.conf.json,
      bundle.windows.webviewInstallMode). No service, configuration or
      state: first-run setup or `smcpctl install` creates them (FR-20.21).
      Not signed (FR-20.30 is deferred); the release's signed checksum file
      covers it.

The MSI version is the numeric part of -Version (major.minor.patch), as
for the smcp .msi; the application reports the full version. Uses
CARGO_TARGET_DIR when set.
#>
param(
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][ValidateSet('x64', 'arm64')][string]$Arch,
  [Parameter(Mandatory = $true)][string]$BinDir,
  [Parameter(Mandatory = $true)][string]$OutDir
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Version = $Version.TrimStart('v')
if ($Version -notmatch '^(\d+\.\d+\.\d+)') { throw "version $Version has no major.minor.patch" }
$msiVersion = $Matches[1]
$goArch = if ($Arch -eq 'x64') { 'amd64' } else { 'arm64' }
$triple = if ($Arch -eq 'x64') { 'x86_64-pc-windows-msvc' } else { 'aarch64-pc-windows-msvc' }
# PE machine types: x64 0x8664, arm64 0xAA64.
$machine = if ($Arch -eq 'x64') { 0x8664 } else { 0xAA64 }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$BinDir = (Resolve-Path $BinDir).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

function PeMachine([string]$path) {
  $b = [IO.File]::ReadAllBytes($path)
  $pe = [BitConverter]::ToInt32($b, 0x3C)
  return [BitConverter]::ToUInt16($b, $pe + 4)
}

# The commands of this architecture, as the smcp .msi carries them.
$resources = [ordered]@{}
foreach ($b in 'smcpd', 'smcpctl', 'smcp-session', 'smcp-stdio', 'smcp-connect', 'smcp-refserver') {
  $src = Join-Path $BinDir "$b.exe"
  if (-not (Test-Path $src)) { throw "$b.exe missing in $BinDir" }
  if ((PeMachine $src) -ne $machine) { throw "$src is not a $goArch executable" }
  $resources[$src.Replace('\', '/')] = "$b.exe"
}
$resources[(Join-Path $repo 'packaging\installers\windows\package-format').Replace('\', '/')] = 'package-format'

$conf = [ordered]@{
  version = $Version
  bundle  = [ordered]@{
    resources = $resources
    # The package removal of FR-20.22 (package-removal.wxs).
    windows   = [ordered]@{ wix = [ordered]@{
        version            = $msiVersion
        fragmentPaths      = @((Join-Path $PSScriptRoot 'package-removal.wxs').Replace('\', '/'))
        componentGroupRefs = @('SmcpPackageRemoval')
      } }
  }
}
$work = Join-Path ([IO.Path]::GetTempPath()) ("smcp-desktop-msi-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$confFile = Join-Path $work 'tauri.json'
$conf | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8NoBOM $confFile

Push-Location (Join-Path $repo 'desktop')
try {
  if (-not (Test-Path node_modules)) {
    npm ci --no-audit --no-fund
    if ($LASTEXITCODE) { throw "npm ci exited $LASTEXITCODE" }
  }
  $target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $repo 'desktop\src-tauri\target' }
  $bundleDir = Join-Path $target "$triple\release\bundle\msi"
  if (Test-Path $bundleDir) { Remove-Item -Recurse -Force $bundleDir }
  npx --no-install tauri build --bundles msi --target $triple --config $confFile
  if ($LASTEXITCODE) { throw "tauri build exited $LASTEXITCODE" }
  $msis = @(Get-ChildItem -Path $bundleDir -Filter *.msi)
  if ($msis.Count -ne 1) { throw "expected one .msi in $bundleDir, found $($msis.Count)" }
  $exe = Join-Path $target "$triple\release\smcp-desktop.exe"
  if ((PeMachine $exe) -ne $machine) { throw "$exe is not a $goArch executable" }
  $out = Join-Path $OutDir ("smcp-desktop_{0}_windows_{1}.msi" -f $Version, $goArch)
  Copy-Item $msis[0].FullName $out -Force
  Get-Item $out | Format-Table Name, Length
}
finally {
  Pop-Location
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

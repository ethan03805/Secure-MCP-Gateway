<#
Builds the Windows Installer package of the CLI and Gateway (smcp.wxs) with
the WiX Toolset (the `wix` .NET tool, version pinned by the caller).

  pwsh packaging/installers/windows/build-msi.ps1 -Version 1.3.0 -Arch x64 `
    -BinDir build\win\amd64 -DocDir build\win\doc -OutDir build\installers

The package version is the numeric part of -Version (MSI versions are
major.minor.build); the file name keeps the full version:
smcp_<version>_windows_<amd64|arm64>.msi.
#>
param(
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][ValidateSet('x64', 'arm64')][string]$Arch,
  [Parameter(Mandatory = $true)][string]$BinDir,
  [Parameter(Mandatory = $true)][string]$DocDir,
  [Parameter(Mandatory = $true)][string]$OutDir
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($Version -notmatch '^v?(\d+\.\d+\.\d+)') { throw "version $Version has no major.minor.patch" }
$msiVersion = $Matches[1]
$goArch = if ($Arch -eq 'x64') { 'amd64' } else { 'arm64' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$out = Join-Path $OutDir ("smcp_{0}_windows_{1}.msi" -f $Version.TrimStart('v'), $goArch)
$src = $PSScriptRoot
& wix build -arch $Arch -d "Version=$msiVersion" -d "BinDir=$((Resolve-Path $BinDir).Path)" -d "DocDir=$((Resolve-Path $DocDir).Path)" `
  -d "SrcDir=$src" -o $out (Join-Path $src 'smcp.wxs')
if ($LASTEXITCODE -ne 0) { throw "wix build exited $LASTEXITCODE" }
Get-Item $out | Format-Table Name, Length

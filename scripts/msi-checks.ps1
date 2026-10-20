<#
Checks of an installed .msi package (SRS SR-4.11-2, FR-20.21), dot-sourced
by scripts/msi-smoke.ps1 and scripts/desktop-msi-smoke.ps1 on a Windows
runner:

  Assert-AdminsOnlyWrite <dir>
      every file and directory below <dir>, and <dir> itself, grants write,
      delete or permission changes to SYSTEM, Administrators and
      TrustedInstaller only (inherit-only entries, which do not apply to
      the object, are skipped);
  Assert-UserCannotWrite <dir>
      a standard local user created for the check, logged on with a
      network logon and impersonated, cannot open any of those files for
      writing or create a file in any of those directories. The runner's
      own account is an elevated Administrator, which the ACL lets write,
      so it cannot stand for an agent running as a user;
  Get-Digests <dir>, Compare-Digests <before> <after> <what>
      SHA-256 of every file below a directory, and their comparison.
#>

$script:AdminWriters = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')

function Get-InstalledItems([string]$dir) {
  @(Get-Item -LiteralPath $dir -Force) + @(Get-ChildItem -LiteralPath $dir -Recurse -Force)
}

function Assert-AdminsOnlyWrite([string]$dir) {
  $write = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, Delete, ChangePermissions, TakeOwnership'
  $n = 0
  foreach ($f in Get-InstalledItems $dir) {
    foreach ($r in (Get-Acl -LiteralPath $f.FullName).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
      if ($r.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
      if ($r.AccessControlType -eq 'Allow' -and ($r.FileSystemRights -band $write) -and $script:AdminWriters -notcontains $r.IdentityReference.Value) {
        throw "$($f.FullName) is writable by $($r.IdentityReference.Value) (SR-4.11-2)"
      }
    }
    $n++
  }
  Write-Host "$n files and directories in $dir`: write access for SYSTEM, Administrators and TrustedInstaller only"
}

function Assert-UserCannotWrite([string]$dir) {
  if (-not ('SmcpSmokeLogon' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SmcpSmokeLogon {
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  public static extern bool LogonUser(string user, string domain, string password, int logonType, int provider, out IntPtr token);
}
'@
  }
  $name = 'smcpsmoke' + (Get-Random -Maximum 99999)
  # 14 characters: net user asks for confirmation of a longer password.
  $plain = 'Sm0!' + [Guid]::NewGuid().ToString('N').Substring(0, 10)
  & net.exe user $name $plain /add | Out-Null
  if ($LASTEXITCODE) { throw "net user /add exited $LASTEXITCODE" }
  try {
    $tok = [IntPtr]::Zero
    # LOGON32_LOGON_NETWORK (3), LOGON32_PROVIDER_DEFAULT (0).
    if (-not [SmcpSmokeLogon]::LogonUser($name, '.', $plain, 3, 0, [ref]$tok)) {
      throw "LogonUser $name failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    $handle = [Microsoft.Win32.SafeHandles.SafeAccessTokenHandle]::new($tok)
    $script:smokeItems = Get-InstalledItems $dir
    $script:smokeWritable = [Collections.Generic.List[string]]::new()
    $script:smokeErrors = [Collections.Generic.List[string]]::new()
    $script:smokeChecked = 0
    [Security.Principal.WindowsIdentity]::RunImpersonated($handle, [Action] {
        foreach ($f in $script:smokeItems) {
          $script:smokeChecked++
          try {
            if ($f.PSIsContainer) {
              $p = Join-Path $f.FullName ('smcp-smoke-' + [Guid]::NewGuid().ToString('N'))
              [IO.File]::Open($p, 'CreateNew', 'Write').Dispose()
              Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
            }
            else {
              [IO.File]::Open($f.FullName, 'Open', 'Write').Dispose()
            }
            $script:smokeWritable.Add($f.FullName)
          }
          catch {
            $e = $_.Exception
            while ($e.InnerException) { $e = $e.InnerException }
            if ($e -isnot [UnauthorizedAccessException]) { $script:smokeErrors.Add("$($f.FullName): $($e.GetType().Name) $($e.Message)") }
          }
        }
      })
    $handle.Dispose()
    if ($script:smokeErrors.Count) { throw "the write check as $name did not run cleanly: $($script:smokeErrors -join '; ')" }
    if ($script:smokeWritable.Count) { throw "the standard user $name could write: $($script:smokeWritable -join ', ') (SR-4.11-2)" }
    Write-Host "a standard user could not write any of the $($script:smokeChecked) files and directories in $dir"
  }
  finally {
    & net.exe user $name /delete | Out-Null
  }
}

function Get-Digests([string]$root) {
  $h = [ordered]@{}
  Get-ChildItem -LiteralPath $root -Recurse -File -Force | Sort-Object FullName | ForEach-Object {
    $h[$_.FullName.Substring($root.Length)] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
  }
  return $h
}

function Compare-Digests($before, $after, [string]$what) {
  $b = ($before.GetEnumerator() | ForEach-Object { "$($_.Key) $($_.Value)" }) -join "`n"
  $a = ($after.GetEnumerator() | ForEach-Object { "$($_.Key) $($_.Value)" }) -join "`n"
  if ($a -ne $b) { Write-Host "before:`n$b`nafter:`n$a"; throw "$what changed" }
  Write-Host "$what unchanged: $($after.Count) files"
}

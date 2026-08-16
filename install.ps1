# sevra installer (Windows) — the command line for the Sevra hub (the managed
# home for db.md brains).
#
#   irm https://www.sevrahq.com/install/sevra.ps1 | iex
#
# Downloads the signed `sevra.exe` static binary, verifies its SHA-256 against
# Sevra's independently deployed manifest (required) and its Ed25519 publisher
# signature when a verifier is present, then drops it in a user directory. No runtime, no
# package manager, no admin rights. Native x64; Windows-on-ARM runs the same
# binary under the built-in x64 emulation.
#
# Honors: SEVRA_INSTALL_DIR (default ~\.sevra\bin), SEVRA_VERSION (default
# latest), SEVRA_INSTALL_BASE (default GitHub releases),
# SEVRA_TRUSTED_MANIFEST_BASE (defaults to the Sevra origin), and
# SEVRA_REQUIRE_SIGNATURE=1 (refuse when neither Node nor OpenSSL 3 can verify).
#
# Everything runs through Invoke-Main on the LAST line, so a truncated
# `irm | iex` stream can never execute a partial script.

$ErrorActionPreference = 'Stop'

$Repo = 'sevrahq/sevra'
$Dir = if ($env:SEVRA_INSTALL_DIR) { $env:SEVRA_INSTALL_DIR } else { Join-Path $env:USERPROFILE '.sevra\bin' }
$Base = if ($env:SEVRA_INSTALL_BASE) { $env:SEVRA_INSTALL_BASE } else { "https://github.com/$Repo/releases/download" }
$Api = 'https://www.sevrahq.com/api/hub/versions'
$ManifestBase = if ($env:SEVRA_TRUSTED_MANIFEST_BASE) { $env:SEVRA_TRUSTED_MANIFEST_BASE } else { 'https://www.sevrahq.com/api/hub/releases/sevra' }

# The pinned publisher keys (Ed25519 SPKI). v0.2.9 introduced compatibility
# signer A; v0.2.10 is signed by A while introducing offline signer B.
$PubkeyOldPem = @'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA+v5mafEPcIwKAU/DO/z8MM/cT9ndgE1saSUfvcrzLKA=
-----END PUBLIC KEY-----
'@
$PubkeyNextPem = @'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAasunxAjcJp8W30eF0ndPlLXqwSjZ/u5raivn3QmaKcc=
-----END PUBLIC KEY-----
'@
$PubkeyOfflinePem = @'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAzOIUB6eaOlwx1PqHCUBDF2+F3FLa5VK1u6QoFOVyXME=
-----END PUBLIC KEY-----
'@
$PubkeyPems = @($PubkeyOldPem, $PubkeyNextPem, $PubkeyOfflinePem)

function Fail([string]$Msg) { Write-Error "sevra install: $Msg" -ErrorAction Stop }
function Info([string]$Msg) { Write-Host $Msg }
function Have([string]$Cmd) { [bool](Get-Command $Cmd -ErrorAction SilentlyContinue) }

# The final install is a filesystem security boundary, so path inspection and
# replacement use no-follow Windows handles rather than PowerShell's
# path-following Move-Item. Every directory handle omits FILE_SHARE_DELETE and
# remains open until MoveFileExW completes.
if (-not ('SevraInstallerNative' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class SevraInstallerNative {
  public const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;
  public const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
  private const uint FILE_READ_ATTRIBUTES = 0x80;
  private const uint FILE_SHARE_READ = 0x1;
  private const uint FILE_SHARE_WRITE = 0x2;
  private const uint OPEN_EXISTING = 3;
  private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
  private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
  private const uint MOVEFILE_REPLACE_EXISTING = 0x1;
  private const uint MOVEFILE_WRITE_THROUGH = 0x8;

  [StructLayout(LayoutKind.Sequential)]
  public struct ByHandleFileInformation {
    public uint FileAttributes;
    public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
    public uint VolumeSerialNumber;
    public uint FileSizeHigh;
    public uint FileSizeLow;
    public uint NumberOfLinks;
    public uint FileIndexHigh;
    public uint FileIndexLow;
  }

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  private static extern SafeFileHandle CreateFileW(
    string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
    uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

  [DllImport("kernel32.dll", SetLastError = true)]
  private static extern bool GetFileInformationByHandle(
    SafeFileHandle file, out ByHandleFileInformation information);

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  private static extern bool MoveFileExW(string existing, string replacement, uint flags);

  public static SafeFileHandle OpenNoFollow(string path) {
    return CreateFileW(
      path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
      IntPtr.Zero, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
  }

  public static uint Attributes(SafeFileHandle handle) {
    ByHandleFileInformation information;
    if (!GetFileInformationByHandle(handle, out information)) {
      throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    return information.FileAttributes;
  }

  public static void Replace(string source, string destination) {
    if (!MoveFileExW(source, destination, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
      throw new Win32Exception(Marshal.GetLastWin32Error());
    }
  }
}
'@
}

function Open-NoFollow([string]$Path, [bool]$AllowMissing = $false) {
  $handle = [SevraInstallerNative]::OpenNoFollow($Path)
  if ($handle.IsInvalid) {
    $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    $handle.Dispose()
    if ($AllowMissing -and $code -in @(2, 3)) { return $null }
    throw [ComponentModel.Win32Exception]::new($code)
  }
  return $handle
}

function Open-LockedInstallDirectory([string]$Path) {
  $full = [IO.Path]::GetFullPath($Path)
  $root = [IO.Path]::GetPathRoot($full)
  if (-not $root) { Fail 'install directory must be an absolute filesystem path' }
  $handles = [Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]]::new()
  $current = $root
  $parts = $full.Substring($root.Length) -split '[\\/]'
  try {
    $components = @($root) + @($parts | Where-Object { $_ })
    foreach ($component in $components) {
      $handle = $null
      try {
        if ($component -ne $root) {
          $current = Join-Path $current $component
          $handle = Open-NoFollow $current $true
          if ($null -eq $handle) {
            [IO.Directory]::CreateDirectory($current) | Out-Null
            $handle = Open-NoFollow $current
          }
        } else {
          $handle = Open-NoFollow $current
        }
        $attributes = [SevraInstallerNative]::Attributes($handle)
        if (($attributes -band [SevraInstallerNative]::FILE_ATTRIBUTE_REPARSE_POINT) -ne 0) {
          Fail "install directory must not contain reparse points: $current"
        }
        if (($attributes -band [SevraInstallerNative]::FILE_ATTRIBUTE_DIRECTORY) -eq 0) {
          Fail "install path component is not a directory: $current"
        }
        $handles.Add($handle)
        # The returned capability object owns this handle now.
        $handle = $null
      } finally {
        if ($handle) { $handle.Dispose() }
      }
    }
    return [pscustomobject]@{ FullPath = $full; Handles = $handles }
  } catch {
    foreach ($handle in $handles) { $handle.Dispose() }
    throw
  }
}

function Assert-SafeInstallLeaf([string]$Path) {
  $handle = Open-NoFollow $Path $true
  if ($null -eq $handle) { return }
  try {
    $attributes = [SevraInstallerNative]::Attributes($handle)
    if (($attributes -band [SevraInstallerNative]::FILE_ATTRIBUTE_REPARSE_POINT) -ne 0) {
      Fail "install destination must not be a reparse point: $Path"
    }
    if (($attributes -band [SevraInstallerNative]::FILE_ATTRIBUTE_DIRECTORY) -ne 0) {
      Fail "install destination must be absent or a regular file: $Path"
    }
  } finally {
    $handle.Dispose()
  }
}

function Fetch([string]$Url, [string]$OutFile) {
  try { Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing } catch {
    if ($Url -match '/sevra-windows-') {
      Fail ("download failed: $Url`n  If this release predates Windows support, it has no Windows asset yet: " +
        "pin a newer release with `$env:SEVRA_VERSION, or install under WSL with the sh installer.")
    }
    Fail "download failed: $Url"
  }
}

function Invoke-Main {

  if ($env:SEVRA_REQUIRE_SIGNATURE -and $env:SEVRA_REQUIRE_SIGNATURE -notin @('0', '1')) {
    Fail 'SEVRA_REQUIRE_SIGNATURE must be 0 or 1'
  }
  $requireSignature = $env:SEVRA_REQUIRE_SIGNATURE -eq '1'

  # ── Platform ──────────────────────────────────────────────────────────────
  $arch = $env:PROCESSOR_ARCHITECTURE
  switch -Regex ($arch) {
    '^(AMD64|ARM64)$' { }
    default { Fail "unsupported arch: $arch (x64 and ARM64-via-emulation only)" }
  }
  if ($arch -eq 'ARM64') {
    Info 'note: ARM64 detected; installing the x64 binary (runs under the built-in emulation).'
  }
  $target = 'windows-x86_64'
  $assetName = "sevra-$target.exe"

  # ── Version ───────────────────────────────────────────────────────────────
  $version = $env:SEVRA_VERSION
  if (-not $version) {
    Info 'Resolving the latest sevra release...'
    try { $release = Invoke-RestMethod -Uri $Api -UseBasicParsing } catch {
      Fail 'could not resolve the trusted latest release; pin SEVRA_VERSION to retry'
    }
    $version = "$($release.sevra.latest)"
    if (-not $version) { Fail 'could not resolve the latest release (empty tag)' }
  }
  $url = "$Base/v$version/$assetName"

  # A PID-derived temp name can be pre-planted as a junction or directory.
  # Create an unpredictable directory without -Force so an existing entry is
  # a refusal, never something we reuse.
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ("sevra-install-" + [IO.Path]::GetRandomFileName())
  New-Item -ItemType Directory -Path $tmp | Out-Null
  $stageDir = $null
  $lockedDir = $null
  try {

    Info "Downloading sevra $version ($target)..."
    $bin = Join-Path $tmp 'sevra.exe'
    Fetch $url $bin
    Fetch "$url.sig" (Join-Path $tmp 'sevra.exe.sig')

    # ── Verify checksum against the independently deployed manifest ────────
    # A custom binary mirror never silently becomes its own trust root. Tests
    # and private mirrors must separately set SEVRA_TRUSTED_MANIFEST_BASE.
    # WinHTTP/WinINet can reuse a cached manifest response inside one process.
    # Integrity metadata must be fetched for this install attempt, not inherited
    # from an earlier request that may predate a revocation or manifest change.
    $manifestNonce = [Guid]::NewGuid().ToString('N')
    $manifestResource = "$ManifestBase/$version/$assetName"
    $manifestSeparator = if ($manifestResource -match '\?') { '&' } else { '?' }
    $manifestUrl = "${manifestResource}${manifestSeparator}nonce=$manifestNonce"
    try {
      $expected = "$(Invoke-RestMethod -Uri $manifestUrl -UseBasicParsing -Headers @{
        'Cache-Control' = 'no-cache, no-store'
        'Pragma' = 'no-cache'
      })".Trim().ToLowerInvariant()
    } catch {
      Fail "no trusted checksum for sevra $version $assetName"
    }
    if ($expected -notmatch '^[0-9a-f]{64}$') { Fail "no trusted checksum for sevra $version $assetName" }
    $actual = (Get-FileHash -Algorithm SHA256 -Path $bin).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { Fail "checksum mismatch (expected $expected, got $actual). Refusing to install" }
    Info 'checksum: verified (sha256)'

    # ── Verify signature (required when a verifier is available) ───────────
    $verifiedSig = $false
    $verifierAvailable = $false
    if (Have 'node') {
      $verifierAvailable = $true
      $env:SEVRA_PUBKEY_OLD = $PubkeyPems[0]
      $env:SEVRA_PUBKEY_NEXT = $PubkeyPems[1]
      $env:SEVRA_PUBKEY_OFFLINE = $PubkeyPems[2]
      $nodeScript = @'
const { createPublicKey, verify } = require("node:crypto");
const { readFileSync } = require("node:fs");
const message = readFileSync(process.argv[1]);
const signature = Buffer.from(readFileSync(process.argv[2], "utf8").trim(), "base64");
const keys = [process.env.SEVRA_PUBKEY_OLD, process.env.SEVRA_PUBKEY_NEXT, process.env.SEVRA_PUBKEY_OFFLINE];
const ok = keys.some((pem) =>
  verify(null, message, createPublicKey(pem), signature));
process.exit(ok ? 0 : 1);
'@
      & node -e $nodeScript $bin (Join-Path $tmp 'sevra.exe.sig') 2>$null
      if ($LASTEXITCODE -eq 0) { $verifiedSig = $true }
      Remove-Item Env:SEVRA_PUBKEY_OLD -ErrorAction SilentlyContinue
      Remove-Item Env:SEVRA_PUBKEY_NEXT -ErrorAction SilentlyContinue
      Remove-Item Env:SEVRA_PUBKEY_OFFLINE -ErrorAction SilentlyContinue
    }
    if (-not $verifiedSig -and (Have 'openssl')) {
      $pubPem = Join-Path $tmp 'pub.pem'
      foreach ($pubkeyPem in $PubkeyPems) {
        Set-Content -Path $pubPem -Value $pubkeyPem -NoNewline
        # Capability probe, not mere presence: only OpenSSL 3+ can do Ed25519.
        # An older build cannot even load this key, and treating that as an
        # available verifier turns a good download into "signature failed" and
        # aborts the install. Only a CAPABLE verifier's failure is fatal.
        & openssl pkey -pubin -in $pubPem -noout 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
          $verifierAvailable = $true
          try {
            $sigB64 = (Get-Content (Join-Path $tmp 'sevra.exe.sig') -Raw).Trim()
            $sigBin = Join-Path $tmp 'sig.bin'
            [IO.File]::WriteAllBytes($sigBin, [Convert]::FromBase64String($sigB64))
            & openssl pkeyutl -verify -pubin -inkey $pubPem -rawin -in $bin -sigfile $sigBin 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) {
              $verifiedSig = $true
              break
            }
          } catch {
            # A malformed signature is a normal verification failure. Try no
            # other representation and fail closed after the trusted-key set.
          }
        }
      }
    }
    if ($verifiedSig) {
      Info 'signature: verified (ed25519)'
    } elseif ($verifierAvailable) {
      Fail 'publisher signature verification failed. Refusing to install'
    } elseif ($requireSignature) {
      Fail 'publisher signature verification is required, but neither Node nor an Ed25519-capable OpenSSL is available. Refusing to install'
    } else {
      Info 'signature: verifier unavailable; the required SHA-256 came from the independently deployed Sevra manifest'
    }

    # ── Install ─────────────────────────────────────────────────────────────
    $lockedDir = Open-LockedInstallDirectory $Dir
    $Dir = $lockedDir.FullPath
    # Stage under the handle-locked install directory and then replace through
    # MoveFileExW. The unpredictable stage is CREATE_NEW-created and itself
    # opened no-follow before any bytes are copied.
    $stageDir = Join-Path $Dir (".sevra-stage-" + [IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $stageDir | Out-Null
    $stageHandle = Open-NoFollow $stageDir
    $stageAttributes = [SevraInstallerNative]::Attributes($stageHandle)
    if (($stageAttributes -band [SevraInstallerNative]::FILE_ATTRIBUTE_REPARSE_POINT) -ne 0 -or
        ($stageAttributes -band [SevraInstallerNative]::FILE_ATTRIBUTE_DIRECTORY) -eq 0) {
      $stageHandle.Dispose()
      Fail 'private installer stage became a reparse point or non-directory'
    }
    $lockedDir.Handles.Add($stageHandle)
    $staged = Join-Path $stageDir 'sevra.exe'
    $sourceStream = [IO.File]::Open($bin, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
      $stageStream = [IO.File]::Open($staged, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try {
        $sourceStream.CopyTo($stageStream)
        $stageStream.Flush($true)
      } finally {
        $stageStream.Dispose()
      }
    } finally {
      $sourceStream.Dispose()
    }
    $destination = Join-Path $Dir 'sevra.exe'
    # Repeat immediately before the single entry replacement.
    Assert-SafeInstallLeaf $destination
    [SevraInstallerNative]::Replace($staged, $destination)
    foreach ($handle in $lockedDir.Handles) { $handle.Dispose() }
    $lockedDir = $null
    Remove-Item -Path $stageDir -Force
    $stageDir = $null
    Info "sevra $version installed to $(Join-Path $Dir 'sevra.exe')"

    $onPath = ($env:Path -split ';') -contains $Dir
    if ($onPath) {
      Info 'Next: sevra login   (approve once in your browser)'
    } else {
      Info 'Add it to your PATH (user scope, new shells), then log in:'
      Info "  [Environment]::SetEnvironmentVariable('Path', `"$Dir;`" + [Environment]::GetEnvironmentVariable('Path','User'), 'User')"
      Info "  `$env:Path = `"$Dir;`" + `$env:Path   # this shell too"
      Info '  sevra login'
    }

  } finally {
    if ($lockedDir) {
      foreach ($handle in $lockedDir.Handles) { $handle.Dispose() }
    }
    if ($stageDir) {
      Remove-Item -Recurse -Force $stageDir -ErrorAction SilentlyContinue
    }
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  }
}

Invoke-Main

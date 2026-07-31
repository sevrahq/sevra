# Exercise the Windows installer's dual-key verification and strict-signature
# negative path against a loopback-only fake release.
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$tmp = Join-Path ([IO.Path]::GetTempPath()) "sevra-installer-test-$PID"
$release = Join-Path $tmp 'release\v9.9.9'
$trusted = Join-Path $tmp 'trusted\9.9.9'
$installDir = Join-Path $tmp 'install'
New-Item -ItemType Directory -Force -Path $release | Out-Null
New-Item -ItemType Directory -Force -Path $trusted | Out-Null

$asset = 'sevra-windows-x86_64.exe'
$binary = Join-Path $release $asset
[IO.File]::WriteAllText($binary, 'sevra release signing trust-set regression v0.2.8')
[IO.File]::WriteAllText("$binary.sig", "FCNsagdkJcD/ZDs5k0BhL8t23AKGLwO5Zrq0sv1BZr4HN8vHXIXWgrfm6GkV+mnUswY3utnyiCNeCavngLbBDg==`n")
$digest = (Get-FileHash -Algorithm SHA256 $binary).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $release 'SHA256SUMS'), "$digest  $asset`n")
[IO.File]::WriteAllText((Join-Path $trusted $asset), "$digest`n")

$probe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$probe.Start()
$port = ([Net.IPEndPoint]$probe.LocalEndpoint).Port
$probe.Stop()
$python = (Get-Command python).Source
$server = Start-Process -FilePath $python -ArgumentList @(
  '-m', 'http.server', "$port", '--bind', '127.0.0.1', '--directory', "`"$tmp`""
) -WindowStyle Hidden -PassThru

$oldPath = $env:Path
try {
  Start-Sleep -Milliseconds 500
  $env:PROCESSOR_ARCHITECTURE = 'AMD64'
  $env:SEVRA_VERSION = '9.9.9'
  $env:SEVRA_INSTALL_BASE = "http://127.0.0.1:$port/release"
  $env:SEVRA_TRUSTED_MANIFEST_BASE = "http://127.0.0.1:$port/trusted"
  $env:SEVRA_INSTALL_DIR = $installDir
  $env:SEVRA_REQUIRE_SIGNATURE = '1'

  # The successor key is already trusted by the compatibility installer.
  & (Join-Path $root 'install.ps1')
  if ($LASTEXITCODE -ne 0) { throw 'successor-key install failed' }
  if (-not (Test-Path (Join-Path $installDir 'sevra.exe'))) {
    throw 'successor-key install did not write the verified binary'
  }

  # A destination junction makes Move-Item treat `sevra.exe` as a directory
  # and write through it. The no-follow installer must reject the reparse leaf
  # and preserve its target.
  $destinationLinkInstall = Join-Path $tmp 'destination-link-install'
  $destinationLinkOutside = Join-Path $tmp 'destination-link-outside'
  New-Item -ItemType Directory -Path $destinationLinkInstall | Out-Null
  New-Item -ItemType Directory -Path $destinationLinkOutside | Out-Null
  [IO.File]::WriteAllText((Join-Path $destinationLinkOutside 'sevra.exe'), 'SAFE')
  New-Item -ItemType Junction -Path (Join-Path $destinationLinkInstall 'sevra.exe') -Target $destinationLinkOutside | Out-Null
  $env:SEVRA_INSTALL_DIR = $destinationLinkInstall
  $destinationLinkFailed = $false
  try {
    & (Join-Path $root 'install.ps1')
  } catch {
    $destinationLinkFailed = "$_" -match 'install destination must not be a reparse point'
  }
  if (-not $destinationLinkFailed) {
    throw 'installer unexpectedly accepted a destination reparse point'
  }
  if ([IO.File]::ReadAllText((Join-Path $destinationLinkOutside 'sevra.exe')) -ne 'SAFE') {
    throw 'destination reparse target was overwritten'
  }

  # Every existing install-directory component is opened with
  # FILE_FLAG_OPEN_REPARSE_POINT. A junction at `$DIR` itself must not grant
  # write access to its target.
  $parentLinkOutside = Join-Path $tmp 'parent-link-outside'
  $parentLinkInstall = Join-Path $tmp 'parent-link-install'
  New-Item -ItemType Directory -Path $parentLinkOutside | Out-Null
  [IO.File]::WriteAllText((Join-Path $parentLinkOutside 'sevra.exe'), 'SAFE')
  New-Item -ItemType Junction -Path $parentLinkInstall -Target $parentLinkOutside | Out-Null
  $env:SEVRA_INSTALL_DIR = $parentLinkInstall
  $parentLinkFailed = $false
  try {
    & (Join-Path $root 'install.ps1')
  } catch {
    $parentLinkFailed = "$_" -match 'install directory must not contain reparse points'
  }
  if (-not $parentLinkFailed) {
    throw 'installer unexpectedly accepted a reparse-point install directory'
  }
  if ([IO.File]::ReadAllText((Join-Path $parentLinkOutside 'sevra.exe')) -ne 'SAFE') {
    throw 'install-directory reparse target was overwritten'
  }

  # A real directory at the leaf is also unsafe and must not receive a nested
  # sevra.exe through directory-target move semantics.
  $directoryLeafInstall = Join-Path $tmp 'directory-leaf-install'
  New-Item -ItemType Directory -Path (Join-Path $directoryLeafInstall 'sevra.exe') -Force | Out-Null
  $env:SEVRA_INSTALL_DIR = $directoryLeafInstall
  $directoryLeafFailed = $false
  try {
    & (Join-Path $root 'install.ps1')
  } catch {
    $directoryLeafFailed = "$_" -match 'install destination must be absent or a regular file'
  }
  if (-not $directoryLeafFailed) {
    throw 'installer unexpectedly accepted a directory destination'
  }
  if (Test-Path (Join-Path $directoryLeafInstall 'sevra.exe\sevra.exe')) {
    throw 'installer wrote into a directory destination'
  }

  # Dual-key acceptance never bypasses the independent digest root.
  [IO.File]::WriteAllText((Join-Path $trusted $asset), "$('0' * 64)`n")
  $env:SEVRA_INSTALL_DIR = Join-Path $tmp 'bad-digest-install'
  $digestFailed = $false
  try {
    & (Join-Path $root 'install.ps1')
  } catch {
    $digestFailed = "$_" -match 'checksum mismatch'
  }
  if (-not $digestFailed) {
    throw 'installer unexpectedly accepted a bad independent digest'
  }
  if (Test-Path (Join-Path $env:SEVRA_INSTALL_DIR 'sevra.exe')) {
    throw 'installer wrote a binary after digest refusal'
  }
  [IO.File]::WriteAllText((Join-Path $trusted $asset), "$digest`n")

  # A custom binary origin's colocated SHA256SUMS is not a second root.
  $env:SEVRA_TRUSTED_MANIFEST_BASE = "http://127.0.0.1:$port/missing-trust-root"
  $env:SEVRA_INSTALL_DIR = Join-Path $tmp 'missing-manifest-install'
  $missingManifestFailed = $false
  try {
    & (Join-Path $root 'install.ps1')
  } catch {
    $missingManifestFailed = "$_" -match 'no trusted checksum'
  }
  if (-not $missingManifestFailed) {
    throw 'installer unexpectedly fell back to colocated SHA256SUMS'
  }
  if (Test-Path (Join-Path $env:SEVRA_INSTALL_DIR 'sevra.exe')) {
    throw 'installer wrote a binary without the independent manifest'
  }
  $env:SEVRA_TRUSTED_MANIFEST_BASE = "http://127.0.0.1:$port/trusted"

  # A valid signature from an unrelated Ed25519 key must fail.
  [IO.File]::WriteAllText("$binary.sig", "OS0fG3e4xQd6KTgUQallkV2RgzZQrB+b/rKAetJi9NWFe6se2U9LMu6GQfbDClgR3KwI36e6X8nWJATMoL2zCg==`n")
  $env:SEVRA_INSTALL_DIR = Join-Path $tmp 'unrelated-install'
  $unrelatedFailed = $false
  try {
    & (Join-Path $root 'install.ps1')
  } catch {
    $unrelatedFailed = "$_" -match 'publisher signature verification failed'
  }
  if (-not $unrelatedFailed) {
    throw 'installer unexpectedly trusted an unrelated signer'
  }
  if (Test-Path (Join-Path $env:SEVRA_INSTALL_DIR 'sevra.exe')) {
    throw 'installer wrote a binary after unrelated-signer refusal'
  }

  # Empty PATH only after the positive verifier checks, so neither Node nor
  # OpenSSL can be discovered for the strict no-verifier path.
  [IO.File]::WriteAllText("$binary.sig", "not-a-real-signature`n")
  $env:Path = ''
  $env:SEVRA_INSTALL_DIR = Join-Path $tmp 'no-verifier-install'
  $failedClosed = $false
  try {
    & (Join-Path $root 'install.ps1')
  } catch {
    $failedClosed = "$_" -match 'publisher signature verification is required'
  }
  if (-not $failedClosed) {
    throw 'strict installer did not fail closed without a signature verifier'
  }
  if (Test-Path (Join-Path $env:SEVRA_INSTALL_DIR 'sevra.exe')) {
    throw 'strict installer wrote a binary after signature refusal'
  }
} finally {
  $env:Path = $oldPath
  Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

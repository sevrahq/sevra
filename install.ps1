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
# SEVRA_TRUSTED_MANIFEST_BASE (defaults to the Sevra origin).
#
# Everything runs through Invoke-Main on the LAST line, so a truncated
# `irm | iex` stream can never execute a partial script.

$ErrorActionPreference = 'Stop'

$Repo = 'sevrahq/sevra'
$Dir = if ($env:SEVRA_INSTALL_DIR) { $env:SEVRA_INSTALL_DIR } else { Join-Path $env:USERPROFILE '.sevra\bin' }
$Base = if ($env:SEVRA_INSTALL_BASE) { $env:SEVRA_INSTALL_BASE } else { "https://github.com/$Repo/releases/download" }
$Api = 'https://www.sevrahq.com/api/hub/versions'
$ManifestBase = if ($env:SEVRA_TRUSTED_MANIFEST_BASE) { $env:SEVRA_TRUSTED_MANIFEST_BASE } else { 'https://www.sevrahq.com/api/hub/releases/sevra' }

# The pinned publisher key (Ed25519 SPKI) — the same key that signs releases
# in CI and is pinned inside the binary for self-update.
$PubkeyPem = @'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA+v5mafEPcIwKAU/DO/z8MM/cT9ndgE1saSUfvcrzLKA=
-----END PUBLIC KEY-----
'@

function Fail([string]$Msg) { Write-Error "sevra install: $Msg" -ErrorAction Stop }
function Info([string]$Msg) { Write-Host $Msg }
function Have([string]$Cmd) { [bool](Get-Command $Cmd -ErrorAction SilentlyContinue) }

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

  $tmp = Join-Path ([IO.Path]::GetTempPath()) "sevra-install-$PID"
  New-Item -ItemType Directory -Force -Path $tmp | Out-Null
  try {

    Info "Downloading sevra $version ($target)..."
    $bin = Join-Path $tmp 'sevra.exe'
    Fetch $url $bin
    Fetch "$url.sig" (Join-Path $tmp 'sevra.exe.sig')

    # ── Verify checksum against the independently deployed manifest ────────
    if ($env:SEVRA_INSTALL_BASE -and -not $env:SEVRA_TRUSTED_MANIFEST_BASE) {
      Fetch "$Base/v$version/SHA256SUMS" (Join-Path $tmp 'SHA256SUMS')
      $sums = Get-Content (Join-Path $tmp 'SHA256SUMS')
      $line = $sums | Where-Object { $_.TrimEnd().EndsWith(" $assetName") } | Select-Object -First 1
      if (-not $line) { Fail "no checksum for $assetName in SHA256SUMS" }
      $expected = ($line -split '\s+')[0].ToLowerInvariant()
    } else {
      try { $expected = "$(Invoke-RestMethod -Uri "$ManifestBase/$version/$assetName" -UseBasicParsing)".Trim().ToLowerInvariant() } catch {
        Fail "no trusted checksum for sevra $version $assetName"
      }
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
      $env:SEVRA_PUBKEY = $PubkeyPem
      $nodeScript = @'
const { createPublicKey, verify } = require("node:crypto");
const { readFileSync } = require("node:fs");
const ok = verify(null, readFileSync(process.argv[1]),
  createPublicKey(process.env.SEVRA_PUBKEY),
  Buffer.from(readFileSync(process.argv[2], "utf8").trim(), "base64"));
process.exit(ok ? 0 : 1);
'@
      & node -e $nodeScript $bin (Join-Path $tmp 'sevra.exe.sig') 2>$null
      if ($LASTEXITCODE -eq 0) { $verifiedSig = $true }
      Remove-Item Env:SEVRA_PUBKEY -ErrorAction SilentlyContinue
    }
    if (-not $verifiedSig -and (Have 'openssl')) {
      $verifierAvailable = $true
      $pubPem = Join-Path $tmp 'pub.pem'
      Set-Content -Path $pubPem -Value $PubkeyPem -NoNewline
      $sigB64 = (Get-Content (Join-Path $tmp 'sevra.exe.sig') -Raw).Trim()
      $sigBin = Join-Path $tmp 'sig.bin'
      [IO.File]::WriteAllBytes($sigBin, [Convert]::FromBase64String($sigB64))
      & openssl pkeyutl -verify -pubin -inkey $pubPem -rawin -in $bin -sigfile $sigBin 2>$null | Out-Null
      if ($LASTEXITCODE -eq 0) { $verifiedSig = $true }
    }
    if ($verifiedSig) {
      Info 'signature: verified (ed25519)'
    } elseif ($verifierAvailable) {
      Fail 'publisher signature verification failed. Refusing to install'
    } else {
      Info 'signature: verifier unavailable; the required SHA-256 came from the independently deployed Sevra manifest'
    }

    # ── Install ─────────────────────────────────────────────────────────────
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    # Stage inside $Dir, then rename: same-volume, so a reinstall never leaves
    # a half-written binary. (A RUNNING sevra.exe blocks the final move — the
    # binary's own `sevra update` handles that case; a fresh install won't hit
    # it.)
    $staged = Join-Path $Dir ".sevra.new.$PID"
    Copy-Item $bin $staged -Force
    Move-Item $staged (Join-Path $Dir 'sevra.exe') -Force
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
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  }
}

Invoke-Main

# sevra installer (Windows) — the command line for the Sevra hub (the managed
# home for db.md brains).
#
#   irm https://www.sevrahq.com/install/sevra.ps1 | iex
#
# Downloads the signed `sevra.exe` static binary, verifies its SHA-256
# (required, via Get-FileHash) and its Ed25519 publisher signature (when node
# or openssl 3 is present), and drops it in a user directory. No runtime, no
# package manager, no admin rights. Native x64; Windows-on-ARM runs the same
# binary under the built-in x64 emulation.
#
# Honors: SEVRA_INSTALL_DIR (default ~\.sevra\bin), SEVRA_VERSION (default
# latest), SEVRA_INSTALL_BASE (default GitHub releases),
# SEVRA_REQUIRE_SIGNATURE=1 (fail the install when the Ed25519 signature
# cannot be checked here, instead of relying on SHA-256 + HTTPS alone),
# GITHUB_TOKEN (authenticates only the api.github.com latest lookup).
#
# Everything runs through Invoke-Main on the LAST line, so a truncated
# `irm | iex` stream can never execute a partial script.

$ErrorActionPreference = 'Stop'

$Repo = 'sevrahq/sevra'
$Dir = if ($env:SEVRA_INSTALL_DIR) { $env:SEVRA_INSTALL_DIR } else { Join-Path $env:USERPROFILE '.sevra\bin' }
$Base = if ($env:SEVRA_INSTALL_BASE) { $env:SEVRA_INSTALL_BASE } else { "https://github.com/$Repo/releases/download" }
$Api = "https://api.github.com/repos/$Repo/releases/latest"

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
    # GITHUB_TOKEN authenticates ONLY this hardcoded api.github.com lookup
    # (CI runners share rate-limited IPs); it is never sent to the download
    # host.
    $headers = @{}
    if ($env:GITHUB_TOKEN) { $headers['authorization'] = "Bearer $($env:GITHUB_TOKEN)" }
    try { $release = Invoke-RestMethod -Uri $Api -Headers $headers -UseBasicParsing } catch {
      Fail 'could not resolve the latest release (rate-limited? set GITHUB_TOKEN, or pin SEVRA_VERSION)'
    }
    $version = "$($release.tag_name)" -replace '^v', ''
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
    Fetch "$Base/v$version/SHA256SUMS" (Join-Path $tmp 'SHA256SUMS')

    # ── Verify checksum (required) ──────────────────────────────────────────
    $sums = Get-Content (Join-Path $tmp 'SHA256SUMS')
    $line = $sums | Where-Object { $_.TrimEnd().EndsWith(" $assetName") } | Select-Object -First 1
    if (-not $line) { Fail "no checksum for $assetName in SHA256SUMS" }
    $expected = ($line -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 -Path $bin).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { Fail "checksum mismatch (expected $expected, got $actual). Refusing to install" }
    Info 'checksum: verified (sha256)'

    # ── Verify signature (best-effort: node, else openssl 3) ────────────────
    $verifiedSig = $false
    if (Have 'node') {
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
    } elseif ($env:SEVRA_REQUIRE_SIGNATURE -eq '1') {
      Fail 'signature could not be checked (no node or openssl 3) and SEVRA_REQUIRE_SIGNATURE=1. Refusing to install'
    } else {
      Info 'signature: not checked here (no node or openssl 3); the SHA-256 above was verified over HTTPS, and the binary re-verifies its signature on every self-update. Set SEVRA_REQUIRE_SIGNATURE=1 to make this check mandatory.'
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
      Info 'Next: sevra login --key sevra_account_...   (create a key in the dashboard)'
    } else {
      Info 'Add it to your PATH (user scope, new shells), then log in:'
      Info "  [Environment]::SetEnvironmentVariable('Path', `"$Dir;`" + [Environment]::GetEnvironmentVariable('Path','User'), 'User')"
      Info "  `$env:Path = `"$Dir;`" + `$env:Path   # this shell too"
      Info '  sevra login --key sevra_account_...'
    }

  } finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  }
}

Invoke-Main

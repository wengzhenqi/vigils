#Requires -Version 5.1
<#
  Vigils one-line installer (Windows).

      irm https://vigils.ai/install.ps1 | iex

  Downloads the latest Vigils CLI (vigil-hub.exe + vigil-native-host.exe) from GitHub
  Releases and installs it to %LOCALAPPDATA%\Vigils\bin. Pin a version or change the
  target dir with env vars:

      $env:VIGILS_VERSION='v0.1.26'; $env:VIGILS_INSTALL_DIR="$HOME\bin"; irm https://vigils.ai/install.ps1 | iex

  Conservative by design (this is a security tool): it ONLY downloads the binaries and
  puts them on disk. It does NOT edit your PATH, does NOT run `setup`, and does NOT touch
  any agent config — it prints what to do next so you stay in control.

  Integrity (fail-closed): downloaded over HTTPS from github.com (TLS-authenticated), AND
  verified against the SHA-256 published with the release asset (<asset>.sha256) before
  anything is unpacked — a missing checksum or a mismatch aborts the install. The archive
  is also validated to be exactly the two expected files before extraction. The .sha256
  lives in the same release, so it detects transit corruption/tampering; it is not an
  independent offline signature. Read this script before piping it to iex:
      https://github.com/duncatzat/vigils/blob/main/install.ps1
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# TLS 1.2 for Windows PowerShell 5.1 (older defaults can fail the GitHub handshake).
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocol]::Tls12 } catch {}

$Repo = 'duncatzat/vigils'
# Sanitize hostile env values so they can't poison the terminal (control chars). Version also
# feeds a URL path, so it keeps only safe version-tag chars; the install dir keeps path chars
# but drops control chars (it's printed in copy-pasteable commands later).
$Version = if ($env:VIGILS_VERSION) { ($env:VIGILS_VERSION -replace '[^\w.\-+]', '') } else { 'latest' }
if (-not $Version) { $Version = 'latest' }
$InstallDir = if ($env:VIGILS_INSTALL_DIR) { ($env:VIGILS_INSTALL_DIR -replace '[\x00-\x1f]', '') } else { Join-Path $env:LOCALAPPDATA 'Vigils\bin' }
$Allowed = @('vigil-hub.exe', 'vigil-native-host.exe')

function Die($msg) { Write-Error "vigils-install: $msg"; exit 1 }

# ── platform (prebuilt CLI is x64 only) ─────────────────────────────────────
$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -ne 'AMD64') {
  Die "no prebuilt Windows CLI for '$arch' (x64 only). Build from source: https://github.com/$Repo"
}
$asset = 'vigils-cli-windows-x64.zip'

if ($Version -eq 'latest') {
  $base = "https://github.com/$Repo/releases/latest/download"
} else {
  $base = "https://github.com/$Repo/releases/download/$Version"
}
$url = "$base/$asset"

$tmp = Join-Path $env:TEMP ('vigils-' + [IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
  Write-Host 'Vigils installer'
  Write-Host "  platform : Windows/$arch  ->  $asset"
  Write-Host "  version  : $Version"
  Write-Host "  target   : $InstallDir"
  Write-Host ''
  Write-Host "Downloading $url"
  $zip = Join-Path $tmp $asset
  try { Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing } catch { Die "download failed: $url" }

  # ── integrity (fail-closed): SHA-256 must match the checksum in the release ──
  $shaFile = "$zip.sha256"
  try { Invoke-WebRequest -Uri "$url.sha256" -OutFile $shaFile -UseBasicParsing }
  catch { Die "no published checksum (.sha256) for $Version — refusing to install unverified. Use a release >= v0.1.26, or download + verify manually: https://github.com/$Repo/releases" }
  $want = (((Get-Content -Path $shaFile -TotalCount 1) -split '\s+')[0]).ToLower()
  if ($want -notmatch '^[0-9a-f]{64}$') { Die 'published checksum is malformed — refusing to install' }
  $got = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLower()
  if ($got -ne $want) { Die "CHECKSUM MISMATCH — refusing to install. expected $want, got $got" }
  Write-Host "Checksum OK (sha256 $got)"

  # ── archive safety: validate members BEFORE extracting ──────────────────────
  # Exactly the two expected bare filenames, no paths/traversal, no duplicates, no extras.
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $archive = [IO.Compression.ZipFile]::OpenRead($zip)
  try {
    $names = @($archive.Entries | ForEach-Object { $_.FullName })
  } finally { $archive.Dispose() }
  if ($names.Count -ne 2) { Die "archive must contain exactly 2 entries, found $($names.Count) (refusing to extract)" }
  # A path component, '..', or a subdir makes FullName differ from the bare allowed name.
  $sorted = ($names | Sort-Object -Unique) -join ','
  if ($sorted -ne 'vigil-hub.exe,vigil-native-host.exe') {
    Die "archive entries are not exactly the two expected binaries (got: $($names -join ', ')) — refusing to extract"
  }

  $ex = Join-Path $tmp 'x'
  Expand-Archive -Path $zip -DestinationPath $ex -Force
  # Final state: exactly two files, expected names, top-level, no dirs, no reparse points.
  $items = @(Get-ChildItem -Force -Recurse -Path $ex)
  if (@($items | Where-Object { $_.PSIsContainer }).Count -ne 0) { Die 'archive contained directories — refusing to install' }
  $files = @($items | Where-Object { -not $_.PSIsContainer })
  if ($files.Count -ne 2) { Die 'unexpected files after extraction — refusing to install' }
  foreach ($f in $files) {
    if ($Allowed -notcontains $f.Name) { Die "unexpected extracted file: $($f.Name)" }
    if ($f.DirectoryName -ne $ex) { Die "extracted file not at top level: $($f.FullName)" }
    if ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) { Die "extracted file is a reparse point/link: $($f.Name)" }
  }

  # ── install (reject reparse-point target; stage-then-replace; never edit PATH) ──
  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  $dirInfo = Get-Item -LiteralPath $InstallDir -Force
  if (-not $dirInfo.PSIsContainer) { Die "install target is not a directory: $InstallDir" }
  # If the target dir is a junction/symlink, Copy-Item would write through it to elsewhere.
  if ($dirInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    Die "install dir is a reparse point/junction ($InstallDir) — refusing to write through it"
  }
  # Stage both binaries under temp names, then move into place. On ANY failure: roll back files
  # already moved and remove staging leftovers, so a failed install never leaves a mixed-version
  # pair or `*.vigils-tmp` behind. (Two separate file moves can't be made truly atomic on Windows;
  # rollback collapses a partial failure back to the prior state instead.)
  $moved = @()
  try {
    foreach ($name in $Allowed) {
      Copy-Item -LiteralPath (Join-Path $ex $name) -Destination (Join-Path $InstallDir ($name + '.vigils-tmp')) -Force
    }
    foreach ($name in $Allowed) {
      $dst = Join-Path $InstallDir $name
      if (Test-Path -LiteralPath $dst) { Write-Host "Replacing existing $dst" }
      Move-Item -LiteralPath (Join-Path $InstallDir ($name + '.vigils-tmp')) -Destination $dst -Force
      $moved += $dst
    }
  } catch {
    foreach ($d in $moved) { Remove-Item -LiteralPath $d -Force -ErrorAction SilentlyContinue }
    foreach ($name in $Allowed) { Remove-Item -LiteralPath (Join-Path $InstallDir ($name + '.vigils-tmp')) -Force -ErrorAction SilentlyContinue }
    Die "install failed while writing binaries — rolled back, no partial install left: $($_.Exception.Message)"
  }

  Write-Host ''
  Write-Host 'Installed:'
  Write-Host "  $InstallDir\vigil-hub.exe"
  Write-Host "  $InstallDir\vigil-native-host.exe"
  Write-Host ''

  # ── PATH hint — we never edit your PATH; you decide. ────────────────────────
  $onPath = ($env:PATH -split ';') -contains $InstallDir
  if ($onPath) {
    $run = 'vigil-hub'
  } else {
    Write-Host "NOTE: $InstallDir is not on your PATH. Add it for this session:"
    Write-Host "      `$env:PATH = `"$InstallDir;`$env:PATH`""
    Write-Host '  (to add it permanently: Windows Settings -> "Edit environment variables for your account")'
    Write-Host ''
    $run = "$InstallDir\vigil-hub.exe"
  }

  Write-Host 'See Vigils protect a real secret in ~10s (zero setup, no LLM, no account):'
  Write-Host "      $run demo"
  Write-Host ''
  Write-Host 'Then protect your agent:'
  Write-Host "      $run setup --all      # Claude Code: one-command turnkey protection"
  Write-Host "      $run serve --stdio    # any MCP agent (Codex / Cursor / Zed): point it here"
  Write-Host ''
  Write-Host 'Docs: https://duncatzat.github.io/vigils'
  Write-Host "Uninstall: Remove-Item `"$InstallDir\vigil-hub.exe`", `"$InstallDir\vigil-native-host.exe`""
} finally {
  Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
}

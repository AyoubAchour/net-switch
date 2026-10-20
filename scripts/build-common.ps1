# Windows PowerShell 5.1. Shared by build-release.ps1 and build-helper.ps1, which
# dot-source it, so both download, cache and check pinned files the same way.
# Downloads are cached, but their hashes are always checked.

function Get-BuildCache([string] $Dist) {
  if ($env:NETSWITCH_CACHE) { return [IO.Path]::GetFullPath($env:NETSWITCH_CACHE) }
  return Join-Path $Dist 'cache'
}

function Get-NativeArchitecture {
  # This system key is shared with emulated processes. Keep the source-engine
  # downloader in agreement with lib/architecture.mjs, even in an x64 shell.
  $native = Get-ItemPropertyValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name PROCESSOR_ARCHITECTURE
  switch ($native) {
    'AMD64' { return 'x64' }
    'ARM64' { return 'arm64' }
    default { throw "Unsupported Windows architecture: $native" }
  }
}

function Get-ArchitecturePins($Pins, [string] $Arch) {
  switch ($Arch) {
    'x64' { return $Pins }
    'arm64' {
      # Licenses and source revisions are shared, so both payloads must use the
      # same upstream versions even though their binary hashes differ.
      if ($Pins.arm64.node.version -ne $Pins.node.version -or
          $Pins.arm64.singBox.version -ne $Pins.singBox.version) {
        throw 'ARM64 and x64 runtime/engine versions disagree; review the shared licenses and source pins.'
      }
      return $Pins.arm64
    }
    default { throw "Unsupported build architecture: $Arch" }
  }
}

function Get-EngineChecksumFile([string] $RepoRoot, [string] $Arch) {
  $name = if ($Arch -eq 'arm64') { 'SHA256SUMS-arm64.txt' } else { 'SHA256SUMS.txt' }
  return Join-Path $RepoRoot "engine/$name"
}

function Get-HelperBinaryPath([string] $RepoRoot, [string] $Arch) {
  # A cross-build must not replace the helper used to run this checkout.
  if ($Arch -eq (Get-NativeArchitecture)) { return Join-Path $RepoRoot 'helper/bin/netswitch-helper.exe' }
  return Join-Path $RepoRoot "helper/bin/$Arch/netswitch-helper.exe"
}

function Assert-EnginePins($Pin, [string] $ChecksumFile, [string] $Arch) {
  Assert-NoLink $ChecksumFile
  $sums = @{}
  foreach ($line in Get-Content -LiteralPath $ChecksumFile) {
    if ($line -match '^\s*(?:#.*)?$') { continue }
    if ($line -notmatch '^([a-fA-F0-9]{64})\s+\*?([^\s]+)\s*$') { throw "Invalid engine checksum line: $line" }
    if ($sums.ContainsKey($Matches[2])) { throw "Duplicate engine checksum: $($Matches[2])" }
    $sums[$Matches[2]] = $Matches[1]
  }
  $files = @($Pin.files.PSObject.Properties)
  if (-not $sums.ContainsKey('sing-box.exe') -or
      ($Arch -eq 'x64' -and -not $sums.ContainsKey('libcronet.dll')) -or
      @($sums.Keys | Where-Object { $_ -notin @('sing-box.exe', 'libcronet.dll') }).Count -or
      $sums.Count -ne $files.Count) {
    throw "Invalid $Arch engine file list in versions.json or $ChecksumFile"
  }
  foreach ($file in $files) {
    if ($sums[$file.Name] -ne $file.Value) { throw "Engine pin disagrees with ${ChecksumFile}: $($file.Name)" }
  }
}

function Assert-PeArchitecture([string] $Path, [string] $Arch) {
  $reader = [IO.BinaryReader]::new([IO.File]::OpenRead($Path))
  try {
    if ($reader.ReadUInt16() -ne 0x5a4d) { throw "Not a PE file: $Path" }
    $reader.BaseStream.Position = 0x3c
    $offset = $reader.ReadUInt32()
    $reader.BaseStream.Position = $offset
    if ($reader.ReadUInt32() -ne 0x4550) { throw "Invalid PE signature: $Path" }
    $machine = $reader.ReadUInt16()
    if ($Arch -eq 'AnyCPU') {
      # Read the CLR header directly: loading two copies of the tray assembly
      # into PowerShell's AppDomain fails even in reflection-only mode.
      $sections = $reader.ReadUInt16()
      $reader.BaseStream.Position = $offset + 20
      $optionalSize = $reader.ReadUInt16()
      $reader.BaseStream.Position = $offset + 24
      if ($reader.ReadUInt16() -ne 0x10b) { throw "AnyCPU tray must use a PE32 header: $Path" }
      $reader.BaseStream.Position = $offset + 24 + 96 + 14 * 8
      $clrRva = $reader.ReadUInt32()
      $flags = $null
      for ($i = 0; $i -lt $sections; $i++) {
        $reader.BaseStream.Position = $offset + 24 + $optionalSize + $i * 40 + 12
        $virtualAddress = $reader.ReadUInt32()
        $rawSize = $reader.ReadUInt32()
        $rawOffset = $reader.ReadUInt32()
        if ($clrRva -ge $virtualAddress -and $clrRva + 20 -le $virtualAddress + $rawSize) {
          $reader.BaseStream.Position = $rawOffset + ($clrRva - $virtualAddress) + 16
          $flags = $reader.ReadUInt32()
          break
        }
      }
      # ILONLY=1, with neither 32BITREQUIRED=2 nor 32BITPREFERRED=0x20000.
      if ($null -eq $flags -or $flags -ne 1) { throw "Tray must be IL-only AnyCPU without Prefer32Bit: $Path (CLR flags $flags)" }
    }
  } finally { $reader.Dispose() }
  $expected = if ($Arch -eq 'arm64') { 0xaa64 } elseif ($Arch -eq 'x64') { 0x8664 } else { 0x14c }
  if ($machine -ne $expected) { throw ('Wrong architecture for {0}: PE 0x{1:x4}, expected {2}' -f $Path, $machine, $Arch) }
  Write-Host ('PE 0x{0:x4} ({1}): {2}' -f $machine, $Arch, $Path)
}

# Whether Windows gives the program a console window: subsystem 2 is a
# windowless (GUI) program, 3 a console program. The startup task runs the
# helper directly, so it must be windowless.
function Assert-PeWindowless([string] $Path) {
  $reader = [IO.BinaryReader]::new([IO.File]::OpenRead($Path))
  try {
    if ($reader.ReadUInt16() -ne 0x5a4d) { throw "Not a PE file: $Path" }
    $reader.BaseStream.Position = 0x3c
    $offset = $reader.ReadUInt32()
    $reader.BaseStream.Position = $offset
    if ($reader.ReadUInt32() -ne 0x4550) { throw "Invalid PE signature: $Path" }
    # The subsystem sits at the same place in 32- and 64-bit optional headers.
    $reader.BaseStream.Position = $offset + 24 + 68
    $subsystem = $reader.ReadUInt16()
  } finally { $reader.Dispose() }
  if ($subsystem -ne 2) { throw "Expected a windowless program (subsystem 2), got subsystem ${subsystem}: $Path" }
  Write-Host "Windowless program: $Path"
}

function Assert-NoLink([string] $Path) {
  if ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "Refusing a symlink or junction in packaging input/output: $Path"
  }
}

function Get-SafeFiles([string] $Directory) {
  Assert-NoLink $Directory
  foreach ($entry in Get-ChildItem -LiteralPath $Directory -Force) {
    Assert-NoLink $entry.FullName
    if ($entry.PSIsContainer) { Get-SafeFiles $entry.FullName } else { $entry }
  }
}

function Assert-Hash([string] $Path, [string] $Expected) {
  if ($Expected -notmatch '^[0-9a-fA-F]{64}$') { throw "Invalid SHA-256 pin for $Path" }
  $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne $Expected) {
    throw "SHA-256 mismatch for $Path`nExpected: $Expected`nActual:   $actual`nThe file was NOT used. Do not update pins to silence this error."
  }
  Write-Host "Verified SHA-256: $([IO.Path]::GetFileName($Path))"
}

# Downloads a pinned file into $Cache once, and checks its hash every time.
function Get-Artifact($Pin, [string] $Cache) {
  $uri = [Uri]$Pin.url
  if ($uri.Scheme -ne 'https') { throw "Artifact URL must use HTTPS: $uri" }
  if ($Pin.sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw "Invalid SHA-256 pin for $uri" }
  $cacheName = [IO.Path]::GetFileName($uri.AbsolutePath)
  if ($Pin.PSObject.Properties['cacheName']) { $cacheName = $Pin.cacheName }
  if (-not $cacheName -or $cacheName -ne [IO.Path]::GetFileName($cacheName)) { throw 'Invalid artifact cache filename.' }
  $target = Join-Path $Cache $cacheName
  if (Test-Path -LiteralPath $target) {
    Assert-NoLink $target
    try {
      Assert-Hash $target $Pin.sha256
      return $target
    } catch {
      Write-Warning "Discarding unusable cached artifact: $($_.Exception.Message)"
      Remove-Item -LiteralPath $target -Force
    }
  }
  $partial = "$target.partial"
  $waits = @(5, 15, 30)
  for ($attempt = 0; ; $attempt++) {
    $failure = $null
    # Neither interrupted transfers nor mismatches may seed the next attempt.
    if (Test-Path -LiteralPath $partial) {
      Assert-NoLink $partial
      Remove-Item -LiteralPath $partial -Force
    }
    Write-Host "Downloading $uri (attempt $($attempt + 1)/$($waits.Count + 1))"
    try {
      Invoke-WebRequest -UseBasicParsing -Uri $uri -OutFile $partial -TimeoutSec 300 -ErrorAction Stop
      Assert-Hash $partial $Pin.sha256
    } catch {
      $failure = $_.Exception.Message
      if ($attempt -ge $waits.Count) {
        throw "Download failed after $($attempt + 1) attempts: $uri`n$failure"
      }
      Write-Warning "Download rejected ($failure); retrying in $($waits[$attempt]) s"
      Start-Sleep -Seconds $waits[$attempt]
      continue
    } finally {
      # A verified file is promoted below. On failure, remove even the last
      # partial so neither a later run nor actions/cache can reuse it.
      if ($failure -and (Test-Path -LiteralPath $partial)) {
        Assert-NoLink $partial
        Remove-Item -LiteralPath $partial -Force
      }
    }
    Move-Item -LiteralPath $partial -Destination $target
    return $target
  }
}

function Copy-ArchiveFile([string] $Archive, [string] $Entry, [string] $Destination) {
  $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
  try {
    $matches = @($zip.Entries | Where-Object { $_.FullName -ceq $Entry })
    if ($matches.Count -ne 1) { throw "Expected exactly one '$Entry' in $Archive; found $($matches.Count)." }
    New-Item -ItemType Directory -Path (Split-Path $Destination -Parent) -Force | Out-Null
    [IO.Compression.ZipFileExtensions]::ExtractToFile($matches[0], $Destination, $false)
  } finally { $zip.Dispose() }
}

# Windows PowerShell 5.1. Shared by build-release.ps1 and build-helper.ps1, which
# dot-source it, so both download, cache and check pinned files the same way.
# Downloads are cached, but their hashes are always checked.

function Get-BuildCache([string] $Dist) {
  if ($env:NETSWITCH_CACHE) { return [IO.Path]::GetFullPath($env:NETSWITCH_CACHE) }
  return Join-Path $Dist 'cache'
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
    throw "SHA-256 mismatch for $Path`nExpected: $Expected`nActual:   $actual`nThe file was NOT used. Remove this cache file and retry; do not update pins to silence this error."
  }
  Write-Host "Verified SHA-256: $([IO.Path]::GetFileName($Path))"
}

# Downloads a pinned file into $Cache once, and checks its hash every time.
function Get-Artifact($Pin, [string] $Cache) {
  $uri = [Uri]$Pin.url
  if ($uri.Scheme -ne 'https') { throw "Artifact URL must use HTTPS: $uri" }
  $cacheName = [IO.Path]::GetFileName($uri.AbsolutePath)
  if ($Pin.PSObject.Properties['cacheName']) { $cacheName = $Pin.cacheName }
  if (-not $cacheName -or $cacheName -ne [IO.Path]::GetFileName($cacheName)) { throw 'Invalid artifact cache filename.' }
  $target = Join-Path $Cache $cacheName
  if (Test-Path -LiteralPath $target) {
    Assert-NoLink $target
  } else {
    Write-Host "Downloading $uri"
    # A partial download is never considered a reusable artifact.
    $partial = "$target.partial"
    if (Test-Path -LiteralPath $partial) { Assert-NoLink $partial }
    # A host can refuse a connection for a moment, so a failed download is
    # retried. A file that downloads but doesn't match its pin is never
    # retried: that stops the build below.
    $waits = @(5, 15, 30)
    for ($attempt = 0; ; $attempt++) {
      try {
        Invoke-WebRequest -UseBasicParsing -Uri $uri -OutFile $partial
        break
      } catch {
        if ($attempt -ge $waits.Count) { throw "Download failed after $($attempt + 1) attempts: $uri`n$($_.Exception.Message)" }
        Write-Host "Download failed ($($_.Exception.Message)); retrying in $($waits[$attempt]) s"
        Start-Sleep -Seconds $waits[$attempt]
      }
    }
    Assert-Hash $partial $Pin.sha256
    Move-Item -LiteralPath $partial -Destination $target
  }
  Assert-Hash $target $Pin.sha256
  return $target
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

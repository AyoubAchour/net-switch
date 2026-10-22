param([Parameter(Mandatory)][string]$ProbeDirectory)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Run this proof only on a hosted CI runner.' }

$reader = (Resolve-Path (Join-Path $ProbeDirectory 'locationfree.test.exe')).Path
$legacy = (Resolve-Path (Join-Path $ProbeDirectory 'legacy.test.exe')).Path
$store = 'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\NonPackaged'

function Get-LocationRecords([string]$Binary) {
    $name = $Binary.Replace('\', '#')
    # The runner user's hive, machine-wide accounting, and SYSTEM's user hive.
    foreach ($root in @('Registry::HKEY_CURRENT_USER', 'Registry::HKEY_LOCAL_MACHINE', 'Registry::HKEY_USERS\S-1-5-18')) {
        $path = "$root\$store\$name"
        if (Test-Path -LiteralPath $path) {
            $value = Get-ItemProperty -LiteralPath $path
            [pscustomobject]@{ Path = $path; Start = $value.LastUsedTimeStart; Stop = $value.LastUsedTimeStop }
        }
    }
}

# Each CI invocation builds into a fresh GUID directory. Never delete consent
# records to force the starting condition or hide records from an earlier run.
foreach ($binary in @($reader, $legacy)) {
    if (@(Get-LocationRecords $binary).Count -ne 0) { throw "Precondition failed: location record already exists for $binary" }
}
Write-Host "OS: $([Environment]::OSVersion.VersionString)"
Get-Service WlanSvc -ErrorAction SilentlyContinue | Format-Table Name, Status
& $reader '-test.run=^TestWiFiLocationProbeCI$' '-test.v' '-wifi-location-mode=reader'
if ($LASTEXITCODE -ne 0) { throw "Network reader failed: $LASTEXITCODE" }

# Exercise the unpackaged reader under the identity used by a Windows service.
# pwsh is used solely to pass the CI marker to the scheduled child process.
$taskName = "NetSwitch-WiFi-Privacy-$([Guid]::NewGuid().ToString('N'))"
$quotedReader = $reader.Replace("'", "''")
$command = "`$env:GITHUB_ACTIONS='true'; & '$quotedReader' '-test.run=^TestWiFiLocationProbeCI$' '-wifi-location-mode=reader'; exit `$LASTEXITCODE"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
$action = New-ScheduledTaskAction -Execute (Get-Command pwsh).Source -Argument "-NoProfile -NonInteractive -EncodedCommand $encoded"
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
try {
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal | Out-Null
    $before = (Get-ScheduledTaskInfo -TaskName $taskName).LastRunTime
    Start-ScheduledTask -TaskName $taskName
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    do {
        Start-Sleep -Milliseconds 500
        $task = Get-ScheduledTask -TaskName $taskName
        $info = Get-ScheduledTaskInfo -TaskName $taskName
        $finished = $info.LastRunTime -gt $before -and $task.State -ne 'Running' -and $task.State -ne 'Queued'
    } while (-not $finished -and [DateTime]::UtcNow -lt $deadline)
    if (-not $finished -or $info.LastTaskResult -ne 0) { throw "SYSTEM reader failed or timed out: $($info.LastTaskResult)" }
    Write-Host 'SYSTEM network reader completed successfully (optional SSID may be null).'
} finally {
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
}

$control = & $legacy '-test.run=^TestWiFiLocationProbeCI$' '-test.v' '-wifi-location-mode=legacy' 2>&1
if ($LASTEXITCODE -ne 0) { throw "Legacy control failed: $LASTEXITCODE" }
$control | Write-Host

# Accounting is asynchronous. Observe both identities for the whole bounded
# window, even when the legacy control has no WLAN hardware to exercise.
$positive = $false
for ($i = 0; $i -lt 20; $i++) {
    if (@(Get-LocationRecords $reader).Count -ne 0) { throw 'Location-free network reader created a location record.' }
    foreach ($record in @(Get-LocationRecords $legacy)) {
        Write-Host "Legacy record: $($record.Path) LastUsedTimeStart=$($record.Start) LastUsedTimeStop=$($record.Stop)"
        if ([long]$record.Start -gt 0 -or [long]$record.Stop -gt 0) { $positive = $true }
    }
    Start-Sleep -Milliseconds 500
}
if ($positive -and ($control -match 'WIFI_CONTROL_QUERY opcode=7').Count -gt 0) {
    Write-Host 'PRIVACY_PROOF=PASS: old opcode 7 recorded location use; new reader created no entry (user and SYSTEM).'
} else {
    Write-Warning 'PRIVACY_PROOF=INCONCLUSIVE: hosted runner did not demonstrate old opcode-7 location accounting. No reader entry was observed; that alone does not prove the distinction. Rely on Microsoft documentation and TestSSIDNoLocationAPIs.'
}

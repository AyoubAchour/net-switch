param([string]$Trace)
$ErrorActionPreference = 'Stop'
$events = @(Get-WinEvent -Path $Trace -Oldest)
$trayIds = @($events | Where-Object { ($_.Properties.Value -join ' ') -match 'NetSwitchTray.exe' } | Select-Object -ExpandProperty ProcessId -Unique)
foreach ($trayId in $trayIds) {
  $previous = $null
  foreach ($event in $events | Where-Object ProcessId -eq $trayId) {
    $values = $event.Properties.Value -join ' | '
    $gap = if ($previous) { ($event.TimeCreated - $previous).TotalMilliseconds } else { 0 }
    if (-not $previous -or $gap -gt 100 -or $values -match 'NetSwitch|mscorlib|Windows.Forms|clr.dll|Microsoft.NET') {
      Write-Host ('ETW pid={0} at={1} id={2} gapMs={3} {4}' -f $trayId, $event.TimeCreated.ToUniversalTime().ToString('o'), $event.Id, $gap, $values)
    }
    $previous = $event.TimeCreated
  }
}

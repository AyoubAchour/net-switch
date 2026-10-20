$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Hosted Windows runners only.' }
$since = [DateTime]::Parse($env:NETSWITCH_UDP_CAPTURE_SINCE).ToUniversalTime()
try {
  $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5152, 5157; StartTime = $since })
} catch {
  if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
  $events = @()
}
@($events | ForEach-Object {
  $xml = [xml]$_.ToXml()
  $fields = @{}
  foreach ($field in $xml.Event.EventData.Data) { $fields[$field.Name] = $field.'#text' }
  [pscustomobject]@{ at = $_.TimeCreated.ToUniversalTime().ToString('o'); id = $_.Id; fields = $fields }
}) | ConvertTo-Json -Depth 5 -Compress

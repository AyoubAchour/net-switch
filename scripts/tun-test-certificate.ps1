# Ephemeral TLS identity for the disposable runner, never installed as trusted.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
  throw 'TUN certificates are restricted to GitHub-hosted runners.'
}
$cert = New-SelfSignedCertificate -DnsName 'netswitch.invalid' -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable -NotAfter (Get-Date).AddDays(1)
try {
  [pscustomobject]@{
    pfx = [Convert]::ToBase64String($cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $env:NETSWITCH_TEST_CERT_PASSWORD))
    cert = [Convert]::ToBase64String($cert.RawData)
  } | ConvertTo-Json -Compress
} finally {
  Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($cert.Thumbprint)" -DeleteKey
}

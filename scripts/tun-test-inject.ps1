# Temporary CI-only proof. Removed before the final PR head.
param([int] $EnginePid, [ValidateSet('suspend', 'resume')] [string] $Action)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:NETSWITCH_INJECT_DIAGNOSTICS -ne '1') {
  throw 'Fault injection requires the explicit hosted-runner dispatch'
}
$engineProcess = Get-Process -Id $EnginePid
if ($engineProcess.ProcessName -ne 'sing-box') { throw 'Refusing to suspend a process other than the test engine' }
Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class TestSuspension { [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint access, bool inherit, int pid); [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle); [DllImport("ntdll.dll")] public static extern int NtSuspendProcess(IntPtr handle); [DllImport("ntdll.dll")] public static extern int NtResumeProcess(IntPtr handle); }'
$handle = [TestSuspension]::OpenProcess(0x0800, $false, $EnginePid)
if ($handle -eq [IntPtr]::Zero) { throw 'Cannot open test engine for suspend/resume' }
try {
  $status = if ($Action -eq 'suspend') { [TestSuspension]::NtSuspendProcess($handle) } else { [TestSuspension]::NtResumeProcess($handle) }
  if ($status -ne 0) { throw "Engine $Action returned NTSTATUS $status" }
  Write-Output "INJECTED engine $Action succeeded: pid=$EnginePid"
} finally { $null = [TestSuspension]::CloseHandle($handle) }

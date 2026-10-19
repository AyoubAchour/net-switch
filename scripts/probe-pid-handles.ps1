# Temporary native diagnosis, restricted to disposable hosted runners.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
  throw 'This diagnosis may run only in hosted CI.'
}
$env:NETSWITCH_PID_PROBE = Join-Path $pwd 'dist/pid-handles/engine.pid'
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class PidHandles {
    [StructLayout(LayoutKind.Sequential)]
    struct IOStatus { public IntPtr Status; public UIntPtr Information; }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint mode, uint flags, IntPtr template);
    [DllImport("ntdll.dll")]
    static extern uint NtSetInformationFile(SafeFileHandle file, out IOStatus io, ref uint flags, uint length, int kind);
    [DllImport("ntdll.dll")]
    static extern uint RtlNtStatusToDosError(uint status);
    static SafeFileHandle Open(string path) {
        var handle = CreateFileW(path, 0x10080, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (handle.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        return handle;
    }
    static string Delete(SafeFileHandle handle, bool posix) {
        uint flags = posix ? 0x13U : 1U;
        IOStatus io;
        uint status = NtSetInformationFile(handle, out io, ref flags, posix ? 4U : 1U, posix ? 64 : 13);
        return "NT=0x" + status.ToString("x8") + " Win32=" + RtlNtStatusToDosError(status);
    }
    static string RemoveWithNode(string node) {
        var info = new ProcessStartInfo(node, "-e \"require('fs').promises.rm(process.env.NETSWITCH_PID_PROBE,{force:true}).then(()=>console.log('ok'),e=>console.log(e.code))\"");
        info.UseShellExecute = false;
        info.CreateNoWindow = true;
        info.RedirectStandardOutput = true;
        info.RedirectStandardError = true;
        using (var process = Process.Start(info)) {
            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();
            process.WaitForExit();
            if (process.ExitCode != 0) throw new Exception(error);
            return output.Trim();
        }
    }
    public static void Run(string path, string node) {
        Directory.CreateDirectory(Path.GetDirectoryName(path));
        File.WriteAllText(path, "1234");
        using (var first = Open(path)) using (var second = Open(path)) {
            Console.WriteLine("PID-NATIVE both handles share delete; first " + Delete(first, true));
            Console.WriteLine("PID-NATIVE second POSIX deletion " + Delete(second, true));
            Console.WriteLine("PID-NATIVE Node while POSIX handles remain " + RemoveWithNode(node));
        }
        File.WriteAllText(path, "1234");
        using (var held = Open(path)) {
            Console.WriteLine("PID-NATIVE legacy delete " + Delete(held, false));
            Console.WriteLine("PID-NATIVE Node while legacy delete pending " + RemoveWithNode(node));
        }
        File.WriteAllText(path, "1234");
        using (var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)) {
            Console.WriteLine("PID-NATIVE Node with reader denying delete sharing " + RemoveWithNode(node));
        }
        Console.WriteLine("PID-NATIVE Node after reader closes " + RemoveWithNode(node));
    }
}
'@
Write-Output "PID-NATIVE Windows $([Environment]::OSVersion.Version)"
Get-Volume | Select-Object DriveLetter, FileSystem, FileSystemLabel | Format-Table
[PidHandles]::Run($env:NETSWITCH_PID_PROBE, (Get-Command node.exe).Source)

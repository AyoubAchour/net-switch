// NetSwitchTray.exe's entry point. It does what tray.ps1 does before it calls
// Tray.Run, so the tray icon can run as a small program of its own: no
// PowerShell stays running for it, and nothing is compiled when it starts.
// scripts\build-tray.ps1 compiles this file together with lib\tray.cs; Add-Type
// (tray.ps1 and test\tray.test.mjs) compiles tray.cs alone. Keep this in step
// with tray.ps1, and at C# 5 like tray.cs.
using System;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

// Windows shows this name for the program in the taskbar's icon settings and in Task Manager.
[assembly: AssemblyTitle("Net Switch")]
[assembly: AssemblyProduct("Net Switch")]

namespace NetSwitch
{
    static class TrayProgram
    {
        // NetSwitchTray.exe [-DataDir <folder>]
        //
        // The folder holds server.json, and tray.log is written there: launch.ps1
        // passes it. A relative path is taken from the app folder, so
        // `-DataDir data-test` watches test mode (node server.mjs --dev-proxy).
        // One copy runs per folder, whether it was started as this program or as
        // tray.ps1; another copy exits at once.
        //
        // Exit code 0: the icon is gone, or another copy already shows it.
        // 1: it stopped on an error, which tray.log describes. 2: the arguments
        // aren't ones it knows, or the folder isn't a usable path.
        [STAThread]
        static int Main(string[] args)
        {
            string dataDir = "data";
            for (int i = 0; i < args.Length; i++)
            {
                if (i + 1 < args.Length && string.Equals(args[i], "-DataDir", StringComparison.OrdinalIgnoreCase))
                {
                    i++;
                    dataDir = args[i];
                }
                else
                {
                    return 2;
                }
            }

            string root;
            string dataPath;
            try
            {
                root = AppFolder();
                dataPath = Path.GetFullPath(Path.IsPathRooted(dataDir) ? dataDir : Path.Combine(root, dataDir));
            }
            catch (Exception)
            {
                // Characters a path can't hold, or a path that is too long.
                return 2;
            }
            string logFile = Path.Combine(dataPath, "tray.log");

            try
            {
                // A mutex name can't hold backslashes, so the folder is named by
                // its hash. tray.ps1 makes the same name.
                using (Mutex mutex = new Mutex(false, @"Local\NetSwitchTray-" + FolderHash(dataPath)))
                {
                    bool owned;
                    try
                    {
                        owned = mutex.WaitOne(0);
                    }
                    catch (AbandonedMutexException)
                    {
                        // The previous copy ended without letting go; this one takes over.
                        owned = true;
                    }
                    if (!owned) return 0;
                    try
                    {
                        Tray.Run(root, dataPath, logFile, CanLaunch(root, dataPath));
                    }
                    finally
                    {
                        mutex.ReleaseMutex();
                    }
                }
                return 0;
            }
            catch (Exception error)
            {
                // A program started without a window has nowhere else to say why it stopped.
                Log(logFile, "the tray icon stopped on an error: " + error);
                return 1;
            }
        }

        // The app folder, where tray.ps1 and launch.ps1 are. An installed copy
        // keeps this program in <app>\tray and a source checkout in tray\bin,
        // so it is the nearest folder at or above the program's own that holds
        // launch.ps1, at most two levels up.
        static string AppFolder()
        {
            string own = Path.GetDirectoryName(Path.GetFullPath(typeof(TrayProgram).Assembly.Location));
            DirectoryInfo folder = new DirectoryInfo(own);
            for (int level = 0; level < 3 && folder != null; level++)
            {
                if (File.Exists(Path.Combine(folder.FullName, "launch.ps1"))) return folder.FullName;
                folder = folder.Parent;
            }
            return own;
        }

        // The first 8 bytes of the SHA-256 of the lowercased path, as hex.
        static string FolderHash(string dataPath)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(dataPath.ToLowerInvariant()));
                StringBuilder text = new StringBuilder(16);
                for (int i = 0; i < 8; i++) text.Append(hash[i].ToString("x2", CultureInfo.InvariantCulture));
                return text.ToString();
            }
        }

        // The icon may start Net Switch through launch.ps1 only when it watches
        // the folder launch.ps1 itself uses; a test-mode icon must never start real routing.
        static bool CanLaunch(string root, string dataPath)
        {
            string launcherDir;
            if (File.Exists(Path.Combine(root, @"runtime\node.exe")))
            {
                string localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
                if (string.IsNullOrEmpty(localAppData)) return false;
                launcherDir = Path.Combine(localAppData, "Net Switch");
            }
            else
            {
                launcherDir = Path.Combine(root, "data");
            }
            return string.Equals(Path.GetFullPath(launcherDir).TrimEnd('\\'), dataPath.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
        }

        static void Log(string logFile, string line)
        {
            try
            {
                File.AppendAllText(logFile, DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture) + " " + line + Environment.NewLine);
            }
            catch (Exception)
            {
                // No folder to write to.
            }
        }
    }
}

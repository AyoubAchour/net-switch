// Net Switch's tray icon, run as the normal user. scripts\build-tray.ps1 builds
// it, with lib\tray-main.cs, into NetSwitchTray.exe using the C# compiler that
// comes with Windows; without that program, tray.ps1 compiles it with Add-Type
// in Windows PowerShell 5.1. Both compilers know only C# 5, so the code stays
// at version 5.
// Once a second it reads the same /api/state the window reads: the icon shows
// the lines' load, the tooltip their speeds, the flyout the lines and the
// busiest apps, and a notification says when a line goes down or comes back.
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Drawing.Text;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;

namespace NetSwitch
{
    // ------------------------------------------------------------ what the tray shows

    // One line, as the icon and its tooltip show it.
    public sealed class LineView
    {
        public string Label;
        // Its place in the palette: the main line 0, then by priority.
        public int Color;
        // Connected, with no problem: its row of the icon is lit.
        public bool Working;
        // The window's health word for a line with a problem ("No internet"), else null.
        public string Problem;
        // Windows gave a speed reading.
        public bool Measured;
        public double Down;
        public double Up;
    }

    // Everything the icon and its tooltip show at one moment.
    public sealed class TrayView
    {
        public string Status;
        // Takes the lines' place when Net Switch can't be reached.
        public string Hint;
        // Routing is on, so the icon keeps the lines' colors.
        public bool Routing;
        // In priority order: the first is the main line.
        public List<LineView> Lines = new List<LineView>();
    }

    // How one row of the icon looks.
    public struct IconRow
    {
        public bool Available;
        public int Lit;
    }

    // Pure logic with no Windows calls, so test/tray.test.mjs can check it.
    public static class TrayModel
    {
        public const int Cells = 5;
        // NOTIFYICONDATA.szTip holds 128 characters, the last one the terminating null.
        public const int MaxTip = 127;
        // The icon has a row for each of the first three lines. With one line the
        // second row stays faint, so the icon keeps its shape.
        public const int MaxRows = 3;
        // Line colors by position, as in the window (ui/styles.css --line-0 to
        // --line-5); a seventh line starts over.
        public const int PaletteSize = 6;
        const int MaxLabel = 18;
        const int MaxBriefLabel = 14;

        // The window's top bar says the same (ui/app.js renderTopbar).
        static readonly Dictionary<string, string> Statuses = new Dictionary<string, string>
        {
            { "on", "Net Switch: routing is on" },
            { "starting", "Net Switch: starting routing…" },
            { "stopping", "Net Switch: turning off routing…" },
            { "off", "Net Switch: routing is off" },
            { "error", "Net Switch: routing stopped" },
        };

        const string InstallerPrefix = "https://github.com/AyoubAchour/net-switch/releases/download/";

        // A newer release the server offers, as { version, installer link }, or
        // null. Only a link to this project's own releases is ever opened.
        public static string[] UpdateOffer(IDictionary<string, object> state)
        {
            IDictionary<string, object> update = Child(state, "update");
            string version = Text(update, "version");
            string installer = Text(update, "installer");
            if (string.IsNullOrEmpty(version) || string.IsNullOrEmpty(installer)) return null;
            if (!installer.StartsWith(InstallerPrefix, StringComparison.Ordinal)) return null;
            return new string[] { version, installer };
        }

        public static TrayView FromState(IDictionary<string, object> state)
        {
            IDictionary<string, object> routing = Child(state, "routing");
            string status = Text(routing, "status") ?? "";
            string headline;
            if (!Statuses.TryGetValue(status, out headline)) headline = "Net Switch";
            if (Text(state, "mode") == "proxy") headline += " (test mode)";

            TrayView view = new TrayView();
            view.Status = headline;
            view.Routing = status == "on";
            List<IDictionary<string, object>> lines = Lines(state);
            for (int i = 0; i < lines.Count; i++) view.Lines.Add(Line(lines[i], i, view.Routing));
            return view;
        }

        // Before Net Switch has answered for the first time.
        public static TrayView Waiting()
        {
            return new TrayView { Status = "Net Switch" };
        }

        public static TrayView Unreachable(bool processRunning)
        {
            return new TrayView
            {
                Status = processRunning ? "Net Switch isn’t responding" : "Net Switch isn’t running",
                Hint = "Click for Open Net Switch.",
            };
        }

        public static TrayView Quitting()
        {
            return new TrayView { Status = "Net Switch is quitting…" };
        }

        static LineView Line(IDictionary<string, object> line, int index, bool routingOn)
        {
            LineView view = new LineView();
            view.Label = LineLabel(line, index);
            view.Color = index % PaletteSize;
            view.Working = Flag(line, "connected") && string.IsNullOrEmpty(Text(line, "problem"));
            string tone;
            string health = Health(line, routingOn, out tone);
            view.Problem = tone == "ok" ? null : health;
            IDictionary<string, object> rate = Child(line, "rate");
            // Unknown, which is not the same as zero.
            view.Measured = rate != null;
            view.Down = Number(rate, "down");
            view.Up = Number(rate, "up");
            return view;
        }

        // The window's health words for a line (ui/app.js lineHealth), and their
        // tone: "ok", "warn" or "down". The ping is the last internet test's round
        // trip, which only runs while routing is on.
        public static string Health(IDictionary<string, object> line, bool routingOn, out string tone)
        {
            string problem = Text(line, "problem");
            tone = "warn";
            // Connected again, and trusted once an internet test passes.
            if (problem == "checking") return "Checking…";
            if (problem == "no internet") return "No internet";
            tone = "down";
            if (!string.IsNullOrEmpty(problem)) return problem == "no address" ? "No address" : "No route";
            if (!Flag(line, "connected")) return "Not connected";
            tone = "warn";
            if (Flag(line, "exhausted")) return "Cap reached";
            tone = "ok";
            object ping;
            if (routingOn && line.TryGetValue("ping", out ping) && IsNumber(ping))
            {
                return Number(line, "ping").ToString("0", CultureInfo.InvariantCulture) + " ms";
            }
            return "Online";
        }

        // A short line per line. When they don't all fit in what Windows shows,
        // each gives only its download; the ones that still don't fit are
        // counted on the last line instead.
        public static string Tooltip(TrayView view)
        {
            bool complete;
            string tip = Tooltip(view, false, out complete);
            if (!complete) tip = Tooltip(view, true, out complete);
            return tip.Length <= MaxTip ? tip : tip.Substring(0, MaxTip - 1) + "…";
        }

        static string Tooltip(TrayView view, bool brief, out bool complete)
        {
            List<string> lines = new List<string>();
            lines.Add(view.Status);
            if (view.Hint != null) lines.Add(view.Hint);
            int length = string.Join("\n", lines).Length;
            int count = view.Lines.Count;
            complete = true;
            for (int i = 0; i < count; i++)
            {
                string text = LineText(view.Lines[i], brief);
                int rest = count - i - 1;
                int needed = 1 + text.Length + (rest > 0 ? 1 + More(rest).Length : 0);
                if (length + needed > MaxTip)
                {
                    lines.Add(More(count - i));
                    complete = false;
                    break;
                }
                lines.Add(text);
                length += 1 + text.Length;
            }
            return string.Join("\n", lines);
        }

        public static string More(int count)
        {
            return "+" + count.ToString(CultureInfo.InvariantCulture) + (count == 1 ? " more line" : " more lines");
        }

        public static string LineText(LineView line, bool brief)
        {
            string label = Shorten(line.Label, brief ? MaxBriefLabel : MaxLabel);
            if (line.Problem != null) return label + ": " + Lower(line.Problem);
            if (!line.Measured) return label + (brief ? ": no speed" : ": speed not available");
            return label + ": ↓ " + Rate(line.Down) + (brief ? "" : "  ↑ " + Rate(line.Up));
        }

        // Same wording as the window (ui/app.js formatRate).
        public static string Rate(double bytesPerSecond)
        {
            if (!(bytesPerSecond >= 1)) return "0 KB/s";
            if (bytesPerSecond < 1024) return "<1 KB/s";
            if (bytesPerSecond < 1024 * 1024)
            {
                return Math.Round(bytesPerSecond / 1024, MidpointRounding.AwayFromZero).ToString(CultureInfo.InvariantCulture) + " KB/s";
            }
            return (bytesPerSecond / 1024 / 1024).ToString("0.0", CultureInfo.InvariantCulture) + " MB/s";
        }

        // Same scale as the window's meters (ui/app.js litCells): 1 KB/s lights
        // the first cell and 10 MB/s lights them all.
        public static int Lit(double bytesPerSecond)
        {
            if (!(bytesPerSecond >= 1)) return 0;
            double level = Math.Log10(bytesPerSecond / 1024) / Math.Log10(10 * 1024);
            int lit = (int)Math.Round(level * Cells, MidpointRounding.AwayFromZero);
            return Math.Max(1, Math.Min(Cells, lit));
        }

        // Upload counts as well as download, so a line that is busy sending doesn't look idle.
        public static IconRow Row(LineView line)
        {
            IconRow row = new IconRow();
            row.Available = line != null && line.Working;
            row.Lit = row.Available && line.Measured ? Lit(line.Down + line.Up) : 0;
            return row;
        }

        public static IconRow[] Rows(TrayView view)
        {
            IconRow[] rows = new IconRow[Math.Max(2, Math.Min(MaxRows, view.Lines.Count))];
            for (int i = 0; i < rows.Length; i++) rows[i] = Row(i < view.Lines.Count ? view.Lines[i] : null);
            return rows;
        }

        // The icon is redrawn only when this changes, not on every reading.
        public static string IconSignature(TrayView view)
        {
            StringBuilder signature = new StringBuilder(view.Routing ? "on" : "off");
            foreach (IconRow row in Rows(view)) signature.Append("|").Append(row.Available).Append(row.Lit);
            return signature.ToString();
        }

        // The line's name, or its adapter's while it has none.
        public static string LineLabel(IDictionary<string, object> line, int index)
        {
            string label = (Text(line, "label") ?? "").Trim();
            if (label.Length == 0) label = (Text(line, "alias") ?? "").Trim();
            return label.Length > 0 ? label : "Line " + (index + 1).ToString(CultureInfo.InvariantCulture);
        }

        // "Fibre from…", not "Fibre from …".
        public static string Shorten(string text, int max)
        {
            text = (text ?? "").Trim();
            return text.Length <= max ? text : text.Substring(0, max - 1).TrimEnd() + "…";
        }

        // "No internet" in the middle of a sentence: "no internet".
        public static string Lower(string text)
        {
            if (string.IsNullOrEmpty(text)) return text;
            return char.ToLowerInvariant(text[0]) + text.Substring(1);
        }

        internal static List<IDictionary<string, object>> Lines(IDictionary<string, object> state)
        {
            return Items(state, "lines");
        }

        internal static List<IDictionary<string, object>> Items(IDictionary<string, object> parent, string key)
        {
            List<IDictionary<string, object>> items = new List<IDictionary<string, object>>();
            object raw;
            IEnumerable list = parent != null && parent.TryGetValue(key, out raw) && !(raw is string) ? raw as IEnumerable : null;
            if (list == null) return items;
            foreach (object item in list)
            {
                IDictionary<string, object> entry = item as IDictionary<string, object>;
                if (entry != null) items.Add(entry);
            }
            return items;
        }

        internal static IDictionary<string, object> Child(IDictionary<string, object> parent, string key)
        {
            object value;
            return parent != null && parent.TryGetValue(key, out value) ? value as IDictionary<string, object> : null;
        }

        internal static string Text(IDictionary<string, object> parent, string key)
        {
            object value;
            return parent != null && parent.TryGetValue(key, out value) ? value as string : null;
        }

        internal static bool Flag(IDictionary<string, object> parent, string key)
        {
            object value;
            return parent != null && parent.TryGetValue(key, out value) && value is bool && (bool)value;
        }

        internal static bool IsNumber(object value)
        {
            return value is int || value is long || value is double || value is decimal || value is float;
        }

        internal static double Number(IDictionary<string, object> parent, string key)
        {
            object value;
            if (parent == null || !parent.TryGetValue(key, out value) || value == null) return 0;
            try
            {
                double number = Convert.ToDouble(value, CultureInfo.InvariantCulture);
                return double.IsNaN(number) || double.IsInfinity(number) ? 0 : Math.Max(0, number);
            }
            catch (Exception)
            {
                return 0;
            }
        }
    }

    public sealed class FlyoutLine
    {
        public string Id;
        public string Name;
        public int Color;
        // Marked Main: the first line, when there are others.
        public bool Main;
        public bool Metered;
        // The window's health words and their tone ("ok", "warn" or "down").
        public string Health;
        public string Tone;
        public bool Healthy;
        // Beside the name: the adapter (and network) or the data used, then the
        // health of a line that works.
        public string Detail;
        // Where its apps went while it can't take them; shown in its meter's place.
        public string Note;
        // The line its apps use instead, while they use another.
        public string StandIn;
        public string Speed;
        public double Down;
        public int Lit;
        // Everything about it, for the tooltip over its row.
        public string Tip;
    }

    // One line an app can be put on, or Shared while combining.
    public sealed class FlyoutOption
    {
        // The line's id, or null for Shared.
        public string Value;
        // What choosing it sends to /api/app-line: null is the default.
        public string Send;
        public string Label;
        public string Name;
        // The line's palette color; -1 for Shared.
        public int Color;
        public bool Shared;
    }

    public sealed class FlyoutApp
    {
        public string Name;
        public string Path;
        // The option shown as chosen: a line's id, or null for Shared.
        public string Choice;
        public string Speed;
        public string Initial;
        public int ColorIndex;
        public bool CanMove;
        public double Score;
        public bool HasTraffic;
    }

    public sealed class FlyoutView
    {
        public bool Available;
        public string Message;
        public string Status;
        public string Tone;
        public double TotalDown;
        public bool RoutingWanted;
        public bool CombineOn;
        public bool CanCombine;
        public string CombineName;
        public string CombineDetail;
        public string Health;
        public string HealthTone;
        // The first lines in priority order; MoreLines counts the others.
        public List<FlyoutLine> Lines = new List<FlyoutLine>();
        public int MoreLines;
        // The palette colors of the lines that take part in sharing, for the Shared mark.
        public List<int> SharingColors = new List<int>();
        public List<FlyoutOption> Options = new List<FlyoutOption>();
        // Few enough options for a compact control in each app's row; with more,
        // the row has a Change link that opens the window.
        public bool CompactChoice;
        public List<FlyoutApp> Apps = new List<FlyoutApp>();
    }

    // No window or network work here: missing measurements and older servers
    // take the same path in the flyout and in its tests.
    public static class FlyoutModel
    {
        public const int MaxLines = 3;
        public const int MaxOptions = 3;
        // The flyout shortens further, with "…", when the options don't fit.
        const int MaxOptionLabel = 12;
        const double MB = 1024.0 * 1024;
        const double GB = 1024.0 * MB;

        public static FlyoutView Unavailable(string message)
        {
            return new FlyoutView { Message = message, Status = "Not connected", Tone = "dim" };
        }

        public static FlyoutView FromState(IDictionary<string, object> state)
        {
            if (state == null) return Unavailable("Net Switch isn’t responding.");
            IDictionary<string, object> routing = TrayModel.Child(state, "routing");
            string status = TrayModel.Text(routing, "status") ?? "off";
            bool routingOn = status == "on";
            List<IDictionary<string, object>> lines = TrayModel.Lines(state);
            FlyoutView view = new FlyoutView();
            view.Available = true;
            view.RoutingWanted = OptionalFlag(routing, "wanted", routingOn);

            Dictionary<string, string> names = new Dictionary<string, string>();
            for (int i = 0; i < lines.Count; i++)
            {
                string id = TrayModel.Text(lines[i], "id");
                if (id != null && !names.ContainsKey(id)) names[id] = TrayModel.LineLabel(lines[i], i);
            }
            List<FlyoutLine> all = new List<FlyoutLine>();
            for (int i = 0; i < lines.Count; i++) all.Add(Line(lines[i], i, lines.Count, routingOn, names));
            foreach (FlyoutLine line in all) view.TotalDown += line.Down;
            view.Lines = all.GetRange(0, Math.Min(MaxLines, all.Count));
            view.MoreLines = all.Count - view.Lines.Count;

            // The person chose to combine, and there are lines to combine (ui/app.js combining).
            IDictionary<string, object> combine = TrayModel.Child(state, "combine");
            bool combining = TrayModel.Flag(combine, "on") && lines.Count > 1;
            bool active = combining && TrayModel.Flag(combine, "active");
            for (int i = 0; i < lines.Count; i++)
            {
                // Lines kept for chosen apps, or over their cap, don't share.
                if (!TrayModel.Flag(lines[i], "strict") && !TrayModel.Flag(lines[i], "exhausted")) view.SharingColors.Add(i % TrayModel.PaletteSize);
            }
            view.CombineOn = combining;
            view.CanCombine = combining || view.SharingColors.Count >= 2;
            view.CombineName = lines.Count == 2 ? "Both lines" : "Combine lines";
            if (combining) view.CombineDetail = !routingOn ? "On" : active ? "Combining" : "Paused";
            else if (view.CanCombine) view.CombineDetail = "Off";
            else view.CombineDetail = lines.Count < 2 ? "Add a second line" : "Needs two lines";

            string headline = "Routing off";
            if (status == "on") headline = "Routing on";
            else if (status == "starting") headline = "Starting routing…";
            else if (status == "stopping") headline = "Turning routing off…";
            else if (status == "error") headline = "Routing stopped";
            view.Status = headline + " · " + TrayModel.Rate(view.TotalDown);
            view.Tone = status == "on" ? "ok" : status == "error" ? "error" : "dim";
            Health(view, status, all);
            // Like the window's top bar: routing is on, but not every line works.
            if (status == "on" && view.HealthTone != "ok") view.Tone = view.HealthTone;

            // The window's choices (ui/app.js lineOptions): Shared while combining,
            // then every line. Without combining the main line is the default, so
            // choosing it clears the app's choice.
            string mainId = lines.Count > 0 ? TrayModel.Text(lines[0], "id") : null;
            if (combining) view.Options.Add(new FlyoutOption { Label = "Shared", Name = "Shared", Color = -1, Shared = true });
            for (int i = 0; i < lines.Count; i++)
            {
                string id = TrayModel.Text(lines[i], "id");
                if (id == null) continue;
                string name = TrayModel.LineLabel(lines[i], i);
                view.Options.Add(new FlyoutOption
                {
                    Value = id,
                    Send = !combining && id == mainId ? null : id,
                    Label = TrayModel.Shorten(name, MaxOptionLabel),
                    Name = name,
                    Color = i % TrayModel.PaletteSize,
                });
            }
            view.CompactChoice = view.Options.Count <= MaxOptions;

            foreach (IDictionary<string, object> app in TrayModel.Items(state, "apps"))
            {
                IDictionary<string, object> rate = TrayModel.Child(app, "rate");
                FlyoutApp row = new FlyoutApp();
                row.Name = TrayModel.Text(app, "name") ?? "App";
                if (string.IsNullOrWhiteSpace(row.Name)) row.Name = "App";
                row.Path = TrayModel.Text(app, "path") ?? "";
                string pinned = TrayModel.Text(app, "line");
                if (pinned != null && !names.ContainsKey(pinned)) pinned = null;
                // Without combining, an app with no choice of its own shows the main line chosen.
                row.Choice = combining ? pinned : pinned ?? mainId;
                row.Speed = TrayModel.Rate(TrayModel.Number(rate, "down"));
                row.Score = TrayModel.Number(app, "sortScore");
                row.HasTraffic = TrayModel.Number(rate, "down") + TrayModel.Number(rate, "up") > 0;
                row.CanMove = OptionalFlag(app, "switchable", true) && row.Path.Length > 0;
                row.Initial = StringInfo.GetNextTextElement(row.Name.Trim()).ToUpperInvariant();
                uint hash = 0;
                foreach (char letter in row.Name) hash = unchecked(hash * 31 + letter);
                row.ColorIndex = (int)(hash % 6);
                view.Apps.Add(row);
            }
            // Keep idle apps useful when nothing is transferring, but do not let
            // their historical score displace an app that is busy now.
            if (view.Apps.Exists(delegate (FlyoutApp app) { return app.HasTraffic; }))
                view.Apps.RemoveAll(delegate (FlyoutApp app) { return !app.HasTraffic; });
            view.Apps.Sort(delegate (FlyoutApp a, FlyoutApp b)
            {
                int score = b.Score.CompareTo(a.Score);
                if (score != 0) return score;
                int name = string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
                return name != 0 ? name : string.Compare(a.Path, b.Path, StringComparison.OrdinalIgnoreCase);
            });
            if (view.Apps.Count > 3) view.Apps.RemoveRange(3, view.Apps.Count - 3);
            return view;
        }

        static bool OptionalFlag(IDictionary<string, object> value, string key, bool fallback)
        {
            object raw;
            return value != null && value.TryGetValue(key, out raw) && raw is bool ? (bool)raw : fallback;
        }

        static FlyoutLine Line(IDictionary<string, object> line, int index, int count, bool routingOn, Dictionary<string, string> names)
        {
            FlyoutLine row = new FlyoutLine();
            row.Id = TrayModel.Text(line, "id") ?? "";
            row.Name = TrayModel.LineLabel(line, index);
            row.Color = index % TrayModel.PaletteSize;
            // "Main" only means something next to other lines.
            row.Main = index == 0 && count > 1;
            row.Metered = TrayModel.Flag(line, "metered");
            string tone;
            row.Health = TrayModel.Health(line, routingOn, out tone);
            row.Tone = tone;
            row.Healthy = tone == "ok";
            IDictionary<string, object> rate = TrayModel.Child(line, "rate");
            row.Down = TrayModel.Number(rate, "down");
            row.Speed = rate == null ? "Not measured" : TrayModel.Rate(row.Down);
            row.Lit = row.Healthy ? Lit(row.Down) : 0;

            string where = Join(TrayModel.Text(line, "alias"), TrayModel.Text(line, "ssid"));
            IDictionary<string, object> cap = TrayModel.Child(line, "cap");
            double used = TrayModel.Number(TrayModel.Child(line, "usage"), "bytes");
            // The window's words (ui/app.js usageText); the row leaves out the
            // period, which its tooltip says.
            string usage = null;
            string period = null;
            if (cap != null)
            {
                usage = Data(used) + " of " + Data(TrayModel.Number(cap, "bytes"));
                period = TrayModel.Text(cap, "period") == "day" ? " today" : " this month";
            }
            else if (row.Metered)
            {
                usage = Data(used) + " used";
            }
            row.Detail = Join(usage ?? where, row.Healthy ? row.Health : null);

            // Its own apps use another line while it is down or out of data
            // (ui/app.js lineFoot), which only happens while routing is on.
            string target = TrayModel.Text(line, "target");
            if (routingOn && target != null && target != row.Id && names.ContainsKey(target))
            {
                row.StandIn = names[target];
                row.Note = "Its apps use the " + row.StandIn + (TrayModel.Flag(line, "exhausted") ? " until the cap resets" : " until it’s back");
            }
            row.Tip = Join(Join(row.Name, where), Join(usage == null ? null : usage + period, row.Health)) + (row.Note != null ? "\n" + row.Note : "");
            return row;
        }

        // "a · b", leaving out the empty ones.
        static string Join(string first, string second)
        {
            if (string.IsNullOrEmpty(first)) return second ?? "";
            if (string.IsNullOrEmpty(second)) return first;
            return first + " · " + second;
        }

        // Data amounts as the window writes them (ui/app.js formatData): MB under
        // a gigabyte, then GB with one decimal ("10 GB", not "10.0 GB").
        public static string Data(double bytes)
        {
            if (!(bytes >= MB)) return bytes > 0 ? "<1 MB" : "0 MB";
            if (bytes < GB) return Math.Round(bytes / MB, MidpointRounding.AwayFromZero).ToString(CultureInfo.InvariantCulture) + " MB";
            double gigabytes = bytes / GB;
            string number = gigabytes >= 100
                ? Math.Round(gigabytes, MidpointRounding.AwayFromZero).ToString(CultureInfo.InvariantCulture)
                : Math.Round(gigabytes, 1, MidpointRounding.AwayFromZero).ToString("0.#", CultureInfo.InvariantCulture);
            return number + " GB";
        }

        public static int Lit(double down)
        {
            if (!(down >= 1) || double.IsInfinity(down)) return 0;
            double level = Math.Log10(down / 1024) / Math.Log10(10 * 1024);
            return Math.Max(1, Math.Min(24, (int)Math.Round(level * 24, MidpointRounding.AwayFromZero)));
        }

        // The footer: what is wrong, if anything, across all the lines.
        static void Health(FlyoutView view, string status, List<FlyoutLine> lines)
        {
            view.HealthTone = "dim";
            if (status != "on")
            {
                view.Health = status == "starting" ? "Routing is starting…" : status == "stopping" ? "Routing is turning off…" :
                    status == "error" ? "Routing stopped · apps use Windows' connection" : "Routing is off · apps use Windows' connection";
                if (status == "error") view.HealthTone = "error";
                return;
            }
            List<FlyoutLine> problems = lines.FindAll(delegate (FlyoutLine line) { return !line.Healthy; });
            int working = lines.Count - problems.Count;
            if (lines.Count == 0)
            {
                view.HealthTone = "warning";
                view.Health = "No line is set up";
                return;
            }
            if (problems.Count == 0)
            {
                view.HealthTone = "ok";
                view.Health = lines.Count == 1 ? lines[0].Name + " reaches the internet"
                    : lines.Count == 2 ? "Both lines reach the internet"
                    : "All " + lines.Count.ToString(CultureInfo.InvariantCulture) + " lines reach the internet";
                return;
            }
            view.HealthTone = working == 0 ? "error" : "warning";
            if (problems.Count == 1)
            {
                FlyoutLine line = problems[0];
                string moved = line.StandIn == null ? "" : (lines.IndexOf(line) == 0 ? " · apps use the " : " · its apps use the ") + line.StandIn;
                // "checking", without the "…" it has on its own.
                view.Health = line.Name + ": " + TrayModel.Lower(line.Health).TrimEnd('…') + moved;
                return;
            }
            FlyoutLine first = lines.Find(delegate (FlyoutLine line) { return line.Healthy; });
            view.Health = working == 0 ? "No line reaches the internet"
                : working == 1 ? "Only the " + first.Name + " reaches the internet"
                : working.ToString(CultureInfo.InvariantCulture) + " of " + lines.Count.ToString(CultureInfo.InvariantCulture) + " lines reach the internet";
        }
    }

    // ------------------------------------------------------------ notifications

    // One line event from the server: a line went down, came back, used up its
    // data cap, or can be used again.
    public sealed class LineEvent
    {
        public string Id;
        public string Kind;
        public string LineId;
        public string Text;
    }

    public sealed class Notice
    {
        public string EventId;
        public string LineId;
        public string Title;
        public string Text;
        public bool Warning;
    }

    // Which line events become notifications, and when. Each event is shown at
    // most once. Those already there on the tray's first reading happened before
    // it started, so they are only marked seen. A line notifies at most once per
    // PerLineSeconds: while it flaps, only its newest event waits, and shows once
    // the time is up. Notifications also keep GapSeconds apart, so each one is on
    // screen long enough to read before the next replaces it.
    public sealed class EventNotifier
    {
        public const int PerLineSeconds = 30;
        public const int GapSeconds = 4;
        // Event ids, as keys: HashSet is in System.Core, which the tray doesn't reference.
        readonly Dictionary<string, bool> seen = new Dictionary<string, bool>();
        // The newest event waiting to be shown, by line id; order keeps the lines oldest first.
        readonly Dictionary<string, LineEvent> waiting = new Dictionary<string, LineEvent>();
        readonly List<string> order = new List<string>();
        readonly Dictionary<string, DateTime> shownAt = new Dictionary<string, DateTime>();
        DateTime lastShown = DateTime.MinValue;
        bool primed;

        // The state's events, oldest first; null from a server that has none.
        public static List<LineEvent> FromState(IDictionary<string, object> state)
        {
            object raw;
            if (state == null || !state.TryGetValue("events", out raw) || !(raw is IEnumerable) || raw is string) return null;
            List<LineEvent> events = new List<LineEvent>();
            foreach (IDictionary<string, object> item in TrayModel.Items(state, "events"))
            {
                events.Add(new LineEvent
                {
                    Id = TrayModel.Text(item, "id"),
                    Kind = TrayModel.Text(item, "kind"),
                    LineId = TrayModel.Text(item, "lineId"),
                    Text = TrayModel.Text(item, "text"),
                });
            }
            return events;
        }

        public void Read(List<LineEvent> events, bool enabled)
        {
            if (!enabled)
            {
                waiting.Clear();
                order.Clear();
            }
            if (events == null)
            {
                primed = true;
                return;
            }
            Dictionary<string, bool> current = new Dictionary<string, bool>();
            foreach (LineEvent item in events)
            {
                if (string.IsNullOrEmpty(item.Id)) continue;
                current[item.Id] = true;
                if (seen.ContainsKey(item.Id)) continue;
                seen[item.Id] = true;
                if (!primed || !enabled || string.IsNullOrEmpty(item.Text)) continue;
                string line = item.LineId ?? "";
                if (!waiting.ContainsKey(line)) order.Add(line);
                waiting[line] = item;
            }
            // The server keeps the last 20 events; one that has left the list never comes back.
            List<string> gone = new List<string>();
            foreach (string id in seen.Keys) if (!current.ContainsKey(id)) gone.Add(id);
            foreach (string id in gone) seen.Remove(id);
            primed = true;
        }

        // The notification to show now, or null.
        public Notice Next(DateTime now)
        {
            if ((now - lastShown).TotalSeconds < GapSeconds) return null;
            for (int i = 0; i < order.Count; i++)
            {
                string line = order[i];
                DateTime last;
                if (shownAt.TryGetValue(line, out last) && (now - last).TotalSeconds < PerLineSeconds) continue;
                LineEvent item = waiting[line];
                waiting.Remove(line);
                order.RemoveAt(i);
                shownAt[line] = now;
                lastShown = now;
                return new Notice
                {
                    EventId = item.Id,
                    LineId = item.LineId,
                    Title = Title(item.Kind),
                    Text = item.Text,
                    Warning = item.Kind == "down" || item.Kind == "exhausted",
                };
            }
            return null;
        }

        static string Title(string kind)
        {
            if (kind == "down") return "Line down";
            if (kind == "up") return "Line back";
            if (kind == "exhausted") return "Data cap reached";
            if (kind == "cap-reset") return "Data cap reset";
            return "Net Switch";
        }
    }

    // What the tray remembers between runs, in tray-settings.json in the data folder.
    public sealed class TraySettings
    {
        public bool LineNotifications = true;

        // A missing or damaged file means the defaults.
        public static TraySettings Load(string file)
        {
            TraySettings settings = new TraySettings();
            try
            {
                IDictionary<string, object> saved = new JavaScriptSerializer().DeserializeObject(File.ReadAllText(file)) as IDictionary<string, object>;
                object value;
                if (saved != null && saved.TryGetValue("lineNotifications", out value) && value is bool) settings.LineNotifications = (bool)value;
            }
            catch (Exception)
            {
            }
            return settings;
        }

        public void Save(string file)
        {
            Dictionary<string, object> values = new Dictionary<string, object> { { "lineNotifications", LineNotifications } };
            File.WriteAllText(file, new JavaScriptSerializer().Serialize(values) + Environment.NewLine);
        }
    }

    // ------------------------------------------------------------ the picture

    public static class TrayPainter
    {
        // The window's colors (ui/favicon.svg).
        static readonly Color Panel = Color.FromArgb(0x14, 0x16, 0x19);
        static readonly Color Gray = Color.FromArgb(0xa8, 0xad, 0xb3);
        // A row's color by the line's position: the favicon's amber and cyan,
        // then the window's other line colors (ui/styles.css --line-2 to --line-5).
        static readonly Color[] Lines =
        {
            Color.FromArgb(0xf0, 0xb2, 0x3e), Color.FromArgb(0x4c, 0xc3, 0xe8), Color.FromArgb(0xb3, 0x94, 0xff),
            Color.FromArgb(0xf5, 0x84, 0xc8), Color.FromArgb(0xb9, 0xdc, 0x58), Color.FromArgb(0x7f, 0x99, 0xff),
        };

        // A row of cells per line on the dark panel, like the favicon's bars: the
        // main line on top in amber, the next in cyan, a third below in violet.
        // While routing isn't on the colors give way to gray; a line that isn't
        // there or doesn't work stays faint. Every pixel is either fully drawn or
        // fully clear, so the icon stays crisp at its real size.
        public static Bitmap Paint(TrayView view, int size)
        {
            Bitmap bitmap = new Bitmap(size, size, PixelFormat.Format32bppArgb);
            IconRow[] rows = TrayModel.Rows(view);
            using (Graphics g = Graphics.FromImage(bitmap))
            {
                using (SolidBrush panel = new SolidBrush(Panel))
                {
                    g.FillRectangle(panel, 0, 0, size, size);
                }
                int cell = Math.Max(2, size / 8);
                int gap = Math.Max(1, size / 16);
                // Two rows as the favicon draws them; three thinner ones, closer together.
                int height = rows.Length == 2 ? Math.Max(3, size / 4) : Math.Max(2, size * 3 / 16);
                int rowGap = rows.Length == 2 ? 2 * gap : gap;
                int left = (size - (TrayModel.Cells * cell + (TrayModel.Cells - 1) * gap)) / 2;
                int top = (size - (rows.Length * height + (rows.Length - 1) * rowGap)) / 2;
                for (int i = 0; i < rows.Length; i++)
                {
                    DrawRow(g, rows[i], view.Routing ? Lines[i % Lines.Length] : Gray, left, top + i * (height + rowGap), cell, gap, height);
                }
            }
            RoundCorners(bitmap, Math.Max(2, size / 8));
            return bitmap;
        }

        static void DrawRow(Graphics g, IconRow row, Color color, int left, int top, int cell, int gap, int height)
        {
            using (SolidBrush lit = new SolidBrush(color))
            using (SolidBrush unlit = new SolidBrush(row.Available ? Color.FromArgb(70, color) : Color.FromArgb(40, Gray)))
            {
                for (int i = 0; i < TrayModel.Cells; i++)
                {
                    g.FillRectangle(i < row.Lit ? lit : unlit, left + i * (cell + gap), top, cell, height);
                }
            }
        }

        // Clears a small staircase at each corner, the pixel version of the favicon's rounded square.
        static void RoundCorners(Bitmap bitmap, int radius)
        {
            Color clear = Color.FromArgb(0);
            int last = bitmap.Width - 1;
            for (int y = 0; y < radius; y++)
            {
                for (int x = 0; x < radius - y; x++)
                {
                    bitmap.SetPixel(x, y, clear);
                    bitmap.SetPixel(last - x, y, clear);
                    bitmap.SetPixel(x, last - y, clear);
                    bitmap.SetPixel(last - x, last - y, clear);
                }
            }
        }
    }

    // ------------------------------------------------------------ the flyout

    public sealed class FlyoutAction
    {
        public string Key;
        public string Endpoint;
        public IDictionary<string, object> Body;
    }

    // Logical pixels keep painting and hit-testing together at every DPI. Sizes
    // and colors follow the flyout's design (design/viNaw.png, drawn at 2x).
    public sealed class FlyoutForm : Form
    {
        const int WidthDip = 372;
        const int Pad = 16;
        const int Gap = 14;
        const int Inner = WidthDip - 2 * Pad;
        const int HeaderHeight = 35;
        const int TilesTop = Pad + HeaderHeight + Gap;
        const int TileWidth = (Inner - 8) / 2;
        const int TileHeight = 82;
        const int LinesTop = TilesTop + TileHeight + Gap;
        // Between two line rows, and the "+N more" link under them.
        const int LineGap = 10;
        const int MoreHeight = 16;
        const int AppsHeadHeight = 18;
        const int RowHeight = 39;
        const int RowGap = 2;
        const int UnavailableHeight = 84;
        // An app's name keeps at least this much room beside its speed; with
        // less, the speed goes under the name.
        const int MinNameRoom = 96;
        // The widest an app's line control gets, with two options and with three.
        const int MaxControl2 = 196;
        const int MaxControl3 = 216;
        // The chosen line's caption beside Change.
        const int MaxChosen = 110;
        static readonly Color Background = Color.FromArgb(32, 32, 32);
        static readonly Color Card = Color.FromArgb(43, 43, 43);
        static readonly Color Stroke = Color.FromArgb(58, 58, 58);
        // The hairline box around Main and Metered.
        static readonly Color Hairline = Color.FromArgb(74, 74, 74);
        // The design's #FFFFFF1A edge, over the background.
        static readonly Color Edge = Color.FromArgb(54, 54, 54);
        static readonly Color FooterFill = Color.FromArgb(26, 26, 26);
        static readonly Color SegmentFill = Color.FromArgb(28, 28, 28);
        static readonly Color SelectedFill = Color.FromArgb(50, 50, 50);
        static readonly Color Unlit = Color.FromArgb(68, 68, 68);
        static readonly Color UnlitDown = Color.FromArgb(52, 52, 52);
        static readonly Color Secondary = Color.FromArgb(197, 197, 197);
        static readonly Color Dim = Color.FromArgb(142, 142, 142);
        // Text of a control that can't be used now.
        static readonly Color Faint = Color.FromArgb(96, 96, 96);
        static readonly Color Accent = Color.FromArgb(76, 194, 255);
        static readonly Color Ink = Color.FromArgb(0, 42, 61);
        static readonly Color InkSoft = Color.FromArgb(0, 64, 92);
        static readonly Color AvatarInk = Color.FromArgb(17, 17, 17);
        static readonly Color Green = Color.FromArgb(108, 203, 95);
        static readonly Color Warning = Color.FromArgb(242, 178, 77);
        static readonly Color Red = Color.FromArgb(242, 109, 109);
        // The lines' colors by position, as in the window (ui/styles.css --line-0 to --line-5).
        static readonly Color[] Palette =
        {
            Color.FromArgb(245, 177, 61), Color.FromArgb(60, 200, 234), Color.FromArgb(179, 148, 255),
            Color.FromArgb(245, 132, 200), Color.FromArgb(185, 220, 88), Color.FromArgb(127, 153, 255),
        };
        // Solid tiles under a dark letter; the first three are the design's.
        static readonly Color[] Avatars =
        {
            Color.FromArgb(61, 220, 132), Color.FromArgb(154, 164, 178), Color.FromArgb(255, 113, 57),
            Accent, Palette[0], Color.FromArgb(199, 161, 245),
        };

        sealed class Hit
        {
            public RectangleF Bounds;
            public FlyoutAction Action;
            public string Tip;
        }

        readonly List<Hit> hits = new List<Hit>();
        // Tooltips over things that can't be pressed, such as a line's row or an app that can't move.
        readonly List<Hit> notes = new List<Hit>();
        readonly ToolTip tips = new ToolTip();
        // Segoe UI Variable has no Medium, so the design's 500 weight uses Regular.
        readonly Font title = MakeFont("Segoe UI Variable Text Semibold", "Segoe UI Semibold", 14, FontStyle.Regular);
        readonly Font label = MakeFont("Segoe UI Variable Text Semibold", "Segoe UI Semibold", 13, FontStyle.Regular);
        readonly Font strong = MakeFont("Segoe UI Variable Text Semibold", "Segoe UI Semibold", 12, FontStyle.Regular);
        readonly Font body = MakeFont("Segoe UI Variable Text", "Segoe UI", 12, FontStyle.Regular);
        readonly Font smallStrong = MakeFont("Segoe UI Variable Text Semibold", "Segoe UI Semibold", 11, FontStyle.Regular);
        readonly Font small = MakeFont("Segoe UI Variable Text", "Segoe UI", 11, FontStyle.Regular);
        readonly Font badge = MakeFont("Segoe UI Variable Text Semibold", "Segoe UI Semibold", 9, FontStyle.Regular);
        readonly Font letter = MakeFont("Segoe UI Variable Text", "Segoe UI", 11, FontStyle.Bold);
        readonly Font mono = MakeFont("Cascadia Mono", "Consolas", 12, FontStyle.Regular);
        readonly Font monoSmall = MakeFont("Cascadia Mono", "Consolas", 11, FontStyle.Regular);
        FlyoutView view = FlyoutModel.Unavailable("Connecting to Net Switch…");
        float scale = 1;
        // Windows draws the rounded edge itself on Windows 11; older Windows gets a painted one.
        bool windowEdge;
        Rectangle workArea;
        string hover;
        string keyboard;
        string pressed;
        string pending;
        string error;
        string tip;
        bool quitting;
        public Action<FlyoutAction> Requested;
        public DateTime DismissedAt = DateTime.MinValue;
        public Point DismissedPoint;

        public FlyoutForm()
        {
            Text = "Net Switch flyout";
            AccessibleName = Text;
            FormBorderStyle = FormBorderStyle.None;
            ShowInTaskbar = false;
            TopMost = true;
            StartPosition = FormStartPosition.Manual;
            AutoScaleMode = AutoScaleMode.None;
            BackColor = Background;
            DoubleBuffered = true;
            SetStyle(ControlStyles.ResizeRedraw, true);
            KeyPreview = true;
            tips.ShowAlways = true;
        }

        static Font MakeFont(string preferred, string fallback, float size, FontStyle style)
        {
            try
            {
                using (FontFamily family = new FontFamily(preferred)) return new Font(family, size, style, GraphicsUnit.Pixel);
            }
            catch (ArgumentException) { return new Font(fallback, size, style, GraphicsUnit.Pixel); }
        }

        // The flyout drawn into a picture at a display scale, as it looks on
        // screen, for the tests and dev/render-tray.mjs. Windows 11 rounds the
        // real flyout's corners itself; the picture has the square, painted edge
        // older Windows gets.
        public static Bitmap Snapshot(FlyoutView view, float scale)
        {
            using (FlyoutForm form = new FlyoutForm())
            {
                form.view = view;
                form.scale = scale;
                int width = (int)Math.Round(WidthDip * scale);
                int height = (int)Math.Round((form.ContentBottom() + form.FooterHeight()) * scale);
                Bitmap bitmap = new Bitmap(width, height, PixelFormat.Format32bppArgb);
                using (Graphics g = Graphics.FromImage(bitmap))
                {
                    g.Clear(Background);
                    form.Draw(g, height / scale);
                }
                return bitmap;
            }
        }

        public void SetView(FlyoutView next)
        {
            view = next;
            hits.Clear();
            if (Visible) Place();
            Invalidate();
        }

        public void Feedback(string action, string message, bool isQuitting)
        {
            pending = action;
            // An empty message is no error, not a blank red footer.
            error = string.IsNullOrEmpty(message) ? null : message;
            quitting = isQuitting;
            hits.Clear();
            // A long error makes the footer taller.
            if (Visible) Place();
            Invalidate();
        }

        public void ShowAtCursor()
        {
            Point cursor = Cursor.Position;
            workArea = Screen.FromPoint(cursor).WorkingArea;
            scale = Native.ScaleAt(cursor);
            hover = keyboard = pressed = null;
            Place();
            Show();
            Native.SetForegroundWindow(Handle);
            Activate();
        }

        // A line's row: its name, then its meter, or where its apps went in the meter's place.
        static int LineRowHeight(FlyoutLine line)
        {
            return 23 + (line.Note != null ? 14 : 6);
        }

        // The body is a vertical stack: header, toggles, lines card, apps head, app rows.
        int LinesHeight()
        {
            int height = 12;
            if (view.Lines.Count == 0) height += 16;
            for (int i = 0; i < view.Lines.Count; i++) height += (i > 0 ? LineGap : 0) + LineRowHeight(view.Lines[i]);
            if (view.MoreLines > 0) height += LineGap + MoreHeight;
            return height + 12;
        }

        int AppsTop()
        {
            return LinesTop + LinesHeight() + Gap;
        }

        int RowsTop()
        {
            return AppsTop() + AppsHeadHeight + Gap;
        }

        // Where the footer starts.
        int ContentBottom()
        {
            if (!view.Available) return TilesTop + UnavailableHeight + Pad;
            int rows = Math.Max(1, view.Apps.Count);
            return RowsTop() + rows * RowHeight + (rows - 1) * RowGap + Pad;
        }

        string FooterMessage()
        {
            return quitting ? "Net Switch is quitting…" : error ?? (view.Available ? view.Health : "Open Net Switch to reconnect");
        }

        // Leaves room for "Quit" on the right.
        const float FooterTextLeft = Pad + 13 + 6;
        const float FooterTextWidth = 280;

        // How many lines the footer's message takes: one, as in the design, but
        // a long error wraps onto up to three rather than losing its end.
        int FooterLines()
        {
            using (Graphics g = Graphics.FromHwnd(IntPtr.Zero))
            using (StringFormat format = Format(StringAlignment.Near, true))
            {
                g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
                float line = small.GetHeight();
                SizeF room = new SizeF(FooterTextWidth + 2 * TextPad(small), 3 * line + 1);
                float height = g.MeasureString(FooterMessage(), small, room, format).Height;
                return Math.Max(1, Math.Min(3, (int)Math.Round(height / line)));
            }
        }

        // 10 px above and below a 13 px line, like the design; wrapped lines take Segoe's full line height.
        int FooterHeight()
        {
            int lines = FooterLines();
            return lines == 1 ? 33 : 20 + (int)Math.Ceiling(lines * small.GetHeight());
        }

        void Place()
        {
            int width = (int)Math.Round(WidthDip * scale);
            int height = (int)Math.Round((ContentBottom() + FooterHeight()) * scale);
            int margin = (int)Math.Round(12 * scale);
            SetBounds(workArea.Right - width - margin, workArea.Bottom - height - margin, width, height);
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            // Unsupported DWM attributes are harmless on older Windows.
            windowEdge = Native.FlyoutStyle(Handle, Edge);
        }

        protected override void OnDeactivate(EventArgs e)
        {
            base.OnDeactivate(e);
            DismissedAt = DateTime.UtcNow;
            DismissedPoint = Cursor.Position;
            Hide();
        }

        protected override void WndProc(ref Message message)
        {
            if (message.Msg == 0x02E0) // WM_DPICHANGED
            {
                scale = ((long)message.WParam & 0xFFFF) / 96f;
                base.WndProc(ref message);
                workArea = Screen.FromHandle(Handle).WorkingArea;
                Place();
                return;
            }
            base.WndProc(ref message);
        }

        static Color Tone(string tone)
        {
            return tone == "ok" ? Green : tone == "error" || tone == "down" ? Red : tone == "warning" || tone == "warn" ? Warning : Dim;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            Draw(e.Graphics, ClientSize.Height / scale);
        }

        // height: the flyout's height in logical pixels.
        void Draw(Graphics g, float height)
        {
            g.ScaleTransform(scale, scale);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            // Whole logical pixels land on whole device pixels, so fills stay crisp.
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
            g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
            hits.Clear();
            notes.Clear();

            // Header: title and status on the left, the open button on the right.
            Caption(g, "Net Switch", title, Color.White, Pad, Pad + 8.5f, 300, StringAlignment.Near);
            using (SolidBrush dot = new SolidBrush(Tone(view.Tone))) g.FillEllipse(dot, Pad, 40, 7, 7);
            Caption(g, view.Status, body, Secondary, Pad + 13, 43.5f, 290, StringAlignment.Near);
            FlyoutAction open = new FlyoutAction { Key = "open" };
            Button(g, new RectangleF(WidthDip - Pad - 26, 20.5f, 26, 26), open, "Open Net Switch", !quitting, Card, false, 6);
            Glyph(g, "maximize", WidthDip - Pad - 20, 26.5f, 14, quitting ? Faint : Secondary);

            if (!view.Available)
            {
                Paragraph(g, view.Message, body, Secondary, new RectangleF(Pad, TilesTop, Inner, 36));
                RectangleF button = new RectangleF(Pad, TilesTop + 48, Inner, 36);
                Button(g, button, open, "Open Net Switch", !quitting, Accent, false, 8);
                Caption(g, "Open Net Switch", label, Ink, button.X, button.Y + 18, button.Width, StringAlignment.Center);
            }
            else
            {
                Tile(g, Pad, "routing", "Routing", view.RoutingWanted ? "On" : "Off", view.RoutingWanted, true);
                Tile(g, Pad + TileWidth + 8, "combine", view.CombineName, view.CombineDetail, view.CombineOn, view.CanCombine);
                Round(g, new RectangleF(Pad, LinesTop, Inner, LinesHeight()), 8, Card, Color.Transparent);
                int y = LinesTop + 12;
                if (view.Lines.Count == 0) Caption(g, "No line is set up yet", body, Dim, Pad + 12, y + 8, Inner - 24, StringAlignment.Near);
                foreach (FlyoutLine line in view.Lines)
                {
                    Line(g, line, y);
                    y += LineRowHeight(line) + LineGap;
                }
                if (view.MoreLines > 0) MoreLink(g, y);
                AppsHead(g, AppsTop());
                int top = RowsTop();
                if (view.Apps.Count == 0) Caption(g, "No apps using the connection yet", body, Dim, Pad + 2, top + RowHeight / 2f, Inner - 4, StringAlignment.Near);
                AppLayout layout = LayOutApps(g);
                for (int i = 0; i < view.Apps.Count; i++) AppRow(g, view.Apps[i], top + i * (RowHeight + RowGap), layout);
            }
            Footer(g, ContentBottom(), height);
            if (!windowEdge)
                using (Pen edge = new Pen(Edge, 1)) g.DrawRectangle(edge, 0.5f, 0.5f, WidthDip - 1, height - 1);
        }

        // A square toggle: glyph, then its name and state under it.
        void Tile(Graphics g, float x, string key, string name, string detail, bool on, bool enabled)
        {
            FlyoutAction action = new FlyoutAction { Key = key, Endpoint = "/api/" + key, Body = new Dictionary<string, object> { { "on", !on } } };
            Button(g, new RectangleF(x, TilesTop, TileWidth, TileHeight), action, name + ": " + detail, enabled && !quitting && pending == null, on ? Accent : Card, !on, 8);
            Glyph(g, key == "routing" ? "power" : "merge", x + 12, TilesTop + 12, 18, on ? Ink : enabled ? Secondary : Faint);
            Caption(g, name, label, on ? Ink : enabled ? Color.White : Dim, x + 12, TilesTop + 48, TileWidth - 24, StringAlignment.Near);
            Caption(g, detail, small, on ? InkSoft : Dim, x + 12, TilesTop + 63.5f, TileWidth - 24, StringAlignment.Near);
        }

        // One line in the lines card: its color, name and marks, what it is and
        // how it is doing beside them, and its speed on the right (or its health,
        // while it has a problem). Under them its meter, or where its apps went
        // while it can't take them.
        void Line(Graphics g, FlyoutLine line, float y)
        {
            Color color = Palette[line.Color % Palette.Length];
            float middle = y + 8;
            float right = WidthDip - Pad - 12;
            float left = Pad + 12;
            Round(g, new RectangleF(left, middle - 4, 8, 8), 2, line.Healthy ? color : Dim, Color.Transparent);
            string reading = line.Healthy ? line.Speed : line.Health;
            Font readingFont = line.Healthy && line.Speed != "Not measured" ? mono : small;
            // Measured widths place things; the boxes drawn into stay roomy,
            // because GDI+ trims against a wider estimate than the letters' own.
            float readingWidth = Math.Min(140, Measure(g, reading, readingFont));
            Caption(g, reading, readingFont, line.Healthy ? Color.White : Tone(line.Tone), right - 140, middle, 140, StringAlignment.Far);
            float nameLeft = left + 16;
            float room = right - readingWidth - 12 - nameLeft;

            List<string> marks = new List<string>();
            if (line.Main) marks.Add("MAIN");
            if (line.Metered) marks.Add("METERED");
            float marksWidth = 0;
            foreach (string mark in marks) marksWidth += 6 + Measure(g, mark, badge) + 10;
            float nameRoom = Math.Max(40, room - marksWidth);
            float nameWidth = Math.Min(nameRoom, Measure(g, line.Name, strong));
            Caption(g, line.Name, strong, line.Healthy ? Color.White : Secondary, nameLeft, middle, nameRoom, StringAlignment.Near);
            float x = nameLeft + nameWidth;
            foreach (string mark in marks)
            {
                RectangleF box = new RectangleF(x + 6, middle - 7, Measure(g, mark, badge) + 10, 14);
                if (box.Right > nameLeft + room) break;
                Round(g, box, 4, Color.Transparent, Hairline);
                Caption(g, mark, badge, Secondary, box.X, middle, box.Width, StringAlignment.Center);
                x = box.Right;
            }
            float detailLeft = x + 8;
            float detailRoom = nameLeft + room - detailLeft;
            if (!string.IsNullOrEmpty(line.Detail) && detailRoom > 24)
                Caption(g, line.Detail, small, Dim, detailLeft, middle, detailRoom, StringAlignment.Near);

            if (line.Note != null)
            {
                Caption(g, line.Note, small, Secondary, left, y + 30, right - left, StringAlignment.Near);
            }
            else
            {
                float cell = (Inner - 24 - 23 * 2) / 24f;
                Color off = line.Healthy ? Unlit : UnlitDown;
                for (int i = 0; i < 24; i++)
                    Round(g, new RectangleF(left + i * (cell + 2), y + 23, cell, 6), 1, i < line.Lit ? color : off, Color.Transparent);
            }
            notes.Add(new Hit { Bounds = new RectangleF(Pad, y - 5, Inner, LineRowHeight(line) + 10), Tip = line.Tip });
        }

        // Under the first lines, for the others: the window shows them all.
        void MoreLink(Graphics g, float y)
        {
            string text = TrayModel.More(view.MoreLines);
            float left = Pad + 12;
            float middle = y + MoreHeight / 2f;
            float width = Measure(g, text, small);
            Button(g, new RectangleF(left - 6, middle - 11, width + 12, 22), new FlyoutAction { Key = "more" }, "See every line in Net Switch", !quitting, Card, false, 6);
            Caption(g, text, small, quitting ? Faint : Accent, left, middle, width + 20, StringAlignment.Near);
        }

        void AppsHead(Graphics g, float y)
        {
            float middle = y + 2 + 8;
            Caption(g, "Busiest apps", strong, Secondary, Pad + 2, middle, 200, StringAlignment.Near);
            float width = Measure(g, "See all", body);
            float right = WidthDip - Pad - 2;
            Button(g, new RectangleF(right - width - 6, middle - 11, width + 12, 22), new FlyoutAction { Key = "all" }, "See all apps in Net Switch", !quitting, Background, false, 6);
            Caption(g, "See all", body, quitting ? Faint : Accent, right - 100, middle, 100, StringAlignment.Far);
        }

        // The app rows' columns, the same for every row so they line up.
        sealed class AppLayout
        {
            // Each option's width in the compact control.
            public float[] Widths;
            // Where the control on the right starts.
            public float ControlLeft;
            // The name above its speed, when beside it would leave the name too little room.
            public bool Stacked;
        }

        // The colored mark of an option: a dot for a line, a striped pill for Shared.
        float MarkWidth(FlyoutOption option)
        {
            return option.Shared ? Math.Max(12, view.SharingColors.Count * 5) : 6;
        }

        AppLayout LayOutApps(Graphics g)
        {
            AppLayout layout = new AppLayout();
            float right = WidthDip - Pad - 8;
            layout.ControlLeft = right;
            if (view.Options.Count >= 2)
            {
                if (view.CompactChoice)
                {
                    // Each option as wide as its caption in the bold face with the
                    // mark beside it, so the control doesn't move when the choice
                    // changes. Past the control's widest, which leaves the app's
                    // name its room, the widest options give way first; a caption
                    // that doesn't fit is shortened with "…".
                    int count = view.Options.Count;
                    float[] natural = new float[count];
                    for (int i = 0; i < count; i++) natural[i] = Measure(g, view.Options[i].Label, smallStrong) + MarkWidth(view.Options[i]) + 5 + 14;
                    float cap = WidestFitting(natural, (count == 2 ? MaxControl2 : MaxControl3) - 4 - 2 * (count - 1));
                    layout.Widths = new float[count];
                    float total = 4;
                    for (int i = 0; i < count; i++)
                    {
                        layout.Widths[i] = Math.Min(cap, natural[i]);
                        total += layout.Widths[i] + (i > 0 ? 2 : 0);
                    }
                    layout.ControlLeft = right - total;
                }
                else
                {
                    layout.ControlLeft = right - ChangeWidth(g) - 8 - ChosenWidth(g);
                }
            }
            float nameLeft = Pad + 8 + 22 + 10;
            float speedWidth = Measure(g, "999 KB/s", monoSmall);
            layout.Stacked = layout.ControlLeft - 10 - speedWidth - 10 - nameLeft < MinNameRoom;
            return layout;
        }

        // The largest width each option may take so that, with the narrower ones
        // at their own width, they all add up to no more than room.
        static float WidestFitting(float[] widths, float room)
        {
            float[] sorted = (float[])widths.Clone();
            Array.Sort(sorted);
            float used = 0;
            for (int i = 0; i < sorted.Length; i++)
            {
                float even = (room - used) / (sorted.Length - i);
                if (sorted[i] > even) return even;
                used += sorted[i];
            }
            return float.MaxValue;
        }

        float ChangeWidth(Graphics g)
        {
            return Measure(g, "Change", body) + 12;
        }

        // The chosen line's pill beside Change, wide enough for any line's short name.
        float ChosenWidth(Graphics g)
        {
            float widest = 0;
            foreach (FlyoutOption option in view.Options) widest = Math.Max(widest, Measure(g, option.Label, small) + MarkWidth(option) + 5);
            return Math.Min(MaxChosen, widest + 16);
        }

        void AppRow(Graphics g, FlyoutApp app, float y, AppLayout layout)
        {
            float middle = y + RowHeight / 2f;
            Round(g, new RectangleF(Pad, y, Inner, RowHeight), 6, Card, Color.Transparent);
            float left = Pad + 8;
            RectangleF avatar = new RectangleF(left, middle - 11, 22, 22);
            Round(g, avatar, 5, Avatars[app.ColorIndex], Color.Transparent);
            Caption(g, app.Initial, letter, AvatarInk, avatar.X, middle, avatar.Width, StringAlignment.Center);

            float control = layout.ControlLeft;
            if (view.Options.Count >= 2 && view.CompactChoice)
            {
                RectangleF segment = new RectangleF(control, middle - 11.5f, WidthDip - Pad - 8 - control, 23);
                Round(g, segment, 6, SegmentFill, Color.Transparent);
                float x = segment.X + 2;
                for (int i = 0; i < view.Options.Count; i++)
                {
                    AppOption(g, app, view.Options[i], new RectangleF(x, segment.Y + 2, layout.Widths[i], 19));
                    x += layout.Widths[i] + 2;
                }
                if (!app.CanMove) notes.Add(new Hit { Bounds = segment, Tip = app.Name + " can’t be moved" });
            }
            else if (view.Options.Count >= 2)
            {
                // More lines than fit: what is chosen, and Change, which opens the window.
                FlyoutOption chosen = view.Options.Find(delegate (FlyoutOption option) { return option.Value == app.Choice; }) ?? view.Options[0];
                float changeWidth = ChangeWidth(g);
                RectangleF pill = new RectangleF(control, middle - 11.5f, ChosenWidth(g), 23);
                Round(g, pill, 6, SegmentFill, Color.Transparent);
                MarkedCaption(g, chosen, chosen.Label, small, app.CanMove ? Secondary : Dim, pill);
                notes.Add(new Hit { Bounds = pill, Tip = app.Name + ": " + chosen.Name });
                float changeLeft = WidthDip - Pad - 8 - changeWidth;
                if (app.CanMove)
                {
                    Button(g, new RectangleF(changeLeft, middle - 11, changeWidth, 22), new FlyoutAction { Key = "change:" + app.Path },
                        "Choose the line for " + app.Name + " in Net Switch", !quitting, Card, false, 6);
                    Caption(g, "Change", body, quitting ? Faint : Accent, changeLeft, middle, changeWidth, StringAlignment.Center);
                }
                else
                {
                    notes.Add(new Hit { Bounds = new RectangleF(changeLeft, middle - 11, changeWidth, 22), Tip = app.Name + " can’t be moved" });
                }
            }

            float nameLeft = left + 22 + 10;
            if (layout.Stacked)
            {
                float nameRoom = control - 10 - nameLeft;
                Caption(g, app.Name, body, Color.White, nameLeft, middle - 7, nameRoom, StringAlignment.Near);
                Caption(g, app.Speed, monoSmall, Dim, nameLeft, middle + 7.5f, nameRoom, StringAlignment.Near);
            }
            else
            {
                float speedRight = control - 10;
                float speedWidth = Measure(g, app.Speed, monoSmall);
                Caption(g, app.Speed, monoSmall, Dim, speedRight - 100, middle, 100, StringAlignment.Far);
                Caption(g, app.Name, body, Color.White, nameLeft, middle, speedRight - speedWidth - 10 - nameLeft, StringAlignment.Near);
            }
        }

        void Mark(Graphics g, FlyoutOption option, float x, float middle)
        {
            if (!option.Shared)
            {
                using (SolidBrush dot = new SolidBrush(Palette[option.Color % Palette.Length])) g.FillEllipse(dot, x, middle - 3, 6, 6);
                return;
            }
            // A stripe per line that shares, like the window's Shared mark.
            RectangleF pill = new RectangleF(x, middle - 3, MarkWidth(option), 6);
            List<int> colors = view.SharingColors.Count > 0 ? view.SharingColors : new List<int> { 0 };
            GraphicsState state = g.Save();
            using (GraphicsPath path = RoundPath(pill, 3)) g.SetClip(path);
            float step = pill.Width / colors.Count;
            for (int i = 0; i < colors.Count; i++)
                using (SolidBrush stripe = new SolidBrush(Palette[colors[i] % Palette.Length])) g.FillRectangle(stripe, pill.X + i * step, pill.Y, step + 0.5f, pill.Height);
            g.Restore(state);
        }

        // One option of an app's compact control. The chosen one shows its line's
        // mark, as the window's keys do; pressing it changes nothing.
        void AppOption(Graphics g, FlyoutApp app, FlyoutOption option, RectangleF bounds)
        {
            bool selected = app.Choice == option.Value;
            bool enabled = !selected && app.CanMove && !quitting && pending == null;
            FlyoutAction action = new FlyoutAction
            {
                Key = "app:" + app.Path + ":" + (option.Value ?? ""),
                Endpoint = "/api/app-line",
                Body = new Dictionary<string, object> { { "path", app.Path }, { "line", option.Send } },
            };
            string hint = option.Shared ? "Share " + app.Name + "’s new connections between the lines" : "Put " + app.Name + " on the " + option.Name;
            Button(g, bounds, action, hint, enabled, selected ? SelectedFill : SegmentFill, false, 4);
            Font font = selected ? smallStrong : small;
            Color color = selected ? app.CanMove ? Color.White : Dim : enabled ? Dim : Faint;
            if (selected) MarkedCaption(g, option, option.Label, font, color, bounds);
            else Caption(g, option.Label, font, color, bounds.X + 7, bounds.Y + bounds.Height / 2, bounds.Width - 14, StringAlignment.Center);
        }

        // An option's mark and caption, centered together in bounds; a caption
        // too long for what is left beside the mark is shortened with "…".
        void MarkedCaption(Graphics g, FlyoutOption option, string text, Font font, Color color, RectangleF bounds)
        {
            float markWidth = MarkWidth(option);
            float room = bounds.Width - 14 - markWidth - 5;
            float textWidth = Measure(g, text, font);
            bool fits = textWidth <= room;
            float shown = fits ? textWidth : room;
            float middle = bounds.Y + bounds.Height / 2;
            float start = bounds.X + (bounds.Width - (markWidth + 5 + shown)) / 2;
            Mark(g, option, start, middle);
            // A roomy box when it fits, because GDI+ trims against a wider estimate than the letters' own.
            Caption(g, text, font, color, start + markWidth + 5, middle, fits ? textWidth + 12 : room, StringAlignment.Near);
        }

        void Footer(Graphics g, int y, float flyoutHeight)
        {
            float height = flyoutHeight - y;
            using (SolidBrush brush = new SolidBrush(FooterFill)) g.FillRectangle(brush, 0, y, WidthDip, height);
            using (Pen pen = new Pen(Stroke)) g.DrawLine(pen, 0, y + 0.5f, WidthDip, y + 0.5f);
            // While quitting, the health reading no longer applies.
            Color color = error != null ? Red : view.Available && !quitting ? Tone(view.HealthTone) : Dim;
            Color text = error != null ? Red : Dim;
            float middle = y + height / 2;
            if (FooterLines() == 1)
            {
                Glyph(g, "shield", Pad, middle - 6.5f, 13, color);
                Caption(g, FooterMessage(), small, text, FooterTextLeft, middle, FooterTextWidth, StringAlignment.Near);
            }
            else
            {
                // The shield sits beside the first line.
                Glyph(g, "shield", Pad, y + 10 + small.GetHeight() / 2 - 6.5f, 13, color);
                Paragraph(g, FooterMessage(), small, text, new RectangleF(FooterTextLeft, y + 10, FooterTextWidth, height - 18));
            }
            float width = Measure(g, "Quit", small);
            float right = WidthDip - Pad;
            Button(g, new RectangleF(right - width - 6, middle - 11, width + 12, 22), new FlyoutAction { Key = "quit" }, "Quit Net Switch", !quitting, FooterFill, false, 6);
            Caption(g, "Quit", small, quitting ? Faint : Secondary, right - 60, middle, 60, StringAlignment.Far);
        }

        void Button(Graphics g, RectangleF bounds, FlyoutAction action, string hint, bool enabled, Color fill, bool border, float radius)
        {
            bool over = enabled && (hover == action.Key || keyboard == action.Key);
            if (over) fill = ControlPaint.Light(fill, 0.12f);
            Round(g, bounds, radius, fill, border ? Stroke : Color.Transparent);
            if (pending == action.Key || pressed == action.Key)
                Round(g, bounds, radius, Color.FromArgb(60, 0, 0, 0), Color.Transparent);
            // White shows on the blue tiles as well as on the dark ones.
            if (keyboard == action.Key && enabled)
                Round(g, RectangleF.Inflate(bounds, -1, -1), Math.Max(1, radius - 1), Color.Transparent, Color.White);
            if (enabled) hits.Add(new Hit { Bounds = bounds, Action = action, Tip = hint });
        }

        static void Round(Graphics g, RectangleF bounds, float radius, Color fill, Color border)
        {
            if (fill.A != 0)
                using (GraphicsPath path = RoundPath(bounds, radius))
                using (SolidBrush brush = new SolidBrush(fill)) g.FillPath(brush, path);
            // Inset by half the pen, so the 1 px edge sits on whole pixels.
            if (border.A != 0)
                using (GraphicsPath path = RoundPath(RectangleF.Inflate(bounds, -0.5f, -0.5f), Math.Max(0.5f, radius - 0.5f)))
                using (Pen pen = new Pen(border)) g.DrawPath(pen, path);
        }

        static GraphicsPath RoundPath(RectangleF bounds, float radius)
        {
            float d = radius * 2;
            GraphicsPath path = new GraphicsPath();
            path.AddArc(bounds.X, bounds.Y, d, d, 180, 90);
            path.AddArc(bounds.Right - d, bounds.Y, d, d, 270, 90);
            path.AddArc(bounds.Right - d, bounds.Bottom - d, d, d, 0, 90);
            path.AddArc(bounds.X, bounds.Bottom - d, d, d, 90, 90);
            path.CloseFigure();
            return path;
        }

        // Lucide's icons (the design's set), drawn from their 24-unit outlines with a 2-unit stroke.
        static void Glyph(Graphics g, string name, float x, float y, float size, Color color)
        {
            GraphicsState state = g.Save();
            g.TranslateTransform(x, y);
            g.ScaleTransform(size / 24f, size / 24f);
            using (Pen pen = new Pen(color, 2f))
            using (GraphicsPath path = new GraphicsPath())
            {
                pen.StartCap = LineCap.Round;
                pen.EndCap = LineCap.Round;
                pen.LineJoin = LineJoin.Round;
                if (name == "power")
                {
                    path.AddLine(12, 2, 12, 12);
                    path.StartFigure();
                    path.AddArc(3, 4, 18, 18, -45, 270);
                }
                else if (name == "merge")
                {
                    path.AddLines(new PointF[] { new PointF(8, 6), new PointF(12, 2), new PointF(16, 6) });
                    path.StartFigure();
                    path.AddLine(12, 2, 12, 12.3f);
                    path.AddArc(4, 8.3f, 8, 8, 0, 45);
                    path.AddLine(10.83f, 15.13f, 4, 22);
                    path.StartFigure();
                    path.AddLine(20, 22, 15, 17);
                }
                else if (name == "maximize")
                {
                    path.AddLines(new PointF[] { new PointF(15, 3), new PointF(21, 3), new PointF(21, 9) });
                    path.StartFigure();
                    path.AddLine(21, 3, 14, 10);
                    path.StartFigure();
                    path.AddLines(new PointF[] { new PointF(9, 21), new PointF(3, 21), new PointF(3, 15) });
                    path.StartFigure();
                    path.AddLine(3, 21, 10, 14);
                }
                else if (name == "shield")
                {
                    path.AddBezier(20, 13, 20, 18, 16.5f, 20.5f, 12.34f, 21.95f);
                    path.AddBezier(11.66f, 21.94f, 7.5f, 20.5f, 4, 18, 4, 13);
                    path.AddLine(4, 13, 4, 6);
                    path.AddBezier(4, 6, 4, 5.45f, 4.45f, 5, 5, 5);
                    path.AddBezier(5, 5, 7, 5, 9.5f, 3.8f, 11.24f, 2.28f);
                    path.AddBezier(11.24f, 2.28f, 11.7f, 1.9f, 12.3f, 1.9f, 12.76f, 2.28f);
                    path.AddBezier(12.76f, 2.28f, 14.51f, 3.81f, 17, 5, 19, 5);
                    path.AddBezier(19, 5, 19.55f, 5, 20, 5.45f, 20, 6);
                    path.CloseFigure();
                    path.StartFigure();
                    path.AddLines(new PointF[] { new PointF(9, 12), new PointF(11, 14), new PointF(15, 10) });
                }
                g.DrawPath(pen, path);
            }
            g.Restore(state);
        }

        // The default layout, not GenericTypographic: with ClearType's grid
        // fitting, the typographic one squeezes spaces ("reachthe internet").
        static StringFormat Format(StringAlignment alignment, bool wrap)
        {
            StringFormat format = new StringFormat();
            format.Alignment = alignment;
            format.LineAlignment = wrap ? StringAlignment.Near : StringAlignment.Center;
            format.Trimming = StringTrimming.EllipsisCharacter;
            format.FormatFlags = wrap ? StringFormatFlags.LineLimit : StringFormatFlags.NoWrap;
            return format;
        }

        // The default layout pads each side of a line by 1/6 em; text is placed
        // by its letters, so that padding is taken back out.
        static float TextPad(Font font)
        {
            return font.Size / 6;
        }

        // The width of the letters themselves, for placing what comes next to them.
        static float Measure(Graphics g, string text, Font font)
        {
            if (string.IsNullOrEmpty(text)) return 0;
            using (StringFormat format = Format(StringAlignment.Near, false))
            {
                format.SetMeasurableCharacterRanges(new CharacterRange[] { new CharacterRange(0, text.Length) });
                Region[] regions = g.MeasureCharacterRanges(text, font, new RectangleF(0, 0, 10000, 1000), format);
                float width = regions[0].GetBounds(g).Width;
                foreach (Region region in regions) region.Dispose();
                return (float)Math.Ceiling(width);
            }
        }

        // One line of text whose letters start at x (or end at x + width) and whose middle is at y.
        static void Caption(Graphics g, string text, Font font, Color color, float x, float y, float width, StringAlignment alignment)
        {
            if (width <= 0) return;
            float pad = TextPad(font);
            using (StringFormat format = Format(alignment, false))
            using (SolidBrush brush = new SolidBrush(color))
                g.DrawString(text ?? "", font, brush, new RectangleF(x - pad, y - font.Size, width + 2 * pad, 2 * font.Size), format);
        }

        static void Paragraph(Graphics g, string text, Font font, Color color, RectangleF bounds)
        {
            float pad = TextPad(font);
            using (StringFormat format = Format(StringAlignment.Near, true))
            using (SolidBrush brush = new SolidBrush(color))
                g.DrawString(text ?? "", font, brush, new RectangleF(bounds.X - pad, bounds.Y, bounds.Width + 2 * pad, bounds.Height), format);
        }

        Hit At(Point point)
        {
            PointF logical = new PointF(point.X / scale, point.Y / scale);
            return hits.Find(delegate (Hit hit) { return hit.Bounds.Contains(logical); });
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            Hit hit = At(e.Location);
            string next = hit == null ? null : hit.Action.Key;
            Cursor = hit == null ? Cursors.Default : Cursors.Hand;
            PointF logical = new PointF(e.X / scale, e.Y / scale);
            Hit note = hit == null ? notes.Find(delegate (Hit item) { return item.Bounds.Contains(logical); }) : null;
            string nextTip = hit != null ? hit.Tip : note != null ? note.Tip : logical.Y >= ContentBottom() ? FooterMessage() : null;
            if (nextTip != tip) { tip = nextTip; tips.SetToolTip(this, tip); }
            if (hover != next) { hover = next; Invalidate(); }
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            hover = null;
            Invalidate();
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            Hit hit = At(e.Location);
            pressed = e.Button == MouseButtons.Left && hit != null ? hit.Action.Key : null;
            keyboard = null;
            Invalidate();
        }

        protected override void OnMouseUp(MouseEventArgs e)
        {
            base.OnMouseUp(e);
            Hit hit = At(e.Location);
            string before = pressed;
            pressed = null;
            Invalidate();
            if (e.Button == MouseButtons.Left && hit != null && hit.Action.Key == before && Requested != null) Requested(hit.Action);
        }

        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            if (keyData == Keys.Escape) { Hide(); return true; }
            if (keyData == Keys.Tab || keyData == (Keys.Tab | Keys.Shift))
            {
                if (hits.Count > 0)
                {
                    int index = hits.FindIndex(delegate (Hit hit) { return hit.Action.Key == keyboard; });
                    int step = (keyData & Keys.Shift) != 0 ? -1 : 1;
                    keyboard = hits[(index + step + hits.Count) % hits.Count].Action.Key;
                    Invalidate();
                }
                return true;
            }
            if (keyData == Keys.Enter || keyData == Keys.Space)
            {
                Hit hit = hits.Find(delegate (Hit item) { return item.Action.Key == keyboard; });
                if (hit != null && Requested != null) Requested(hit.Action);
                return true;
            }
            return base.ProcessCmdKey(ref msg, keyData);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                tips.Dispose(); title.Dispose(); label.Dispose(); strong.Dispose(); body.Dispose();
                smallStrong.Dispose(); small.Dispose(); badge.Dispose(); letter.Dispose(); mono.Dispose(); monoSmall.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    // ------------------------------------------------------------ Windows

    static class Native
    {
        public const int WM_NULL = 0x0000;
        public const int WM_CONTEXTMENU = 0x007B;
        public const int WM_COMMAND = 0x0111;
        public const int NIN_SELECT = 0x0400;
        public const int NIN_KEYSELECT = 0x0401;
        public const int NIN_BALLOONUSERCLICK = 0x0405;
        public const int NIM_ADD = 0;
        public const int NIM_MODIFY = 1;
        public const int NIM_DELETE = 2;
        public const int NIM_SETFOCUS = 3;
        public const int NIM_SETVERSION = 4;
        public const int NIF_MESSAGE = 0x01;
        public const int NIF_ICON = 0x02;
        public const int NIF_TIP = 0x04;
        public const int NIF_INFO = 0x10;
        public const int NIF_SHOWTIP = 0x80;
        public const int NIIF_INFO = 0x01;
        public const int NIIF_WARNING = 0x02;
        public const int NOTIFYICON_VERSION_4 = 4;
        public const int MF_STRING = 0x0000;
        public const int MF_GRAYED = 0x0001;
        public const int MF_CHECKED = 0x0008;
        public const int MF_SEPARATOR = 0x0800;
        public const int TPM_LEFTALIGN = 0x0000;
        public const int TPM_RIGHTBUTTON = 0x0002;
        public const int TPM_RIGHTALIGN = 0x0008;
        public const int TPM_RETURNCMD = 0x0100;
        public const int SM_MENUDROPALIGNMENT = 40;
        public const int SM_CXSMICON = 49;
        public const int SW_RESTORE = 9;
        public const int ASFW_ANY = -1;
        public const uint MSGFLT_ALLOW = 1;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct NOTIFYICONDATA
        {
            public int cbSize;
            public IntPtr hWnd;
            public int uID;
            public int uFlags;
            public int uCallbackMessage;
            public IntPtr hIcon;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szTip;
            public int dwState;
            public int dwStateMask;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szInfo;
            public int uVersion;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string szInfoTitle;
            public int dwInfoFlags;
            public Guid guidItem;
            public IntPtr hBalloonIcon;
        }

        public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)] public static extern bool Shell_NotifyIcon(int message, ref NOTIFYICONDATA data);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int RegisterWindowMessage(string name);
        [DllImport("user32.dll")] public static extern bool ChangeWindowMessageFilterEx(IntPtr hWnd, int message, uint action, IntPtr filter);
        [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
        [DllImport("user32.dll")] public static extern int GetSystemMetrics(int index);
        [DllImport("user32.dll")] public static extern bool DestroyIcon(IntPtr icon);
        [DllImport("user32.dll")] public static extern IntPtr CreatePopupMenu();
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern bool AppendMenu(IntPtr menu, int flags, IntPtr id, string text);
        [DllImport("user32.dll")] public static extern bool SetMenuDefaultItem(IntPtr menu, int item, int byPosition);
        // With TPM_RETURNCMD it returns the chosen item, or 0 when the menu was closed without a choice.
        [DllImport("user32.dll")] public static extern int TrackPopupMenuEx(IntPtr menu, int flags, int x, int y, IntPtr hWnd, IntPtr options);
        [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")] public static extern bool DestroyMenu(IntPtr menu);
        [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
        [DllImport("user32.dll")] public static extern bool AllowSetForegroundWindow(int processId);
        [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr hWnd, int message, IntPtr wParam, IntPtr lParam);
        [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc callback, IntPtr lParam);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int max);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetClassName(IntPtr hWnd, StringBuilder text, int max);
        [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
        [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr hWnd);
        [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int command);
        [DllImport("user32.dll")] static extern bool SetProcessDpiAwarenessContext(IntPtr context);
        [DllImport("user32.dll")] static extern IntPtr MonitorFromPoint(Point point, int flags);
        [DllImport("shcore.dll")] static extern int GetDpiForMonitor(IntPtr monitor, int type, out uint x, out uint y);
        [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr window, int attribute, ref int value, int size);

        public static void EnableDpi()
        {
            try { if (SetProcessDpiAwarenessContext(new IntPtr(-4))) return; }
            catch (EntryPointNotFoundException) { }
            SetProcessDPIAware();
        }

        public static float ScaleAt(Point point)
        {
            try
            {
                uint x, y;
                if (GetDpiForMonitor(MonitorFromPoint(point, 2), 0, out x, out y) == 0) return x / 96f;
            }
            catch (EntryPointNotFoundException) { }
            catch (DllNotFoundException) { }
            using (Graphics graphics = Graphics.FromHwnd(IntPtr.Zero)) return graphics.DpiX / 96f;
        }

        // Dark, rounded, with a 1 px edge in this color. True when Windows took
        // the corners and the edge (Windows 11); otherwise the flyout paints its own edge.
        public static bool FlyoutStyle(IntPtr window, Color edge)
        {
            try
            {
                int dark = 1, corners = 2, backdrop = 3;
                int border = edge.R | (edge.G << 8) | (edge.B << 16);
                DwmSetWindowAttribute(window, 20, ref dark, 4);
                DwmSetWindowAttribute(window, 38, ref backdrop, 4);
                return DwmSetWindowAttribute(window, 33, ref corners, 4) == 0 &&
                    DwmSetWindowAttribute(window, 34, ref border, 4) == 0;
            }
            catch (EntryPointNotFoundException) { return false; }
            catch (DllNotFoundException) { return false; }
        }
    }

    // The hidden window that owns the icon and hears its clicks.
    sealed class TrayWindow : NativeWindow
    {
        public const int CallbackMessage = 0x8001; // WM_APP + 1
        readonly int taskbarCreated;
        public Action Selected;
        public Action<int, int> MenuRequested;
        public Action TaskbarRestarted;
        public Action BalloonClicked;
        public Action<int> Command;

        public TrayWindow(string caption)
        {
            taskbarCreated = Native.RegisterWindowMessage("TaskbarCreated");
            CreateParams parameters = new CreateParams();
            parameters.Caption = caption;
            // Hidden and top-level: only top-level windows hear that the taskbar restarted.
            CreateHandle(parameters);
            // Harmless as the normal user; lets Explorer's message through if this ever runs elevated.
            Native.ChangeWindowMessageFilterEx(Handle, taskbarCreated, Native.MSGFLT_ALLOW, IntPtr.Zero);
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == CallbackMessage)
            {
                // NOTIFYICON_VERSION_4: the event is in the low word of lParam,
                // the menu position in wParam.
                int notification = (int)((long)m.LParam & 0xFFFF);
                long anchor = (long)m.WParam;
                if (notification == Native.NIN_SELECT || notification == Native.NIN_KEYSELECT)
                {
                    if (Selected != null) Selected();
                }
                else if (notification == Native.WM_CONTEXTMENU)
                {
                    if (MenuRequested != null) MenuRequested((short)(anchor & 0xFFFF), (short)((anchor >> 16) & 0xFFFF));
                }
                else if (notification == Native.NIN_BALLOONUSERCLICK)
                {
                    if (BalloonClicked != null) BalloonClicked();
                }
                return;
            }
            if (taskbarCreated != 0 && m.Msg == taskbarCreated)
            {
                if (TaskbarRestarted != null) TaskbarRestarted();
                return;
            }
            // The menu returns its choice directly; WM_COMMAND with the same item
            // numbers lets a script choose one too, the way the menu would.
            if (m.Msg == Native.WM_COMMAND)
            {
                if (Command != null) Command((int)((long)m.WParam & 0xFFFF));
                return;
            }
            base.WndProc(ref m);
        }
    }

    // The icon in the taskbar corner.
    sealed class TrayIcon
    {
        // Windows keeps an icon's taskbar settings by program and this number;
        // under tray.ps1, the number keeps it apart from other PowerShell icons.
        const int IconId = 0x4E53;
        readonly TrayWindow window;
        IntPtr picture = IntPtr.Zero;
        string tip = "Net Switch";
        bool added;

        public TrayIcon(TrayWindow window)
        {
            this.window = window;
        }

        // Shows this picture and tooltip, adding the icon when it isn't in the
        // taskbar yet (or any more). Takes ownership of newPicture; Zero keeps the
        // current picture.
        public void Show(IntPtr newPicture, string newTip)
        {
            IntPtr old = IntPtr.Zero;
            if (newPicture != IntPtr.Zero)
            {
                old = picture;
                picture = newPicture;
            }
            bool changed = newPicture != IntPtr.Zero || newTip != tip;
            tip = newTip;
            if (!added)
            {
                Add();
            }
            else if (changed)
            {
                Native.NOTIFYICONDATA data = Data(Native.NIF_ICON | Native.NIF_TIP | Native.NIF_SHOWTIP);
                // A failure means the taskbar lost the icon; the next reading adds it again.
                if (!Native.Shell_NotifyIcon(Native.NIM_MODIFY, ref data)) added = false;
            }
            if (old != IntPtr.Zero) Native.DestroyIcon(old);
        }

        // Explorer restarted, and with it the taskbar: every icon must be added again.
        public void Restore()
        {
            added = false;
            Add();
        }

        // Returns the keyboard to the taskbar corner, where the person was before the menu.
        public void ReturnFocus()
        {
            if (!added) return;
            Native.NOTIFYICONDATA data = Data(0);
            Native.Shell_NotifyIcon(Native.NIM_SETFOCUS, ref data);
        }

        public void Balloon(string title, string text)
        {
            Balloon(title, text, true);
        }

        // A notification from the icon; Windows 10 and 11 show it as a toast. False when it couldn't be shown.
        public bool Balloon(string title, string text, bool warning)
        {
            if (!added) return false;
            Native.NOTIFYICONDATA data = Data(Native.NIF_INFO);
            data.szInfoTitle = title;
            data.szInfo = text;
            data.dwInfoFlags = warning ? Native.NIIF_WARNING : Native.NIIF_INFO;
            return Native.Shell_NotifyIcon(Native.NIM_MODIFY, ref data);
        }

        public void Remove()
        {
            if (added)
            {
                Native.NOTIFYICONDATA data = Data(0);
                Native.Shell_NotifyIcon(Native.NIM_DELETE, ref data);
                added = false;
            }
            if (picture != IntPtr.Zero)
            {
                Native.DestroyIcon(picture);
                picture = IntPtr.Zero;
            }
        }

        void Add()
        {
            Native.NOTIFYICONDATA data = Data(Native.NIF_MESSAGE | Native.NIF_ICON | Native.NIF_TIP | Native.NIF_SHOWTIP);
            added = Native.Shell_NotifyIcon(Native.NIM_ADD, ref data) || Native.Shell_NotifyIcon(Native.NIM_MODIFY, ref data);
            if (!added) return;
            data.uVersion = Native.NOTIFYICON_VERSION_4;
            Native.Shell_NotifyIcon(Native.NIM_SETVERSION, ref data);
        }

        Native.NOTIFYICONDATA Data(int flags)
        {
            Native.NOTIFYICONDATA data = new Native.NOTIFYICONDATA();
            data.cbSize = Marshal.SizeOf(typeof(Native.NOTIFYICONDATA));
            data.hWnd = window.Handle;
            data.uID = IconId;
            data.uFlags = flags;
            data.uCallbackMessage = TrayWindow.CallbackMessage;
            data.hIcon = picture;
            data.szTip = tip;
            data.szInfo = "";
            data.szInfoTitle = "";
            return data;
        }
    }

    // ------------------------------------------------------------ the tray

    public sealed class Tray
    {
        const int PollMs = 1000;
        const int RequestTimeoutMs = 2500;
        // Readings that can fail in a row, while Net Switch's process is still there,
        // before the tray says it isn't responding.
        const int FailureLimit = 3;
        // Net Switch answers a quit only once routing has stopped, which can wait
        // behind a start that is under way (up to about 15 seconds) and then take
        // up to about 8 seconds more, so the request gets its own, longer wait.
        const int QuitRequestTimeoutMs = 35000;
        // After that, the server file has this long to go away.
        const int QuitDeadlineMs = 45000;
        // A double-click must not open two windows.
        const int OpenDebounceMs = 1500;
        const int MaxLogBytes = 512 * 1024;
        const int MenuOpen = 1;
        const int MenuQuit = 2;
        const int MenuRemove = 3;
        const int MenuUpdate = 4;
        const int MenuNotifications = 5;

        sealed class Server
        {
            public int Port;
            public string Token;
            public int Pid;
            // "proxy" for test mode (node server.mjs --dev-proxy), else "tun".
            public string Mode;
        }

        enum FileState { Missing, Unreadable, Ok }

        readonly string root;
        readonly string serverFile;
        readonly string settingsFile;
        readonly string logFile;
        // Whether this icon watches the folder launch.ps1 uses, so running the
        // launcher starts the Net Switch it watches. False for test mode.
        readonly bool canLaunch;
        readonly TrayWindow window;
        readonly TrayIcon icon;
        readonly HttpClient http;
        readonly HttpClient quitHttp;
        readonly HttpClient actionHttp;
        readonly FlyoutForm flyout;
        readonly JavaScriptSerializer json = new JavaScriptSerializer();
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();
        readonly EventNotifier notifier = new EventNotifier();
        readonly TraySettings settings;
        readonly int iconSize;

        // What data/server.json said last.
        Server server;
        TrayView view = TrayModel.Waiting();
        string iconSignature;
        bool polling;
        bool reachable;
        bool quitting;
        bool exiting;
        int failures;
        int missing;
        DateTime quitStarted;
        DateTime lastOpen = DateTime.MinValue;
        DateTime lastToggle = DateTime.MinValue;
        string pendingAction;
        string actionError;
        bool actionSending;
        int actionVersion;
        // A newer release from the last reading: { version, installer link }, or null.
        string[] update;

        Tray(string root, string dataDir, string logFile, bool canLaunch)
        {
            this.root = root;
            this.logFile = logFile;
            this.canLaunch = canLaunch;
            serverFile = Path.Combine(dataDir, "server.json");
            settingsFile = Path.Combine(dataDir, "tray-settings.json");
            settings = TraySettings.Load(settingsFile);
            window = new TrayWindow("Net Switch tray (" + Path.GetFileName(dataDir) + ")");
            icon = new TrayIcon(window);
            HttpClientHandler handler = new HttpClientHandler();
            // Only ever talks to 127.0.0.1, which must never go through a proxy.
            handler.UseProxy = false;
            http = new HttpClient(handler);
            http.Timeout = TimeSpan.FromMilliseconds(RequestTimeoutMs);
            HttpClientHandler quitHandler = new HttpClientHandler();
            quitHandler.UseProxy = false;
            quitHttp = new HttpClient(quitHandler);
            quitHttp.Timeout = TimeSpan.FromMilliseconds(QuitRequestTimeoutMs);
            HttpClientHandler actionHandler = new HttpClientHandler();
            actionHandler.UseProxy = false;
            actionHttp = new HttpClient(actionHandler);
            // Starting routing can take longer than a state reading.
            actionHttp.Timeout = TimeSpan.FromMilliseconds(QuitRequestTimeoutMs);
            flyout = new FlyoutForm();
            flyout.Requested = delegate (FlyoutAction action) { Guard(delegate { FlyoutRequested(action); }); };
            iconSize = Math.Max(16, Native.GetSystemMetrics(Native.SM_CXSMICON));
            window.Selected = delegate { Guard(ToggleFlyout); };
            window.MenuRequested = delegate (int x, int y) { Guard(delegate { ShowMenu(x, y); }); };
            window.TaskbarRestarted = delegate { Guard(icon.Restore); };
            // A click on a notification opens Net Switch, where the lines are.
            window.BalloonClicked = delegate { Guard(OpenFromClick); };
            window.Command = delegate (int id) { Guard(delegate { OnCommand(id); }); };
        }

        // Called by NetSwitchTray.exe (lib\tray-main.cs) or tray.ps1; returns once the icon is gone.
        public static void Run(string root, string dataDir, string logFile)
        {
            Run(root, dataDir, logFile, true);
        }

        public static void Run(string root, string dataDir, string logFile, bool canLaunch)
        {
            // Before any window exists: crisp icon and menu at any display scale.
            Native.EnableDpi();
            try
            {
                Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            }
            catch (InvalidOperationException)
            {
            }
            SynchronizationContext.SetSynchronizationContext(new WindowsFormsSynchronizationContext());
            Tray tray = new Tray(root, dataDir, logFile, canLaunch);
            Application.ThreadException += delegate (object sender, ThreadExceptionEventArgs e) { tray.Log("unexpected error: " + e.Exception); };
            AppDomain.CurrentDomain.UnhandledException += delegate (object sender, UnhandledExceptionEventArgs e) { tray.Log("unexpected error: " + e.ExceptionObject); };
            tray.Start();
            Application.Run();
            tray.http.Dispose();
            tray.quitHttp.Dispose();
            tray.actionHttp.Dispose();
            tray.flyout.Dispose();
            tray.timer.Dispose();
            tray.window.DestroyHandle();
            tray.Log("stopped");
        }

        void Start()
        {
            TrimLog();
            Log("started");
            Render(view);
            timer.Interval = PollMs;
            timer.Tick += delegate { Poll(); };
            timer.Start();
            Poll();
        }

        void Guard(Action action)
        {
            try
            {
                action();
            }
            catch (Exception error)
            {
                Log("unexpected error: " + error);
            }
        }

        // ------------------------------------------------------------ readings

        async void Poll()
        {
            if (polling || exiting) return;
            polling = true;
            try
            {
                int pollVersion = actionVersion;
                bool canFinishAction = !actionSending;
                Server current;
                FileState file = ReadServerFile(out current);
                if (file == FileState.Missing)
                {
                    flyout.SetView(FlyoutModel.Unavailable("Net Switch isn’t running."));
                    // Net Switch deletes the file when it quits. It must be gone on two
                    // readings in a row, so a restart that rewrites it isn't taken for a quit.
                    missing += 1;
                    if (missing >= 2)
                    {
                        Log(quitting ? "Net Switch quit" : "Net Switch is no longer running");
                        Exit();
                    }
                    return;
                }
                missing = 0;
                // A half-written file keeps the last good one; the port and key can change on a restart.
                if (file == FileState.Ok)
                {
                    if (server != null && server.Token != current.Token) Log("Net Switch restarted");
                    server = current;
                }

                IDictionary<string, object> state = server == null ? null : await FetchState(server);
                if (exiting) return;
                failures = state != null ? 0 : failures + 1;

                if (quitting)
                {
                    if ((DateTime.UtcNow - quitStarted).TotalMilliseconds <= QuitDeadlineMs) return;
                    quitting = false;
                    Log("Net Switch didn't quit within " + (QuitDeadlineMs / 1000) + " seconds");
                    actionError = "Net Switch didn’t quit. Open it and try again.";
                    flyout.Feedback(pendingAction, actionError, false);
                    icon.Balloon("Net Switch didn’t quit", "Open Net Switch and press Quit Net Switch there.");
                }
                if (state != null)
                {
                    reachable = true;
                    update = TrayModel.UpdateOffer(state);
                    Render(TrayModel.FromState(state));
                    flyout.SetView(FlyoutModel.FromState(state));
                    // An older in-flight poll must not clear feedback for a new action.
                    if (canFinishAction && !actionSending && pollVersion == actionVersion) pendingAction = null;
                    flyout.Feedback(pendingAction, actionError, quitting);
                    notifier.Read(EventNotifier.FromState(state), settings.LineNotifications);
                    Notify(notifier.Next(DateTime.UtcNow));
                    return;
                }
                flyout.SetView(FlyoutModel.Unavailable("Net Switch isn’t responding. Open it to reconnect."));
                // A process that is gone can't answer again, so the tray says so at
                // once; one that is still there may only be busy for a moment.
                bool running = ProcessIsRunning(server);
                if (!running || failures >= FailureLimit)
                {
                    reachable = false;
                    Render(TrayModel.Unreachable(running));
                }
                else
                {
                    // Unchanged, but shows the icon if the taskbar wasn't ready before.
                    Render(view);
                }
            }
            catch (Exception error)
            {
                Log("reading failed: " + error.Message);
                flyout.SetView(FlyoutModel.Unavailable("Couldn’t read Net Switch. Open it to reconnect."));
            }
            finally
            {
                polling = false;
            }
        }

        // A line event as a notification. The log keeps it too, so a missed one can be found.
        void Notify(Notice notice)
        {
            if (notice == null) return;
            bool shown = icon.Balloon(notice.Title, notice.Text, notice.Warning);
            Log((shown ? "notified: " : "could not notify: ") + notice.Text);
        }

        FileState ReadServerFile(out Server read)
        {
            read = null;
            string text;
            try
            {
                text = File.ReadAllText(serverFile);
            }
            catch (FileNotFoundException)
            {
                return FileState.Missing;
            }
            catch (DirectoryNotFoundException)
            {
                return FileState.Missing;
            }
            catch (Exception)
            {
                // Busy while Net Switch writes it.
                return FileState.Unreadable;
            }
            try
            {
                IDictionary<string, object> saved = json.DeserializeObject(text) as IDictionary<string, object>;
                if (saved == null) return FileState.Unreadable;
                Server parsed = new Server();
                parsed.Port = Convert.ToInt32(saved["port"], CultureInfo.InvariantCulture);
                parsed.Token = saved["token"] as string;
                object pid;
                parsed.Pid = saved.TryGetValue("pid", out pid) && pid != null ? Convert.ToInt32(pid, CultureInfo.InvariantCulture) : 0;
                object mode;
                parsed.Mode = saved.TryGetValue("mode", out mode) ? mode as string : null;
                if (parsed.Port <= 0 || string.IsNullOrEmpty(parsed.Token)) return FileState.Unreadable;
                read = parsed;
                return FileState.Ok;
            }
            catch (Exception)
            {
                // Half written.
                return FileState.Unreadable;
            }
        }

        async Task<IDictionary<string, object>> FetchState(Server target)
        {
            return await FetchState(target, true);
        }

        async Task<IDictionary<string, object>> FetchState(Server target, bool retry)
        {
            try
            {
                using (HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, Url(target, "/api/state")))
                {
                    request.Headers.Add("X-Token", target.Token);
                    using (HttpResponseMessage response = await http.SendAsync(request))
                    {
                        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized && retry)
                        {
                            Server fresh;
                            if (ReadServerFile(out fresh) == FileState.Ok)
                            {
                                server = fresh;
                                return await FetchState(fresh, false);
                            }
                        }
                        if (!response.IsSuccessStatusCode) return null;
                        string body = await response.Content.ReadAsStringAsync();
                        return json.DeserializeObject(body) as IDictionary<string, object>;
                    }
                }
            }
            catch (Exception)
            {
                // Not answering, too slow, or not JSON.
                return null;
            }
        }

        // Tells "stopped" apart from "stuck". The process list is readable even for
        // a process running as administrator; its handle wouldn't be.
        static bool ProcessIsRunning(Server target)
        {
            if (target == null || target.Pid <= 0) return false;
            try
            {
                using (Process process = Process.GetProcessById(target.Pid))
                {
                    return process.ProcessName.Equals("node", StringComparison.OrdinalIgnoreCase);
                }
            }
            catch (Exception)
            {
                return false;
            }
        }

        void Render(TrayView next)
        {
            view = next;
            string signature = TrayModel.IconSignature(next);
            IntPtr picture = IntPtr.Zero;
            if (signature != iconSignature)
            {
                using (Bitmap bitmap = TrayPainter.Paint(next, iconSize))
                {
                    picture = bitmap.GetHicon();
                }
                iconSignature = signature;
            }
            icon.Show(picture, TrayModel.Tooltip(next));
        }

        // Net Switch answered the last readings, so there is a window to bring back and something to quit.
        bool Answering()
        {
            return reachable;
        }

        // ------------------------------------------------------------ actions

        void ToggleFlyout()
        {
            if (exiting) return;
            DateTime now = DateTime.UtcNow;
            if ((now - lastToggle).TotalMilliseconds < SystemInformation.DoubleClickTime) return;
            lastToggle = now;
            if (flyout.Visible) { flyout.Hide(); return; }
            // Clicking the icon first deactivates the flyout, then delivers the
            // tray notification. That same click should close it, not reopen it.
            Point point = Cursor.Position;
            Point dismissedPoint = flyout.DismissedPoint;
            if ((now - flyout.DismissedAt).TotalMilliseconds < 500 &&
                Math.Abs(point.X - dismissedPoint.X) < 4 && Math.Abs(point.Y - dismissedPoint.Y) < 4) return;
            flyout.ShowAtCursor();
        }

        void FlyoutRequested(FlyoutAction action)
        {
            // The window has what the flyout leaves out: every line, every app,
            // and the choice of line when there are too many for the flyout.
            if (action.Key == "open" || action.Key == "all" || action.Key == "more" || action.Key.StartsWith("change:", StringComparison.Ordinal))
            {
                flyout.Hide();
                OpenFromClick();
            }
            else if (action.Key == "quit") Quit();
            else ChangeFromFlyout(action);
        }

        async void ChangeFromFlyout(FlyoutAction action)
        {
            if (pendingAction != null || quitting || exiting || server == null) return;
            pendingAction = action.Key;
            actionError = null;
            actionSending = true;
            actionVersion++;
            flyout.Feedback(pendingAction, null, false);
            string failure = null;
            try
            {
                failure = await PostAction(server, action, true);
            }
            catch (TaskCanceledException)
            {
                failure = "No answer yet. Check the current state before trying again.";
            }
            catch (Exception error)
            {
                failure = "Couldn’t reach Net Switch. Open it to reconnect.";
                Log("flyout " + action.Endpoint + " failed: " + error.Message);
            }
            finally
            {
                actionSending = false;
            }
            if (exiting) return;
            if (failure != null)
            {
                pendingAction = null;
                actionError = failure;
                Log("flyout " + action.Endpoint + ": " + failure);
            }
            flyout.Feedback(pendingAction, actionError, quitting);
            Poll();
        }

        async Task<string> PostAction(Server target, FlyoutAction action, bool retry)
        {
            using (HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, Url(target, action.Endpoint)))
            {
                request.Headers.Add("X-Token", target.Token);
                request.Content = new StringContent(json.Serialize(action.Body), Encoding.UTF8, "application/json");
                using (HttpResponseMessage response = await actionHttp.SendAsync(request))
                {
                    if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized && retry)
                    {
                        Server fresh;
                        if (ReadServerFile(out fresh) == FileState.Ok)
                        {
                            server = fresh;
                            return await PostAction(fresh, action, false);
                        }
                    }
                    if (response.IsSuccessStatusCode) return null;
                    string body = await response.Content.ReadAsStringAsync();
                    try
                    {
                        string message = TrayModel.Text(json.DeserializeObject(body) as IDictionary<string, object>, "error");
                        if (!string.IsNullOrWhiteSpace(message)) return message.Replace('\r', ' ').Replace('\n', ' ');
                    }
                    catch (ArgumentException) { }
                    catch (InvalidOperationException) { }
                    return "Couldn’t apply that change (HTTP " + ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture) + ").";
                }
            }
        }

        void OpenFromClick()
        {
            if ((DateTime.UtcNow - lastOpen).TotalMilliseconds < OpenDebounceMs) return;
            Open();
        }

        // Brings back the window of the Net Switch this icon watches. While it
        // runs, that is its own window, or a new one on its own address. When it
        // isn't running, the icon of the normal setup starts it the way the
        // shortcut does; a test-mode icon never does, so it can't start real routing.
        void Open()
        {
            if (quitting || exiting) return;
            lastOpen = DateTime.UtcNow;
            Server current = server;
            if (Answering() && current != null)
            {
                IntPtr existing = FindCurrentWindow(current.Mode == "proxy" ? "Net Switch (test mode)" : "Net Switch");
                if (existing != IntPtr.Zero)
                {
                    if (Native.IsIconic(existing)) Native.ShowWindow(existing, Native.SW_RESTORE);
                    Native.SetForegroundWindow(existing);
                    return;
                }
                OpenServerWindow(current);
                return;
            }
            if (canLaunch)
            {
                RunLauncher();
                return;
            }
            Log("not opening: this icon watches test mode, which isn't running");
            icon.Balloon("Test mode isn’t running", "Start it with: node server.mjs --dev-proxy");
        }

        // A window on the running server, as launch.ps1 opens it: Chrome or Edge as
        // an app window, else the default browser.
        void OpenServerWindow(Server current)
        {
            string url = "http://127.0.0.1:" + current.Port.ToString(CultureInfo.InvariantCulture) + "/#token=" + current.Token;
            string browser = FindBrowser();
            ProcessStartInfo start = browser != null
                ? new ProcessStartInfo(browser, "--app=" + url + " --window-size=800,700")
                : new ProcessStartInfo(url);
            start.UseShellExecute = browser == null;
            // The click gave this process the right to bring a window forward; pass it on.
            Native.AllowSetForegroundWindow(Native.ASFW_ANY);
            try
            {
                Process started = Process.Start(start);
                if (started != null) started.Dispose();
            }
            catch (Exception error)
            {
                Log("could not open the Net Switch window: " + error.Message);
                icon.Balloon("Net Switch didn’t open", "Open it from the Start menu.");
            }
        }

        static string FindBrowser()
        {
            foreach (string name in new[] { "chrome.exe", "msedge.exe" })
            {
                foreach (RegistryKey hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
                {
                    using (RegistryKey key = hive.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\" + name))
                    {
                        string path = key == null ? null : key.GetValue(null) as string;
                        if (!string.IsNullOrEmpty(path) && File.Exists(path)) return path;
                    }
                }
            }
            return null;
        }

        // Windows from an earlier run of Net Switch, and the closed screen, have a
        // different title (ui/app.js), so only a current window is titled exactly this.
        static IntPtr FindCurrentWindow(string expectedTitle)
        {
            IntPtr found = IntPtr.Zero;
            StringBuilder title = new StringBuilder(64);
            StringBuilder kind = new StringBuilder(64);
            Native.EnumWindows(delegate (IntPtr hWnd, IntPtr unused)
            {
                if (!Native.IsWindowVisible(hWnd)) return true;
                title.Length = 0;
                Native.GetWindowText(hWnd, title, title.Capacity);
                if (title.ToString() != expectedTitle) return true;
                kind.Length = 0;
                Native.GetClassName(hWnd, kind, kind.Capacity);
                if (kind.ToString() != "Chrome_WidgetWin_1") return true;
                found = hWnd;
                return false;
            }, IntPtr.Zero);
            return found;
        }

        void RunLauncher()
        {
            string powershell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe");
            string launcher = Path.Combine(root, "launch.ps1");
            ProcessStartInfo start = new ProcessStartInfo(powershell, "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + launcher + "\"");
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            start.WorkingDirectory = root;
            // The click gave this process the right to bring a window forward; pass it on.
            Native.AllowSetForegroundWindow(Native.ASFW_ANY);
            try
            {
                Process.Start(start).Dispose();
            }
            catch (Exception error)
            {
                Log("could not open Net Switch: " + error.Message);
                icon.Balloon("Net Switch didn’t open", "Open it from the Net Switch shortcut on the desktop.");
            }
        }

        void ShowMenu(int x, int y)
        {
            if (exiting) return;
            flyout.Hide();
            int chosen = 0;
            IntPtr menu = Native.CreatePopupMenu();
            try
            {
                Native.AppendMenu(menu, quitting ? Native.MF_GRAYED : Native.MF_STRING, (IntPtr)MenuOpen, "Open Net Switch");
                Native.SetMenuDefaultItem(menu, MenuOpen, 0);
                if (update != null && reachable && !quitting)
                    Native.AppendMenu(menu, Native.MF_STRING, (IntPtr)MenuUpdate, "Download Net Switch " + update[0]);
                Native.AppendMenu(menu, Native.MF_SEPARATOR, IntPtr.Zero, null);
                Native.AppendMenu(menu, settings.LineNotifications ? Native.MF_CHECKED : Native.MF_STRING, (IntPtr)MenuNotifications, "Show line notifications");
                Native.AppendMenu(menu, Native.MF_SEPARATOR, IntPtr.Zero, null);
                if (quitting) Native.AppendMenu(menu, Native.MF_GRAYED, (IntPtr)MenuQuit, "Quitting…");
                else if (Answering()) Native.AppendMenu(menu, Native.MF_STRING, (IntPtr)MenuQuit, "Quit Net Switch");
                // Nothing left to quit: the icon itself can go.
                else Native.AppendMenu(menu, Native.MF_STRING, (IntPtr)MenuRemove, "Remove this icon");
                // Without this the menu stays open when the person clicks elsewhere.
                Native.SetForegroundWindow(window.Handle);
                int align = Native.GetSystemMetrics(Native.SM_MENUDROPALIGNMENT) != 0 ? Native.TPM_RIGHTALIGN : Native.TPM_LEFTALIGN;
                chosen = Native.TrackPopupMenuEx(menu, align | Native.TPM_RIGHTBUTTON | Native.TPM_RETURNCMD, x, y, window.Handle, IntPtr.Zero);
                Native.PostMessage(window.Handle, Native.WM_NULL, IntPtr.Zero, IntPtr.Zero);
            }
            finally
            {
                Native.DestroyMenu(menu);
            }
            if (chosen != 0)
            {
                OnCommand(chosen);
            }
            else if (Native.GetForegroundWindow() == window.Handle)
            {
                // Closed with Esc, so this window still has the keyboard: hand it back
                // to the taskbar corner. A click elsewhere has already moved it.
                icon.ReturnFocus();
            }
        }

        void OnCommand(int id)
        {
            if (id == MenuOpen) Open();
            else if (id == MenuQuit) Quit();
            else if (id == MenuRemove) Exit();
            else if (id == MenuUpdate) DownloadUpdate();
            else if (id == MenuNotifications) ToggleNotifications();
        }

        // Kept in tray-settings.json, so the choice holds after a restart.
        void ToggleNotifications()
        {
            settings.LineNotifications = !settings.LineNotifications;
            Log(settings.LineNotifications ? "line notifications turned on" : "line notifications turned off");
            try
            {
                settings.Save(settingsFile);
            }
            catch (Exception error)
            {
                Log("could not save the tray settings: " + error.Message);
            }
        }

        // The installer downloads in the person's own browser, as from the
        // releases page; running it updates this copy.
        void DownloadUpdate()
        {
            string[] offer = update;
            if (offer == null) return;
            try
            {
                ProcessStartInfo start = new ProcessStartInfo(offer[1]);
                start.UseShellExecute = true;
                Process started = Process.Start(start);
                if (started != null) started.Dispose();
                Log("opened the download of Net Switch " + offer[0]);
            }
            catch (Exception error)
            {
                Log("could not open the update download: " + error.Message);
                icon.Balloon("The download didn’t open", "Get Net Switch " + offer[0] + " from its GitHub releases page.");
            }
        }

        // Net Switch answers once routing has stopped, then removes its server
        // file; the icon says "quitting" until the file is gone.
        async void Quit()
        {
            if (quitting || exiting || server == null) return;
            TrayView before = view;
            quitting = true;
            flyout.Feedback(null, null, true);
            quitStarted = DateTime.UtcNow;
            Render(TrayModel.Quitting());
            bool? accepted = await PostQuit(server);
            if (accepted == false)
            {
                // Net Switch may have restarted with a new key since the last reading.
                Server fresh;
                if (ReadServerFile(out fresh) == FileState.Ok)
                {
                    server = fresh;
                    accepted = await PostQuit(fresh);
                }
            }
            // No answer in time may still be a quit under way: the deadline on the
            // server file decides, rather than saying it failed.
            if (accepted != false || exiting) return;
            quitting = false;
            Log("quit was not accepted");
            actionError = "Net Switch didn’t quit. Open it and try again.";
            flyout.Feedback(null, actionError, false);
            Render(before);
            icon.Balloon("Net Switch didn’t quit", "Open Net Switch and press Quit Net Switch there.");
        }

        // True when Net Switch quit, false when it refused or isn't there, null
        // when it didn't answer in time.
        async Task<bool?> PostQuit(Server target)
        {
            try
            {
                using (HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, Url(target, "/api/quit")))
                {
                    request.Headers.Add("X-Token", target.Token);
                    request.Content = new StringContent("{}", Encoding.UTF8, "application/json");
                    using (HttpResponseMessage response = await quitHttp.SendAsync(request))
                    {
                        return response.IsSuccessStatusCode;
                    }
                }
            }
            catch (TaskCanceledException)
            {
                return null;
            }
            catch (Exception)
            {
                return false;
            }
        }

        void Exit()
        {
            if (exiting) return;
            exiting = true;
            timer.Stop();
            flyout.Hide();
            icon.Remove();
            Application.ExitThread();
        }

        static string Url(Server target, string path)
        {
            return "http://127.0.0.1:" + target.Port.ToString(CultureInfo.InvariantCulture) + path;
        }

        // ------------------------------------------------------------ log

        void TrimLog()
        {
            try
            {
                if (new FileInfo(logFile).Length > MaxLogBytes) File.Delete(logFile);
            }
            catch (Exception)
            {
                // No log yet.
            }
        }

        void Log(string line)
        {
            try
            {
                File.AppendAllText(logFile, DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture) + " " + line + Environment.NewLine);
            }
            catch (Exception)
            {
                // Logging must never stop the tray.
            }
        }
    }
}

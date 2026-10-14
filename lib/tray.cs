// Net Switch's tray icon. tray.ps1 compiles this file with Add-Type in Windows
// PowerShell 5.1, so the C# stays at version 5, and runs it as the normal user.
// Once a second it reads the same /api/state the window reads: the icon shows
// both lines' load, the tooltip their speeds, and its menu opens or quits Net Switch.
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

    public enum LineState { NotSetUp, NotConnected, NoSpeed, Measured }

    // One line, the cable or the second connection, as the tray shows it.
    public sealed class LineView
    {
        public string Label;
        public LineState State;
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
        public LineView Cable;
        public LineView Second;
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
        const int MaxLabel = 18;

        // The window's top bar says the same (ui/app.js renderTopbar).
        static readonly Dictionary<string, string> Statuses = new Dictionary<string, string>
        {
            { "on", "Net Switch: routing is on" },
            { "starting", "Net Switch: starting routing\u2026" },
            { "stopping", "Net Switch: turning off routing\u2026" },
            { "off", "Net Switch: routing is off" },
            { "error", "Net Switch: routing stopped" },
        };

        public static TrayView FromState(IDictionary<string, object> state)
        {
            IDictionary<string, object> routing = Child(state, "routing");
            IDictionary<string, object> lanes = Child(state, "lanes");
            IDictionary<string, object> second = Child(lanes, "second");
            string status = Text(routing, "status") ?? "";
            string headline;
            if (!Statuses.TryGetValue(status, out headline)) headline = "Net Switch";
            if (Text(state, "mode") == "proxy") headline += " (test mode)";

            TrayView view = new TrayView();
            view.Status = headline;
            view.Routing = status == "on";
            view.Cable = Line(Child(lanes, "main"), "Cable");
            view.Second = second == null
                ? new LineView { Label = "Second connection", State = LineState.NotSetUp }
                : Line(second, "Second connection");
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
                Status = processRunning ? "Net Switch isn\u2019t responding" : "Net Switch isn\u2019t running",
                Hint = "Click for Open Net Switch.",
            };
        }

        public static TrayView Quitting()
        {
            return new TrayView { Status = "Net Switch is quitting\u2026" };
        }

        static LineView Line(IDictionary<string, object> lane, string fallbackLabel)
        {
            LineView line = new LineView();
            line.Label = Text(lane, "label") ?? fallbackLabel;
            IDictionary<string, object> rate = Child(lane, "rate");
            if (!Flag(lane, "connected"))
            {
                line.State = LineState.NotConnected;
            }
            else if (rate == null)
            {
                // Unknown, which is not the same as zero.
                line.State = LineState.NoSpeed;
            }
            else
            {
                line.State = LineState.Measured;
                line.Down = Number(rate, "down");
                line.Up = Number(rate, "up");
            }
            return line;
        }

        public static string Tooltip(TrayView view)
        {
            List<string> lines = new List<string>();
            lines.Add(view.Status);
            if (view.Hint != null) lines.Add(view.Hint);
            if (view.Cable != null) lines.Add(LineText(view.Cable));
            if (view.Second != null) lines.Add(LineText(view.Second));
            string text = string.Join("\n", lines);
            return text.Length <= MaxTip ? text : text.Substring(0, MaxTip - 1) + "\u2026";
        }

        public static string LineText(LineView line)
        {
            string label = Shorten(line.Label, MaxLabel);
            switch (line.State)
            {
                case LineState.NotSetUp: return label + ": not set up";
                case LineState.NotConnected: return label + ": not connected";
                case LineState.NoSpeed: return label + ": speed not available";
                default: return label + ": \u2193 " + Rate(line.Down) + "  \u2191 " + Rate(line.Up);
            }
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
            row.Available = line != null && (line.State == LineState.Measured || line.State == LineState.NoSpeed);
            row.Lit = line != null && line.State == LineState.Measured ? Lit(line.Down + line.Up) : 0;
            return row;
        }

        // The icon is redrawn only when this changes, not on every reading.
        public static string IconSignature(TrayView view)
        {
            IconRow cable = Row(view.Cable);
            IconRow second = Row(view.Second);
            return (view.Routing ? "on" : "off") + "|" + cable.Available + cable.Lit + "|" + second.Available + second.Lit;
        }

        static string Shorten(string text, int max)
        {
            text = (text ?? "").Trim();
            return text.Length <= max ? text : text.Substring(0, max - 1) + "\u2026";
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
        public string Name;
        public string Title;
        public string Detail;
        public string Speed;
        public string Problem;
        public bool Healthy;
        public bool Carrying;
        public double Down;
        public int Lit;
    }

    public sealed class FlyoutApp
    {
        public string Name;
        public string Path;
        public string Lane;
        public string Speed;
        public string Initial;
        public int ColorIndex;
        public bool CanMove;
        public bool CanSecond;
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
        public string MainOption;
        public string SecondOption;
        public string Health;
        public string HealthTone;
        public FlyoutLine Main;
        public FlyoutLine Second;
        public List<FlyoutApp> Apps = new List<FlyoutApp>();
    }

    // No window or network work here: older servers and missing measurements
    // take the same path in the flyout and in its tests.
    public static class FlyoutModel
    {
        public static FlyoutView Unavailable(string message)
        {
            return new FlyoutView { Message = message, Status = "Not connected", Tone = "dim" };
        }

        public static FlyoutView FromState(IDictionary<string, object> state)
        {
            if (state == null) return Unavailable("Net Switch isn\u2019t responding.");
            IDictionary<string, object> routing = TrayModel.Child(state, "routing");
            IDictionary<string, object> lanes = TrayModel.Child(state, "lanes");
            IDictionary<string, object> second = TrayModel.Child(lanes, "second");
            string status = TrayModel.Text(routing, "status") ?? "off";
            FlyoutView view = new FlyoutView();
            view.Available = true;
            view.RoutingWanted = OptionalFlag(routing, "wanted", status == "on");
            view.CanCombine = second != null;
            view.CombineOn = second != null && TrayModel.Flag(TrayModel.Child(state, "combine"), "on");
            view.MainOption = view.CombineOn ? "Both" : "Cable";
            view.SecondOption = ShortOption(second);
            view.Main = Line(TrayModel.Child(lanes, "main"), "Cable");
            view.Second = second == null ? null : Line(second, TrayModel.Text(second, "label") ?? "Second connection");
            view.TotalDown = view.Main.Down + (view.Second == null ? 0 : view.Second.Down);
            string headline = "Routing off";
            if (status == "on") headline = "Routing on";
            else if (status == "starting") headline = "Starting routing\u2026";
            else if (status == "stopping") headline = "Turning routing off\u2026";
            else if (status == "error") headline = "Routing stopped";
            view.Status = headline + " \u00b7 " + TrayModel.Rate(view.TotalDown);
            view.Tone = status == "on" ? "ok" : status == "error" ? "error" : "dim";
            Health(view, status);

            object raw;
            IEnumerable apps = state.TryGetValue("apps", out raw) ? raw as IEnumerable : null;
            if (apps != null)
            {
                foreach (object item in apps)
                {
                    IDictionary<string, object> app = item as IDictionary<string, object>;
                    if (app == null) continue;
                    IDictionary<string, object> rate = TrayModel.Child(app, "rate");
                    FlyoutApp row = new FlyoutApp();
                    row.Name = TrayModel.Text(app, "name") ?? "App";
                    if (string.IsNullOrWhiteSpace(row.Name)) row.Name = "App";
                    row.Path = TrayModel.Text(app, "path") ?? "";
                    row.Lane = TrayModel.Text(app, "lane") == "second" ? "second" : "main";
                    row.Speed = TrayModel.Rate(TrayModel.Number(rate, "down"));
                    row.Score = TrayModel.Number(app, "sortScore");
                    row.HasTraffic = TrayModel.Number(rate, "down") + TrayModel.Number(rate, "up") > 0;
                    row.CanMove = OptionalFlag(app, "switchable", true) && row.Path.Length > 0;
                    row.CanSecond = row.CanMove && second != null;
                    row.Initial = StringInfo.GetNextTextElement(row.Name.Trim()).ToUpperInvariant();
                    uint hash = 0;
                    foreach (char letter in row.Name) hash = unchecked(hash * 31 + letter);
                    row.ColorIndex = (int)(hash % 6);
                    view.Apps.Add(row);
                }
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

        static string ShortOption(IDictionary<string, object> second)
        {
            string kind = (TrayModel.Text(second, "kind") ?? "").ToLowerInvariant();
            string label = TrayModel.Text(second, "label") ?? "Wi-Fi";
            if (kind == "wifi" || label.IndexOf("wi-fi", StringComparison.OrdinalIgnoreCase) >= 0) return "Wi-Fi";
            if (kind == "phone" || kind == "tether" || label.IndexOf("phone", StringComparison.OrdinalIgnoreCase) >= 0) return "Phone";
            return label.Length <= 8 ? label : label.Substring(0, 7) + "\u2026";
        }

        static FlyoutLine Line(IDictionary<string, object> lane, string name)
        {
            FlyoutLine line = new FlyoutLine();
            line.Name = name;
            line.Title = name;
            object ping;
            if (lane != null && lane.TryGetValue("ping", out ping) && ping != null && !(ping is string) && !(ping is bool))
                line.Title += " \u00b7 " + TrayModel.Number(lane, "ping").ToString("0", CultureInfo.InvariantCulture) + " ms";
            string alias = TrayModel.Text(lane, "alias") ?? "";
            string ssid = TrayModel.Text(lane, "ssid") ?? "";
            line.Detail = alias + (ssid.Length > 0 ? (alias.Length > 0 ? " \u00b7 " : "") + ssid : "");
            line.Problem = TrayModel.Text(lane, "problem");
            if (string.IsNullOrEmpty(line.Problem) && !TrayModel.Flag(lane, "connected")) line.Problem = "not connected";
            line.Healthy = string.IsNullOrEmpty(line.Problem);
            line.Carrying = OptionalFlag(lane, "carryingApps", line.Healthy);
            IDictionary<string, object> rate = TrayModel.Child(lane, "rate");
            line.Down = TrayModel.Number(rate, "down");
            line.Speed = !line.Healthy ? line.Problem : rate == null ? "Not measured" : TrayModel.Rate(line.Down);
            line.Lit = line.Healthy ? Lit(line.Down) : 0;
            return line;
        }

        public static int Lit(double down)
        {
            if (!(down >= 1) || double.IsInfinity(down)) return 0;
            double level = Math.Log10(down / 1024) / Math.Log10(10 * 1024);
            return Math.Max(1, Math.Min(24, (int)Math.Round(level * 24, MidpointRounding.AwayFromZero)));
        }

        static void Health(FlyoutView view, string status)
        {
            view.HealthTone = "dim";
            if (status != "on")
            {
                view.Health = status == "starting" ? "Routing is starting\u2026" : status == "stopping" ? "Routing is turning off\u2026" :
                    status == "error" ? "Routing stopped \u00b7 apps use Windows' connection" : "Routing is off \u00b7 apps use Windows' connection";
                if (status == "error") view.HealthTone = "error";
                return;
            }
            FlyoutLine main = view.Main;
            FlyoutLine second = view.Second;
            view.HealthTone = "warning";
            if (!main.Healthy && second != null && !second.Healthy)
                view.Health = "Cable: " + main.Problem + " \u00b7 " + second.Name + ": " + second.Problem;
            else if (!main.Healthy)
                view.Health = "Cable: " + main.Problem + (second != null && second.Carrying && !main.Carrying ? " \u00b7 apps use the " + second.Name : "");
            else if (second != null && !second.Healthy)
                view.Health = second.Name + ": " + second.Problem + (main.Carrying && !second.Carrying ? " \u00b7 its apps use the cable" : "");
            else if (!main.Carrying && second != null && second.Carrying)
                view.Health = "Cable is recovering \u00b7 apps use the " + second.Name;
            else if (second != null && !second.Carrying && main.Carrying)
                view.Health = second.Name + " is recovering \u00b7 its apps use the cable";
            else
            {
                view.HealthTone = "ok";
                view.Health = second == null ? "Cable reaches the internet" : "Both lines reach the internet";
            }
        }
    }

    // ------------------------------------------------------------ the picture

    public static class TrayPainter
    {
        // The window's colors (ui/favicon.svg).
        static readonly Color Panel = Color.FromArgb(0x14, 0x16, 0x19);
        static readonly Color Amber = Color.FromArgb(0xf0, 0xb2, 0x3e);
        static readonly Color Cyan = Color.FromArgb(0x4c, 0xc3, 0xe8);
        static readonly Color Gray = Color.FromArgb(0xa8, 0xad, 0xb3);

        // Two rows of cells on the dark panel, like the favicon's two bars: the
        // cable on top in amber, the second connection below in cyan. While
        // routing isn't on the colors give way to gray; a line that isn't there
        // stays faint. Every pixel is either fully drawn or fully clear, so the
        // icon stays crisp at its real size.
        public static Bitmap Paint(TrayView view, int size)
        {
            Bitmap bitmap = new Bitmap(size, size, PixelFormat.Format32bppArgb);
            using (Graphics g = Graphics.FromImage(bitmap))
            {
                using (SolidBrush panel = new SolidBrush(Panel))
                {
                    g.FillRectangle(panel, 0, 0, size, size);
                }
                int cell = Math.Max(2, size / 8);
                int gap = Math.Max(1, size / 16);
                int height = Math.Max(3, size / 4);
                int left = (size - (TrayModel.Cells * cell + (TrayModel.Cells - 1) * gap)) / 2;
                int top = (size - (2 * height + 2 * gap)) / 2;
                DrawRow(g, TrayModel.Row(view.Cable), view.Routing ? Amber : Gray, left, top, cell, gap, height);
                DrawRow(g, TrayModel.Row(view.Second), view.Routing ? Cyan : Gray, left, top + height + 2 * gap, cell, gap, height);
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
        // A line's name row, the gap under it, and its meter.
        const int LineHeight = 16 + 7 + 6;
        const int AppsHeadHeight = 18;
        const int RowHeight = 39;
        const int RowGap = 2;
        const int UnavailableHeight = 84;
        static readonly Color Background = Color.FromArgb(32, 32, 32);
        static readonly Color Card = Color.FromArgb(43, 43, 43);
        static readonly Color Stroke = Color.FromArgb(58, 58, 58);
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
        static readonly Color Amber = Color.FromArgb(245, 177, 61);
        static readonly Color Cyan = Color.FromArgb(60, 200, 234);
        static readonly Color Green = Color.FromArgb(108, 203, 95);
        static readonly Color Warning = Color.FromArgb(242, 178, 77);
        static readonly Color Red = Color.FromArgb(242, 109, 109);
        // Solid tiles under a dark letter; the first three are the design's.
        static readonly Color[] Avatars =
        {
            Color.FromArgb(61, 220, 132), Color.FromArgb(154, 164, 178), Color.FromArgb(255, 113, 57),
            Accent, Amber, Color.FromArgb(199, 161, 245),
        };

        sealed class Hit
        {
            public RectangleF Bounds;
            public FlyoutAction Action;
            public string Tip;
        }

        readonly List<Hit> hits = new List<Hit>();
        // Tooltips over things that can't be pressed, such as an app that can't move.
        readonly List<Hit> notes = new List<Hit>();
        readonly ToolTip tips = new ToolTip();
        // Segoe UI Variable has no Medium, so the design's 500 weight uses Regular.
        readonly Font title = MakeFont("Segoe UI Variable Text Semibold", "Segoe UI Semibold", 14, FontStyle.Regular);
        readonly Font label = MakeFont("Segoe UI Variable Text Semibold", "Segoe UI Semibold", 13, FontStyle.Regular);
        readonly Font strong = MakeFont("Segoe UI Variable Text Semibold", "Segoe UI Semibold", 12, FontStyle.Regular);
        readonly Font body = MakeFont("Segoe UI Variable Text", "Segoe UI", 12, FontStyle.Regular);
        readonly Font smallStrong = MakeFont("Segoe UI Variable Text Semibold", "Segoe UI Semibold", 11, FontStyle.Regular);
        readonly Font small = MakeFont("Segoe UI Variable Text", "Segoe UI", 11, FontStyle.Regular);
        readonly Font letter = MakeFont("Segoe UI Variable Text", "Segoe UI", 11, FontStyle.Bold);
        readonly Font mono = MakeFont("Cascadia Mono", "Consolas", 12, FontStyle.Regular);
        readonly Font monoSmall = MakeFont("Cascadia Mono", "Consolas", 11, FontStyle.Regular);
        FlyoutView view = FlyoutModel.Unavailable("Connecting to Net Switch\u2026");
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

        // The body is a vertical stack: header, toggles, lines card, apps head, app rows.
        int LinesHeight()
        {
            return 12 + LineHeight + (view.Second == null ? 0 : 10 + LineHeight) + 12;
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
            return tone == "ok" ? Green : tone == "error" ? Red : tone == "warning" ? Warning : Dim;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            Graphics g = e.Graphics;
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
                Tile(g, Pad + TileWidth + 8, "combine", "Both lines", view.CanCombine ? view.CombineOn ? "Combining" : "Off" : "Set up a second connection", view.CombineOn, view.CanCombine);
                Round(g, new RectangleF(Pad, LinesTop, Inner, LinesHeight()), 8, Card, Color.Transparent);
                Line(g, view.Main, LinesTop + 12, Amber);
                if (view.Second != null) Line(g, view.Second, LinesTop + 12 + LineHeight + 10, Cyan);
                AppsHead(g, AppsTop());
                int top = RowsTop();
                if (view.Apps.Count == 0) Caption(g, "No apps using the connection yet", body, Dim, Pad + 2, top + RowHeight / 2f, Inner - 4, StringAlignment.Near);
                for (int i = 0; i < view.Apps.Count; i++) AppRow(g, view.Apps[i], top + i * (RowHeight + RowGap));
            }
            Footer(g, ContentBottom());
            if (!windowEdge)
                using (Pen edge = new Pen(Edge, 1)) g.DrawRectangle(edge, 0.5f, 0.5f, WidthDip - 1, ClientSize.Height / scale - 1);
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

        // One line in the lines card: swatch, name and details, speed on the right, meter under them.
        void Line(Graphics g, FlyoutLine line, float y, Color color)
        {
            float middle = y + 8;
            float right = WidthDip - Pad - 12;
            float left = Pad + 12;
            Round(g, new RectangleF(left, middle - 4, 8, 8), 2, line.Healthy ? color : Dim, Color.Transparent);
            Font speedFont = line.Healthy ? mono : small;
            // Measured widths place things; the boxes drawn into stay roomy,
            // because GDI+ trims against a wider estimate than the letters' own.
            float speedWidth = Math.Min(140, Measure(g, line.Speed, speedFont));
            Caption(g, line.Speed, speedFont, line.Healthy ? Color.White : Warning, right - 140, middle, 140, StringAlignment.Far);
            float nameLeft = left + 16;
            float room = right - speedWidth - 12 - nameLeft;
            float nameWidth = Math.Min(room, Measure(g, line.Name, strong));
            Caption(g, line.Name, strong, line.Healthy ? Color.White : Dim, nameLeft, middle, room, StringAlignment.Near);
            // The model's title is the name with the ping after it; the ping
            // joins the adapter details in the quieter text.
            string ping = line.Title != null && line.Title.Length > line.Name.Length + 3 ? line.Title.Substring(line.Name.Length + 3) : "";
            string detail = line.Detail ?? "";
            if (ping.Length > 0) detail = detail.Length > 0 ? detail + " \u00b7 " + ping : ping;
            float detailLeft = nameLeft + nameWidth + 8;
            if (detail.Length > 0 && room - nameWidth - 8 > 12)
                Caption(g, detail, small, Dim, detailLeft, middle, room - nameWidth - 8, StringAlignment.Near);
            float cell = (Inner - 24 - 23 * 2) / 24f;
            Color off = line.Healthy ? Unlit : UnlitDown;
            for (int i = 0; i < 24; i++)
                Round(g, new RectangleF(left + i * (cell + 2), y + 23, cell, 6), 1, i < line.Lit ? color : off, Color.Transparent);
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

        void AppRow(Graphics g, FlyoutApp app, float y)
        {
            float middle = y + RowHeight / 2f;
            Round(g, new RectangleF(Pad, y, Inner, RowHeight), 6, Card, Color.Transparent);
            float left = Pad + 8;
            RectangleF avatar = new RectangleF(left, middle - 11, 22, 22);
            Round(g, avatar, 5, Avatars[app.ColorIndex], Color.Transparent);
            Caption(g, app.Initial, letter, AvatarInk, avatar.X, middle, avatar.Width, StringAlignment.Center);

            // The segmented control, sized by its captions; both are measured in
            // the bold face so the control doesn't move when the choice changes.
            float mainWidth = Measure(g, view.MainOption, smallStrong) + 16;
            float secondWidth = Measure(g, view.SecondOption, smallStrong) + 16;
            float segmentRight = WidthDip - Pad - 8;
            RectangleF segment = new RectangleF(segmentRight - (mainWidth + secondWidth + 6), middle - 11.5f, mainWidth + secondWidth + 6, 23);
            Round(g, segment, 6, SegmentFill, Color.Transparent);
            AppOption(g, app, "main", view.MainOption, new RectangleF(segment.X + 2, segment.Y + 2, mainWidth, 19), app.CanMove);
            AppOption(g, app, "second", view.SecondOption, new RectangleF(segment.X + 4 + mainWidth, segment.Y + 2, secondWidth, 19), app.CanSecond);
            if (!app.CanMove) notes.Add(new Hit { Bounds = segment, Tip = app.Name + " can\u2019t be moved" });

            float speedRight = segment.X - 10;
            float speedWidth = Measure(g, app.Speed, monoSmall);
            Caption(g, app.Speed, monoSmall, Dim, speedRight - 100, middle, 100, StringAlignment.Far);
            float nameLeft = left + 22 + 10;
            Caption(g, app.Name, body, Color.White, nameLeft, middle, speedRight - speedWidth - 10 - nameLeft, StringAlignment.Near);
        }

        void AppOption(Graphics g, FlyoutApp app, string lane, string caption, RectangleF bounds, bool enabled)
        {
            bool selected = app.Lane == lane;
            FlyoutAction action = new FlyoutAction { Key = "app:" + app.Path + ":" + lane, Endpoint = "/api/app-lane",
                Body = new Dictionary<string, object> { { "path", app.Path }, { "lane", lane } } };
            Button(g, bounds, action, "Move " + app.Name + " to " + caption, enabled && !quitting && pending == null, selected ? SelectedFill : SegmentFill, false, 4);
            Color color = selected ? enabled ? Color.White : Dim : enabled ? Dim : Faint;
            Caption(g, caption, selected ? smallStrong : small, color, bounds.X, bounds.Y + bounds.Height / 2, bounds.Width, StringAlignment.Center);
        }

        void Footer(Graphics g, int y)
        {
            float height = ClientSize.Height / scale - y;
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
                smallStrong.Dispose(); small.Dispose(); letter.Dispose(); mono.Dispose(); monoSmall.Dispose();
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
        public const int NIIF_WARNING = 0x02;
        public const int NOTIFYICON_VERSION_4 = 4;
        public const int MF_STRING = 0x0000;
        public const int MF_GRAYED = 0x0001;
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
        // Its own entry in the taskbar's icon settings, apart from other PowerShell icons.
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
            if (!added) return;
            Native.NOTIFYICONDATA data = Data(Native.NIF_INFO);
            data.szInfoTitle = title;
            data.szInfo = text;
            data.dwInfoFlags = Native.NIIF_WARNING;
            Native.Shell_NotifyIcon(Native.NIM_MODIFY, ref data);
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

        Tray(string root, string dataDir, string logFile, bool canLaunch)
        {
            this.root = root;
            this.logFile = logFile;
            this.canLaunch = canLaunch;
            serverFile = Path.Combine(dataDir, "server.json");
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
            window.Command = delegate (int id) { Guard(delegate { OnCommand(id); }); };
        }

        // Called by tray.ps1; returns once the icon is gone.
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
                    flyout.SetView(FlyoutModel.Unavailable("Net Switch isn\u2019t running."));
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
                    actionError = "Net Switch didn\u2019t quit. Open it and try again.";
                    flyout.Feedback(pendingAction, actionError, false);
                    icon.Balloon("Net Switch didn\u2019t quit", "Open Net Switch and press Quit Net Switch there.");
                }
                if (state != null)
                {
                    reachable = true;
                    Render(TrayModel.FromState(state));
                    flyout.SetView(FlyoutModel.FromState(state));
                    // An older in-flight poll must not clear feedback for a new action.
                    if (canFinishAction && !actionSending && pollVersion == actionVersion) pendingAction = null;
                    flyout.Feedback(pendingAction, actionError, quitting);
                    return;
                }
                flyout.SetView(FlyoutModel.Unavailable("Net Switch isn\u2019t responding. Open it to reconnect."));
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
                flyout.SetView(FlyoutModel.Unavailable("Couldn\u2019t read Net Switch. Open it to reconnect."));
            }
            finally
            {
                polling = false;
            }
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
            if (action.Key == "open" || action.Key == "all")
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
                failure = "Couldn\u2019t reach Net Switch. Open it to reconnect.";
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
                    return "Couldn\u2019t apply that change (HTTP " + ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture) + ").";
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
                icon.Balloon("Net Switch didn\u2019t open", "Open it from the Net Switch shortcut on the desktop.");
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
                Native.AppendMenu(menu, Native.MF_SEPARATOR, IntPtr.Zero, null);
                if (quitting) Native.AppendMenu(menu, Native.MF_GRAYED, (IntPtr)MenuQuit, "Quitting\u2026");
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
            actionError = "Net Switch didn\u2019t quit. Open it and try again.";
            flyout.Feedback(null, actionError, false);
            Render(before);
            icon.Balloon("Net Switch didn\u2019t quit", "Open Net Switch and press Quit Net Switch there.");
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

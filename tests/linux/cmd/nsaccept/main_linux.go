//go:build linux

// Command nsaccept is Net Switch's Linux acceptance harness. One binary plays
// every part:
//
//	nsaccept run             build the namespace network and run the cases (root)
//	nsaccept list            print the cases and their labels
//	nsaccept serve           the fake internet's servers (started by run)
//	nsaccept app <mode>      the test app; run copies it to /opt/nsapps/<name>/nsapp
//	nsaccept exec            start a program as an app on the fake PC (used by run)
//	nsaccept fetch-sing-box  download the pinned sing-box and check its SHA-256
//
// See tests/linux/suite and tests/linux/harness for what is checked and how
// results decide the job.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/app"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
	"github.com/AyoubAchour/net-switch/tests/linux/engine/nsengine"
	"github.com/AyoubAchour/net-switch/tests/linux/engine/singbox"
	"github.com/AyoubAchour/net-switch/tests/linux/harness"
	"github.com/AyoubAchour/net-switch/tests/linux/inet"
	"github.com/AyoubAchour/net-switch/tests/linux/suite"
	"github.com/AyoubAchour/net-switch/tests/linux/topo"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "run":
		os.Exit(runMain(os.Args[2:]))
	case "list":
		err = listMain()
	case "serve":
		err = inet.Main(os.Args[2:])
	case "app":
		os.Exit(app.Main(os.Args[2:]))
	case "exec":
		err = execMain(os.Args[2:])
	case "fetch-sing-box":
		err = fetchMain(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "nsaccept %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: nsaccept run|list|serve|app|exec|fetch-sing-box [flags]")
	os.Exit(2)
}

func listMain() error {
	cases := suite.Cases(suite.Config{})
	if err := harness.Validate(cases); err != nil {
		return err
	}
	for _, c := range cases {
		fmt.Printf("%-48s %-16s %-14s %s\n", c.ID, c.Label, c.Spec, c.Title)
		if c.Defect != "" {
			fmt.Printf("%-48s defect: %s\n", "", c.Defect)
		}
		if c.Waits != "" {
			fmt.Printf("%-48s waits for: %s\n", "", c.Waits)
		}
	}
	return nil
}

// repoRoot finds the checkout from the working directory.
func repoRoot() string {
	dir, _ := os.Getwd()
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "packaging", "versions.json")); err == nil {
			return d
		}
		if filepath.Dir(d) == d {
			return dir
		}
	}
}

func fetchMain(args []string) error {
	fs := flag.NewFlagSet("fetch-sing-box", flag.ContinueOnError)
	repo := fs.String("repo", repoRoot(), "the checkout")
	version := fs.String("version", "", "sing-box version (default: packaging/versions.json's)")
	dest := fs.String("dest", "/opt/sing-box", "folder to put sing-box and its LICENSE in")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *version == "" {
		v, err := singbox.PinnedVersion(filepath.Join(*repo, "packaging", "versions.json"))
		if err != nil {
			return err
		}
		*version = v
	}
	pin, err := singbox.LookupPin(filepath.Join(*repo, "tests", "linux", "sing-box-linux.json"), *version, runtime.GOARCH)
	if err != nil {
		return err
	}
	fmt.Printf("downloading %s\n", pin.URL)
	data, err := singbox.Download(context.Background(), pin)
	if err != nil {
		return err
	}
	fmt.Printf("verified: %d bytes, SHA-256 %s\n", len(data), pin.SHA256)
	if err := singbox.Extract(data, *dest); err != nil {
		return err
	}
	bin := filepath.Join(*dest, "sing-box")
	sum, err := harness.FileSHA256(bin)
	if err != nil {
		return err
	}
	out, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s version: %v: %s", bin, err, out)
	}
	fmt.Printf("installed %s (SHA-256 %s)\n%s", bin, sum, out)
	return nil
}

type options struct {
	engine, enginePath, expect, node, repo, out string
	quic                                        string
	uid, gid                                    int
	run, labels                                 string
	github                                      bool
}

func runMain(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var o options
	fs.StringVar(&o.engine, "engine", "sing-box", `engine under test: "sing-box" (baseline) or "netswitch-engine" (1.0)`)
	fs.StringVar(&o.enginePath, "engine-path", "/opt/sing-box/sing-box", "the engine's program")
	fs.StringVar(&o.expect, "expect-version", "", "the version the engine must report (default for sing-box: packaging/versions.json's)")
	fs.StringVar(&o.node, "node", "node", "Node.js, to run the app's config generator (sing-box)")
	fs.StringVar(&o.repo, "repo", repoRoot(), "the checkout")
	fs.StringVar(&o.out, "out", "acceptance-out", "folder for the report and logs")
	fs.StringVar(&o.quic, "quic", "", "the QUIC fixture (tests/quicfixture), for the QUIC cases")
	fs.IntVar(&o.uid, "app-uid", envInt("SUDO_UID", -1), "the desktop user apps run as")
	fs.IntVar(&o.gid, "app-gid", envInt("SUDO_GID", -1), "and their group")
	fs.StringVar(&o.run, "run", "", "only cases whose id matches this regular expression")
	fs.StringVar(&o.labels, "labels", "", "only cases with these labels (comma-separated)")
	fs.BoolVar(&o.github, "github", os.Getenv("GITHUB_ACTIONS") == "true", "GitHub annotations and step summary")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	report := harness.NewReport()
	code, err := run(o, report)
	if err != nil {
		report.Fail("%v", err)
		fmt.Fprintf(os.Stderr, "nsaccept run: %v\n", err)
		if o.github {
			fmt.Printf("::error title=Linux acceptance::%s\n", strings.ReplaceAll(err.Error(), "\n", " "))
		}
		code = 1
	}
	if werr := report.WriteFiles(o.out); werr != nil {
		fmt.Fprintf(os.Stderr, "writing the report: %v\n", werr)
		code = 1
	}
	if o.github {
		if path := os.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
			if f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644); err == nil {
				report.WriteMarkdown(f)
				f.Close()
			}
		}
	}
	// The report is written as root; the upload step runs as the runner user.
	_ = filepath.Walk(o.out, func(p string, info os.FileInfo, err error) error {
		if err == nil {
			mode := os.FileMode(0o644)
			if info.IsDir() {
				mode = 0o755
			}
			_ = os.Chmod(p, mode)
		}
		return nil
	})
	return code
}

func envInt(name string, fallback int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return v
	}
	return fallback
}

func run(o options, report *harness.Report) (int, error) {
	if err := os.MkdirAll(o.out, 0o755); err != nil {
		return 1, err
	}
	if os.Geteuid() != 0 {
		return 1, errors.New("run needs root (the namespaces, the engine and the app users)")
	}
	if o.uid <= 0 || o.gid <= 0 {
		return 1, errors.New("--app-uid and --app-gid must name the desktop user (not root); sudo sets SUDO_UID")
	}
	self, err := os.Executable()
	if err != nil {
		return 1, err
	}
	// The overload cases hold tens of thousands of connections at once: the
	// engine, the apps and the servers all inherit this limit.
	const nofile = 1 << 20
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{Cur: nofile, Max: nofile}); err != nil {
		return 1, fmt.Errorf("raising the open-file limit to %d: %w", nofile, err)
	}
	report.System["nofile"] = strconv.Itoa(nofile)
	describeSystem(report)
	harnessExe := harness.Executable{Role: "harness", Name: "nsaccept", Path: self, Version: goVersion()}
	if harnessExe.SHA256, err = harness.FileSHA256(self); err != nil {
		return 1, err
	}
	report.Executables = append(report.Executables, harnessExe)

	var drv engine.Driver
	switch o.engine {
	case "sing-box":
		if o.expect == "" {
			if o.expect, err = singbox.PinnedVersion(filepath.Join(o.repo, "packaging", "versions.json")); err != nil {
				return 1, err
			}
		}
		drv = singbox.New(singbox.Options{Binary: o.enginePath, Expect: o.expect, Node: o.node, RepoRoot: o.repo})
	case "netswitch-engine":
		drv = nsengine.New(o.enginePath)
	default:
		return 1, fmt.Errorf("unknown engine %q", o.engine)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	prepErr := drv.Prepare(ctx)
	exe := drv.Executable()
	report.Executables = append(report.Executables, exe)
	fmt.Printf("engine under test: %s %s (%s)\n  path   %s\n  sha256 %s\nharness: %s (%s)\n  sha256 %s\n",
		exe.Name, exe.Version, drv.Kind(), exe.Path, exe.SHA256, harnessExe.Path, harnessExe.Version, harnessExe.SHA256)
	if prepErr != nil {
		return 1, fmt.Errorf("the engine can't be tested: %w", prepErr)
	}

	users, err := prepareUsers(o.uid, o.gid)
	if err != nil {
		return 1, err
	}
	if err := installApps(self); err != nil {
		return 1, err
	}
	quicApp := ""
	if o.quic != "" {
		exe, err := installQUIC(ctx, o.quic)
		if err != nil {
			return 1, fmt.Errorf("the QUIC fixture: %w", err)
		}
		report.Executables = append(report.Executables, exe)
		fmt.Printf("QUIC fixture: %s %s\n  path   %s\n  sha256 %s\n", exe.Name, exe.Version, exe.Path, exe.SHA256)
		quicApp = suite.QUICApp
	}
	if left := topo.Leftovers(); len(left) > 0 {
		return 1, fmt.Errorf("namespaces from an earlier run are still there: %v", left)
	}

	cgroups, err := delegatedCgroup()
	if err != nil {
		return 1, err
	}
	report.System["cgroup"] = cgroups
	fixtures := &suite.Fixtures{}
	cases := suite.Cases(suite.Config{Self: self, Driver: drv, Users: users, Fixtures: fixtures, CgroupRoot: cgroups, QUIC: quicApp})
	if err := harness.Validate(cases); err != nil {
		return 1, err
	}
	selected, err := filter(cases, o.run, o.labels)
	if err != nil {
		return 1, err
	}
	if len(selected) == 0 {
		return 1, errors.New("no case matches the filters")
	}
	var ids []string
	for _, c := range selected {
		ids = append(ids, c.ID)
	}
	if suite.NeedsFixtures(ids) {
		// Downloads and builds happen here, once, outside any case's time.
		fmt.Println("provisioning the identity fixtures (Snap, Flatpak, AppImage)")
		started := time.Now()
		fx, err := suite.Provision(ctx, self, func(format string, args ...any) { fmt.Printf("  "+format+"\n", args...) })
		if err != nil {
			return 1, fmt.Errorf("provisioning the identity fixtures: %w", err)
		}
		*fixtures = *fx
		for key, value := range fx.Recorded {
			report.System[key] = value
			fmt.Printf("  %s: %s\n", key, value)
		}
		fmt.Printf("  done in %s\n", time.Since(started).Round(time.Second))
	}
	fmt.Printf("running %d of %d cases\n\n", len(selected), len(cases))
	harness.Run(ctx, selected, report, harness.Options{
		Kind:     drv.Kind(),
		OutDir:   o.out,
		Console:  os.Stdout,
		GitHub:   o.github,
		Progress: func(r *harness.Report) { _ = r.WriteFiles(o.out) },
	})
	if ctx.Err() != nil {
		report.Fail("the run was interrupted")
	}
	fmt.Println()
	report.WriteMarkdown(os.Stdout)
	if report.JobFailed {
		return 1, nil
	}
	return 0, nil
}

func filter(cases []*harness.Case, pattern, labels string) ([]*harness.Case, error) {
	var re *regexp.Regexp
	if pattern != "" {
		var err error
		if re, err = regexp.Compile(pattern); err != nil {
			return nil, err
		}
	}
	want := map[harness.Label]bool{}
	for _, l := range strings.Split(labels, ",") {
		if l = strings.TrimSpace(l); l != "" {
			if !harness.Label(l).Valid() {
				return nil, fmt.Errorf("unknown label %q", l)
			}
			want[harness.Label(l)] = true
		}
	}
	var out []*harness.Case
	for _, c := range cases {
		if (re == nil || re.MatchString(c.ID)) && (len(want) == 0 || want[c.Label]) {
			out = append(out, c)
		}
	}
	return out, nil
}

func goVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		return info.GoVersion
	}
	return runtime.Version()
}

func describeSystem(r *harness.Report) {
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
				r.System["os"] = strings.Trim(v, `"`)
			}
		}
	}
	var u syscall.Utsname
	if syscall.Uname(&u) == nil {
		r.System["kernel"] = utsString(u.Release[:])
	}
	r.System["arch"] = runtime.GOARCH
	r.System["cpus"] = strconv.Itoa(runtime.NumCPU())
	for key, env := range map[string]string{"runner": "RUNNER_NAME", "image": "ImageOS", "imageVersion": "ImageVersion"} {
		if v := os.Getenv(env); v != "" {
			r.System[key] = v
		}
	}
	if out, err := exec.Command("ip", "-V").Output(); err == nil {
		r.System["iproute2"] = strings.TrimSpace(string(out))
	}
}

func utsString[T int8 | uint8](b []T) string {
	var s strings.Builder
	for _, c := range b {
		if c == 0 {
			break
		}
		s.WriteByte(byte(c))
	}
	return s.String()
}

// delegatedCgroup returns the cgroup v2 folder the cases may create cgroups
// in. Systemd owns the cgroup tree; a program may only create cgroups in a
// subtree delegated to it (systemd.io/CGROUP_DELEGATION). So the harness must
// run in a delegated scope (systemd-run --scope -p Delegate=yes), and moves
// itself into a "harness" leaf, since a cgroup with children can't also hold
// processes.
func delegatedCgroup() (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	own := ""
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			own = p
		}
	}
	if own == "" {
		return "", errors.New("no cgroup v2 membership in /proc/self/cgroup")
	}
	if filepath.Base(own) == "harness" {
		own = filepath.Dir(own)
	}
	unit := filepath.Base(own)
	out, err := exec.Command("systemctl", "show", "--property=Delegate", "--value", unit).Output()
	if err != nil || strings.TrimSpace(string(out)) != "yes" {
		return "", fmt.Errorf("the harness's cgroup %s isn't delegated to it (Delegate=%q): run it with systemd-run --scope -p Delegate=yes", own, strings.TrimSpace(string(out)))
	}
	root := filepath.Join("/sys/fs/cgroup", own)
	leaf := filepath.Join(root, "harness")
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(leaf, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		return "", fmt.Errorf("moving the harness into %s: %w", leaf, err)
	}
	return root, nil
}

// prepareUsers checks the desktop user and makes the second user.
func prepareUsers(uid, gid int) (suite.Users, error) {
	users := suite.Users{UID: uid, GID: gid}
	const other = "nsaccept2"
	u, err := user.Lookup(other)
	if err != nil {
		if out, err := exec.Command("useradd", "--no-create-home", "--shell", "/usr/sbin/nologin", other).CombinedOutput(); err != nil {
			return users, fmt.Errorf("useradd %s: %v: %s", other, err, out)
		}
		if u, err = user.Lookup(other); err != nil {
			return users, err
		}
	}
	users.OtherUID, _ = strconv.Atoi(u.Uid)
	users.OtherGID, _ = strconv.Atoi(u.Gid)
	if users.OtherUID == uid || users.OtherUID <= 0 {
		return users, fmt.Errorf("the second user %s needs its own uid (got %d)", other, users.OtherUID)
	}
	return users, nil
}

// installQUIC copies the QUIC fixture to where the QUIC cases run it as an
// app, and identifies it for the report.
func installQUIC(ctx context.Context, src string) (harness.Executable, error) {
	exe := harness.Executable{Role: "fixture", Name: "nsquic", Path: suite.QUICApp}
	if err := installFile(src, suite.QUICApp); err != nil {
		return exe, err
	}
	var err error
	if exe.SHA256, err = harness.FileSHA256(suite.QUICApp); err != nil {
		return exe, err
	}
	out, err := exec.CommandContext(ctx, suite.QUICApp, "version").Output()
	if err != nil {
		return exe, fmt.Errorf("%s version: %w", suite.QUICApp, err)
	}
	exe.Version = strings.TrimSpace(string(out))
	return exe, nil
}

// installFile copies a program into place, readable and runnable by all.
func installFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// installApps copies this program to each app's folder.
func installApps(self string) error {
	src, err := os.Open(self)
	if err != nil {
		return err
	}
	defer src.Close()
	if err := os.MkdirAll(suite.AppsDir, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(suite.AppsDir, 0o755); err != nil {
		return err
	}
	for _, name := range suite.AppNames {
		path := suite.AppPath(name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if _, err := src.Seek(0, io.SeekStart); err != nil {
			return err
		}
		tmp := path + ".tmp"
		dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		_, err = io.Copy(dst, src)
		if cerr := dst.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
	}
	return nil
}

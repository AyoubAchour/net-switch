//go:build linux

package suite

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/tests/linux/app"
	"github.com/AyoubAchour/net-switch/tests/linux/engine"
	"github.com/AyoubAchour/net-switch/tests/linux/engine/singbox"
	"github.com/AyoubAchour/net-switch/tests/linux/harness"
	"github.com/AyoubAchour/net-switch/tests/linux/topo"
	"github.com/AyoubAchour/net-switch/tests/linux/wire"
)

func init() { register(40, addIdentity) }

func addIdentity(r *registry) {
	r.add("identity.snap", "A Snap app pinned by its Snap name uses its line", harness.Parity, "5.4, 10", 0, snapIdentity)
	r.defect("identity.flatpak-same-path", "Two Flatpak apps with the same /app/bin path, pinned to different lines, each use their own",
		"rules match the program path only, and both apps run /app/bin/nsapp, so one rule decides for both", "5.4, 10", 0, flatpakIdentity)
	r.add("identity.appimage", "A registered AppImage, mounted at a new random path each run, uses its line", harness.Parity, "5.4, 10", 0, appImageIdentity)
	r.add("identity.replaced-binary", "An app whose program file is replaced while it runs keeps its line", harness.Parity, "5.4, 5.6", 0, replacedBinary)
}

// Fixtures are the packaged apps the identity cases run, provisioned once
// before any case so building and installing never count against a case's
// time. Each is built here around the harness's own test app, so what it
// runs never moves: no store decides its content. The Snap's base and snapd
// itself are pinned and cached before provisioning.
// Both are recorded, and all Snap installs are offline. These cases are
// required (SYSTEM-DESIGN.md 10), so a fixture that can't be provisioned
// fails the run rather than skipping anything.
type Fixtures struct {
	SnapProgram string // the test app inside the snap: /snap/nsaccept-tool/<revision>/bin/nsapp
	SnapCommand string // how it's started: /snap/bin/nsaccept-tool
	AppImage    string // NsTool.AppImage
	// Recorded identifies each fixture for the report.
	Recorded map[string]string
}

// The packaged test apps' names.
const (
	snapName       = "nsaccept-tool"
	snapBase       = "core24"
	flatpakRuntime = "com.netswitch.TestPlatform"
	flatpakBranch  = "1"
)

// NeedsFixtures reports whether any of the cases uses them.
func NeedsFixtures(ids []string) bool {
	for _, id := range ids {
		if strings.HasPrefix(id, "identity.snap") || strings.HasPrefix(id, "identity.flatpak") || strings.HasPrefix(id, "identity.appimage") {
			return true
		}
	}
	return false
}

const fixtureDir = "/opt/nsaccept-fixtures"

// Provision installs and builds the fixtures. self is the harness binary,
// which the Flatpak and AppImage test apps run.
func Provision(ctx context.Context, self string, logf func(string, ...any)) (*Fixtures, error) {
	f := &Fixtures{Recorded: map[string]string{}}
	host := func(timeout time.Duration, tries int, name string, args ...string) (string, error) {
		var out []byte
		var err error
		for i := 0; i < tries; i++ {
			c, cancel := context.WithTimeout(ctx, timeout)
			cmd := exec.CommandContext(c, name, args...)
			cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
			out, err = cmd.CombinedOutput()
			cancel()
			if err == nil {
				return string(out), nil
			}
			logf("provision: %s %s failed (try %d): %v", name, strings.Join(args, " "), i+1, err)
			time.Sleep(time.Duration(5*(i+1)) * time.Second)
		}
		return string(out), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
		return nil, err
	}
	sum, err := harness.FileSHA256(self)
	if err != nil {
		return nil, err
	}

	// Snap: install the verified cached base before the locally packed app.
	// Keep the store offline throughout the run; missing prerequisites fail.
	baseRecord, err := installSnapInputs(ctx, host, logf)
	if err != nil {
		return nil, err
	}
	f.Recorded["fixture snap inputs"] = baseRecord
	// The strict test snap is unsigned, so its revision reads x1, x2...
	arch := map[string]string{"amd64": "amd64", "arm64": "arm64"}[runtime.GOARCH]
	snapWork := filepath.Join(fixtureDir, "snap")
	_ = os.RemoveAll(snapWork)
	root := filepath.Join(snapWork, "root")
	yaml := fmt.Sprintf("name: %s\nversion: '1'\nsummary: Net Switch acceptance test app\ndescription: The Linux acceptance harness's test app, packaged as a Snap.\n"+
		"base: %s\nconfinement: strict\ngrade: devel\narchitectures: [%s]\napps:\n  %s:\n    command: bin/nsapp\n    plugs: [network]\n", snapName, snapBase, arch, snapName)
	if err := writeFile(filepath.Join(root, "meta", "snap.yaml"), yaml, 0o644); err != nil {
		return nil, err
	}
	if err := copyFile(self, filepath.Join(root, "bin", "nsapp"), 0o755); err != nil {
		return nil, err
	}
	if _, err := host(2*time.Minute, 1, "snap", "pack", root, snapWork); err != nil {
		return nil, err
	}
	snapFile := filepath.Join(snapWork, fmt.Sprintf("%s_1_%s.snap", snapName, arch))
	snapSum, err := harness.FileSHA256(snapFile)
	if err != nil {
		return nil, err
	}
	if _, err := host(3*time.Minute, 1, "snap", "install", "--dangerous", snapFile); err != nil {
		return nil, fmt.Errorf("installing the test snap offline (core24 is cached; any attempt to fetch prerequisites from the store is forbidden): %w", err)
	}
	rev, err := os.Readlink(filepath.Join("/snap", snapName, "current"))
	if err != nil {
		return nil, fmt.Errorf("snap %s has no current revision: %w", snapName, err)
	}
	f.SnapProgram = filepath.Join("/snap", snapName, rev, "bin", "nsapp")
	f.SnapCommand = filepath.Join("/snap", "bin", snapName)
	if _, err := os.Stat(f.SnapProgram); err != nil {
		return nil, err
	}
	f.Recorded["fixture snap"] = fmt.Sprintf("%s built here from the harness (snap SHA-256 %s), installed as revision %s", snapName, snapSum, rev)
	list, err := host(time.Minute, 1, "snap", "list", snapBase, "snapd")
	if err != nil {
		return nil, err
	}
	f.Recorded["fixture snap installed"] = strings.Join(strings.Fields(strings.ReplaceAll(strings.TrimSpace(list), "\n", " | ")), " ")

	// Flatpak: a runtime and two apps built here; nothing from Flathub. The
	// runtime is a metadata file and ldconfig (flatpak runs it when an app
	// starts), as flatpak's own test suite builds one: the apps' program is
	// the harness's static binary, which needs nothing else from it.
	if _, err := os.Stat("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"); err == nil {
		// Ubuntu restricts unprivileged user namespaces, which bwrap needs.
		if _, err := host(time.Minute, 1, "sysctl", "-q", "-w", "kernel.apparmor_restrict_unprivileged_userns=0"); err != nil {
			return nil, err
		}
	}
	work := filepath.Join(fixtureDir, "flatpak")
	_ = os.RemoveAll(work)
	rt := filepath.Join(work, "runtime")
	if err := writeFile(filepath.Join(rt, "metadata"), "[Runtime]\nname="+flatpakRuntime+"\n", 0o644); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(rt, "files"), 0o755); err != nil {
		return nil, err
	}
	ldconfig := ""
	for _, p := range []string{"/usr/sbin/ldconfig.real", "/sbin/ldconfig.real", "/usr/sbin/ldconfig", "/sbin/ldconfig"} {
		if _, err := os.Stat(p); err == nil {
			ldconfig = p
			break
		}
	}
	if ldconfig == "" {
		return nil, errors.New("no ldconfig to put in the test Flatpak runtime")
	}
	if err := copyFile(ldconfig, filepath.Join(rt, "usr", "bin", "ldconfig"), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(rt, "usr", "lib"), 0o755); err != nil {
		return nil, err
	}
	runtimeRepo, appRepo := filepath.Join(work, "runtime-repo"), filepath.Join(work, "app-repo")
	if _, err := host(2*time.Minute, 1, "flatpak", "build-export", "--runtime", "--disable-sandbox", runtimeRepo, rt, flatpakBranch); err != nil {
		return nil, err
	}
	if _, err := host(time.Minute, 1, "flatpak", "remote-add", "--system", "--no-gpg-verify", "--if-not-exists", "nsaccept-runtime", runtimeRepo); err != nil {
		return nil, err
	}
	if _, err := host(3*time.Minute, 1, "flatpak", "install", "--system", "-y", "--noninteractive", "--reinstall", "nsaccept-runtime", flatpakRuntime+"//"+flatpakBranch); err != nil {
		return nil, err
	}
	for _, id := range strings.Fields(flatpakApps) {
		dir := filepath.Join(work, id)
		if _, err := host(2*time.Minute, 1, "flatpak", "build-init", dir, id, flatpakRuntime, flatpakRuntime, flatpakBranch); err != nil {
			return nil, err
		}
		// Both apps' program is the same file at the same path, /app/bin/nsapp.
		if err := copyFile(self, filepath.Join(dir, "files", "bin", "nsapp"), 0o755); err != nil {
			return nil, err
		}
		if _, err := host(2*time.Minute, 1, "flatpak", "build-finish", dir, "--command=nsapp", "--share=network"); err != nil {
			return nil, err
		}
		if _, err := host(2*time.Minute, 1, "flatpak", "build-export", "--disable-sandbox", appRepo, dir); err != nil {
			return nil, err
		}
	}
	if _, err := host(time.Minute, 1, "flatpak", "remote-add", "--system", "--no-gpg-verify", "--if-not-exists", "nsaccept-apps", appRepo); err != nil {
		return nil, err
	}
	if _, err := host(3*time.Minute, 1, "flatpak", append([]string{"install", "--system", "-y", "--noninteractive", "--reinstall", "nsaccept-apps"}, strings.Fields(flatpakApps)...)...); err != nil {
		return nil, err
	}
	var commits []string
	for _, ref := range append([]string{flatpakRuntime + "//" + flatpakBranch}, strings.Fields(flatpakApps)...) {
		commit, err := host(time.Minute, 1, "flatpak", "info", "--system", "--show-commit", ref)
		if err != nil {
			return nil, err
		}
		commits = append(commits, ref+" "+strings.TrimSpace(commit))
	}
	f.Recorded["fixture flatpak"] = "built here from the harness (SHA-256 " + sum + "): " + strings.Join(commits, ", ")

	// AppImage: built with pinned tools.
	tools := appImageTools[runtime.GOARCH]
	if tools == nil {
		return nil, fmt.Errorf("no AppImage tooling pinned for %s", runtime.GOARCH)
	}
	aw := filepath.Join(fixtureDir, "appimage")
	appDir := filepath.Join(aw, "AppDir")
	_ = os.RemoveAll(aw)
	if err := os.MkdirAll(filepath.Join(appDir, "usr", "bin"), 0o755); err != nil {
		return nil, err
	}
	for name, pin := range tools {
		data, err := singbox.Download(ctx, pin)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(aw, name), data, 0o755); err != nil {
			return nil, err
		}
		f.Recorded["fixture "+name] = pin.URL + " sha256 " + pin.SHA256
	}
	files := map[string]string{
		"AppRun":         "#!/bin/sh\nexec \"$APPDIR/usr/bin/nsapp\" \"$@\"\n",
		"nstool.desktop": "[Desktop Entry]\nType=Application\nName=NsTool\nExec=nsapp\nIcon=nstool\nCategories=Network;\n",
		"nstool.svg":     "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\"><rect width=\"64\" height=\"64\" fill=\"#3a6\"/></svg>\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(appDir, name), []byte(body), 0o755); err != nil {
			return nil, err
		}
	}
	if err := copyFile(self, filepath.Join(appDir, "usr", "bin", "nsapp"), 0o755); err != nil {
		return nil, err
	}
	f.AppImage = filepath.Join(aw, "NsTool.AppImage")
	appImageArch := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]
	c, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	build := exec.CommandContext(c, filepath.Join(aw, "appimagetool"), "--no-appstream", "--runtime-file", filepath.Join(aw, "runtime"), appDir, f.AppImage)
	build.Env = append(os.Environ(), "ARCH="+appImageArch, "APPIMAGE_EXTRACT_AND_RUN=1")
	if out, err := build.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("appimagetool: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if err := os.Chmod(f.AppImage, 0o755); err != nil {
		return nil, err
	}
	return f, nil
}

func (e *Env) fixtures() *Fixtures {
	if e.cfg.Fixtures == nil || e.cfg.Fixtures.AppImage == "" {
		e.T.Fatalf("the identity fixtures weren't provisioned")
	}
	return e.cfg.Fixtures
}

func snapIdentity(e *Env) {
	fx := e.fixtures()
	cfg := e.DefaultConfig()
	cfg.Policy.Pins = append(cfg.Policy.Pins, engine.Pin{App: engine.App{ID: "snap:" + snapName, Path: fx.SnapProgram}, Line: "b"})
	e.StartEngine(cfg)
	for _, c := range []struct {
		label, program string
		args           []string
		want           engine.LineID
	}{
		{"the " + snapName + " snap, pinned to b", fx.SnapCommand, []string{"app"}, "b"},
		// The same program outside the snap isn't the snap.
		{"the same program as delta, unpinned", AppPath("delta"), []string{"app"}, "a"},
	} {
		var r app.TCPResult
		e.RunJSON(Run{Program: c.program, Args: append(c.args, "tcp", "--to", To(topo.Server4, wire.PortWhoami), "--count", "3"), Timeout: 2 * time.Minute}, &r)
		lines := Lines(r.Seen)
		e.T.Check(r.OK == 3 && lines[c.want] == 3, "%s: 3 connections on line %s (lines %s, errors %v)", c.label, c.want, Describe(lines), r.Errors)
	}
}

func writeFile(path, body string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(body), mode)
}

const flatpakApps = "com.netswitch.TestA com.netswitch.TestB"

func flatpakIdentity(e *Env) {
	e.fixtures()
	cfg := e.DefaultConfig()
	cfg.Policy.Pins = append(cfg.Policy.Pins,
		engine.Pin{App: engine.App{ID: "flatpak:com.netswitch.TestA", Path: "/app/bin/nsapp"}, Line: "b"},
		engine.Pin{App: engine.App{ID: "flatpak:com.netswitch.TestB", Path: "/app/bin/nsapp"}, Line: "c"},
	)
	e.StartEngine(cfg)
	var got []string
	ok := true
	for _, c := range []struct {
		id   string
		want engine.LineID
	}{{"com.netswitch.TestA", "b"}, {"com.netswitch.TestB", "c"}} {
		for _, large := range []bool{false, true} {
			var r app.TCPResult
			args := []string{"run"}
			if large {
				args = append(args, "--env=NETSWITCH_TEST_LARGE_FLATPAK=1", "--env=PAD="+strings.Repeat("x", 70000))
			}
			args = append(args, c.id, "app", "tcp", "--to", To(topo.Server4, wire.PortWhoami), "--count", "3")
			e.RunJSON(Run{Program: "flatpak", Args: args, Timeout: 2 * time.Minute}, &r)
			lines := Lines(r.Seen)
			e.T.Check(r.OK == 3, "Flatpak %s (large environment=%t) ran and connected 3 times (errors %v)", c.id, large, r.Errors)
			ok = ok && lines[c.want] == 3
			got = append(got, fmt.Sprintf("%s large=%t pinned to %s: lines %s", c.id, large, c.want, Describe(lines)))
		}
	}
	e.T.Expect(ok, "each Flatpak app (both /app/bin/nsapp) uses its own pinned line (%s)", strings.Join(got, "; "))
}

// AppImage tooling, pinned (sizes and SHA-256 from the GitHub release assets).
var appImageTools = map[string]map[string]singbox.Pin{
	"amd64": {
		"appimagetool": {URL: "https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-x86_64.AppImage", Size: 15092216, SHA256: "ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0"},
		"runtime":      {URL: "https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-x86_64", Size: 944632, SHA256: "2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d"},
	},
	"arm64": {
		"appimagetool": {URL: "https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-aarch64.AppImage", Size: 14678536, SHA256: "f0837e7448a0c1e4e650a93bb3e85802546e60654ef287576f46c71c126a9158"},
		"runtime":      {URL: "https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-aarch64", Size: 936456, SHA256: "00cbdfcf917cc6c0ff6d3347d59e0ca1f7f45a6df1a428a0d6d8a78664d87444"},
	},
}

func appImageIdentity(e *Env) {
	fx := e.fixtures()
	cfg := e.DefaultConfig()
	// The mount folder is /tmp/.mount_NsTool<6 random characters>; what's
	// pinned is the registered AppImage, seen at any such folder.
	cfg.Policy.Pins = append(cfg.Policy.Pins, engine.Pin{App: engine.App{ID: "appimage:NsTool", Path: "/tmp/.mount_NsToolAAAAAA/usr/bin/nsapp"}, Line: "c"})
	e.StartEngine(cfg)
	for run := 1; run <= 2; run++ {
		var r app.TCPResult
		e.RunJSON(Run{Program: fx.AppImage, Args: []string{"app", "tcp", "--to", To(topo.Server4, wire.PortWhoami), "--count", "3"}, Timeout: 2 * time.Minute}, &r)
		lines := Lines(r.Seen)
		e.T.Check(r.OK == 3 && lines["c"] == 3, "NsTool.AppImage run %d, pinned to c: lines %s (errors %v)", run, Describe(lines), r.Errors)
	}
}

func replacedBinary(e *Env) {
	cfg := e.DefaultConfig()
	cfg.Policy.Pins = append(cfg.Policy.Pins, engine.Pin{App: e.App("delta"), Line: "c"})
	e.StartEngine(cfg)
	trigger := filepath.Join(e.SharedDir(), "go")
	bg := e.Start(Run{App: "delta", Args: []string{"tcp", "--to", To(topo.Server4, wire.PortWhoami), "--count", "3", "--wait-file", trigger}})
	bg.WaitLine(e, "waiting ", 30*time.Second)
	// An update replaces the file while delta runs: its /proc exe now ends in
	// " (deleted)".
	path := AppPath("delta")
	if err := copyFile(e.cfg.Self, path+".new", 0o755); err != nil {
		e.T.Fatalf("%v", err)
	}
	if err := os.Rename(path+".new", path); err != nil {
		e.T.Fatalf("%v", err)
	}
	exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", bg.Pid()))
	e.T.Logf("delta's program is now seen as %q", exe)
	if err := os.WriteFile(trigger, nil, 0o644); err != nil {
		e.T.Fatalf("%v", err)
	}
	var r app.TCPResult
	bg.WaitJSON(e, 30*time.Second, &r)
	lines := Lines(r.Seen)
	e.T.Check(strings.HasSuffix(exe, " (deleted)"), "the running program shows as replaced (%q)", exe)
	e.T.Check(r.OK == 3 && lines["c"] == 3, "delta, replaced while running, stays on c: lines %s (errors %v)", Describe(lines), r.Errors)
}

func copyFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, mode)
}

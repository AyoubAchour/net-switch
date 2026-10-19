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

// Fixtures are the outside programs the identity cases run, provisioned once
// before any case so downloads never count against a case's time.
type Fixtures struct {
	SnapProgram   string // e.g. /snap/curl/2423/usr/local/bin/curl
	FlatpakBranch string // the Freedesktop runtime branch the test apps use
	AppImage      string // NsTool.AppImage
	// Recorded identifies each fixture for the report (the Snap Store and
	// Flathub can't be pinned from CI, so what was used is recorded).
	Recorded map[string]string
}

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

	// Snap: the Snap Store's curl.
	if _, err := host(3*time.Minute, 3, "snap", "install", "curl"); err != nil {
		return nil, err
	}
	rev, err := os.Readlink("/snap/curl/current")
	if err != nil {
		return nil, fmt.Errorf("snap curl has no current revision: %w", err)
	}
	for _, p := range []string{"usr/local/bin/curl", "usr/bin/curl", "bin/curl"} {
		if _, err := os.Stat(filepath.Join("/snap/curl", rev, p)); err == nil {
			f.SnapProgram = filepath.Join("/snap/curl", rev, p)
			break
		}
	}
	if f.SnapProgram == "" {
		return nil, fmt.Errorf("can't find curl inside /snap/curl/%s", rev)
	}
	f.Recorded["fixture snap"] = "curl revision " + rev + " (latest/stable)"

	// Flatpak: the Freedesktop runtime from Flathub, and two apps built here.
	if _, err := os.Stat("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"); err == nil {
		// Ubuntu restricts unprivileged user namespaces, which bwrap needs.
		if _, err := host(time.Minute, 1, "sysctl", "-q", "-w", "kernel.apparmor_restrict_unprivileged_userns=0"); err != nil {
			return nil, err
		}
	}
	if _, err := host(2*time.Minute, 3, "flatpak", "remote-add", "--system", "--if-not-exists", "flathub", "https://dl.flathub.org/repo/flathub.flatpakrepo"); err != nil {
		return nil, err
	}
	for _, b := range []string{"25.08", "24.08"} {
		if _, err := host(6*time.Minute, 2, "flatpak", "install", "--system", "-y", "--noninteractive", "flathub", "org.freedesktop.Platform//"+b); err == nil {
			f.FlatpakBranch = b
			break
		}
	}
	if f.FlatpakBranch == "" {
		return nil, errors.New("couldn't install a Freedesktop runtime from Flathub")
	}
	commit, err := host(time.Minute, 1, "flatpak", "info", "--system", "--show-commit", "org.freedesktop.Platform//"+f.FlatpakBranch)
	if err != nil {
		return nil, err
	}
	f.Recorded["fixture flatpak"] = "org.freedesktop.Platform//" + f.FlatpakBranch + " commit " + strings.TrimSpace(commit)
	work := filepath.Join(fixtureDir, "flatpak")
	_ = os.RemoveAll(work)
	for _, id := range strings.Fields(flatpakApps) {
		dir := filepath.Join(work, id)
		if _, err := host(2*time.Minute, 1, "flatpak", "build-init", dir, id, "org.freedesktop.Platform", "org.freedesktop.Platform", f.FlatpakBranch); err != nil {
			return nil, err
		}
		// Both apps' program is the same file at the same path, /app/bin/nsapp.
		if err := copyFile(self, filepath.Join(dir, "files", "bin", "nsapp"), 0o755); err != nil {
			return nil, err
		}
		if _, err := host(2*time.Minute, 1, "flatpak", "build-finish", dir, "--command=nsapp", "--share=network"); err != nil {
			return nil, err
		}
		if _, err := host(2*time.Minute, 1, "flatpak", "build-export", filepath.Join(work, "repo"), dir); err != nil {
			return nil, err
		}
	}
	if _, err := host(time.Minute, 1, "flatpak", "remote-add", "--system", "--no-gpg-verify", "--if-not-exists", "nsaccept-local", filepath.Join(work, "repo")); err != nil {
		return nil, err
	}
	if _, err := host(3*time.Minute, 1, "flatpak", append([]string{"install", "--system", "-y", "--noninteractive", "--reinstall", "nsaccept-local"}, strings.Fields(flatpakApps)...)...); err != nil {
		return nil, err
	}

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
	arch := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]
	c, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	build := exec.CommandContext(c, filepath.Join(aw, "appimagetool"), "--no-appstream", "--runtime-file", filepath.Join(aw, "runtime"), appDir, f.AppImage)
	build.Env = append(os.Environ(), "ARCH="+arch, "APPIMAGE_EXTRACT_AND_RUN=1")
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
	cfg.Policy.Pins = append(cfg.Policy.Pins, engine.Pin{App: engine.App{ID: "snap:curl", Path: fx.SnapProgram}, Line: "b"})
	e.StartEngine(cfg)
	url := "http://" + To(topo.Server4, wire.PortHTTP) + "/"
	for _, c := range []struct {
		label, program string
		want           engine.LineID
	}{
		{"the curl snap, pinned to b", "/snap/bin/curl", "b"},
		{"the system's /usr/bin/curl, unpinned", "/usr/bin/curl", "a"},
	} {
		got := map[engine.LineID]int{}
		for range 3 {
			out, err := e.TryExec(Run{Program: c.program, Args: []string{"-s", "--max-time", "5", url}})
			id := topo.LineOfText(strings.TrimSpace(string(out)))
			if err != nil || id == "" {
				id = "?"
			}
			got[id]++
		}
		e.T.Check(got[c.want] == 3, "%s: 3 requests on line %s (lines %s)", c.label, c.want, Describe(got))
	}
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
		var r app.TCPResult
		e.RunJSON(Run{Program: "flatpak", Args: []string{"run", c.id, "app", "tcp", "--to", To(topo.Server4, wire.PortWhoami), "--count", "3"}, Timeout: 2 * time.Minute}, &r)
		lines := Lines(r.Seen)
		e.T.Check(r.OK == 3, "Flatpak %s ran and connected 3 times (errors %v)", c.id, r.Errors)
		ok = ok && lines[c.want] == 3
		got = append(got, fmt.Sprintf("%s pinned to %s: lines %s", c.id, c.want, Describe(lines)))
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

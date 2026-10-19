//go:build linux

package suite

import (
	"context"
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
	r.add("identity.snap", "A Snap app pinned by its Snap name uses its line", harness.Parity, "5.4, 10", 5*time.Minute, snapIdentity)
	r.add("identity.flatpak-same-path", "Two Flatpak apps with the same /app/bin path, pinned to different lines, each use their own", harness.BaselineDefect, "5.4, 10", 10*time.Minute, flatpakIdentity)
	r.add("identity.appimage", "A registered AppImage, mounted at a new random path each run, uses its line", harness.Parity, "5.4, 10", 5*time.Minute, appImageIdentity)
	r.add("identity.replaced-binary", "An app whose program file is replaced while it runs keeps its line", harness.Parity, "5.4, 5.6", 0, replacedBinary)
}

// Host runs a command in the runner's own namespace (installing packages,
// building test apps), logging it with the case's apps.
func (e *Env) Host(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(e.Ctx(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.CombinedOutput()
	e.logRun(Run{Program: name, Args: args}, out, nil)
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, truncate(out, 600))
	}
	return string(out), nil
}

// Retry runs Host up to tries times, for steps that download.
func (e *Env) Retry(tries int, timeout time.Duration, name string, args ...string) (string, error) {
	var out string
	var err error
	for i := 0; i < tries; i++ {
		if out, err = e.Host(timeout, name, args...); err == nil {
			return out, nil
		}
		e.Sleep(time.Duration(5*(i+1)) * time.Second)
	}
	return out, err
}

func snapIdentity(e *Env) {
	if _, err := e.Retry(3, 3*time.Minute, "snap", "install", "curl"); err != nil {
		e.T.Fatalf("snap install curl: %v", err)
	}
	rev, err := os.Readlink("/snap/curl/current")
	if err != nil {
		e.T.Fatalf("snap curl has no current revision: %v", err)
	}
	var program string
	for _, p := range []string{"usr/local/bin/curl", "usr/bin/curl", "bin/curl"} {
		if _, err := os.Stat(filepath.Join("/snap/curl", rev, p)); err == nil {
			program = filepath.Join("/snap/curl", rev, p)
			break
		}
	}
	if program == "" {
		e.T.Fatalf("can't find curl inside /snap/curl/%s", rev)
	}
	e.T.Logf("the snap's program is %s", program)
	cfg := e.DefaultConfig()
	cfg.Policy.Pins = append(cfg.Policy.Pins, engine.Pin{App: engine.App{ID: "snap:curl", Path: program}, Line: "b"})
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
	if _, err := e.Host(time.Minute, "flatpak", "--version"); err != nil {
		e.T.Fatalf("flatpak isn't installed: %v", err)
	}
	// Ubuntu restricts unprivileged user namespaces, which bwrap needs.
	if _, err := os.Stat("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"); err == nil {
		if _, err := e.Host(time.Minute, "sysctl", "-q", "-w", "kernel.apparmor_restrict_unprivileged_userns=0"); err != nil {
			e.T.Fatalf("%v", err)
		}
	}
	if _, err := e.Retry(3, 2*time.Minute, "flatpak", "remote-add", "--system", "--if-not-exists", "flathub", "https://dl.flathub.org/repo/flathub.flatpakrepo"); err != nil {
		e.T.Fatalf("%v", err)
	}
	branch := ""
	for _, b := range []string{"25.08", "24.08"} {
		if _, err := e.Retry(2, 6*time.Minute, "flatpak", "install", "--system", "-y", "--noninteractive", "flathub", "org.freedesktop.Platform//"+b); err == nil {
			branch = b
			break
		}
	}
	if branch == "" {
		e.T.Fatalf("couldn't install a Freedesktop runtime from Flathub")
	}
	work := filepath.Join(os.TempDir(), "nsaccept-flatpak")
	_ = os.RemoveAll(work)
	for _, id := range strings.Fields(flatpakApps) {
		dir := filepath.Join(work, id)
		steps := [][]string{
			{"flatpak", "build-init", dir, id, "org.freedesktop.Platform", "org.freedesktop.Platform", branch},
		}
		for _, s := range steps {
			if _, err := e.Host(2*time.Minute, s[0], s[1:]...); err != nil {
				e.T.Fatalf("%v", err)
			}
		}
		// Both apps' program is the same file at the same path, /app/bin/nsapp.
		if err := copyFile(e.cfg.Self, filepath.Join(dir, "files", "bin", "nsapp"), 0o755); err != nil {
			e.T.Fatalf("%v", err)
		}
		for _, s := range [][]string{
			{"flatpak", "build-finish", dir, "--command=nsapp", "--share=network"},
			{"flatpak", "build-export", filepath.Join(work, "repo"), dir},
		} {
			if _, err := e.Host(2*time.Minute, s[0], s[1:]...); err != nil {
				e.T.Fatalf("%v", err)
			}
		}
	}
	if _, err := e.Host(time.Minute, "flatpak", "remote-add", "--system", "--no-gpg-verify", "--if-not-exists", "nsaccept-local", filepath.Join(work, "repo")); err != nil {
		e.T.Fatalf("%v", err)
	}
	args := append([]string{"install", "--system", "-y", "--noninteractive", "--reinstall", "nsaccept-local"}, strings.Fields(flatpakApps)...)
	if _, err := e.Host(3*time.Minute, "flatpak", args...); err != nil {
		e.T.Fatalf("%v", err)
	}
	e.T.Cleanup(func() {
		_, _ = e.Host(2*time.Minute, "flatpak", append([]string{"uninstall", "--system", "-y", "--noninteractive"}, strings.Fields(flatpakApps)...)...)
		_, _ = e.Host(time.Minute, "flatpak", "remote-delete", "--system", "--force", "nsaccept-local")
		_ = os.RemoveAll(work)
	})

	cfg := e.DefaultConfig()
	cfg.Policy.Pins = append(cfg.Policy.Pins,
		engine.Pin{App: engine.App{ID: "flatpak:com.netswitch.TestA", Path: "/app/bin/nsapp"}, Line: "b"},
		engine.Pin{App: engine.App{ID: "flatpak:com.netswitch.TestB", Path: "/app/bin/nsapp"}, Line: "c"},
	)
	e.StartEngine(cfg)
	for _, c := range []struct {
		id   string
		want engine.LineID
	}{{"com.netswitch.TestA", "b"}, {"com.netswitch.TestB", "c"}} {
		var r app.TCPResult
		e.RunJSON(Run{Program: "flatpak", Args: []string{"run", c.id, "app", "tcp", "--to", To(topo.Server4, wire.PortWhoami), "--count", "3"}, Timeout: 2 * time.Minute}, &r)
		lines := Lines(r.Seen)
		e.T.Check(r.OK == 3 && lines[c.want] == 3, "Flatpak %s (/app/bin/nsapp), pinned to %s: lines %s (errors %v)", c.id, c.want, Describe(lines), r.Errors)
	}
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
	tools := appImageTools[runtime.GOARCH]
	if tools == nil {
		e.T.Fatalf("no AppImage tooling pinned for %s", runtime.GOARCH)
	}
	work := filepath.Join(e.SharedDir(), "appimage")
	appDir := filepath.Join(work, "AppDir")
	if err := os.MkdirAll(filepath.Join(appDir, "usr", "bin"), 0o755); err != nil {
		e.T.Fatalf("%v", err)
	}
	for name, pin := range tools {
		data, err := singbox.Download(e.Ctx(), pin)
		if err != nil {
			e.T.Fatalf("%s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(work, name), data, 0o755); err != nil {
			e.T.Fatalf("%v", err)
		}
	}
	files := map[string]string{
		"AppRun":         "#!/bin/sh\nexec \"$APPDIR/usr/bin/nsapp\" \"$@\"\n",
		"nstool.desktop": "[Desktop Entry]\nType=Application\nName=NsTool\nExec=nsapp\nIcon=nstool\nCategories=Network;\n",
		"nstool.svg":     "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\"><rect width=\"64\" height=\"64\" fill=\"#3a6\"/></svg>\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(appDir, name), []byte(body), 0o755); err != nil {
			e.T.Fatalf("%v", err)
		}
	}
	if err := copyFile(e.cfg.Self, filepath.Join(appDir, "usr", "bin", "nsapp"), 0o755); err != nil {
		e.T.Fatalf("%v", err)
	}
	image := filepath.Join(work, "NsTool.AppImage")
	arch := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]
	ctx, cancel := context.WithTimeout(e.Ctx(), 3*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, filepath.Join(work, "appimagetool"), "--no-appstream", "--runtime-file", filepath.Join(work, "runtime"), appDir, image)
	build.Env = append(os.Environ(), "ARCH="+arch, "APPIMAGE_EXTRACT_AND_RUN=1")
	if out, err := build.CombinedOutput(); err != nil {
		e.T.Fatalf("appimagetool: %v: %s", err, truncate(out, 800))
	}
	if err := os.Chmod(image, 0o755); err != nil {
		e.T.Fatalf("%v", err)
	}
	cfg := e.DefaultConfig()
	// The mount folder is /tmp/.mount_NsTool<6 random characters>; what's
	// pinned is the registered AppImage, seen at any such folder.
	cfg.Policy.Pins = append(cfg.Policy.Pins, engine.Pin{App: engine.App{ID: "appimage:NsTool", Path: "/tmp/.mount_NsToolAAAAAA/usr/bin/nsapp"}, Line: "c"})
	e.StartEngine(cfg)
	for run := 1; run <= 2; run++ {
		var r app.TCPResult
		e.RunJSON(Run{Program: image, Args: []string{"app", "tcp", "--to", To(topo.Server4, wire.PortWhoami), "--count", "3"}, Timeout: 2 * time.Minute}, &r)
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
	e.Sleep(500 * time.Millisecond)
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

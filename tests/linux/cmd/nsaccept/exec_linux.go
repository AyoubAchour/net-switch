//go:build linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/AyoubAchour/net-switch/tests/linux/netns"
)

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// execMain is "nsaccept exec": start a program the way a desktop app runs on
// the fake PC. It moves into a cgroup (optional), enters the namespace, drops
// to the user, then execs the program, so the program itself is what the
// engine sees.
func execMain(args []string) error {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	ns := fs.String("netns", "", "network namespace to run in")
	uid := fs.Int("uid", -1, "run as this user (default: stay root)")
	gid := fs.Int("gid", -1, "and this group")
	cgroup := fs.String("cgroup", "", "cgroup v2 folder to move into first")
	var env listFlag
	fs.Var(&env, "env", "KEY=VALUE to add to the environment (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	argv := fs.Args()
	if len(argv) == 0 {
		return errors.New("usage: nsaccept exec [--netns NS] [--uid U --gid G] [--cgroup DIR] -- program [args...]")
	}
	if *cgroup != "" {
		if err := os.WriteFile(filepath.Join(*cgroup, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
			return fmt.Errorf("move into %s: %w", *cgroup, err)
		}
	}
	if *ns != "" {
		if err := netns.Enter(*ns); err != nil {
			return err
		}
	}
	vars := map[string]string{
		"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin",
		"LANG": "C.UTF-8",
	}
	if *uid >= 0 {
		if *gid < 0 {
			return errors.New("--uid needs --gid")
		}
		vars["HOME"] = "/"
		if u, err := user.LookupId(strconv.Itoa(*uid)); err == nil {
			vars["HOME"], vars["USER"], vars["LOGNAME"] = u.HomeDir, u.Username, u.Username
		}
		runtimeDir := fmt.Sprintf("/run/user/%d", *uid)
		if _, err := os.Stat(runtimeDir); err == nil {
			vars["XDG_RUNTIME_DIR"] = runtimeDir
			if _, err := os.Stat(runtimeDir + "/bus"); err == nil {
				vars["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + runtimeDir + "/bus"
			}
		}
	} else {
		vars["HOME"] = "/root"
	}
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("--env %q isn't KEY=VALUE", kv)
		}
		vars[k] = v
	}
	os.Setenv("PATH", vars["PATH"])
	program, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}
	if *uid >= 0 {
		if err := syscall.Setgroups([]int{*gid}); err != nil {
			return fmt.Errorf("setgroups: %w", err)
		}
		if err := syscall.Setgid(*gid); err != nil {
			return fmt.Errorf("setgid: %w", err)
		}
		if err := syscall.Setuid(*uid); err != nil {
			return fmt.Errorf("setuid: %w", err)
		}
	}
	envList := make([]string, 0, len(vars))
	for k, v := range vars {
		envList = append(envList, k+"="+v)
	}
	return syscall.Exec(program, argv, envList)
}

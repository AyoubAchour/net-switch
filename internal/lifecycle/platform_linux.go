package lifecycle

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/internal/platform"
	"github.com/AyoubAchour/net-switch/internal/platform/worker"
)

type linuxPlatform struct{ workers worker.Supervisor }

func nativePlatform(c Config, log func(string)) platform.System {
	return &linuxPlatform{workers: worker.Supervisor{Executable: filepath.Join(c.Directory, "netswitch-engine"), Log: func(err error) { log(err.Error()) }}}
}
func (p *linuxPlatform) Call(ctx context.Context, op string, args map[string]any) (any, error) {
	return p.workers.Once(ctx, op, args)
}
func (p *linuxPlatform) Stream(ctx context.Context, mode string, emit func([]byte), report func(error)) {
	p.workers.Stream(ctx, mode, nil, emit, report)
}
func linuxCall(op string, args map[string]any) (any, error) {
	switch op {
	case "elevated":
		return os.Geteuid() == 0, nil
	case "architecture":
		return runtime.GOARCH, nil
	case "policy":
		return nil, nil
	case "meters":
		interfaces, err := net.Interfaces()
		if err != nil {
			return nil, err
		}
		adapters := []any{}
		for _, nic := range interfaces {
			if nic.Flags&net.FlagLoopback != 0 || nic.Name == "NetSwitch" {
				continue
			}
			read := func(name string) (uint64, error) {
				b, err := os.ReadFile(filepath.Join("/sys/class/net", nic.Name, "statistics", name))
				if err != nil {
					return 0, err
				}
				return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
			}
			rx, rxErr := read("rx_bytes")
			tx, txErr := read("tx_bytes")
			if rxErr != nil || txErr != nil {
				return nil, fmt.Errorf("read %s counters: %w", nic.Name, errors.Join(rxErr, txErr))
			}
			adapters = append(adapters, map[string]any{"alias": nic.Name, "rx": rx, "tx": tx})
		}
		return map[string]any{"adapters": adapters}, nil
	case "network":
		interfaces, err := net.Interfaces()
		if err != nil {
			return nil, err
		}
		adapters := []any{}
		routes := []any{}
		defaults := map[string]string{}
		b, err := os.ReadFile("/proc/net/route")
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 4 && f[1] == "00000000" {
				gateway, err := strconv.ParseUint(f[2], 16, 32)
				if err == nil {
					defaults[f[0]] = net.IPv4(byte(gateway), byte(gateway>>8), byte(gateway>>16), byte(gateway>>24)).String()
				}
			}
		}
		for _, nic := range interfaces {
			if nic.Flags&net.FlagLoopback != 0 {
				continue
			}
			addresses, err := nic.Addrs()
			if err != nil {
				continue
			}
			ips := []any{}
			ipv6 := false
			for _, address := range addresses {
				ip, _, err := net.ParseCIDR(address.String())
				if err != nil {
					continue
				}
				if ip.To4() != nil {
					ips = append(ips, ip.String())
					if defaults[nic.Name] != "" {
						routes = append(routes, map[string]any{"interfaceAddress": ip.String(), "alias": nic.Name, "index": nic.Index})
					}
				} else if !ip.IsLinkLocalUnicast() {
					ipv6 = true
				}
			}
			status := "Down"
			if nic.Flags&net.FlagUp != 0 {
				status = "Up"
			}
			media := "Ethernet"
			if _, err := os.Stat(filepath.Join("/sys/class/net", nic.Name, "wireless")); err == nil {
				media = "Wireless"
			}
			adapters = append(adapters, map[string]any{"alias": nic.Name, "name": nic.Name, "index": nic.Index, "ipv4s": ips, "ipv6": ipv6, "status": status, "mediaType": media, "gateway": defaults[nic.Name]})
		}
		return map[string]any{"adapters": adapters, "defaultRoutes": routes, "readAt": time.Now().UnixMilli(), "policy": nil}, nil
	case "line-check":
		return map[string]any{"outcome": "engineUnavailable", "delay": nil}, nil
	case "stop-process":
		// Guarded adapter children cannot survive the engine service on Linux.
		// Never kill a PID from a previous boot or a legacy untrusted PID file.
		return nil, errors.New("legacy PID cleanup is not used by the service adapter")
	}
	return nil, fmt.Errorf("Linux operation %q is not available", op)
}
func Worker(args []string) int {
	if len(args) == 2 && args[0] == "query" {
		var input map[string]any
		err := json.NewDecoder(os.Stdin).Decode(&input)
		var value any
		if err == nil {
			value, err = linuxCall(args[1], input)
		}
		out := map[string]any{"value": value}
		if err != nil {
			out["error"] = err.Error()
		}
		if json.NewEncoder(os.Stdout).Encode(out) != nil {
			return 1
		}
		return 0
	}
	if len(args) == 1 && (args[0] == "network" || args[0] == "meters") {
		for {
			value, err := linuxCall(args[0], nil)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			if json.NewEncoder(os.Stdout).Encode(value) != nil {
				return 0
			}
			time.Sleep(2 * time.Second)
		}
	}
	fmt.Fprintln(os.Stderr, "unknown worker mode")
	return 2
}
func DesktopCall(_ context.Context, op string, args map[string]any) (any, error) {
	switch op {
	case "app-info":
		return []any{}, nil
	case "installed-apps":
		list := []any{}
		home, _ := os.UserHomeDir()
		for _, dir := range []string{"/usr/share/applications", filepath.Join(home, ".local/share/applications")} {
			files, _ := filepath.Glob(filepath.Join(dir, "*.desktop"))
			for _, path := range files {
				f, err := os.Open(path)
				if err != nil {
					continue
				}
				scan := bufio.NewScanner(f)
				name, command, hidden := "", "", false
				for scan.Scan() {
					line := scan.Text()
					if strings.HasPrefix(line, "Name=") {
						name = strings.TrimPrefix(line, "Name=")
					}
					if strings.HasPrefix(line, "Exec=") {
						command = strings.TrimPrefix(line, "Exec=")
					}
					hidden = hidden || line == "Hidden=true" || line == "NoDisplay=true"
				}
				f.Close()
				if !hidden && name != "" && command != "" {
					list = append(list, map[string]any{"name": name, "path": strings.Fields(command)[0], "key": filepath.Base(path)})
				}
			}
		}
		return list, nil
	case "autostart":
		return desktopAutostart(nil)
	case "autostart-set":
		value, _ := args["on"].(bool)
		return desktopAutostart(&value)
	case "autostart-upgrade":
		return "unchanged", nil
	}
	return nil, fmt.Errorf("desktop operation %q refused", op)
}

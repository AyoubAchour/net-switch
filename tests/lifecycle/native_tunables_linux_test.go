package lifecycle_test

import (
	"encoding/json"
	"maps"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/tests/linux/topo"
)

func nativeLinuxTun(t *testing.T, instance string) string {
	t.Helper()
	b, err := exec.Command("ip", "-n", topo.DUT, "-j", "link", "show").Output()
	if err != nil {
		t.Fatal(err)
	}
	var links []struct {
		Name  string `json:"ifname"`
		Alias string `json:"ifalias"`
	}
	if err := json.Unmarshal(b, &links); err != nil {
		t.Fatal(err)
	}
	name := ""
	for _, l := range links {
		if l.Alias == "netswitch:"+instance {
			if name != "" {
				t.Fatal("multiple TUNs claim the engine instance")
			}
			name = l.Name
		}
	}
	if name == "" {
		t.Fatal("journal-owned native TUN is absent", instance)
	}
	return name
}

func namespaceSysctl(t *testing.T, args ...string) string {
	t.Helper()
	b, err := exec.Command("ip", append([]string{"netns", "exec", topo.DUT, "sysctl"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatal("native sysctl fixture", err, string(b))
	}
	return strings.TrimSpace(string(b))
}

func prepareNativeTunables(t *testing.T) func(*testing.T, *nativeClient) {
	t.Helper()
	version, err := exec.Command("systemctl", "--version").Output()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("NATIVE_SANDBOX systemd=%s", strings.SplitN(string(version), "\n", 2)[0])
	kernel, err := exec.Command("uname", "-r").Output()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("NATIVE_SANDBOX kernel=%s", strings.TrimSpace(string(kernel)))
	// Existing physical lines retain their usable IPv6 addresses. Every new
	// device must inherit disabled IPv6, so a no-op write cannot pass this case.
	const inherited = "net.ipv6.conf.default.disable_ipv6"
	old := namespaceSysctl(t, "-n", inherited)
	namespaceSysctl(t, "-w", inherited+"=1")
	t.Cleanup(func() { namespaceSysctl(t, "-w", inherited+"="+old) })
	keys := []string{
		"net.ipv4.ip_forward", "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter", "net.ipv4.conf.eth-a.rp_filter",
		"net.ipv4.ping_group_range", "net.ipv6.conf.all.disable_ipv6", inherited,
		"net.ipv6.conf.eth-a.disable_ipv6", "net.ipv6.conf.eth-b.disable_ipv6",
		"net.ipv6.conf.all.forwarding", "net.ipv6.conf.default.forwarding", "net.ipv6.conf.eth-a.forwarding",
		"net.ipv6.conf.all.accept_ra", "net.ipv6.conf.default.accept_ra", "net.ipv6.conf.eth-a.accept_ra",
	}
	read := func(t *testing.T) map[string]string {
		result := map[string]string{}
		for _, line := range strings.Split(namespaceSysctl(t, keys...), "\n") {
			key, value, ok := strings.Cut(line, " = ")
			if !ok {
				t.Fatal("invalid sysctl observation", line)
			}
			result[key] = value
		}
		if len(result) != len(keys) || result[inherited] != "1" {
			t.Fatal("disabled-IPv6 inheritance precondition missing", result)
		}
		return result
	}
	before := read(t)
	return func(t *testing.T, c *nativeClient) {
		t.Helper()
		after := read(t)
		if !maps.Equal(before, after) {
			t.Fatal("native engine changed global or physical-interface tunables", before, after)
		}
		if c == nil {
			return
		}
		name := nativeLinuxTun(t, c.instance)
		if got := namespaceSysctl(t, "-n", "net.ipv6.conf."+name+".disable_ipv6"); got != "0" {
			t.Fatal("installed service did not enable its own TUN", got)
		}
		log, err := exec.Command("journalctl", "-u", "netswitch-engine.service", "--no-pager", "--output=cat", "--lines=80").Output()
		proof := "instance=" + c.instance + " name=" + name + " disable_ipv6_before=1 after=0 wrote=true"
		if err != nil || !strings.Contains(string(log), proof) {
			t.Fatal("installed service did not prove the inherited 1-to-0 write", err, string(log))
		}
		b, err := exec.Command("systemctl", "show", "netswitch-engine.service", "--property=ProtectKernelTunables,ProtectControlGroups,ReadWritePaths,ReadOnlyPaths").Output()
		if err != nil || !strings.Contains(string(b), "ProtectKernelTunables=yes") || !strings.Contains(string(b), "ProtectControlGroups=yes") {
			t.Fatal("installed unit lost kernel hardening", string(b), err)
		}
		t.Logf("NATIVE_SANDBOX tun=%s inherited_disabled=1 enabled=0 unchanged_global_and_line_settings=%d unit=%q", name, len(after), b)
		if os.Getenv("NETSWITCH_NATIVE_FAULTS") == "1" {
			var result map[string]string
			nativeMust(t, c, "testFault", map[string]any{"fault": map[string]any{"kind": "kernel-sandbox"}}, &result)
			owned := "/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6"
			if len(result) != 10 || result[owned] != "writable" {
				t.Fatal("missing live engine sandbox evidence", result)
			}
			for path, mode := range result {
				if path != owned && mode != "read-only" {
					t.Fatal("kernel protection failed in installed engine", path, mode)
				}
			}
			t.Logf("NATIVE_SANDBOX engine_write_opens=%v bytes_written_by_probe=0", result)
		}
	}
}

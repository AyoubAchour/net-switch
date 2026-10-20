//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/winclock"
)

func TestUDPGenerationCollisionWindow(t *testing.T) {
	hosted(t)
	if os.Getenv("NETSWITCH_PORT_GATE") != "1" {
		t.Skip("timestamp-window measurement runs in the native diagnostic job")
	}
	owners := NewOwners()
	for _, gap := range []time.Duration{0, 100 * time.Microsecond, 250 * time.Microsecond, 500 * time.Microsecond,
		time.Millisecond, 2 * time.Millisecond, 5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond} {
		trials := 32
		if gap == 0 {
			trials = 100
		}
		collisions := 0
		var longestCollisionLower, longestCollisionUpper, maxGap time.Duration
		minGap := time.Hour
		for range trials {
			firstBefore := winclock.Now()
			first, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
			firstAfter := winclock.Now()
			if err != nil {
				t.Fatal(err)
			}
			port := first.LocalAddr().(*net.UDPAddr).Port
			key := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
			ownerA, err := owners.UDP(context.Background(), key)
			first.Close()
			if err != nil {
				t.Fatal(err)
			}
			if gap != 0 {
				if err := winclock.System.Wait(context.Background(), gap); err != nil {
					t.Fatal(err)
				}
			}
			secondBefore := winclock.Now()
			second, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
			secondAfter := winclock.Now()
			if err != nil {
				t.Fatal(err)
			}
			ownerB, err := owners.UDP(context.Background(), key)
			second.Close()
			if err != nil || ownerB.PID != ownerA.PID || ownerB.StartTime != ownerA.StartTime ||
				ownerA.Generation == "" || ownerB.Generation == "" {
				t.Fatalf("native identity lost: first=%+v second=%+v error=%v", ownerA, ownerB, err)
			}
			lower, upper := secondBefore-firstAfter, secondAfter-firstBefore
			minGap, maxGap = min(minGap, lower), max(maxGap, upper)
			if ownerA.Generation == ownerB.Generation {
				collisions++
				longestCollisionLower = max(longestCollisionLower, lower)
				longestCollisionUpper = max(longestCollisionUpper, upper)
			}
		}
		evidence, _ := json.Marshal(map[string]any{"requestedGapNanos": gap.Nanoseconds(), "trials": trials, "collisions": collisions,
			"observedGapMinNanos": minGap.Nanoseconds(), "observedGapMaxNanos": maxGap.Nanoseconds(),
			"longestCollisionLowerNanos": longestCollisionLower.Nanoseconds(), "longestCollisionUpperNanos": longestCollisionUpper.Nanoseconds()})
		t.Logf("WINDOWS UDP TIMESTAMP WINDOW %s", evidence)
	}
}

func TestUDPIdentityNativePeer(t *testing.T) {
	portText := os.Getenv("NETSWITCH_UDP_IDENTITY_PEER")
	if portText == "" {
		t.Skip("helper process only")
	}
	hosted(t)
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := json.NewEncoder(os.Stdout).Encode(conn.LocalAddr().(*net.UDPAddr).Port); err != nil {
		t.Fatal(err)
	}
	var stop [1]byte
	os.Stdin.Read(stop[:]) // Parent closes stdin; process exit closes the socket.
}

func TestUDPIdentityDetectsRestartedProcess(t *testing.T) {
	hosted(t)
	owners := NewOwners()
	var previous platform.Owner
	port := 0
	for round := range 3 {
		command := exec.Command(os.Args[0], "-test.run=^TestUDPIdentityNativePeer$")
		command.Env = append(os.Environ(), "NETSWITCH_UDP_IDENTITY_PEER="+strconv.Itoa(port))
		input, err := command.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		output, err := command.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		command.Stderr = os.Stderr
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				input.Close()
				io.Copy(io.Discard, output)
				if err := command.Wait(); err != nil {
					t.Error(err)
				}
			}()
			if err := json.NewDecoder(output).Decode(&port); err != nil {
				t.Fatal(err)
			}
			key := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
			owner, err := owners.UDP(context.Background(), key)
			if err != nil || owner.PID != uint32(command.Process.Pid) || owner.Generation == "" || owner.StartTime == 0 {
				t.Fatalf("new process was not attributed: %+v %v", owner, err)
			}
			snapshot, err := owners.Snapshot(context.Background(), []netip.AddrPort{key})
			if err != nil || snapshot[key] != owner {
				t.Fatalf("periodic snapshot missed the process: %+v %v", snapshot, err)
			}
			if round != 0 && (owner.PID == previous.PID && owner.StartTime == previous.StartTime) {
				t.Fatalf("restarted process inherited its predecessor: %+v %+v", previous, owner)
			}
			t.Logf("restarted UDP process round=%d port=%d pid=%d start=%d timestamp=%s", round, port, owner.PID, owner.StartTime, owner.Generation)
			previous = owner
		}()
	}
}

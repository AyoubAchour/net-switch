//go:build windows

package winengine

import (
	"encoding/hex"
	"os"
	"sync"
	"time"
)

type tracedPacket struct {
	At        int64  `json:"at"`
	Direction string `json:"direction"`
	Bytes     int    `json:"bytes"`
	Header    string `json:"header"`
	Written   int    `json:"batchWritten"`
	Batch     int    `json:"batchPackets"`
	Error     string `json:"error,omitempty"`
}

type packetTrace struct {
	mu      sync.Mutex
	records [1024]tracedPacket
	seen    uint64
}

func newPacketTrace() *packetTrace {
	if !hostedTraceEnabled() {
		return nil
	}
	return &packetTrace{}
}

func hostedTraceEnabled() bool {
	return os.Getenv("NETSWITCH_ENGINE_TEST_TRACE") == "1" && os.Getenv("GITHUB_ACTIONS") == "true" && os.Getenv("RUNNER_ENVIRONMENT") == "github-hosted"
}

// Hosted diagnostics only. Observe the controlled responder's UDP/ICMP and
// TCP SYN/RST headers
// at the real Wintun boundary, without altering packets or doing any I/O here.
func (t *packetTrace) record(direction string, packet []byte, written, batch int, err error) {
	if t == nil || len(packet) < 20 || packet[0]>>4 != 4 {
		return
	}
	if packet[9] == 6 {
		offset := int(packet[0]&15) * 4
		if offset < 20 || len(packet) < offset+20 || packet[offset+13]&0x06 == 0 {
			return
		}
	} else if packet[9] != 1 && packet[9] != 17 {
		return
	}
	target := [4]byte{198, 19, 128, 2}
	if [4]byte(packet[12:16]) != target && [4]byte(packet[16:20]) != target {
		return
	}
	r := tracedPacket{At: time.Now().UnixMilli(), Direction: direction, Bytes: len(packet),
		Header: hex.EncodeToString(packet[:min(96, len(packet))]), Written: written, Batch: batch}
	if err != nil {
		r.Error = err.Error()
	}
	t.mu.Lock()
	t.records[t.seen%uint64(len(t.records))] = r
	t.seen++
	t.mu.Unlock()
}

func (t *packetTrace) snapshot() any {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	count := min(t.seen, uint64(len(t.records)))
	records := make([]tracedPacket, 0, count)
	for i := t.seen - count; i < t.seen; i++ {
		records = append(records, t.records[i%uint64(len(t.records))])
	}
	return map[string]any{"seen": t.seen, "records": records}
}

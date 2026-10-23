//go:build windows

package winengine

import (
	"encoding/json"
	"log"
	"os"
	"runtime"
	"time"
)

// Read-only, trace-only inventory. TryLock avoids turning an observation into
// a dependency of cleanup. Counts cover all registrations; details have a cap.
func (d *Dialer) retirementReferences() {
	if !hostedTraceEnabled() {
		return
	}
	result := map[string]any{"pid": os.Getpid(), "utc": time.Now().UTC(), "submitted": d.pool.submitted.Load(), "completed": d.pool.completed.Load()}
	var watches []*socketWatch
	if d.pool.mu.TryLock() {
		result["tcpRegistrations"], result["tcpWriters"] = len(d.pool.watches), len(d.pool.writers)
		for _, w := range d.pool.watches {
			if len(watches) < 128 {
				watches = append(watches, w)
			}
		}
		d.pool.mu.Unlock()
	} else {
		result["tcpInventoryBusy"] = true
	}
	details := []map[string]any{}
	for _, w := range watches {
		if w.mu.TryLock() {
			row := map[string]any{"key": w.key, "pending": w.pending, "connecting": w.connecting, "detached": w.detached}
			if !w.detached {
				row["handle"] = uint64(w.socket.Handle("retirement TCP inventory"))
			}
			details = append(details, row)
			w.mu.Unlock()
		} else {
			details = append(details, map[string]any{"key": w.key, "busy": true})
		}
	}
	result["tcpOperations"] = details
	udp, busy := 0, 0
	udpDetails := []map[string]any{}
	for i := range d.udp.shards {
		s := &d.udp.shards[i]
		if s.mu.TryLock() {
			udp += len(s.watches)
			for w := range s.watches {
				if len(udpDetails) < 128 {
					udpDetails = append(udpDetails, map[string]any{"handle": uint64(w.socket.Handle("retirement UDP inventory")), "events": w.events, "detached": w.detached})
				}
			}
			s.mu.Unlock()
		} else {
			busy++
		}
	}
	result["udpRegistrations"], result["udpBusyShards"] = udp, busy
	result["udpOperations"] = udpDetails
	stacks := make([]byte, 256<<10)
	n := runtime.Stack(stacks, true)
	result["stacks"], result["stacksTruncated"] = string(stacks[:n]), n == len(stacks)
	b, _ := json.Marshal(result)
	log.Printf("WINDOWS RETIREMENT REFERENCES %s", b)
}

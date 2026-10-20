//go:build windows

package winengine

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"golang.org/x/sys/windows"
)

type lookupFailure struct {
	At         time.Time      `json:"at"`
	Kind       string         `json:"kind"`
	Stage      string         `json:"stage"`
	Source     netip.AddrPort `json:"source"`
	Error      string         `json:"error"`
	Code       uint32         `json:"code,omitempty"`
	Deadline   bool           `json:"deadline,omitempty"`
	Generation string         `json:"generation,omitempty"`
}

func (o *Owners) noteFailure(kind, stage string, source netip.AddrPort, generation string, err error) {
	if err == nil {
		return
	}
	value := lookupFailure{At: time.Now(), Kind: kind, Stage: stage, Source: source,
		Error: err.Error(), Deadline: errors.Is(err, context.DeadlineExceeded), Generation: generation}
	var code windows.Errno
	if errors.As(err, &code) {
		value.Code = uint32(code)
	}
	o.mu.Lock()
	o.failures[o.failureCount%uint64(len(o.failures))] = value
	o.failureCount++
	o.mu.Unlock()
}

func (o *Owners) failureSnapshot() []lookupFailure {
	o.mu.Lock()
	defer o.mu.Unlock()
	var result []lookupFailure
	for i := o.failureCount - min(o.failureCount, uint64(len(o.failures))); i < o.failureCount; i++ {
		result = append(result, o.failures[i%uint64(len(o.failures))])
	}
	return result
}

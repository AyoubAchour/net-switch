//go:build linux

package linux

import (
	"context"
	"time"
)

// A burst must not park hundreds of scanners behind the same process gate.
// Queue time remains inside the original lookup deadline. A published inode
// wakes its own queued lookup without requiring a scanner slot.
func (o *Owners) beginScan(ctx context.Context, ready <-chan struct{}) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	select {
	case <-ready:
		return false, nil
	default:
	}
	select {
	case o.scanSlots <- struct{}{}:
		return true, nil
	default:
	}
	o.scanQueueWaits.Add(1)
	started := time.Now()
	defer func() {
		elapsed := uint64(time.Since(started))
		o.scanQueueNanos.Add(elapsed)
		recordLookupMaximum(&o.scanQueueMaximum, elapsed)
	}()
	select {
	case o.scanSlots <- struct{}{}:
		if err := ctx.Err(); err != nil {
			o.endScan()
			o.scanQueueTimeouts.Add(1)
			return false, err
		}
		return true, nil
	case <-ready:
		return false, nil
	case <-ctx.Done():
		o.scanQueueTimeouts.Add(1)
		return false, ctx.Err()
	}
}

func (o *Owners) endScan() { <-o.scanSlots }

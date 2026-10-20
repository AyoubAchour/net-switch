//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/AyoubAchour/net-switch/internal/wintun"
	"golang.org/x/sys/windows"
)

type bindingTable map[string]Adapter

type Routes struct {
	Instance    string
	mu          sync.Mutex
	session     *journal.Session
	objects     *objects
	tun         *wintun.Session
	lines       []platform.Line
	bindings    atomic.Pointer[bindingTable]
	active      atomic.Bool
	capture     []journal.Fingerprint
	permissions []journal.Creation
	cancel      context.CancelFunc
	done        chan struct{}
	Table       *flows.Table
	Fatal       func(error)
	timings     *phaseTimings
	trace       *packetTrace
}

func NewRoutes(store journal.Store, lock journal.Locker, instance string) (*Routes, error) {
	timings := &phaseTimings{values: map[string]phaseTiming{}}
	defer timings.begin("recovery.total")()
	o := &objects{recovering: true, timings: timings}
	j := &journal.Journal{Store: measuredJournalStore{Store: store, timings: timings, beforeRemoved: o.commitFirewallBatch},
		Lock: lock, Kinds: make(map[string]journal.Object)}
	for _, kind := range []string{"adapter", "interface", "dns", "address", "route", "wfp-sublayer", "wfp-filter"} {
		j.Kinds[kind] = object{o, kind}
	}
	// The precise boot identity is persisted for diagnosis; the complete live
	// object identity, not boot age, governs deletion.
	boot, err := bootIdentity()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := j.Open(ctx, boot, instance)
	if err != nil {
		return nil, err
	}
	if err := s.Cleanup(ctx); err != nil {
		s.Close()
		return nil, fmt.Errorf("engine crash recovery: %w", errors.Join(err, o.closeFirewall()))
	}
	o.recovering = false
	r := &Routes{Instance: instance, session: s, objects: o, timings: timings, trace: newPacketTrace()}
	b := bindingTable{}
	r.bindings.Store(&b)
	return r, nil
}

func (r *Routes) Close() error {
	return errors.Join(r.Cleanup(context.Background()), r.session.Close(), r.objects.closeFirewall())
}

func (r *Routes) OpenTun(ctx context.Context) (platform.TunDevice, error) {
	defer r.timings.begin("tun.setup.total")()
	r.mu.Lock()
	defer r.mu.Unlock()
	tun, err := r.openTun(ctx)
	if err != nil {
		r.objects.recovering = true
		cleanup := r.session.Cleanup(context.WithoutCancel(ctx))
		r.objects.recovering = false
		return nil, errors.Join(err, cleanup)
	}
	return tun, nil
}

func (r *Routes) openTun(ctx context.Context) (platform.TunDevice, error) {
	fp := journal.Fingerprint{"name": "NetSwitch", "guid": wintun.DefaultGUID, "driver": "Wintun"}
	if err := r.session.Create(ctx, "adapter", fp); err != nil {
		return nil, err
	}
	a := r.objects.adapter
	var index uint32
	luid := a.LUID()
	if err := api("ConvertInterfaceLuidToIndex", uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&index))); err != nil {
		return nil, err
	}
	base := journal.Fingerprint{"guid": wintun.DefaultGUID, "luid": number(luid), "index": number(uint64(index))}
	var setup []journal.Creation
	for _, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
		fp := maps.Clone(base)
		fp["family"] = number(uint64(family))
		finish := r.timings.begin("interface.inspect")
		row, err := readInterface(fp)
		finish()
		if err != nil {
			return nil, err
		}
		before, err := json.Marshal(settings(row))
		if err != nil {
			return nil, err
		}
		fp["before"] = string(before)
		if settings(row) != desiredInterface() {
			setup = append(setup, journal.Creation{Kind: "interface", Fingerprint: maps.Clone(fp)})
		}
		finish = r.timings.begin("dns.inspect")
		registration, err := dnsRegistration(fp)
		finish()
		if err != nil {
			return nil, err
		}
		fp["before"] = number(uint64(registration))
		if registration != 0 {
			setup = append(setup, journal.Creation{Kind: "dns", Fingerprint: maps.Clone(fp)})
		}
	}
	for _, prefix := range []string{"198.18.0.1/30", "fdfe:dcba:9876::1/126"} {
		fp := maps.Clone(base)
		fp["prefix"] = prefix
		setup = append(setup, journal.Creation{Kind: "address", Fingerprint: fp})
	}
	layer := journal.Creation{Kind: "wfp-sublayer", Fingerprint: wfpLayerFingerprint(r.Instance)}
	filters := wfpFilterFingerprints(r.Instance, luid, index)
	setup = append(setup, layer)
	setup = append(setup, filters...)
	if err := func() (err error) {
		r.objects.wfpCreates = 1 + len(filters)
		defer func() { err = errors.Join(err, r.objects.abortFirewallBatch()) }()
		return r.session.CreateBatch(ctx, setup)
	}(); err != nil {
		return nil, err
	}
	r.permissions = append([]journal.Creation{layer}, filters...)
	finish := r.timings.begin("tun.session.open")
	s, err := a.StartSession()
	finish()
	if err != nil {
		return nil, err
	}
	r.tun = s
	r.capture = nil
	for _, prefix := range CapturePrefixes() {
		fp := maps.Clone(base)
		fp["prefix"], fp["metric"], fp["protocol"] = prefix.String(), "0", "3"
		fp["nextHop"] = "0.0.0.0"
		if prefix.Addr().Is6() {
			fp["nextHop"] = "::"
		}
		r.capture = append(r.capture, fp)
	}
	// Session.Close leaves adapter ownership with the journal. Cleanup first
	// removes capture, then addresses/settings, then the adapter itself.
	return &measuredTun{Session: s, timings: r.timings, trace: r.trace}, nil
}

func (r *Routes) Bindings() map[string]Adapter {
	return maps.Clone(*r.bindings.Load())
}

func (r *Routes) TunStats() wintun.Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tun == nil {
		return wintun.Stats{}
	}
	return r.tun.Stats()
}

func (r *Routes) resolve(lines []platform.Line) (bindingTable, error) {
	adapters, err := readAdapters()
	if err != nil {
		return nil, err
	}
	b := make(bindingTable, len(lines))
	for _, l := range lines {
		identity := l.Interface
		if identity == "" {
			identity = l.ID
		}
		for _, a := range adapters {
			if identity == a.ID || identity == a.Alias {
				b[l.ID] = a
				break
			}
		}
	}
	return b, nil
}
func (r *Routes) Prepare(ctx context.Context, lines []platform.Line) error {
	defer r.timings.begin("lines.prepare")()
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	b, err := r.resolve(lines)
	if err != nil {
		return err
	}
	r.lines = slices.Clone(lines)
	r.bindings.Store(&b)
	return nil
}
func (r *Routes) Capture(ctx context.Context) error {
	defer r.timings.begin("route.capture.total")()
	r.mu.Lock()
	defer r.mu.Unlock()
	capture := make([]journal.Creation, 0, len(r.capture))
	for _, fp := range r.capture {
		capture = append(capture, journal.Creation{Kind: "route", Fingerprint: fp})
	}
	if err := r.session.CreateBatch(ctx, capture); err != nil {
		return err
	}
	run, cancel := context.WithCancel(context.Background())
	r.cancel, r.done = cancel, make(chan struct{})
	r.active.Store(true)
	go r.monitor(run, r.done)
	return nil
}

func (r *Routes) monitor(ctx context.Context, done chan struct{}) {
	defer close(done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		r.mu.Lock()
		b, err := r.resolve(r.lines)
		old := r.bindings.Load()
		if err == nil {
			r.bindings.Store(&b)
			for id, previous := range *old {
				current, ok := b[id]
				if (!ok || !current.Up || current.LUID != previous.LUID) && r.Table != nil {
					r.Table.CloseFlows(flows.Selector{Line: id}, 0)
				} else if r.Table != nil {
					for _, addr := range previous.Addresses {
						if !slices.Contains(current.Addresses, addr) {
							r.Table.CloseFlows(flows.Selector{Source: addr}, 0)
						}
					}
				}
			}
		}
		// A down Wintun adapter is not a removed adapter. Its session remains
		// registered until the ordered reader gets ErrAdapterRemoved. Restore
		// lost owned routes when it comes back; never create a new session
		// merely because GetIfEntry2 reports down.
		up := false
		if err == nil && r.objects.adapter != nil {
			row := windows.MibIfRow2{InterfaceLuid: r.objects.adapter.LUID()}
			err = windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &row)
			if missing(err) {
				err = nil
			} else {
				up = err == nil && row.OperStatus == windows.IfOperStatusUp
			}
		}
		if err == nil && up {
			for _, permission := range r.permissions {
				live, found, inspectErr := (object{r.objects, permission.Kind}).Inspect(ctx, permission.Fingerprint)
				if inspectErr != nil {
					err = inspectErr
					break
				}
				if !found {
					if err = r.session.Create(ctx, permission.Kind, permission.Fingerprint); err != nil {
						break
					}
				} else if !maps.Equal(live, permission.Fingerprint) {
					err = errors.New("owned WFP ICMP permission changed")
					break
				}
			}
		}
		if err == nil && up {
			for _, fp := range r.capture {
				live, found, inspectErr := (object{r.objects, "route"}).Inspect(ctx, fp)
				if inspectErr != nil {
					err = inspectErr
					break
				}
				if !found {
					if err = r.session.Create(ctx, "route", fp); err != nil {
						break
					}
				} else if !maps.Equal(live, fp) {
					err = fmt.Errorf("owned capture route changed: found=%t expected=%v observed=%v", found, fp, live)
					break
				}
			}
		}
		fatal := r.Fatal
		r.mu.Unlock()
		if err != nil && ctx.Err() == nil && fatal != nil {
			fatal(err)
			return
		}
	}
}

func (r *Routes) Quiesce() {
	r.active.Store(false)
	r.mu.Lock()
	cancel, done := r.cancel, r.done
	r.cancel, r.done = nil, nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func (r *Routes) Cleanup(ctx context.Context) (err error) {
	defer r.timings.begin("cleanup.total")()
	r.Quiesce()
	r.mu.Lock()
	defer r.mu.Unlock()
	if tun := r.tun; tun != nil {
		// Join even if journal reading or a mutation fails. The adapter's
		// Remove also joins before destroying its device, so native rings
		// cannot outlive the final stop acknowledgement or lose an error.
		defer func() {
			finish := r.timings.begin("tun.session.join.wait")
			err = errors.Join(err, tun.Close())
			finish()
		}()
	}
	r.objects.recovering = true
	err = r.session.Cleanup(ctx)
	r.objects.recovering = false
	if err == nil {
		r.capture = nil
		r.permissions = nil
		r.tun = nil
	}
	return err
}

func (r *Routes) binding(line string, v6 bool) (Adapter, netip.Addr, error) {
	b := r.bindings.Load()
	if b == nil {
		return Adapter{}, netip.Addr{}, errors.New("line bindings not ready")
	}
	a, ok := (*b)[line]
	if !ok || !a.Up || (v6 && (!a.Default6 || a.Index6 == 0)) || (!v6 && (!a.Default4 || a.Index4 == 0)) {
		return Adapter{}, netip.Addr{}, fmt.Errorf("line %q has no usable default on its own interface", line)
	}
	for _, addr := range a.Addresses {
		if addr.Is6() == v6 {
			return a, addr, nil
		}
	}
	return Adapter{}, netip.Addr{}, fmt.Errorf("line %q has no source address for this family", line)
}

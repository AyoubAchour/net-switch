//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/netip"
	"runtime"
	"strconv"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/AyoubAchour/net-switch/internal/wintun"
	"golang.org/x/sys/windows"
)

func number(v uint64) string { return strconv.FormatUint(v, 10) }
func uintField(fp journal.Fingerprint, key string) uint64 {
	n, _ := strconv.ParseUint(fp[key], 10, 64)
	return n
}

type objects struct {
	adapter              *wintun.Adapter
	recovering           bool
	timings              *phaseTimings
	wfp                  windows.Handle
	wfpBatch             bool
	wfpCreates           int
	retirementReferences func()
	adapterLUID          uint64
	saveAdapterLUID      func(uint64) error
}
type object struct {
	all  *objects
	kind string
}

func (o object) Validate(fp journal.Fingerprint) error {
	if o.kind == "wfp-sublayer" || o.kind == "wfp-filter" {
		return validateWFP(o.kind, fp)
	}
	if fp["guid"] != wintun.DefaultGUID {
		return errors.New("journal object is not the engine's fixed GUID")
	}
	if o.kind == "adapter" {
		if len(fp) != 3 || fp["name"] != "NetSwitch" || fp["driver"] != "Wintun" {
			return errors.New("invalid adapter fingerprint")
		}
		return nil
	}
	if uintField(fp, "luid") == 0 || uintField(fp, "index") == 0 {
		return errors.New("missing interface identity")
	}
	switch o.kind {
	case "route":
		p, err := netip.ParsePrefix(fp["prefix"])
		if err != nil || p != p.Masked() {
			return errors.New("invalid route prefix")
		}
		next, err := netip.ParseAddr(fp["nextHop"])
		if err != nil || !next.IsUnspecified() || next.Is4() != p.Addr().Is4() || fp["metric"] != "0" || fp["protocol"] != "3" {
			return errors.New("invalid capture route")
		}
	case "address":
		if fp["prefix"] != "198.18.0.1/30" && fp["prefix"] != "fdfe:dcba:9876::1/126" {
			return errors.New("invalid TUN address")
		}
	case "interface":
		var before interfaceSettings
		if err := json.Unmarshal([]byte(fp["before"]), &before); err != nil {
			return err
		}
		if fp["family"] != "2" && fp["family"] != "23" {
			return errors.New("invalid interface family")
		}
	case "dns":
		if fp["family"] != "2" && fp["family"] != "23" {
			return errors.New("invalid DNS family")
		}
		if fp["before"] != "0" && fp["before"] != "1" {
			return errors.New("invalid DNS registration value")
		}
	default:
		return errors.New("unknown Windows journal object")
	}
	return nil
}

func missing(err error) bool {
	return errors.Is(err, windows.ERROR_NOT_FOUND) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}

func interfaceMatches(fp journal.Fingerprint) (bool, error) {
	guid, err := interfaceGUID(uintField(fp, "luid"))
	if missing(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if guid != fp["guid"] {
		return false, nil
	}
	var index uint32
	luid := uintField(fp, "luid")
	err = api("ConvertInterfaceLuidToIndex", uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&index)))
	return err == nil && uint64(index) == uintField(fp, "index"), err
}

func routeRow(fp journal.Fingerprint) windows.MibIpForwardRow2 {
	var r windows.MibIpForwardRow2
	iphlp.NewProc("InitializeIpForwardEntry").Call(uintptr(unsafe.Pointer(&r)))
	p := netip.MustParsePrefix(fp["prefix"])
	r.InterfaceLuid, r.InterfaceIndex = uintField(fp, "luid"), uint32(uintField(fp, "index"))
	r.DestinationPrefix = windows.IpAddressPrefix{Prefix: sockaddr(p.Addr()), PrefixLength: uint8(p.Bits())}
	r.NextHop = sockaddr(netip.MustParseAddr(fp["nextHop"]))
	r.Metric, r.Protocol = uint32(uintField(fp, "metric")), uint32(uintField(fp, "protocol"))
	// InitializeIpForwardEntry enables these flags. Capture routes must not
	// autoconfigure addresses, publish themselves, or become loopback routes.
	r.Loopback, r.AutoconfigureAddress, r.Publish, r.Immortal = 0, 0, 0, 1
	r.SitePrefixLength = 0
	return r
}

func addressRow(fp journal.Fingerprint) windows.MibUnicastIpAddressRow {
	var r windows.MibUnicastIpAddressRow
	iphlp.NewProc("InitializeUnicastIpAddressEntry").Call(uintptr(unsafe.Pointer(&r)))
	p := netip.MustParsePrefix(fp["prefix"])
	raw := sockaddr(p.Addr())
	r.Address = *(*windows.RawSockaddrInet6)(unsafe.Pointer(&raw))
	r.InterfaceLuid, r.InterfaceIndex = uintField(fp, "luid"), uint32(uintField(fp, "index"))
	r.OnLinkPrefixLength = uint8(p.Bits())
	r.PrefixOrigin, r.SuffixOrigin = 1, 1 // IpPrefixOriginManual, IpSuffixOriginManual.
	r.DadState = windows.IpDadStatePreferred
	return r
}

type interfaceSettings struct {
	MTU             uint32
	Metric          uint32
	Automatic       uint8
	DAD             uint32
	RouterDiscovery uint32
}

func settings(r windows.MibIpInterfaceRow) interfaceSettings {
	return interfaceSettings{r.NlMtu, r.Metric, r.UseAutomaticMetric, r.DadTransmits, r.RouterDiscoveryBehavior}
}
func desiredInterface() interfaceSettings {
	return interfaceSettings{MTU: 9000, Metric: 0, RouterDiscovery: 0}
}
func putSettings(r *windows.MibIpInterfaceRow, s interfaceSettings) {
	r.NlMtu, r.Metric, r.UseAutomaticMetric, r.DadTransmits, r.RouterDiscoveryBehavior = s.MTU, s.Metric, s.Automatic, s.DAD, s.RouterDiscovery
	// Windows requires zero for IPv4, even when Get returns a nonzero value.
	if r.Family == windows.AF_INET {
		r.SitePrefixLength = 0
	}
}
func readInterface(fp journal.Fingerprint) (windows.MibIpInterfaceRow, error) {
	r := windows.MibIpInterfaceRow{Family: uint16(uintField(fp, "family")), InterfaceLuid: uintField(fp, "luid"), InterfaceIndex: uint32(uintField(fp, "index"))}
	err := windows.GetIpInterfaceEntry(&r)
	return r, err
}

type dnsSettings struct {
	Version                                      uint32
	Flags                                        uint64
	Domain, NameServer, SearchList               *uint16
	Registration, RegisterName, LLMNR, QueryName uint32
	Profile                                      *uint16
}

// GUID is passed by value in these APIs. Windows x64 passes a pointer to a
// 16-byte aggregate; ARM64 uses two integer registers.
func dnsCall(name string, guid windows.GUID, s *dnsSettings) error {
	if runtime.GOARCH == "arm64" {
		words := *(*[2]uint64)(unsafe.Pointer(&guid))
		return api(name, uintptr(words[0]), uintptr(words[1]), uintptr(unsafe.Pointer(s)))
	}
	return api(name, uintptr(unsafe.Pointer(&guid)), uintptr(unsafe.Pointer(s)))
}
func dnsRegistration(fp journal.Fingerprint) (uint32, error) {
	guid, _ := windows.GUIDFromString(fp["guid"])
	s := dnsSettings{Version: 1}
	if fp["family"] == "23" {
		s.Flags = 1
	}
	err := dnsCall("GetInterfaceDnsSettings", guid, &s)
	if err != nil {
		return 0, err
	}
	defer iphlp.NewProc("FreeInterfaceDnsSettings").Call(uintptr(unsafe.Pointer(&s)))
	return s.Registration, nil
}
func setDNS(fp journal.Fingerprint, registration uint32) error {
	guid, _ := windows.GUIDFromString(fp["guid"])
	s := dnsSettings{Version: 1, Flags: 8, Registration: registration}
	if fp["family"] == "23" {
		s.Flags |= 1
	}
	return dnsCall("SetInterfaceDnsSettings", guid, &s)
}

func (o object) Inspect(ctx context.Context, fp journal.Fingerprint) (journal.Fingerprint, bool, error) {
	defer o.all.timings.begin(o.kind + ".fingerprint.inspect")()
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if o.kind == "wfp-sublayer" || o.kind == "wfp-filter" {
		return inspectWFP(o.all, o.kind, fp)
	}
	if o.kind == "adapter" {
		if o.all.adapter != nil {
			return maps.Clone(fp), true, nil
		}
		if o.all.recovering {
			return maps.Clone(fp), true, nil
		}
		present, err := nativeAdapterPresent(fp["guid"], fp["name"], o.all.adapterLUID)
		other := maps.Clone(fp)
		if present {
			other["foreignLuid"] = number(o.all.adapterLUID)
		}
		return other, present, err
	}
	match, err := interfaceMatches(fp)
	if err != nil || !match {
		return nil, false, err
	}
	live := maps.Clone(fp)
	switch o.kind {
	case "route":
		r := routeRow(fp)
		if err := windows.GetIpForwardEntry2(&r); err != nil {
			return nil, false, ignoreMissing(err)
		}
		live["metric"], live["protocol"] = number(uint64(r.Metric)), number(uint64(r.Protocol))
		if r.Publish != 0 || r.AutoconfigureAddress != 0 || r.Loopback != 0 {
			live["foreignFlags"] = fmt.Sprintf("publish=%d autoconfigure=%d loopback=%d", r.Publish, r.AutoconfigureAddress, r.Loopback)
		}
		return live, true, nil
	case "address":
		r := addressRow(fp)
		if err := windows.GetUnicastIpAddressEntry(&r); err != nil {
			return nil, false, ignoreMissing(err)
		}
		p := netip.MustParsePrefix(fp["prefix"])
		live["prefix"] = netip.PrefixFrom(p.Addr(), int(r.OnLinkPrefixLength)).String()
		if r.PrefixOrigin != 1 || r.SuffixOrigin != 1 || r.SkipAsSource != 0 {
			live["foreignFlags"] = "1"
		}
		return live, true, nil
	case "interface":
		r, err := readInterface(fp)
		if err != nil {
			return nil, false, ignoreMissing(err)
		}
		if settings(r) == desiredInterface() {
			return live, true, nil
		}
		if o.all.recovering {
			live["changed"] = "1"
			return live, true, nil
		}
		var before interfaceSettings
		if err := json.Unmarshal([]byte(fp["before"]), &before); err != nil {
			return nil, false, err
		}
		if settings(r) != before {
			return nil, false, errors.New("interface changed during preparation")
		}
		return nil, false, nil
	case "dns":
		current, err := dnsRegistration(fp)
		if err != nil {
			return nil, false, err
		}
		if current == 0 {
			return live, true, nil
		}
		return nil, false, nil
	}
	return nil, false, errors.New("unknown object")
}
func ignoreMissing(err error) error {
	if missing(err) {
		return nil
	}
	return err
}

func (o object) Create(ctx context.Context, fp journal.Fingerprint) error {
	defer o.all.timings.begin(o.kind + ".create.api")()
	if err := ctx.Err(); err != nil {
		return err
	}
	if o.kind == "wfp-sublayer" || o.kind == "wfp-filter" {
		return createWFP(o.all, o.kind, fp)
	}
	if o.kind == "adapter" {
		a, err := wintun.Create(wintun.Config{Name: fp["name"], GUID: fp["guid"], TunnelType: "NetSwitch", MTU: 9000})
		o.all.adapter = a
		if err == nil {
			err = o.all.rememberAdapter(a.LUID())
		}
		return err
	}
	match, err := interfaceMatches(fp)
	if err != nil {
		return err
	}
	if !match {
		return errors.New("interface identity changed before mutation")
	}
	switch o.kind {
	case "route":
		r := routeRow(fp)
		return api("CreateIpForwardEntry2", uintptr(unsafe.Pointer(&r)))
	case "address":
		r := addressRow(fp)
		return api("CreateUnicastIpAddressEntry", uintptr(unsafe.Pointer(&r)))
	case "interface":
		r, err := readInterface(fp)
		if err != nil {
			return err
		}
		var before interfaceSettings
		if err := json.Unmarshal([]byte(fp["before"]), &before); err != nil {
			return err
		}
		if settings(r) != before {
			return errors.New("interface changed before setting MTU")
		}
		putSettings(&r, desiredInterface())
		return api("SetIpInterfaceEntry", uintptr(unsafe.Pointer(&r)))
	case "dns":
		return setDNS(fp, 0)
	}
	return errors.New("unknown object")
}

func (o object) Remove(ctx context.Context, fp journal.Fingerprint) error {
	defer o.all.timings.begin(o.kind + ".remove.api")()
	if o.kind == "wfp-sublayer" || o.kind == "wfp-filter" {
		return removeWFP(o.all, o.kind, fp)
	}
	live, found, err := o.Inspect(ctx, fp)
	if err != nil || !found || !maps.Equal(live, fp) {
		return err
	}
	switch o.kind {
	case "adapter":
		// Publish fingerprint-checked WFP deletions before removing their
		// interface. Do not hold the BFE transaction across device retirement
		// or its IP Helper confirmation. Durable intents remain until the
		// entire cleanup succeeds, so a crash can replay missing objects safely.
		if err := o.all.commitFirewallBatch(); err != nil {
			return err
		}
		oldLUID := o.all.adapterLUID
		if o.all.adapter != nil {
			oldLUID = o.all.adapter.LUID()
		}
		if _, err := nativeAdapterPresent(fp["guid"], fp["name"], oldLUID); err != nil {
			return err
		}
		if o.all.adapter != nil {
			finish := o.all.timings.begin("adapter.close")
			err := o.all.adapter.Close()
			finish()
			o.all.adapter = nil
			if err != nil {
				return err
			}
		}
		defer o.all.timings.begin("adapter.RecoverAfterCrash")()
		if err := wintun.RecoverAfterCrash(wintun.Config{Name: fp["name"], GUID: fp["guid"]}); err != nil {
			return err
		}
		// PnP plus both IP families, exactly as in the creation guard. NDIS
		// TIME_WAIT rows do not prove that the adapter remains functional.
		defer o.all.timings.begin("adapter.retirement.confirm")()
		observed := false
		began := time.Now()
		return awaitAdapterRemoval(ctx, func() (bool, error) {
			present, err := nativeAdapterPresent(fp["guid"], fp["name"], oldLUID)
			if present && !observed && time.Since(began) >= 250*time.Millisecond && o.all.retirementReferences != nil {
				observed = true
				o.all.retirementReferences()
			}
			return present, err
		})
	case "route":
		r := routeRow(fp)
		return ignoreMissing(api("DeleteIpForwardEntry2", uintptr(unsafe.Pointer(&r))))
	case "address":
		r := addressRow(fp)
		return ignoreMissing(api("DeleteUnicastIpAddressEntry", uintptr(unsafe.Pointer(&r))))
	case "interface":
		r, err := readInterface(fp)
		if err != nil {
			return ignoreMissing(err)
		}
		var before interfaceSettings
		if err := json.Unmarshal([]byte(fp["before"]), &before); err != nil {
			return err
		}
		putSettings(&r, before)
		return api("SetIpInterfaceEntry", uintptr(unsafe.Pointer(&r)))
	case "dns":
		return setDNS(fp, uint32(uintField(fp, "before")))
	}
	return errors.New("unknown object")
}

func awaitAdapterRemoval(parent context.Context, present func() (bool, error)) (result error) {
	// Registrar retirement is bounded at 2+5 s. Reserve the remaining part
	// of the 15 s service shutdown for journal/IPC completion; never spend
	// the host's entire 20 s stopping bound on this one confirmation.
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	started, polls := time.Now(), 0
	defer func() {
		log.Printf("WINDOWS ADAPTER RETIREMENT arch=%s elapsed=%s polls=%d confirmed=%t error=%v", runtime.GOARCH, time.Since(started), polls, result == nil, result)
	}()
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("adapter removal not confirmed by IP Helper: %w", err)
		}
		polls++
		found, err := present()
		if err != nil {
			return fmt.Errorf("inspect retiring adapter: %w", err)
		}
		if !found {
			return nil
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("adapter removal not confirmed by IP Helper: %w", ctx.Err())
		}
	}
}

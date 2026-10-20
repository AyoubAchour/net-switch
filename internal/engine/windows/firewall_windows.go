//go:build windows

package winengine

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"runtime"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/AyoubAchour/net-switch/internal/wintun"
	"golang.org/x/sys/windows"
)

const wfpSubLayerKey = "{F7B27863-9B62-4815-B4F9-51D4986E0805}"
const wfpName = "NetSwitch engine ICMP errors"

var wfpDLL = windows.NewLazySystemDLL("fwpuclnt.dll")
var wfpArrival = mustGUID("{618A9B6D-386B-4136-AD6E-B51587CFB1CD}")
var wfpICMPType = mustGUID("{0C1BA1AF-5765-453F-AF22-A8F791AC775B}")

var icmpFilters = [...]struct {
	key, layer, family, kind string
}{
	{"{5124A4E4-1B2A-40E0-8B86-B73006AFB992}", "{61499990-3CB6-4E84-B950-53B94B6964F3}", "2", "3"},
	{"{C1F1C6A3-B8D3-4B2A-B475-AB90E2445D51}", "{65F9BDFF-3B2D-4E5D-B8C6-C720651FE898}", "23", "1"},
	{"{BA979429-E12C-4AAB-9144-044B656E05BB}", "{65F9BDFF-3B2D-4E5D-B8C6-C720651FE898}", "23", "2"},
}

func mustGUID(s string) windows.GUID {
	g, err := windows.GUIDFromString(s)
	if err != nil {
		panic(err)
	}
	return g
}

// Documented FWPM_*0 layouts; x64 and ARM64 share these sizes and offsets.
type wfpDisplay struct{ Name, Description *uint16 }
type wfpBlob struct {
	Size uint32
	Data *byte
}
type wfpValue struct {
	Type  uint32
	Value uintptr
}
type wfpCondition struct {
	Field windows.GUID
	Match uint32
	Value wfpValue
}
type wfpAction struct {
	Type uint32
	Key  windows.GUID
}
type wfpFilter struct {
	Key        windows.GUID
	Display    wfpDisplay
	Flags      uint32
	Provider   *windows.GUID
	Data       wfpBlob
	Layer      windows.GUID
	SubLayer   windows.GUID
	Weight     wfpValue
	Count      uint32
	Conditions *wfpCondition
	Action     wfpAction
	Context    [2]uint64
	Reserved   *windows.GUID
	ID         uint64
	Effective  wfpValue
}
type wfpSubLayer struct {
	Key      windows.GUID
	Display  wfpDisplay
	Flags    uint32
	Provider *windows.GUID
	Data     wfpBlob
	Weight   uint16
}

//go:uintptrescapes
func wfpCall(name string, args ...uintptr) error {
	result, _, _ := wfpDLL.NewProc(name).Call(args...)
	return wfpStatus(name, result)
}
func wfpStatus(name string, result uintptr) error {
	// These APIs return DWORD, not a pointer-sized status. In particular an
	// HRESULT-shaped FWP_E_* value may have sign bits in the native register.
	// FormatMessage hides that difference; errors.Is must see the DWORD.
	code := uint32(result)
	if code != 0 {
		return fmt.Errorf("%s (status 0x%08x, native 0x%x): %w", name, code, result, windows.Errno(code))
	}
	return nil
}
func wfpMissing(err error) bool {
	return errors.Is(err, windows.Errno(windows.FWP_E_FILTER_NOT_FOUND)) ||
		errors.Is(err, windows.Errno(windows.FWP_E_SUBLAYER_NOT_FOUND))
}
func openWFP() (windows.Handle, error) {
	var h windows.Handle
	// Persistent objects are recovered from the ownership journal. No dynamic
	// session can erase them before the crash-recovery test observes leftovers.
	err := wfpCall("FwpmEngineOpen0", 0, 10, 0, 0, uintptr(unsafe.Pointer(&h))) // RPC_C_AUTHN_WINNT.
	return h, err
}
func (o *objects) firewall() (windows.Handle, error) {
	if o.wfp == 0 {
		h, err := openWFP()
		if err != nil {
			return 0, err
		}
		o.wfp = h
	}
	return o.wfp, nil
}
func (o *objects) closeFirewall() error {
	abortErr := o.abortFirewallBatch()
	if o.wfp == 0 {
		return abortErr
	}
	h := o.wfp
	o.wfp = 0
	return errors.Join(abortErr, wfpCall("FwpmEngineClose0", uintptr(h)))
}

func (o *objects) beginFirewallBatch() error {
	if o.wfpBatch {
		return nil
	}
	h, err := o.firewall()
	if err != nil {
		return err
	}
	if err := wfpCall("FwpmTransactionBegin0", uintptr(h), 0); err != nil {
		return err
	}
	o.wfpBatch = true
	return nil
}

func (o *objects) abortFirewallBatch() error {
	o.wfpCreates = 0
	if !o.wfpBatch {
		return nil
	}
	o.wfpBatch = false
	return wfpCall("FwpmTransactionAbort0", uintptr(o.wfp))
}

func (o *objects) commitFirewallBatch() error {
	if !o.wfpBatch {
		return nil
	}
	defer o.timings.begin("wfp.batch.commit")()
	err := wfpCall("FwpmTransactionCommit0", uintptr(o.wfp))
	if err != nil {
		return errors.Join(err, o.abortFirewallBatch())
	}
	o.wfpBatch, o.wfpCreates = false, 0
	return nil
}

func wfpLayerFingerprint(owner string) journal.Fingerprint {
	return journal.Fingerprint{"guid": wintun.DefaultGUID, "key": wfpSubLayerKey, "owner": owner, "name": wfpName,
		"flags": "1", "weight": "65535"}
}
func wfpFilterFingerprints(owner string, luid uint64, index uint32) []journal.Creation {
	var out []journal.Creation
	for _, filter := range icmpFilters {
		out = append(out, journal.Creation{Kind: "wfp-filter", Fingerprint: journal.Fingerprint{
			"guid": wintun.DefaultGUID, "key": filter.key, "owner": owner, "name": wfpName,
			"luid": number(luid), "index": number(uint64(index)), "family": filter.family, "type": filter.kind,
			"layer": filter.layer, "sublayer": wfpSubLayerKey, "direction": "inbound",
			"action": "permit", "flags": "9", "weight": "15",
		}})
	}
	return out
}
func validateWFP(kind string, fp journal.Fingerprint) error {
	owner, err := hex.DecodeString(fp["owner"])
	if err != nil || len(owner) != 16 {
		return errors.New("invalid WFP ownership marker")
	}
	if kind == "wfp-sublayer" && maps.Equal(fp, wfpLayerFingerprint(fp["owner"])) {
		return nil
	}
	if kind == "wfp-filter" && uintField(fp, "luid") != 0 && uintField(fp, "index") != 0 {
		for _, creation := range wfpFilterFingerprints(fp["owner"], uintField(fp, "luid"), uint32(uintField(fp, "index"))) {
			if maps.Equal(fp, creation.Fingerprint) {
				return nil
			}
		}
	}
	return errors.New("WFP fingerprint is outside the engine's inbound TUN ICMP scope")
}

func wfpMarker(owner string) []byte { return []byte("NetSwitch engine ownership:" + owner) }
func wfpMetadata(owner string) (wfpDisplay, wfpBlob, []byte) {
	name, _ := windows.UTF16PtrFromString(wfpName)
	description, _ := windows.UTF16PtrFromString("Inbound ICMPv4 type 3 and ICMPv6 types 1/2 on the owned NetSwitch TUN only")
	data := wfpMarker(owner)
	return wfpDisplay{name, description}, wfpBlob{Size: uint32(len(data)), Data: &data[0]}, data
}

type wfpInput struct {
	row        wfpFilter
	conditions [2]wfpCondition
	luid       uint64
	marker     []byte
}

func makeWFPFilter(fp journal.Fingerprint) *wfpInput {
	input := &wfpInput{luid: uintField(fp, "luid")}
	display, blob, data := wfpMetadata(fp["owner"])
	input.marker = data
	input.conditions[0] = wfpCondition{Field: wfpArrival, Value: wfpValue{Type: 4, Value: uintptr(unsafe.Pointer(&input.luid))}} // FWP_UINT64.
	input.conditions[1] = wfpCondition{Field: wfpICMPType, Value: wfpValue{Type: 2, Value: uintptr(uintField(fp, "type"))}}      // FWP_UINT16.
	input.row = wfpFilter{
		Key: mustGUID(fp["key"]), Display: display, Flags: 1 | 8, Data: blob, // PERSISTENT | CLEAR_ACTION_RIGHT.
		Layer: mustGUID(fp["layer"]), SubLayer: mustGUID(wfpSubLayerKey), Weight: wfpValue{Type: 1, Value: 15},
		Count: 2, Conditions: &input.conditions[0], Action: wfpAction{Type: 0x1002}, // FWP_ACTION_PERMIT.
	}
	return input
}

func createWFP(o *objects, kind string, fp journal.Fingerprint) (err error) {
	h, err := o.firewall()
	if err != nil {
		return err
	}
	if o.wfpCreates != 0 {
		if err := o.beginFirewallBatch(); err != nil {
			return err
		}
		defer func() {
			if err == nil {
				o.wfpCreates--
				if o.wfpCreates == 0 {
					// All intents are already durable. Commit the OS group
					// before the journal can persist its created marks.
					err = o.commitFirewallBatch()
				}
			}
		}()
	}
	if kind == "wfp-sublayer" {
		display, blob, marker := wfpMetadata(fp["owner"])
		row := wfpSubLayer{Key: mustGUID(wfpSubLayerKey), Display: display, Flags: 1, Data: blob, Weight: 65535}
		err := wfpCall("FwpmSubLayerAdd0", uintptr(h), uintptr(unsafe.Pointer(&row)), 0)
		runtime.KeepAlive(marker)
		return err
	}
	if match, err := interfaceMatches(fp); err != nil || !match {
		return errors.Join(err, errors.New("TUN identity changed before WFP creation"))
	}
	input := makeWFPFilter(fp)
	var pin runtime.Pinner
	pin.Pin(&input.luid) // FWP_UINT64 is an indirect member of a native union.
	defer pin.Unpin()
	err = wfpCall("FwpmFilterAdd0", uintptr(h), uintptr(unsafe.Pointer(&input.row)), 0, 0)
	runtime.KeepAlive(input)
	return err
}

func matchingWFPMetadata(display wfpDisplay, blob wfpBlob, owner string) bool {
	expected, _, _ := wfpMetadata(owner)
	if windows.UTF16PtrToString(display.Name) != wfpName ||
		windows.UTF16PtrToString(display.Description) != windows.UTF16PtrToString(expected.Description) {
		return false
	}
	marker := wfpMarker(owner)
	return blob.Size == uint32(len(marker)) && blob.Data != nil && bytes.Equal(unsafe.Slice(blob.Data, int(blob.Size)), marker)
}

func matchesWFPFilter(row *wfpFilter, fp journal.Fingerprint) bool {
	want := makeWFPFilter(fp)
	if row.Key != want.row.Key || row.Provider != nil || row.Flags&^uint32(32) != want.row.Flags ||
		row.Layer != want.row.Layer || row.SubLayer != want.row.SubLayer ||
		row.Weight.Type != 1 || uint8(row.Weight.Value) != 15 ||
		row.Action.Type != want.row.Action.Type || row.Context[0] != 0 ||
		row.Count != 2 || row.Conditions == nil || !matchingWFPMetadata(row.Display, row.Data, fp["owner"]) {
		return false
	}
	seen := map[windows.GUID]bool{}
	for _, condition := range unsafe.Slice(row.Conditions, int(row.Count)) {
		if condition.Match != 0 || seen[condition.Field] {
			return false
		}
		seen[condition.Field] = true
		switch condition.Field {
		case wfpArrival:
			p := *(**uint64)(unsafe.Pointer(&condition.Value.Value))
			if condition.Value.Type != 4 || p == nil || *p != uintField(fp, "luid") {
				return false
			}
		case wfpICMPType:
			if condition.Value.Type != 2 || uint16(condition.Value.Value) != uint16(uintField(fp, "type")) {
				return false
			}
		default:
			return false
		}
	}
	return seen[wfpArrival] && seen[wfpICMPType]
}

func inspectWFP(o *objects, kind string, fp journal.Fingerprint) (journal.Fingerprint, bool, error) {
	h, err := o.firewall()
	if err != nil {
		return nil, false, err
	}
	key := mustGUID(fp["key"])
	live := maps.Clone(fp)
	if kind == "wfp-sublayer" {
		var row *wfpSubLayer
		if err := wfpCall("FwpmSubLayerGetByKey0", uintptr(h), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&row))); err != nil {
			if wfpMissing(err) {
				return nil, false, nil
			}
			return nil, false, err
		}
		defer wfpDLL.NewProc("FwpmFreeMemory0").Call(uintptr(unsafe.Pointer(&row)))
		if row.Key != key || row.Flags != 1 || row.Provider != nil || row.Weight != 65535 ||
			!matchingWFPMetadata(row.Display, row.Data, fp["owner"]) {
			live["changed"] = "1"
		}
	} else {
		var row *wfpFilter
		if err := wfpCall("FwpmFilterGetByKey0", uintptr(h), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&row))); err != nil {
			if wfpMissing(err) {
				return nil, false, nil
			}
			return nil, false, err
		}
		defer wfpDLL.NewProc("FwpmFreeMemory0").Call(uintptr(unsafe.Pointer(&row)))
		if !matchesWFPFilter(row, fp) {
			live["changed"] = "1"
		} else if row.Flags&32 != 0 && !o.recovering {
			return nil, false, errors.New("owned WFP permission is disabled")
		}
	}
	return live, true, nil
}

func removeWFP(o *objects, kind string, fp journal.Fingerprint) error {
	if err := o.beginFirewallBatch(); err != nil {
		return err
	}
	// Every fingerprint check and delete share this transaction. The Windows
	// store commits it before accepting the journal's removed-mark batch.
	// Thus a crash leaves either the original OS objects/intents or committed
	// deletions whose still-live intents can safely be replayed.
	live, found, err := inspectWFP(o, kind, fp)
	if err != nil || !found || !maps.Equal(live, fp) {
		return err
	}
	name := "FwpmFilterDeleteByKey0"
	if kind == "wfp-sublayer" {
		name = "FwpmSubLayerDeleteByKey0"
	}
	key := mustGUID(fp["key"])
	err = wfpCall(name, uintptr(o.wfp), uintptr(unsafe.Pointer(&key)))
	if wfpMissing(err) {
		err = nil
	}
	if err != nil {
		return err
	}
	return nil
}

// FirewallState is a read-only inspection of our fixed namespace. It loads no
// Wintun DLL, so it cannot accidentally clean up a crashed adapter in the test.
func FirewallState() (map[string]any, error) {
	h, err := openWFP()
	if err != nil {
		return nil, err
	}
	defer wfpCall("FwpmEngineClose0", uintptr(h))
	var layer *wfpSubLayer
	key := mustGUID(wfpSubLayerKey)
	err = wfpCall("FwpmSubLayerGetByKey0", uintptr(h), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&layer)))
	if err != nil && !wfpMissing(err) {
		return nil, err
	}
	if layer != nil {
		defer wfpDLL.NewProc("FwpmFreeMemory0").Call(uintptr(unsafe.Pointer(&layer)))
	}
	filters := []map[string]any{}
	for _, spec := range icmpFilters {
		key := mustGUID(spec.key)
		var filter *wfpFilter
		err := wfpCall("FwpmFilterGetByKey0", uintptr(h), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&filter)))
		if wfpMissing(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		conditions := map[string]any{}
		var arriving uint64
		if filter.Count <= 16 && filter.Conditions != nil {
			for _, condition := range unsafe.Slice(filter.Conditions, int(filter.Count)) {
				value := uint64(condition.Value.Value)
				if condition.Value.Type == 4 {
					if ptr := *(**uint64)(unsafe.Pointer(&condition.Value.Value)); ptr != nil {
						value = *ptr
					}
				}
				conditions[condition.Field.String()] = map[string]any{"type": condition.Value.Type, "match": condition.Match, "value": value}
				if condition.Field == wfpArrival {
					arriving = value
				}
			}
		}
		detail := map[string]any{"key": spec.key, "id": filter.ID, "layer": filter.Layer.String(),
			"flags": filter.Flags, "conditions": conditions, "name": windows.UTF16PtrToString(filter.Display.Name)}
		if guid, err := interfaceGUID(arriving); err == nil {
			detail["interfaceGUID"] = guid
		} else {
			detail["interfaceError"] = err.Error()
		}
		filters = append(filters, detail)
		wfpDLL.NewProc("FwpmFreeMemory0").Call(uintptr(unsafe.Pointer(&filter)))
	}
	return map[string]any{"sublayer": layer != nil, "filters": filters}, nil
}

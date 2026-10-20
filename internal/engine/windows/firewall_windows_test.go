//go:build windows

package winengine

import (
	"maps"
	"testing"
	"unsafe"
)

func TestWFPDocumentedLayouts(t *testing.T) {
	if unsafe.Sizeof(wfpValue{}) != 16 || unsafe.Sizeof(wfpCondition{}) != 40 ||
		unsafe.Sizeof(wfpFilter{}) != 200 || unsafe.Sizeof(wfpSubLayer{}) != 72 ||
		unsafe.Offsetof(wfpFilter{}.Conditions) != 120 || unsafe.Offsetof(wfpFilter{}.Action) != 128 ||
		unsafe.Offsetof(wfpFilter{}.Context) != 152 || unsafe.Offsetof(wfpFilter{}.ID) != 176 {
		t.Fatal("WFP ABI does not match the supported 64-bit Windows SDK layout")
	}
}

func TestWFPAllowsOnlyOwnedInboundErrorTypes(t *testing.T) {
	const owner = "0123456789abcdef0123456789abcdef"
	if err := validateWFP("wfp-sublayer", wfpLayerFingerprint(owner)); err != nil {
		t.Fatal(err)
	}
	for _, creation := range wfpFilterFingerprints(owner, 123456, 42) {
		fp := creation.Fingerprint
		if err := validateWFP(creation.Kind, fp); err != nil {
			t.Fatal(err)
		}
		input := makeWFPFilter(fp)
		if !matchesWFPFilter(&input.row, fp) {
			t.Fatal("our filter did not match its complete fingerprint")
		}
		input.conditions[0].Field = wfpICMPType
		if matchesWFPFilter(&input.row, fp) {
			t.Fatal("filter without its arriving-interface condition was accepted")
		}
		input = makeWFPFilter(fp)
		input.luid++
		if matchesWFPFilter(&input.row, fp) {
			t.Fatal("filter on another interface was adopted")
		}
		input = makeWFPFilter(fp)
		input.conditions[1].Value.Value = 8
		if matchesWFPFilter(&input.row, fp) {
			t.Fatal("ICMP echo permission was accepted")
		}
		input = makeWFPFilter(fp)
		input.marker[0] ^= 1
		if matchesWFPFilter(&input.row, fp) {
			t.Fatal("another owner's rule was adopted")
		}
		for key, value := range map[string]string{"direction": "outbound", "type": "8", "action": "block", "flags": "0", "luid": "0"} {
			changed := maps.Clone(fp)
			changed[key] = value
			if err := validateWFP(creation.Kind, changed); err == nil {
				t.Fatalf("out-of-scope journal fingerprint accepted: %s=%s", key, value)
			}
		}
	}
}

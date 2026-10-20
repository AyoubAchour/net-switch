package worker

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestElevatedGroupNamespaces(t *testing.T) {
	for _, prefix := range []string{"S-1-5-32", "S-1-5-21-1-2-3", "S-1-5-21-999-888-777"} {
		rids := []int{544, 547, 548, 549, 550, 551, 554, 556, 569}
		if prefix != "S-1-5-32" {
			rids = []int{512, 516, 517, 518, 519, 520, 553}
		}
		for _, rid := range rids {
			text := fmt.Sprintf("%s-%d", prefix, rid)
			sid, err := windows.StringToSid(text)
			if err != nil || !elevatedGroup(sid) {
				t.Fatal("elevated group omitted", text, err)
			}
		}
	}
	for _, text := range []string{"S-1-1-0", "S-1-5-32-545", "S-1-5-32-546", "S-1-5-21-1-2-3-513", "S-1-5-21-1-2-3-1001", "S-1-5-32-512", "S-1-5-21-1-2-3-544", "S-1-5-80-512", "S-1-16-8192"} {
		sid, err := windows.StringToSid(text)
		if err != nil || elevatedGroup(sid) {
			t.Fatal("ordinary or unrelated SID disabled", text, err)
		}
	}
}

func TestWorkerGroupSelectionUsesFilteredToken(t *testing.T) {
	admin, _ := windows.StringToSid("S-1-5-32-544")
	crypto, _ := windows.StringToSid("S-1-5-32-569")
	custom, _ := windows.StringToSid("S-1-5-21-1-2-3-1234")
	groups := []windows.SIDAndAttributes{{Sid: admin, Attributes: windows.SE_GROUP_ENABLED}, {Sid: crypto, Attributes: windows.SE_GROUP_ENABLED}, {Sid: custom, Attributes: windows.SE_GROUP_ENABLED}}
	filtered := []windows.SIDAndAttributes{{Sid: admin, Attributes: windows.SE_GROUP_USE_FOR_DENY_ONLY}, {Sid: crypto, Attributes: windows.SE_GROUP_USE_FOR_DENY_ONLY}, {Sid: custom, Attributes: windows.SE_GROUP_USE_FOR_DENY_ONLY}}
	for _, test := range []struct {
		name     string
		filtered []windows.SIDAndAttributes
		count    int
	}{{"linked-token-includes-nonstandard-group", filtered, 3}, {"unsplit-token-fallback-includes-crypto", nil, 2}} {
		t.Run(test.name, func(t *testing.T) {
			disabled, err := disabledWorkerGroups(groups, test.filtered)
			if err != nil || len(disabled) != test.count {
				t.Fatal(disabled, err)
			}
		})
	}
}

// This fixture is deliberately created only on disposable hosted Windows. A
// normal runner token does not belong to the other privileged local groups,
// so merely inspecting it cannot prove those grants have been removed.
func TestReadTokenDisablesAdditionalPrivilegedMemberships(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Skip("requires disposable hosted Windows")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	accountName := fmt.Sprintf("ns-%d-%x", os.Getpid(), random[:3])
	name, _ := windows.UTF16PtrFromString(accountName)
	netapi := windows.NewLazySystemDLL("netapi32.dll")
	var policy *uint32 // USER_MODALS_INFO_0 starts with minimum password length.
	status, _, _ := netapi.NewProc("NetUserModalsGet").Call(0, 0, uintptr(unsafe.Pointer(&policy)))
	if status != 0 || policy == nil {
		t.Fatalf("read disposable-account password policy: %d", status)
	}
	minimum := *policy
	netapi.NewProc("NetApiBufferFree").Call(uintptr(unsafe.Pointer(policy)))
	if minimum > 200 {
		t.Fatalf("unexpected minimum password length: %d", minimum)
	}
	// Keep independent entropy and all character classes. Reusing the name's
	// random suffix in the password can violate Windows' name-token checks.
	var passwordText string
	for attempt := 0; attempt < 20; attempt++ {
		secret := make([]byte, (max(64, int(minimum)+8)-8+1)/2)
		if _, err := rand.Read(secret); err != nil {
			t.Fatal(err)
		}
		candidate := "Q7!bR9@k" + hex.EncodeToString(secret)
		containsName := false
		for _, token := range strings.Split(accountName, "-") {
			containsName = containsName || (len(token) >= 3 && strings.Contains(strings.ToLower(candidate), strings.ToLower(token)))
		}
		if !containsName {
			passwordText = candidate
			break
		}
	}
	if passwordText == "" {
		t.Fatal("could not generate an independent fixture password")
	}
	password, _ := windows.UTF16PtrFromString(passwordText)
	t.Logf("disposable-account policy minimum=%d; generated length=%d; no account-name tokens reused", minimum, len(passwordText))
	type userInfo struct {
		Name, Password         *uint16
		PasswordAge, Privilege uint32
		HomeDir, Comment       *uint16
		Flags                  uint32
		Script                 *uint16
	}
	info := userInfo{Name: name, Password: password, Privilege: 1, Flags: 0x10201}
	var parameter uint32
	status, _, _ = netapi.NewProc("NetUserAdd").Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parameter)))
	if status != 0 {
		t.Fatalf("create disposable account: %d parameter %d (2245 means password-policy rejection; minimum=%d, generated length=%d)", status, parameter, minimum, len(passwordText))
	}
	t.Cleanup(func() {
		status, _, _ := netapi.NewProc("NetUserDel").Call(0, uintptr(unsafe.Pointer(name)))
		if status != 0 {
			t.Errorf("delete disposable account: %d", status)
		}
	})
	groupSIDs := []string{"S-1-5-32-544", "S-1-5-32-547", "S-1-5-32-551", "S-1-5-32-556", "S-1-5-32-569"}
	for _, text := range groupSIDs {
		sid, err := windows.StringToSid(text)
		if err != nil {
			t.Fatal(err)
		}
		account, _, _, err := sid.LookupAccount("")
		if err != nil {
			t.Fatal(err)
		}
		group, _ := windows.UTF16PtrFromString(account)
		member := struct{ Name *uint16 }{name}
		status, _, _ := netapi.NewProc("NetLocalGroupAddMembers").Call(0, uintptr(unsafe.Pointer(group)), 3, uintptr(unsafe.Pointer(&member)), 1)
		if status != 0 {
			t.Fatalf("add membership %s: %d", text, status)
		}
	}
	advapi := windows.NewLazySystemDLL("advapi32.dll")
	domain, _ := windows.UTF16PtrFromString(".")
	var source windows.Token
	ok, _, err := advapi.NewProc("LogonUserW").Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(domain)), uintptr(unsafe.Pointer(password)), 4, 0, uintptr(unsafe.Pointer(&source)))
	if ok == 0 {
		t.Fatal("log on disposable account", err)
	}
	defer source.Close()
	// Interactive logons create the UAC pair. Query both sides, including
	// the identification-only linked handle, without trying to launch it.
	var interactive windows.Token
	ok, _, err = advapi.NewProc("LogonUserW").Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(domain)), uintptr(unsafe.Pointer(password)), 2, 0, uintptr(unsafe.Pointer(&interactive)))
	if ok == 0 {
		t.Fatal("interactive logon for linked-token proof", err)
	}
	defer interactive.Close()
	linked, err := interactive.GetLinkedToken()
	if err != nil {
		t.Fatal("hosted proof requires a real UAC token pair", err)
	}
	defer linked.Close()
	var full, limited windows.Token
	if interactive.IsElevated() {
		full, limited = interactive, linked
	} else {
		full, limited = linked, interactive
	}
	expected, err := limited.GetTokenGroups()
	if err != nil {
		t.Fatal(err)
	}
	actual, err := filteredTokenGroups(full)
	if err != nil || len(actual) == 0 {
		t.Fatal("production did not query the linked filtered groups", err)
	}
	want := map[string]uint32{}
	for _, group := range expected.AllGroups() {
		want[group.Sid.String()] = group.Attributes
	}
	for _, group := range actual {
		if want[group.Sid.String()] != group.Attributes {
			t.Fatal("linked token group mismatch", group.Sid.String())
		}
	}
	if len(actual) != len(want) || want["S-1-5-32-544"]&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
		t.Fatal("fixture did not exercise a filtered administrator token")
	}
	t.Logf("queried %d groups from the real filtered UAC token through the full token's linked handle", len(actual))
	// Use an unfiltered duplicate as the access control, so this proof
	// does not depend on restrictions already applied to its comparison.
	var control windows.Token
	if err := windows.DuplicateTokenEx(source, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenPrimary, &control); err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	if err := mediumIntegrity(control); err != nil {
		t.Fatal(err)
	}
	filtered, err := workerToken(source, false)
	if err != nil {
		t.Fatal(err)
	}
	defer filtered.Close()
	attributes := func(token windows.Token) map[string]uint32 {
		groups, err := token.GetTokenGroups()
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]uint32{}
		for _, g := range groups.AllGroups() {
			out[g.Sid.String()] = g.Attributes
		}
		return out
	}
	before, after := attributes(control), attributes(filtered)
	legacyControl, err := workerToken(source, true)
	if err != nil {
		t.Fatal(err)
	}
	defer legacyControl.Close()
	t.Logf("Crypto membership: source=%x duplicate=%x administrative restricted=%x read=%x; source groups=%v",
		attributes(source)["S-1-5-32-569"], before["S-1-5-32-569"], attributes(legacyControl)["S-1-5-32-569"], after["S-1-5-32-569"], attributes(source))
	for _, text := range groupSIDs {
		afterAttrs, retained := after[text]
		if before[text]&windows.SE_GROUP_ENABLED == 0 || (retained && (afterAttrs&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 || afterAttrs&(windows.SE_GROUP_ENABLED|windows.SE_GROUP_ENABLED_BY_DEFAULT) != 0)) {
			t.Fatalf("membership was not exercised and disabled: %s before=%x after=%x", text, before[text], after[text])
		}
		if !retained {
			t.Logf("Windows removed %s from the restricted token entirely", text)
		}
	}
	for _, text := range groupSIDs[1:] {
		t.Run(text, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "group-only")
			if err := os.WriteFile(path, []byte("unchanged"), 0600); err != nil {
				t.Fatal(err)
			}
			sd, err := windows.SecurityDescriptorFromString("O:BAD:P(A;;FA;;;SY)(A;;GW;;;" + text + ")S:(ML;;NW;;;ME)")
			if err != nil {
				t.Fatal(err)
			}
			owner, _, _ := sd.Owner()
			acl, _, _ := sd.DACL()
			label, _, _ := sd.SACL()
			if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION|windows.LABEL_SECURITY_INFORMATION, owner, nil, acl, label); err != nil {
				t.Fatal(err)
			}
			p, _ := windows.UTF16PtrFromString(path)
			attempt := func(token windows.Token) error {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				ok, _, err := advapi.NewProc("ImpersonateLoggedOnUser").Call(uintptr(token))
				if ok == 0 {
					return err
				}
				defer windows.RevertToSelf()
				h, err := windows.CreateFile(p, windows.FILE_WRITE_DATA, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
				if err == nil {
					windows.CloseHandle(h)
				}
				return err
			}
			if err := attempt(control); err != nil {
				t.Fatal("Medium control token did not exercise the group-only grant", err)
			}
			if err := attempt(filtered); err != windows.ERROR_ACCESS_DENIED {
				t.Fatal("read token retained the group-only grant", err)
			}
			t.Log("Medium control token allowed; production read token denied; source membership enabled and destination deny-only or removed")
		})
	}
}

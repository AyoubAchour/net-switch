package winplatform

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/platform/worker"
	"golang.org/x/sys/windows"
)

type metadataProof struct{ Target, Sentinel, UserSID string }
type metadataAnswer struct {
	Ready, Escaped bool
	Error          string
}

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == "worker" && os.Args[2] == "acl-proof" {
		if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
			os.Exit(2)
		}
		os.Exit(runMetadataProof())
	}
	os.Exit(m.Run())
}

func runMetadataProof() int {
	decoder, encoder := json.NewDecoder(os.Stdin), json.NewEncoder(os.Stdout)
	var input metadataProof
	if err := decoder.Decode(&input); err != nil {
		return 2
	}
	p, err := windows.UTF16PtrFromString(input.Target)
	if err != nil {
		return 2
	}
	h, err := windows.CreateFile(p, windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		_ = encoder.Encode(metadataAnswer{Error: "open WRITE_DAC: " + err.Error()})
		return 1
	}
	defer windows.CloseHandle(h)
	if err := encoder.Encode(metadataAnswer{Ready: true}); err != nil {
		return 1
	}
	var resume bool
	if err := decoder.Decode(&resume); err != nil || !resume {
		return 2
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + input.UserSID + ")")
	if err != nil {
		return 2
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return 2
	}
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		_ = encoder.Encode(metadataAnswer{Error: "retained WRITE_DAC: " + err.Error()})
		return 1
	}
	err = os.WriteFile(input.Sentinel, []byte("untrusted write through retained metadata handle"), 0600)
	result := metadataAnswer{Escaped: err == nil}
	if err != nil {
		result.Error = err.Error()
	}
	_ = encoder.Encode(result)
	return 0
}

func setProofSecurity(t *testing.T, path, userSID, rights string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;" + rights + ";;;" + userSID + ")S:(ML;;NW;;;ME)")
	if err != nil {
		t.Fatal(err)
	}
	owner, _, _ := sd.Owner()
	acl, _, _ := sd.DACL()
	label, _, _ := sd.SACL()
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION|windows.LABEL_SECURITY_INFORMATION, owner, nil, acl, label); err != nil {
		t.Fatal(err)
	}
}

func TestExistingMetadataHandleCannotUndoMachineProtection(t *testing.T) {
	hostedSecurity(t)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"root", "child"} {
		t.Run(kind, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "machine")
			if err := ProtectDirectory(root); err != nil {
				t.Fatal(err)
			}
			target, sentinel := root, filepath.Join(root, "sentinel")
			if kind == "child" {
				setProofSecurity(t, root, user.User.Sid.String(), "0x1200a9")
				target = filepath.Join(root, "record")
				sentinel = target
				if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			setProofSecurity(t, target, user.User.Sid.String(), "0x00040000")
			p, err := worker.Start(exe, []string{"worker", "acl-proof"})
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			stop := context.AfterFunc(ctx, func() { _ = p.Kill() })
			defer stop()
			encoder, decoder := json.NewEncoder(p.Input()), json.NewDecoder(p.Output())
			if err := encoder.Encode(metadataProof{Target: target, Sentinel: sentinel, UserSID: user.User.Sid.String()}); err != nil {
				t.Fatal(err)
			}
			var ready metadataAnswer
			if err := decoder.Decode(&ready); err != nil || !ready.Ready {
				t.Fatalf("Medium worker could not acquire the original grant: %+v %v", ready, err)
			}
			if err := ProtectDirectory(root); err != nil {
				t.Fatal(err)
			}
			if err := encoder.Encode(true); err != nil {
				t.Fatal(err)
			}
			p.Input().Close()
			var answer metadataAnswer
			if err := decoder.Decode(&answer); err != nil {
				t.Fatal(err)
			}
			if err := p.Wait(); err != nil {
				t.Fatalf("metadata proof did not execute: %v %+v", err, answer)
			}
			t.Logf("%s retained WRITE_DAC: escaped=%t, write result=%s", kind, answer.Escaped, answer.Error)
			if answer.Escaped {
				t.Fatal(fmt.Sprintf("%s metadata handle restored attacker write access after protection", kind))
			}
		})
	}
}

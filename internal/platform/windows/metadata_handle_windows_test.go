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
	for _, test := range []struct {
		kind       string
		quarantine bool
	}{
		{"root", false}, {"root", true},
		{"child", false}, {"child", true},
		{"nested-directory", false}, {"nested-directory", true},
	} {
		t.Run(fmt.Sprintf("%s/quarantine=%t", test.kind, test.quarantine), func(t *testing.T) {
			kind := test.kind
			root := filepath.Join(t.TempDir(), "machine")
			if err := ProtectDirectory(root); err != nil {
				t.Fatal(err)
			}
			target, sentinel := root, filepath.Join(root, "sentinel")
			if kind != "root" {
				setProofSecurity(t, root, user.User.Sid.String(), "0x1200a9")
				if kind == "nested-directory" {
					target = filepath.Join(root, "child", "nested")
					if err := os.MkdirAll(target, 0700); err != nil {
						t.Fatal(err)
					}
					setProofSecurity(t, filepath.Dir(target), user.User.Sid.String(), "0x1200a9")
					sentinel = filepath.Join(target, "sentinel")
				} else {
					target = filepath.Join(root, "record")
					sentinel = target
					if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			// CreateFile adds SYNCHRONIZE even for a metadata-only open. The
			// fixture must grant it alongside WRITE_DAC to exercise retention.
			setProofSecurity(t, target, user.User.Sid.String(), "0x00140000")
			before := fileSecurity(t, target)
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
			if test.quarantine {
				if err := ProtectDirectory(root); err != nil {
					t.Fatal(err)
				}
				old, err := filepath.Glob(root + ".untrusted-*")
				if err != nil || len(old) != 1 {
					t.Fatalf("untrusted objects were not quarantined: %v %v", old, err)
				}
				relative, _ := filepath.Rel(root, target)
				if after := fileSecurity(t, filepath.Join(old[0], relative)); before != after {
					t.Fatalf("original ACL was changed before quarantine: %s -> %s", before, after)
				}
			} else {
				// Vulnerable control: remove the dangerous grant in place. The
				// old handle must still undo this, proving the exploit actually ran.
				setProofSecurity(t, target, user.User.Sid.String(), "0x00100000")
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
			t.Logf("%s retained WRITE_DAC: quarantine=%t, escaped=%t, write result=%s", kind, test.quarantine, answer.Escaped, answer.Error)
			if answer.Escaped == test.quarantine {
				t.Fatalf("retained metadata handle: quarantine=%t, escaped=%t", test.quarantine, answer.Escaped)
			}
		})
	}
}

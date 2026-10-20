package winplatform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/platform/worker"
	"golang.org/x/sys/windows"
)

type metadataProof struct {
	Target, Sentinel, UserSID string
	ForgeMarker               bool
}
type metadataAnswer struct {
	Ready, Escaped    bool
	CertificateDenied bool
	Error             string
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
	access := uint32(windows.WRITE_DAC)
	if input.ForgeMarker {
		access |= windows.FILE_READ_ATTRIBUTES
	}
	h, err := windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		_ = encoder.Encode(metadataAnswer{Error: "open WRITE_DAC: " + err.Error()})
		return 1
	}
	defer windows.CloseHandle(h)
	if err := certifyDirectory(input.Target, "attacker-controlled"); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		_ = encoder.Encode(metadataAnswer{Error: fmt.Sprintf("Medium certificate attempt must be access denied: %v", err)})
		return 1
	}
	if input.ForgeMarker {
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(h, &info); err != nil {
			_ = encoder.Encode(metadataAnswer{Error: "read public directory ID: " + err.Error()})
			return 1
		}
		identity := fmt.Sprintf("%08x:%08x%08x", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow)
		b, _ := json.Marshal(directoryMarker{Identity: identity, Target: input.Target, Nonce: strings.Repeat("ab", 32)})
		sd, err := windows.SecurityDescriptorFromString("O:" + input.UserSID + "D:P(A;;FA;;;" + input.UserSID + ")")
		if err != nil {
			return 2
		}
		attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
		name := filepath.Join(input.Target, directoryMarkerName)
		path, _ := windows.UTF16PtrFromString(name)
		marker, err := windows.CreateFile(path, windows.GENERIC_WRITE, windows.FILE_SHARE_READ, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			_ = encoder.Encode(metadataAnswer{Error: "plant marker: " + err.Error()})
			return 1
		}
		file := os.NewFile(uintptr(marker), name)
		_, err = file.Write(b)
		file.Close()
		if err != nil {
			return 1
		}
	}
	if err := encoder.Encode(metadataAnswer{Ready: true, CertificateDenied: true}); err != nil {
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
	// This is deliberately adversarial, not the product's file-security helper.
	// SetSecurityInfo can query additional metadata/inheritance; the direct
	// kernel operation needs only the WRITE_DAC right retained on this handle.
	if err := windows.SetKernelObjectSecurity(h, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, sd); err != nil {
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
		kind        string
		quarantine  bool
		hideGrant   bool
		forgeMarker bool
	}{
		{"root", false, false, false}, {"root", true, false, false},
		{"child", false, false, false}, {"child", true, false, false},
		{"nested-directory", false, false, false}, {"nested-directory", true, false, false},
		{"root", true, true, false}, {"child", true, true, false}, {"nested-directory", true, true, false},
		{"root", false, true, true}, {"root", true, true, true},
	} {
		t.Run(fmt.Sprintf("%s/quarantine=%t/historical=%t/forged-marker=%t", test.kind, test.quarantine, test.hideGrant, test.forgeMarker), func(t *testing.T) {
			kind := test.kind
			root := filepath.Join(t.TempDir(), "machine")
			if err := ProtectDirectory(root); err != nil {
				t.Fatal(err)
			}
			if test.hideGrant {
				if err := os.Remove(filepath.Join(root, directoryMarkerName)); err != nil {
					t.Fatal(err)
				}
			}
			if test.forgeMarker {
				// Model a legacy root: it has never received Go's independent
				// certificate, even if Node later takes ownership of its files.
				key, err := openDirectoryCertificates(true)
				if err != nil {
					t.Fatal(err)
				}
				err = key.DeleteValue(directoryCertificateName(root))
				key.Close()
				if err != nil {
					t.Fatal(err)
				}
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
			rights := "0x00140000"
			if test.forgeMarker {
				rights = "0x00140082" // also create a child and read the public ID
			}
			setProofSecurity(t, target, user.User.Sid.String(), rights)
			before := fileSecurity(t, target)
			rootBefore := fileSecurity(t, root)
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
			if err := encoder.Encode(metadataProof{Target: target, Sentinel: sentinel, UserSID: user.User.Sid.String(), ForgeMarker: test.forgeMarker}); err != nil {
				t.Fatal(err)
			}
			var ready metadataAnswer
			if err := decoder.Decode(&ready); err != nil || !ready.Ready || !ready.CertificateDenied {
				t.Fatalf("Medium worker could not acquire the original grant: %+v %v", ready, err)
			}
			if test.hideGrant {
				// The retained handle now has authority absent from today's ACL.
				setProofSecurity(t, target, user.User.Sid.String(), "0x00100000")
				before, rootBefore = fileSecurity(t, target), fileSecurity(t, root)
			}
			if test.forgeMarker {
				name := filepath.Join(root, directoryMarkerName)
				path, _ := windows.UTF16PtrFromString(name)
				handle, err := windows.CreateFile(path, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
				if err != nil {
					t.Fatal(err)
				}
				// This is the exact effect of Node's descendant ACL loop: a
				// user-planted marker becomes BA-owned with admin-only grants.
				empty, _ := windows.SecurityDescriptorFromString("O:BAD:")
				err = setDirectorySecurity(handle, empty, false)
				windows.CloseHandle(handle)
				if err != nil {
					t.Fatal(err)
				}
				t.Log("Medium worker planted a matching marker; legacy hardening made it admin-owned; independent certification was denied")
			}
			blocked := false
			if test.quarantine {
				if err := ProtectDirectory(root); err != nil {
					// Windows refuses a directory rename while a descendant is
					// open, even with FILE_SHARE_DELETE. Startup must fail closed
					// without rewriting any original ACL or using that old tree.
					if kind == "root" || !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
						t.Fatal(err)
					}
					blocked = true
					if fileSecurity(t, target) != before || fileSecurity(t, root) != rootBefore {
						t.Fatal("failed quarantine changed an original ACL")
					}
					t.Logf("startup refused while descendant handle is open: %v", err)
				} else {
					old, err := filepath.Glob(root + ".untrusted-*")
					if err != nil || len(old) != 1 {
						t.Fatalf("untrusted objects were not quarantined: %v %v", old, err)
					}
					relative, _ := filepath.Rel(root, target)
					if after := fileSecurity(t, filepath.Join(old[0], relative)); before != after {
						t.Fatalf("original ACL was changed before quarantine: %s -> %s", before, after)
					}
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
			t.Logf("%s retained WRITE_DAC: quarantine=%t, startup refused=%t, escaped=%t, write result=%s", kind, test.quarantine, blocked, answer.Escaped, answer.Error)
			if wantEscape := !test.quarantine || blocked; answer.Escaped != wantEscape {
				t.Fatalf("retained metadata handle: escaped=%t, want %t", answer.Escaped, wantEscape)
			}
			if blocked {
				// The worker has exited and closed its handle. Retrying must now
				// quarantine all the old objects, including its last write.
				if err := ProtectDirectory(root); err != nil {
					t.Fatal("quarantine after descendant closes:", err)
				}
				old, err := filepath.Glob(root + ".untrusted-*")
				if err != nil || len(old) != 1 {
					t.Fatalf("retry did not quarantine the untrusted tree: %v %v", old, err)
				}
				items, err := os.ReadDir(root)
				if err != nil || len(items) != 1 || items[0].Name() != directoryMarkerName {
					t.Fatalf("retry kept untrusted data: %v %v", items, err)
				}
				t.Log("quarantine succeeded after the descendant handle closed")
			}
		})
	}
}

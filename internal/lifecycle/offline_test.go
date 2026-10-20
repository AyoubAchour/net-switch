package lifecycle

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"

	assets "github.com/AyoubAchour/net-switch"
	"github.com/AyoubAchour/net-switch/internal/localipc"
)

func TestRPCStopAcknowledgementBeforeEOF(t *testing.T) {
	server, client := net.Pipe()
	rpc := NewRPC(client)
	defer rpc.Close()
	go func() {
		defer server.Close()
		scan := bufio.NewScanner(server)
		if !scan.Scan() {
			return
		}
		var request map[string]any
		_ = json.Unmarshal(scan.Bytes(), &request)
		_ = json.NewEncoder(server).Encode(map[string]any{"id": request["id"], "result": true})
	}()
	var stopped bool
	if err := rpc.Call(context.Background(), map[string]any{"method": "stop"}, &stopped); err != nil || !stopped {
		t.Fatal(stopped, err)
	}
}
func TestOwnerIsNeverFirstClient(t *testing.T) {
	for _, owner := range []Owner{{}, {User: "owner", Name: "Owner"}} {
		a := &Access{Owner: owner, Tokens: NewTokens()}
		for _, method := range []string{"session", "pair", "revoke", "routing", "signin", "desktop-connect", "desktop-result"} {
			if _, err := a.request(context.Background(), localipc.Peer{User: "stranger"}, false, "connection", controlRequest{Method: method}); err == nil {
				t.Fatalf("%s granted to stranger", method)
			}
		}
		if a.Owner != owner {
			t.Fatal("first client enrolled itself")
		}
	}
	a := &Access{Owner: Owner{User: "owner"}, Tokens: NewTokens()}
	if _, err := a.request(context.Background(), localipc.Peer{User: "owner"}, true, "connection", controlRequest{Method: "session"}); err == nil {
		t.Fatal("status pipe issued a token")
	}
}
func TestServiceAssetsDoNotPutCredentialsInURLs(t *testing.T) {
	source, err := assets.UI.ReadFile("ui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	result := string(ServiceAsset("app.js", source))
	for _, bad := range []string{"&token=", "location.hash.slice(1)"} {
		if strings.Contains(result, bad) {
			t.Fatalf("service asset retained %s", bad)
		}
	}
	if !strings.Contains(result, "credentials: 'omit'") {
		t.Fatal("browser still sends ambient credentials")
	}
	if !strings.Contains(string(source), "&token=") {
		t.Fatal("test did not exercise legacy icon source")
	}
}
func TestDurableStorePrimaryAndBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	want := map[string]string{"engineInstanceId": "instance", "sha256": "hash"}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{path, path + ".bak"} {
		var got map[string]string
		if err := Read(file, &got); err != nil || got["engineInstanceId"] != "instance" {
			t.Fatal(got, err)
		}
	}
}

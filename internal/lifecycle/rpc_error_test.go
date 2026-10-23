package lifecycle

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
)

func TestNativeProtocolRejectsLegacyPrimerWithAnImmediateRPCError(t *testing.T) {
	request := []byte("\x00{\"id\":\"1\",\"method\":\"hello\"}\n")
	_, decodeErr := protocol.Decode(request)
	if decodeErr == nil || !strings.Contains(decodeErr.Error(), "invalid character") {
		t.Fatal("legacy primer reproduction did not reject JSON", decodeErr)
	}
	client, server := net.Pipe()
	rpc := NewRPC(client)
	defer rpc.Close()
	defer server.Close()
	go func() {
		_, _ = bufio.NewReader(server).ReadString('\n')
		_ = json.NewEncoder(server).Encode(map[string]string{"error": decodeErr.Error()})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := rpc.Call(ctx, map[string]any{"method": "hello"}, nil)
	if err == nil || errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "invalid character") {
		t.Fatalf("protocol rejection became a misleading deadline: %v", err)
	}
}

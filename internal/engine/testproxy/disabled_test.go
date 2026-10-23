//go:build !lifecycle_test && !acceptance

package testproxy

import (
	"context"
	"net"
	"testing"
)

func TestProductProxyCannotListen(t *testing.T) {
	t.Setenv("NETSWITCH_NATIVE_CI", "1")
	calls := 0
	s, err := New(context.Background(), Options{Address: "127.0.0.1:0", Listen: func(string, string) (net.Listener, error) { calls++; return nil, nil }})
	if Enabled || s != nil || err != ErrDisabled || calls != 0 {
		t.Fatal(s, err, calls)
	}
}

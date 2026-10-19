package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExchangeOverLoopback(t *testing.T) {
	records := filepath.Join(t.TempDir(), "conns.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := listen(ctx, options{address: "127.0.0.1:0,[::1]:0", records: records, initialPacketSize: 1200})
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range s.addresses {
		r, err := dial(ctx, options{address: address, certificate: s.cert, upload: 256 << 10, download: 512 << 10, initialPacketSize: 1200, timeout: 20 * time.Second})
		if err != nil {
			t.Fatalf("%s: %v", address, err)
		}
		if r.Bytes != 256<<10 || r.Download != 512<<10 || r.Version != "v1" || r.ALPN != alpn || r.Source == "" {
			t.Errorf("%s: %+v", address, r)
		}
	}
	if _, err := dial(ctx, options{address: s.addresses[0], certificate: strings.Repeat("0", 64), upload: 1, timeout: 5 * time.Second}); err == nil {
		t.Error("a client must refuse a target whose certificate isn't the pinned one")
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(records)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("one record per completed connection, got %d: %s", len(lines), data)
	}
	for _, line := range lines {
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		if rec.Err != "" || rec.UploadBytes != 256<<10 || rec.DownloadBytes != 512<<10 || rec.Datagrams == 0 || rec.MaxDatagram < 1200 || rec.MaxDatagram > 1452 {
			t.Errorf("record: %+v", rec)
		}
	}
}

func TestOptions(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--serve", "--address", "127.0.0.1:0"},
		{"--address", "127.0.0.1:1"},
		{"--address", "127.0.0.1:1", "--certificate", strings.Repeat("a", 64), "--initial-packet-size", "1000"},
		{"--address", "127.0.0.1:1", "--certificate", strings.Repeat("a", 64), "--upload", "-1"},
	} {
		if _, err := parse(args); err == nil {
			t.Errorf("%q must be refused", args)
		}
	}
	if _, err := parse([]string{"--address", "[::1]:1", "--certificate", strings.Repeat("a", 64), "--download", "1048576"}); err != nil {
		t.Error(err)
	}
}

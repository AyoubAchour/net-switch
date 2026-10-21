package lifecycle

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPairingSingleUseAndConnectionLifetime(t *testing.T) {
	tokens := NewTokens()
	token := tokens.Open("desktop")
	if len(token) != 64 || !tokens.Valid(token) {
		t.Fatal("expected a 256-bit session token")
	}
	code, err := tokens.Pairing("desktop")
	if err != nil || len(code) != 6 {
		t.Fatal(code, err)
	}
	var successes int
	var mu sync.Mutex
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			if got, err := tokens.Redeem(code); err == nil {
				if got != token {
					t.Error("wrong token")
				}
				mu.Lock()
				successes++
				mu.Unlock()
			}
		})
	}
	group.Wait()
	if successes != 1 {
		t.Fatalf("code redeemed %d times", successes)
	}
	tokens.Close("desktop")
	if tokens.Valid(token) {
		t.Fatal("token survived disconnect")
	}
	if _, err := tokens.Pairing("desktop"); err == nil {
		t.Fatal("anonymous code reset")
	}
}
func TestPairingThreeTriesAcrossAllConnections(t *testing.T) {
	tokens := NewTokens()
	tokens.Open("desktop")
	code, _ := tokens.Pairing("desktop")
	wrong := "000000"
	if wrong == code {
		wrong = "000001"
	}
	for range 3 {
		if _, err := tokens.Redeem(wrong); err == nil {
			t.Fatal("wrong code accepted")
		}
	}
	if _, err := tokens.Redeem(code); err == nil {
		t.Fatal("fourth try accepted")
	}
	next, _ := tokens.Pairing("desktop")
	if _, err := tokens.Redeem(next); err != nil {
		t.Fatal("authenticated renewal failed", err)
	}
}
func TestTokenAndPairingExpiry(t *testing.T) {
	tokens := NewTokens()
	now := time.Now()
	tokens.now = func() time.Time { return now }
	token := tokens.Open("desktop")
	code, _ := tokens.Pairing("desktop")
	now = now.Add(2 * time.Minute)
	if _, err := tokens.Redeem(code); err == nil {
		t.Fatal("expired code accepted")
	}
	if !tokens.Valid(token) {
		t.Fatal("token expired too soon")
	}
	now = now.Add(12 * time.Hour)
	if tokens.Valid(token) {
		t.Fatal("12-hour token still valid")
	}
	if NewTokens().Valid(token) {
		t.Fatal("token survived Control restart")
	}
	if tokens.Valid("") || tokens.Valid(strings.Repeat("x", 64)) {
		t.Fatal("invalid token accepted")
	}
}

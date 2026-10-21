package lifecycle

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

type session struct {
	expires     time.Time
	token, code string
	codeExpires time.Time
	attempts    int
}
type Tokens struct {
	mu       sync.Mutex
	now      func() time.Time
	sessions map[string]*session
}

func NewTokens() *Tokens { return &Tokens{now: time.Now, sessions: map[string]*session{}} }
func (t *Tokens) Open(id string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	token := randomID()
	t.sessions[id] = &session{expires: t.now().Add(12 * time.Hour), token: token}
	return token
}
func (t *Tokens) Get(id string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.sessions[id]
	if s == nil || !t.now().Before(s.expires) {
		return "", errors.New("desktop session expired or revoked")
	}
	return s.token, nil
}
func (t *Tokens) Close(id string) { t.mu.Lock(); defer t.mu.Unlock(); delete(t.sessions, id) }
func (t *Tokens) RevokeAll()      { t.mu.Lock(); defer t.mu.Unlock(); t.sessions = map[string]*session{} }
func equal(a, b string) bool {
	return a != "" && len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func (t *Tokens) Valid(token string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range t.sessions {
		if t.now().Before(s.expires) && equal(s.token, token) {
			return true
		}
	}
	return false
}
func (t *Tokens) Pairing(id string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.sessions[id]
	if s == nil || !t.now().Before(s.expires) {
		return "", errors.New("desktop session expired")
	}
	// One active browser fallback code at a time. Rotating a code is possible
	// only through the authenticated desktop connection.
	for _, old := range t.sessions {
		old.code = ""
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	s.code = fmt.Sprintf("%06d", n.Int64())
	s.codeExpires = t.now().Add(2 * time.Minute)
	s.attempts = 0
	return s.code, nil
}
func (t *Tokens) Redeem(code string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range t.sessions {
		if s.code == "" || !t.now().Before(s.codeExpires) || !t.now().Before(s.expires) {
			continue
		}
		s.attempts++
		ok := equal(s.code, code)
		if ok || s.attempts >= 3 {
			s.code = ""
		}
		if ok {
			return s.token, nil
		}
		break
	}
	return "", errors.New("pairing code is invalid or expired")
}

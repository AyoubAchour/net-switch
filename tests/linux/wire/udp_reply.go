package wire

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand/v2"
	"strconv"
	"strings"
)

// UDPReplyRequest asks for a deterministic payload unique to this request.
// Requests stay small so this fixture isolates fragmentation on the reply leg.
func UDPReplyRequest(token string, size, sequence int) string {
	return fmt.Sprintf("T:%s:reply:%d:%d", token, size, sequence)
}

func ParseUDPReplyRequest(request string) (size int, err error) {
	if len(request) > 128 {
		return 0, fmt.Errorf("UDP reply request exceeds 128 bytes")
	}
	f := strings.Split(request, ":")
	if len(f) != 5 || f[0] != "T" || f[2] != "reply" || len(f[1]) != 12 {
		return 0, fmt.Errorf("invalid UDP reply request %q", request)
	}
	if _, err := hex.DecodeString(f[1]); err != nil {
		return 0, err
	}
	size, err = strconv.Atoi(f[3])
	if err != nil || size < 1 || size > 65527 {
		return 0, fmt.Errorf("invalid UDP reply size %q", f[3])
	}
	sequence, err := strconv.Atoi(f[4])
	if err != nil || sequence < 0 || sequence > 1000 {
		return 0, fmt.Errorf("invalid UDP reply sequence %q", f[4])
	}
	return size, nil
}

func UDPReplyPayload(request string) ([]byte, error) {
	size, err := ParseUDPReplyRequest(request)
	if err != nil {
		return nil, err
	}
	b := make([]byte, size)
	_, err = io.ReadFull(rand.NewChaCha8(sha256.Sum256([]byte(request))), b)
	return b, err
}

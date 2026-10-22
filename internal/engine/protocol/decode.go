package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/flows"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

const MessageLimit = 1 << 20
const Outstanding = 16

type Request struct {
	ID       string           `json:"id"`
	Method   string           `json:"method"`
	Instance string           `json:"engineInstanceId"`
	Epoch    uint64           `json:"epoch"`
	Revision *policy.Revision `json:"revision,omitempty"`
	Cursor   string           `json:"cursor,omitempty"`
	Receipt  string           `json:"receipt,omitempty"`
	// All asks flows for every admitted flow, unresolved ones included.
	All           bool            `json:"all,omitempty"`
	OpID          string          `json:"opId,omitempty"`
	Selector      flows.Selector  `json:"selector,omitempty"`
	StartedBefore uint64          `json:"startedBefore,omitempty"`
	Line          string          `json:"line,omitempty"`
	Operator      string          `json:"operator,omitempty"`
	App           string          `json:"app,omitempty"`
	Fault         json.RawMessage `json:"fault,omitempty"`
	// Adapter is the temporary milestone-two compatibility payload. It is
	// accepted only by a runtime advertising singbox-adapter-v1; the lease and
	// fencing are identical to the native engine protocol.
	Adapter json.RawMessage `json:"adapter,omitempty"`
}
type Reply struct {
	ID     string `json:"id"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
	stop   bool
}
type Event = flowapi.Event

func Decode(b []byte) (Request, error) {
	var r Request
	if len(b) > MessageLimit {
		return r, errors.New("message exceeds 1 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return r, errors.New("trailing JSON")
	}
	if r.ID == "" || len(r.ID) > 128 || len(r.OpID) > 128 || len(r.Cursor) > 128 || len(r.Receipt) > 128 || len(r.App) > 512 || len(r.Line) > 64 || len(r.Operator) > 256 {
		return r, errors.New("invalid request fields")
	}
	return r, nil
}

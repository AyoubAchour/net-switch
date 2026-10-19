package control

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
)

func TestUndoFailureOracle(t *testing.T) {
	b, err := os.ReadFile("../../tests/oracle/fixtures/undo.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name       string
		Undo       map[string]json.RawMessage
		LegacyUndo json.RawMessage
		Faults     map[string]any
		Expected   json.RawMessage
	}
	if err := json.Unmarshal(b, &cases); err != nil || len(cases) != 7 {
		t.Fatal("expected all seven Undo oracle cases", err)
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			c, _, _, files := testCore(t, map[string]any{"lines": testLines()})
			if _, err := c.op.Undo.Update(map[string]any{"metrics": tc.Undo["metrics"], "policy": tc.Undo["policy"]}); err != nil {
				t.Fatal(err)
			}
			if len(tc.LegacyUndo) != 0 {
				if err := c.save(map[string]any{"setupUndo": tc.LegacyUndo}); err != nil {
					t.Fatal(err)
				}
				if err := c.migrate(); err != nil {
					t.Fatal(err)
				}
			}
			operations := []any{}
			policy := any(float64(1))
			c.op.Platform.(*fakePlatform).override = func(name string, args map[string]any) (any, error, bool) {
				operation := ""
				arguments := []any{}
				var result any
				var err error
				switch name {
				case "policy-set":
					operation = "network.restoreMinimizeConnectionsPolicy"
					arguments = []any{args["value"]}
					if message := js.Text(tc.Faults["policyFailure"]); message != "" {
						err = errors.New(message)
					} else {
						policy = args["value"]
					}
				case "metrics-restore":
					operation = "network.restoreMetrics"
					arguments = []any{args["alias"], args["metrics"]}
					if message := js.Text(js.Object(tc.Faults["restoreFailures"])[js.Text(args["alias"])]); message != "" {
						err = errors.New(message)
					}
				case "policy":
					operation, result = "platform.readMinimizeConnectionsPolicy", policy
				case "network":
					operation = "platform.detectAdapters"
					result = map[string]any{"adapters": []any{map[string]any{"alias": "Ethernet"}}, "policy": policy}
				default:
					return nil, nil, false
				}
				operations = append(operations, map[string]any{"operation": operation, "args": arguments, "ok": err == nil})
				return result, err, true
			}
			files.logs = nil
			files.fail = tc.Faults["undoWriteFailure"] != nil
			h := &HTTP{Core: c, Port: 47821, Token: "test"}
			r := httptest.NewRequest("POST", "http://127.0.0.1:47821/api/setup/undo", strings.NewReader(`{}`))
			r.Header.Set("X-Token", "test")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			body, err := js.Decode(w.Body.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			logs := []string{}
			for _, line := range files.logs {
				if strings.HasPrefix(line, "undo failed:") {
					logs = append(logs, line)
				}
			}
			actual := map[string]any{"status": w.Code, "error": js.Object(body)["error"], "remaining": c.op.Undo.Values(), "policy": policy, "operations": operations, "logs": logs}
			a, err := js.Marshal(actual)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := js.Decode(a)
			want, _ := js.Decode(tc.Expected)
			if difference := firstDifference(got, want, "$"); difference != "" {
				t.Fatal(difference)
			}
		})
	}
}

package lifecycle_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

type httpInput struct{ URL, Token, Method, Route, Body string }
type httpOutput struct {
	Status int
	Body   []byte
}

func httpClientMain() int {
	var input httpInput
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		return 2
	}
	req, err := http.NewRequest(input.Method, input.URL+strings.TrimPrefix(input.Route, "/"), strings.NewReader(input.Body))
	if err != nil {
		return 2
	}
	req.Header.Set("X-Token", input.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 1
	}
	if json.NewEncoder(os.Stdout).Encode(httpOutput{resp.StatusCode, body}) != nil {
		return 1
	}
	return 0
}
func apiAs(t *testing.T, user actor, url, token, method, route, body string) (int, []byte) {
	t.Helper()
	exe, _ := os.Executable()
	cmd := user.command(exe, "client", "http")
	input, _ := json.Marshal(httpInput{url, token, method, route, body})
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal("user HTTP", err, string(output))
	}
	var response httpOutput
	if err := json.Unmarshal(output, &response); err != nil {
		t.Fatal(err, string(output))
	}
	return response.Status, response.Body
}

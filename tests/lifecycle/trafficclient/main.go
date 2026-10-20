// The hosted lifecycle suite launches this distinct executable as a second
// standard user, so app identity cannot be confused with the root test runner.
package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("NETSWITCH_LIFECYCLE_CI") != "1" || len(os.Args) != 3 {
		os.Exit(2)
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	conn, err := net.DialTimeout("tcp4", os.Args[1], 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", os.Args[2], os.Args[2]); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil {
		return err
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("CONNECT returned %s", response.Status)
	}
	if _, err := conn.Write([]byte("other-user\n")); err != nil {
		return err
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if line != "other-user\n" {
		return fmt.Errorf("unexpected echo response")
	}
	fmt.Println("ready")
	_, err = io.Copy(io.Discard, os.Stdin)
	return err
}

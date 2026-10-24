// The hosted lifecycle suite launches this distinct executable as a second
// standard user, so app identity cannot be confused with the root test runner.
// It sends one line through the routed path to the fixture's target and reads
// the reply line: the Windows target echoes it, the Linux target answers
// "pong <marker> <address>". Both contain the marker.
package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("NETSWITCH_LIFECYCLE_CI") != "1" || len(os.Args) != 2 {
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
	if _, err := io.WriteString(conn, "ping other-user\n"); err != nil {
		return err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(line, "other-user") {
		return fmt.Errorf("unexpected reply %q", line)
	}
	fmt.Println("ready")
	_, err = io.Copy(io.Discard, os.Stdin)
	return err
}

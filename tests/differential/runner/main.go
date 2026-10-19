package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/AyoubAchour/net-switch/tests/testsupport"
	"os"
	"time"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 4*1024*1024)
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()
	for scanner.Scan() {
		var request struct {
			testsupport.Call
			Timezone string `json:"timezone"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		runner := testsupport.New()
		if request.Timezone != "" {
			location, err := time.LoadLocation(request.Timezone)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			runner.Location = location
		}
		result, _ := runner.Call(request.Call)
		if err := json.NewEncoder(writer).Encode(result); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

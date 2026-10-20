package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/AyoubAchour/net-switch/internal/lifecycle"
)

func main() {
	background := flag.Bool("background", false, "owner sign-in startup without opening the browser")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := lifecycle.Desktop(ctx, !*background); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

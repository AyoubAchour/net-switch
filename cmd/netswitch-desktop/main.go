package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/AyoubAchour/net-switch/internal/buildinfo"
	"github.com/AyoubAchour/net-switch/internal/lifecycle"
)

func main() {
	background := flag.Bool("background", false, "owner sign-in startup without opening the browser")
	autostart := flag.String("autostart", "", "on, off or status; configure only this owner's sign-in entry")
	version := flag.Bool("version", false, "print build identity")
	flag.Parse()
	if *version {
		fmt.Println("netswitch-desktop", buildinfo.String())
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *autostart != "" {
		value, err := lifecycle.ConfigureAutostart(ctx, *autostart)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(value)
		return
	}
	if err := lifecycle.Desktop(ctx, !*background); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

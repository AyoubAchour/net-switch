package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/AyoubAchour/net-switch/internal/buildinfo"
	"github.com/AyoubAchour/net-switch/internal/service"
)

func ServiceCommand(name string, args []string) error {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	data := flags.String("data", DefaultData(), "protected machine store")
	if err := flags.Parse(args); err != nil {
		return err
	}
	c, err := LoadConfig(*data)
	if err != nil {
		return err
	}
	log := Log(c.Data, name)
	run := ControlService
	if name == service.Engine {
		run = EngineService
	}
	err = service.Run(name, func(ctx context.Context, ready func()) error { return run(ctx, ready, c, log) })
	if err != nil {
		log("service failed: " + err.Error())
	}
	return err
}
func Ctl(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: netswitchctl status|enroll|start|stop|journal|install|cleanup|recover|uninstall|migration-check|version")
	}
	command := args[0]
	if command == "version" {
		fmt.Println("netswitchctl", buildinfo.String())
		return nil
	}
	flags := flag.NewFlagSet("netswitchctl "+command, flag.ContinueOnError)
	data := flags.String("data", DefaultData(), "protected machine store")
	dir := flags.String("directory", "", "directory containing the service executables")
	adapter := flags.String("adapter", "", "verified sing-box executable (until the engine swap)")
	mode := flags.String("mode", "tun", "tun or proxy")
	ownerName := flags.String("owner", "", "interactive owner to enroll; omit to leave pending")
	engine := flags.Bool("engine", false, "engine recovery")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	printJSON := func(value any, err error) error {
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(value)
	}
	switch command {
	case "status", "start", "stop":
		if command != "status" {
			if err := service.Activate(ctx); err != nil {
				return err
			}
		}
		rpc, err := ConnectDesktop(ctx, command == "status")
		if err != nil {
			return err
		}
		defer rpc.Close()
		request := map[string]any{"method": "status"}
		if command != "status" {
			request = map[string]any{"method": "routing", "on": command == "start"}
		}
		var result any
		err = rpc.Call(ctx, request, &result)
		return printJSON(result, err)
	case "journal", "migration-check":
		value, err := Inspect(*data)
		return printJSON(value, err)
	case "enroll", "enrol":
		if !Administrator() {
			return errors.New("enrollment requires an administrator")
		}
		name := *ownerName
		if flags.NArg() == 1 {
			name = flags.Arg(0)
		}
		// A changed owner revokes every existing connection and browser token.
		status, queryErr := service.Query(service.Control)
		if queryErr == nil && status.Running {
			if err := service.Stop(ctx, service.Control); err != nil {
				return err
			}
		}
		owner, err := Enroll(ctx, *data, name)
		if err != nil {
			return err
		}
		if err := service.SetOwner(owner.User); err != nil {
			return err
		}
		if queryErr == nil && status.Running {
			if err := service.Start(ctx, service.Control); err != nil {
				return err
			}
		}
		return printJSON(owner, nil)
	case "install":
		if !Administrator() {
			return errors.New("install requires an administrator")
		}
		if *dir == "" || *adapter == "" {
			return errors.New("--directory and --adapter are required")
		}
		var err error
		*dir, err = filepath.Abs(*dir)
		if err != nil {
			return err
		}
		*adapter, err = filepath.Abs(*adapter)
		if err != nil {
			return err
		}
		*data, err = filepath.Abs(*data)
		if err != nil {
			return err
		}
		if *mode != "tun" && *mode != "proxy" {
			return errors.New("mode must be tun or proxy")
		}
		if err := PrepareDirectory(*data); err != nil {
			return err
		}
		c := Config{Directory: *dir, Data: *data, Adapter: *adapter, Mode: *mode}
		if err := Save(filepath.Join(*data, "service-config.json"), c); err != nil {
			return err
		}
		var owner Owner
		if *ownerName != "" {
			owner, err = Enroll(ctx, *data, *ownerName)
			if err != nil {
				return err
			}
		}
		return service.Install(service.Config{Directory: *dir, Data: *data, Owner: owner.User})
	case "cleanup", "recover":
		if !Administrator() {
			return errors.New("cleanup requires an administrator")
		}
		if !*engine {
			return errors.New("specify --engine")
		}
		if err := CheckDirectory(*data); err != nil {
			return err
		}
		short, stop := context.WithTimeout(ctx, 2*time.Second)
		defer stop()
		return Cleanup(short, *data)
	case "uninstall":
		if !Administrator() {
			return errors.New("uninstall requires an administrator")
		}
		if err := service.Uninstall(ctx); err != nil {
			return err
		}
		return Cleanup(ctx, *data)
	case "migrate":
		return errors.New("0.3.x migration belongs to milestone five; migration-check is read-only")
	default:
		return fmt.Errorf("unknown command %q (%s)", command, runtime.GOOS)
	}
}

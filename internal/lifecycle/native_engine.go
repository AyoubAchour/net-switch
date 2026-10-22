package lifecycle

import (
	"context"
	"path/filepath"
	"sync"

	"github.com/AyoubAchour/net-switch/internal/engine/host"
	"github.com/AyoubAchour/net-switch/internal/engine/protocol"
	"github.com/AyoubAchour/net-switch/internal/service"
)

func nativeEngineService(ctx context.Context, ready func(), c Config, log func(string)) error {
	run, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	options := host.Options{
		OpenState: func(instance string) (host.State, error) {
			path := filepath.Join(c.Data, "engine-state.json")
			return host.Open(path, instance, func(record host.Record) error { return Save(path, record) })
		},
		Ready: func(server *protocol.Server) {
			workers.Go(func() {
				events := service.Events(ctx)
				for {
					select {
					case <-run.Done():
						return
					case <-events.Ready():
						for _, event := range events.Take() {
							if event.Resume {
								resumeEngine(server, log)
							}
						}
					}
				}
			})
			ready()
		},
	}
	configureNativeProof(c.Data, &options)
	// Native Serve owns the OS lifetime lock and cleanup. Acquiring the old
	// adapter lock here would deadlock Linux startup on the same engine.lock.
	return serveNative(run, c.Data, options)
}

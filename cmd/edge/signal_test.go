package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// signalCtx returns a context that also keeps SIGHUP from terminating the test binary while the
// edge's watcher is being exercised (signal.Notify in the test process makes it a delivery, not a
// default-action kill, as long as some channel is registered).
func signalCtx() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	return ctx, func() {
		signal.Stop(c)
		cancel()
	}
}

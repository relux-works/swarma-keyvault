package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

type signalKey struct{}
type signalRecord struct {
	mu      sync.Mutex
	signals []string
}

// Keep handling later signals until cleanup/reporting finishes. Only the first
// signal cancels execution; subsequent observations cannot bypass final cleanup.
func signalContext(parent context.Context) (context.Context, func()) {
	r := &signalRecord{}
	ctx, cancel := context.WithCancel(context.WithValue(parent, signalKey{}, r))
	ch := make(chan os.Signal, 8)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case sig := <-ch:
				r.record(sig)
				cancel()
			case <-stop:
				return
			}
		}
	}()
	return ctx, func() { signal.Stop(ch); close(stop); <-done; cancel() }
}

func (s *signalRecord) record(sig os.Signal) {
	name := ""
	switch sig {
	case syscall.SIGINT:
		name = "SIGINT"
	case syscall.SIGTERM:
		name = "SIGTERM"
	}
	if name == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, old := range s.signals {
		if old == name {
			return
		}
	}
	s.signals = append(s.signals, name)
}

func (r *result) observeSignals(ctx context.Context) {
	s, _ := ctx.Value(signalKey{}).(*signalRecord)
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.signals) > 0 {
		r.FirstSignal = s.signals[0]
		r.observe("canceled")
	}
	for _, name := range s.signals {
		r.observe(name)
	}
}

func primaryCause(observed []string) string {
	for _, preferred := range []string{"deadline", "canceled", "active-reap-refused", "exit", "success"} {
		for _, cause := range observed {
			if cause == preferred {
				return preferred
			}
		}
	}
	return "start-refused"
}

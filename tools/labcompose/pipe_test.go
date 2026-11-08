package main

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func pipes(t *testing.T) (*pipe, *os.File, *os.File) {
	t.Helper()
	in, reply, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	request, out, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	p, err := newPipe(in, out)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close(); reply.Close(); request.Close() })
	return p, reply, request
}

func TestPipeResponsiveFramingAndBounds(t *testing.T) {
	p, reply, request := pipes(t)
	for i := 0; i < 256; i++ {
		if _, err := reply.Write([]byte("{\"result\":{\"ok\":true}}\n")); err != nil {
			t.Fatal(err)
		}
		raw, err := p.raw(context.Background(), "name_show", "d/lab", map[string]any{"nameEncoding": "ascii"})
		if err != nil || string(raw) != `{"ok":true}` {
			t.Fatalf("reply %s: %v", raw, err)
		}
		line, err := bufio.NewReader(request).ReadBytes('\n')
		if err != nil || string(line) != "{\"params\":[\"d/lab\",{\"nameEncoding\":\"ascii\"}],\"rpc\":\"name_show\"}\n" {
			t.Fatalf("framing %q: %v", line, err)
		}
	}
	if _, err := p.raw(context.Background(), "name_show"); err == nil || p.calls != 256 {
		t.Fatal("call cap")
	}
	q, _, _ := pipes(t)
	if _, err := q.raw(context.Background(), "sendrawtransaction"); err == nil || q.calls != 0 {
		t.Fatal("method allowlist")
	}
}

func TestPipeStalledReadAndBlockedWrite(t *testing.T) {
	for _, blockedWrite := range []bool{false, true} {
		t.Run(map[bool]string{false: "read", true: "write"}[blockedWrite], func(t *testing.T) {
			p, _, _ := pipes(t)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			args := []any{}
			if blockedWrite {
				args = append(args, strings.Repeat("x", 1<<20))
			}
			start := time.Now()
			raw, err := p.raw(ctx, "getblock", args...)
			if !errors.Is(err, context.DeadlineExceeded) || raw != nil || time.Since(start) > time.Second {
				t.Fatalf("cancel: %s %v", raw, err)
			}
			if _, err := p.in.Read(make([]byte, 1)); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("input not closed: %v", err)
			}
			if _, err := p.out.Write([]byte("x")); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("output not closed: %v", err)
			}
			if _, err := p.raw(context.Background(), "getblock"); err == nil {
				t.Fatal("terminal pipe retried")
			}
		})
	}
}

func TestPipeCanceledBlockedWrite(t *testing.T) {
	p, _, _ := pipes(t)
	ctx, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(30*time.Millisecond, cancel)
	defer timer.Stop()
	defer cancel()
	raw, err := p.raw(ctx, "getblock", strings.Repeat("x", 1<<20))
	if !errors.Is(err, context.Canceled) || raw != nil {
		t.Fatalf("canceled write: %s %v", raw, err)
	}
}

func TestPipeLateReply(t *testing.T) {
	p, reply, request := pipes(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		bufio.NewReader(request).ReadBytes('\n')
		cancel()
		reply.Write([]byte("{\"result\":true}\n"))
	}()
	raw, err := p.raw(ctx, "getblockchaininfo")
	<-done
	if !errors.Is(err, context.Canceled) || raw != nil {
		t.Fatalf("late reply admitted: %s %v", raw, err)
	}
}

func TestPipeAlreadyCanceledWriteAndFinalSend(t *testing.T) {
	p, _, _ := pipes(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.raw(ctx, "getblock"); !errors.Is(err, context.Canceled) || p.calls != 0 {
		t.Fatalf("pre-cancel %v", err)
	}
	if err := p.send(ctx, map[string]any{"done": true}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	if err := p.send(ctx, strings.Repeat("x", 1<<20)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("final write: %v", err)
	}
}

func TestPipeReplyByteCap(t *testing.T) {
	p, reply, _ := pipes(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		reply.Write([]byte("{\"result\":\"" + strings.Repeat("x", 8<<20) + "\"}\n"))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if raw, err := p.raw(ctx, "getblock"); err == nil || raw != nil {
		t.Fatal("oversized reply admitted")
	}
	p.Close()
	<-done
}

func TestPipeCleanupNeighbors(t *testing.T) {
	// Warm up runtime poller/timer before measuring repeated cancellations.
	p, _, _ := pipes(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	p.raw(ctx, "getblock")
	cancel()
	before, _ := os.ReadDir("/proc/self/fd")
	goroutines := runtime.NumGoroutine()
	for i := 0; i < 30; i++ {
		p, reply, request := pipes(t)
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		p.raw(ctx, "getblock")
		cancel()
		p.Close()
		reply.Close()
		request.Close()
	}
	after, _ := os.ReadDir("/proc/self/fd")
	if len(after) != len(before) {
		t.Fatalf("fd leak: before %d after %d", len(before), len(after))
	}
	end := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > goroutines && time.Now().Before(end) {
		runtime.Gosched()
	}
	if runtime.NumGoroutine() > goroutines {
		t.Fatalf("goroutine leak: before %d after %d", goroutines, runtime.NumGoroutine())
	}
}

// Exercise the actual CLI opener against inherited blocking descriptors.
func TestInheritedProtocolHelper(t *testing.T) {
	mode := os.Getenv("LAB_PIPE_HELPER")
	if mode == "" {
		return
	}
	owned := strings.HasPrefix(mode, "owned-")
	mode = strings.TrimPrefix(mode, "owned-")
	flagsIn, _, _ := syscall.Syscall(syscall.SYS_FCNTL, 0, syscall.F_GETFL, 0)
	flagsOut, _, _ := syscall.Syscall(syscall.SYS_FCNTL, 1, syscall.F_GETFL, 0)
	open := openProtocol
	if owned {
		open = openOwnedProtocol
	}
	p, err := open()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	var args []any
	if mode == "write" {
		args = append(args, strings.Repeat("x", 1<<20))
	}
	raw, err := p.raw(ctx, "getblock", args...)
	if mode == "responsive" {
		if err != nil || string(raw) != "true" {
			t.Fatalf("responsive inherited pipe: %s %v", raw, err)
		}
		if err := p.send(ctx, map[string]any{"done": true}); err != nil {
			t.Fatal(err)
		}
	} else if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("inherited %s: %v", mode, err)
	}
	p.Close()
	if owned {
		os.Exit(0)
	}
	// Owned endpoints closed; inherited stdin/stdout still belong to the caller.
	if _, err := os.Stdin.Stat(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stdout.Stat(); err != nil {
		t.Fatal(err)
	}
	afterIn, _, _ := syscall.Syscall(syscall.SYS_FCNTL, 0, syscall.F_GETFL, 0)
	afterOut, _, _ := syscall.Syscall(syscall.SYS_FCNTL, 1, syscall.F_GETFL, 0)
	if flagsIn != afterIn || flagsOut != afterOut {
		t.Fatal("inherited descriptor flags changed")
	}
	os.Exit(0)
}

func TestInheritedProtocolCancellation(t *testing.T) {
	for _, mode := range []string{"write", "read", "responsive", "owned-write", "owned-read", "owned-responsive"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestInheritedProtocolHelper$")
			cmd.Env = append(os.Environ(), "LAB_PIPE_HELPER="+mode)
			in, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer in.Close()
			out, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			baseMode := strings.TrimPrefix(mode, "owned-")
			if baseMode != "write" {
				reader := bufio.NewReader(out)
				if _, err := reader.ReadBytes('\n'); err != nil {
					t.Fatal(err)
				}
				if baseMode == "responsive" {
					if _, err := in.Write([]byte("{\"result\":true}\n")); err != nil {
						t.Fatal(err)
					}
					line, err := reader.ReadBytes('\n')
					if err != nil || string(line) != "{\"done\":true}\n" {
						t.Fatalf("final frame: %q %v", line, err)
					}
				}
			}
			if err := cmd.Wait(); err != nil {
				t.Fatalf("inherited %s: %v", mode, err)
			}
		})
	}
}

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
)

// pipe owns both endpoints. The protocol is serial; cancellation is terminal,
// since a partially sent request or unread reply cannot safely be retried.
type pipe struct {
	in, out   *os.File
	scanner   *bufio.Scanner
	calls     int
	closeOnce sync.Once
}

// Reopen the CLI's inherited pipes as private, nonblocking file descriptions.
// NewFile on a blocking inherited fd would not use Go's interruptible poller.
// Never close the caller's inherited descriptors or change their status flags.
func openProtocol() (*pipe, error) {
	in, err := os.OpenFile("/proc/self/fd/0", os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	out, err := os.OpenFile("/proc/self/fd/1", os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		in.Close()
		return nil, err
	}
	return newPipe(in, out)
}

// openOwnedProtocol is the portable supervisor route. The supervisor creates
// dedicated anonymous pipes and transfers the child endpoints exclusively;
// no other process may retain aliases to these file descriptions. Unlike the
// legacy opener this contract explicitly permits changing flags and closing
// inherited stdin/stdout. It requires no /proc or external platform tools.
func openOwnedProtocol() (*pipe, error) {
	for _, f := range []*os.File{os.Stdin, os.Stdout} {
		st, err := f.Stat()
		if err != nil || st.Mode()&os.ModeNamedPipe == 0 {
			return nil, fmt.Errorf("owned protocol requires dedicated pipes")
		}
	}
	if err := syscall.SetNonblock(0, true); err != nil {
		return nil, err
	}
	if err := syscall.SetNonblock(1, true); err != nil {
		return nil, err
	}
	return newPipe(os.NewFile(0, "owned-protocol-input"), os.NewFile(1, "owned-protocol-output"))
}

// newPipe takes ownership, including on failure. Only pollable pipes qualify.
func newPipe(in, out *os.File) (*pipe, error) {
	if err := in.SetReadDeadline(time.Time{}); err != nil {
		in.Close()
		out.Close()
		return nil, err
	}
	if err := out.SetWriteDeadline(time.Time{}); err != nil {
		in.Close()
		out.Close()
		return nil, err
	}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 4096), 8<<20)
	return &pipe{in: in, out: out, scanner: sc}, nil
}

func (p *pipe) Close() {
	p.closeOnce.Do(func() { p.in.Close(); p.out.Close() })
}

// I/O stays in the caller. The cancellation callback closes owned pollable
// endpoints to unblock it, and is joined before returning. No orphan I/O worker.
func (p *pipe) interrupt(ctx context.Context) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { p.Close(); close(done) })
	return func() {
		if !stop() {
			<-done
		}
	}
}

func (p *pipe) send(ctx context.Context, value any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	finish := p.interrupt(ctx)
	err := json.NewEncoder(p.out).Encode(value)
	finish()
	if canceled := ctx.Err(); canceled != nil {
		return canceled
	}
	return err
}

func (p *pipe) raw(ctx context.Context, method string, args ...any) (result json.RawMessage, err error) {
	switch method {
	case "getblockchaininfo", "getblockhash", "getblockheader", "name_show", "getrawtransaction", "gettxout", "getrawmempool", "getblock":
	default:
		return nil, fmt.Errorf("read method denied")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.calls >= 256 {
		return nil, fmt.Errorf("read bound")
	}
	p.calls++
	finish := p.interrupt(ctx)
	defer func() {
		finish()
		if canceled := ctx.Err(); canceled != nil {
			result, err = nil, canceled
		}
	}()
	if err := json.NewEncoder(p.out).Encode(map[string]any{"rpc": method, "params": args}); err != nil {
		if canceled := ctx.Err(); canceled != nil {
			return nil, canceled
		}
		p.Close()
		return nil, err
	}
	if !p.scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p.Close()
		return nil, fmt.Errorf("read pipe closed")
	}
	var response struct {
		Result json.RawMessage `json:"result"`
		Failed bool            `json:"failed"`
	}
	if json.Unmarshal(p.scanner.Bytes(), &response) != nil || response.Failed {
		return nil, fmt.Errorf("read pipe failed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return response.Result, nil
}

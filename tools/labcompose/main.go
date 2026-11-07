// labcompose connects the lab wrapper/watcher to a closed read pipe.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	wrapper "github.com/relux-works/swarma-keyvault/lab/namecoinwrapper"
	watch "github.com/relux-works/swarma-keyvault/lab/sealwatch"
	"io"
	"os"
	"time"
)

type wpipe struct{ p *pipe }

func (w wpipe) Call(ctx context.Context, m string, a ...any) (json.RawMessage, error) {
	return w.p.raw(ctx, m, a...)
}

type spipe struct{ p *pipe }

func (s spipe) Call(ctx context.Context, m string, a ...any) (io.ReadCloser, error) {
	b, e := s.p.raw(ctx, m, a...)
	return io.NopCloser(bytes.NewReader(b)), e
}

type input struct {
	Policy               wrapper.Policy
	Binding              watch.Binding
	Certificate, Request string
	At                   time.Time
	Mode                 string
}

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	b, e := os.ReadFile(os.Args[1])
	if e != nil {
		os.Exit(2)
	}
	var in input
	if json.Unmarshal(b, &in) != nil {
		os.Exit(2)
	}
	p, e := openProtocol()
	if e != nil {
		os.Exit(2)
	}
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if in.Mode == "watch" {
		l := watch.DefaultLimits()
		l.Polls = 1
		v := watch.New(spipe{p}).Watch(ctx, in.Binding, l)
		p.send(ctx, map[string]any{"done": true, "watch": v})
		return
	}
	cert, e := os.ReadFile(in.Certificate)
	if e != nil {
		os.Exit(2)
	}
	req, e := os.ReadFile(in.Request)
	if e != nil {
		os.Exit(2)
	}
	cli, e := os.ReadFile(in.Policy.CLI)
	if e != nil {
		os.Exit(2)
	}
	h := sha256.Sum256(cli)
	in.Policy.CLIHash = hex.EncodeToString(h[:])
	observation, err := new(wrapper.Verifier).Verify(ctx, wpipe{p}, in.Policy, cert, req, in.At)
	result := map[string]any{"done": true, "verified": err == nil, "observation": observation, "read_calls": p.calls}
	if err != nil {
		result["error"] = "lab verification refused"
	}
	p.send(ctx, result)
}

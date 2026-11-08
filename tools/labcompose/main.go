// labcompose connects the lab wrapper/watcher to a closed read pipe.
package main

import (
	"bytes"
	"context"
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

func readInput(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if int64(len(b)) > max {
		return nil, io.ErrShortBuffer
	}
	return b, err
}

func main() {
	owned := len(os.Args) == 3 && os.Args[1] == "--owned-protocol"
	if len(os.Args) != 2 && !owned {
		os.Exit(2)
	}
	inputPath := os.Args[1]
	if owned {
		inputPath = os.Args[2]
	}
	b, e := readInput(inputPath, 65536)
	if e != nil {
		os.Exit(2)
	}
	var in input
	if json.Unmarshal(b, &in) != nil {
		os.Exit(2)
	}
	open := openProtocol
	if owned {
		open = openOwnedProtocol
	}
	p, e := open()
	if e != nil {
		os.Exit(2)
	}
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if in.Mode == "watch" {
		network, genesis, err := wrapper.NetworkPolicy(in.Policy.Network, in.Policy.Genesis)
		if err != nil || in.Binding.Chain != network || in.Binding.Genesis != genesis {
			os.Exit(2)
		}
		l := watch.DefaultLimits()
		l.Polls = 1
		v := watch.New(spipe{p}).Watch(ctx, in.Binding, l)
		p.send(ctx, map[string]any{"done": true, "watch": v})
		return
	}
	if in.Mode != "verify" {
		os.Exit(2)
	}
	cert, e := readInput(in.Certificate, 98304)
	if e != nil {
		os.Exit(2)
	}
	req, e := readInput(in.Request, 12288)
	if e != nil {
		os.Exit(2)
	}
	observation, err := new(wrapper.Verifier).Verify(ctx, wpipe{p}, in.Policy, cert, req, in.At)
	result := map[string]any{"done": true, "verified": err == nil, "observation": observation, "read_calls": p.calls}
	if err != nil {
		result["error"] = "lab verification refused"
	}
	p.send(ctx, result)
}

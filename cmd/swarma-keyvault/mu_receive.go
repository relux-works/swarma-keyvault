package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/relux-works/swarma-keyvault/internal/grants"
)

// runMUReceiver runs mu-state-init or mu-execute against an owner-pinned
// receiver configuration.
func runMUReceiver(op string, args []string, stdout, stderr io.Writer) int {
	usageText := "swarma-keyvault grants mu-state-init --config FILE | swarma-keyvault grants mu-execute --config FILE --event '$EVENT'"
	f := flag.NewFlagSet(op, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var config, event onceString
	f.Var(&config, "config", "receiver configuration file")
	if op == "mu-execute" {
		f.Var(&event, "event", "event id")
	}
	if err := f.Parse(args); err != nil {
		fmt.Fprintln(stderr, usageText)
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if f.NArg() != 0 || !config.set || config.value == "-" || (op == "mu-execute" && (!event.set || event.value == "")) {
		fmt.Fprintln(stderr, usageText)
		return 2
	}
	svc, err := grants.LoadMUService(config.value)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if op == "mu-state-init" {
		if err := svc.InitState(); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return muWrite(stdout, map[string]string{"type": "mu-state-initialized-1"})
	}
	out, err := svc.Execute(context.Background(), event.value)
	if err != nil {
		state := "refused"
		if out != nil {
			state = out.State
		}
		fmt.Fprintln(stderr, err)
		muWrite(stdout, map[string]string{"type": "mu-execute-result-1", "state": state, "refusal": err.Error()})
		return 1
	}
	return muWrite(stdout, map[string]string{"type": "mu-execute-result-1", "state": out.State, "receipt": string(out.Receipt)})
}

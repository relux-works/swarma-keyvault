// Command suiterunner bounds a complete Linux test invocation and reaps its
// descendants. It is a dedicated process, never an in-process library runner.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type options struct {
	timeout time.Duration
	report  string
	command []string
}

type result struct {
	Reason    string `json:"reason"`
	Cause     string `json:"cause"`
	ExitCode  int    `json:"exit_code"`
	RootExit  int    `json:"root_exit"`
	Reaped    bool   `json:"reaped"`
	ElapsedNS int64  `json:"elapsed_ns"`
}

func parse(args []string) (options, error) {
	o := options{timeout: 30 * time.Minute}
	seen := make(map[string]bool)
	for i, arg := range args {
		if arg == "--" {
			o.command = args[i+1:]
			if len(o.command) == 0 || o.command[0] == "" {
				break
			}
			return o, nil
		}
		key, value, ok := strings.Cut(arg, "=")
		if !ok || seen[key] {
			break
		}
		seen[key] = true
		switch key {
		case "--timeout":
			d, err := time.ParseDuration(value)
			if err != nil || d <= 0 || d > 30*time.Minute {
				return options{}, errors.New("invalid timeout")
			}
			o.timeout = d
		case "--report":
			if !filepath.IsAbs(value) || filepath.Clean(value) != value {
				return options{}, errors.New("invalid report path")
			}
			o.report = value
		default:
			return options{}, errors.New("unknown option")
		}
	}
	return options{}, errors.New("invalid command boundary")
}

func execute(args []string, in, out, diagnostic *os.File) int {
	o, err := parse(args)
	if err != nil {
		fmt.Fprintln(diagnostic, "suite runner: invalid arguments")
		return 64
	}
	var report *os.File
	if o.report != "" {
		info, err := os.Lstat(filepath.Dir(o.report))
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			fmt.Fprintln(diagnostic, "suite runner: report requires a private directory")
			return 64
		}
		// A previous result, symlink or hard-link target is never overwritten.
		report, err = os.OpenFile(o.report, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			fmt.Fprintln(diagnostic, "suite runner: report creation refused")
			return 64
		}
		defer report.Close()
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	r := run(ctx, o.timeout, o.command, in, out, diagnostic)
	if report != nil {
		if err := json.NewEncoder(report).Encode(r); err != nil {
			fmt.Fprintln(diagnostic, "suite runner: result write refused")
			return 125
		}
	}
	// No command arguments, environment, paths or subprocess payloads are echoed.
	fmt.Fprintf(diagnostic, "suite runner: %s; cause=%s; root_exit=%d; reaped=%t\n", r.Reason, r.Cause, r.RootExit, r.Reaped)
	return r.ExitCode
}

func main() { os.Exit(execute(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

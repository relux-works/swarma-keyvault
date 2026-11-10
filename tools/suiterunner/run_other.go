//go:build !linux

package main

import (
	"context"
	"os"
	"time"
)

func run(context.Context, time.Duration, []string, *os.File, *os.File, *os.File) result {
	return result{Reason: "unsupported", Cause: "unsupported", ExitCode: 125, RootExit: -1, ObservedCauses: []string{"unsupported"}}
}

//go:build linux

package main

import (
	"os"
	"syscall"
)

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

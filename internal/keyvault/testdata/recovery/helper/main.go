// A synthetic private-pipe protocol fixture. It never imports custody code,
// contacts Keychain/Enclave, or handles owner material.
package main

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"time"
)

func main() {
	var header [4]byte
	if _, err := io.ReadFull(os.Stdin, header[:]); err != nil {
		os.Exit(2)
	}
	n := binary.BigEndian.Uint32(header[:])
	if n > 32768 {
		os.Exit(2)
	}
	if _, err := io.CopyN(io.Discard, os.Stdin, int64(n)); err != nil {
		os.Exit(2)
	}
	_ = os.WriteFile(os.Args[0]+".received", []byte("request received"), 0600)
	mode := filepath.Base(os.Args[0])
	if mode == "hang" {
		time.Sleep(10 * time.Second)
		return
	}
	length := uint32(68)
	if mode == "oversized" {
		length = 65537
	}
	frame := make([]byte, 5)
	binary.BigEndian.PutUint32(frame[1:], length)
	if mode == "refusal" {
		frame[0] = 1
		length = 14
		binary.BigEndian.PutUint32(frame[1:], length)
	}
	_, _ = os.Stdout.Write(frame)
	if mode == "truncated" || mode == "oversized" {
		return
	}
	if mode == "refusal" {
		_, _ = os.Stdout.Write([]byte("policy_refused"))
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(make([]byte, 68))
	if mode == "extra" {
		_, _ = os.Stdout.Write([]byte{1})
	}
	if mode == "bad-exit" {
		os.Exit(1)
	}
}

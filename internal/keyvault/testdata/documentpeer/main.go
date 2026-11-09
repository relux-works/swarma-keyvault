// documentpeer is an inert JSON peer for the exact-document protocol tests.
// It has no native helper or key custody dependency.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"
)

func run(mode string) error {
	reader := bufio.NewReader(os.Stdin)
	read := func(v any) error {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return err
		}
		return json.Unmarshal(line, v)
	}
	var request struct {
		Review map[string]any `json:"review"`
	}
	if err := read(&request); err != nil {
		return err
	}
	binding := request.Review
	enc := json.NewEncoder(os.Stdout)
	switch mode {
	case "timeout":
		time.Sleep(5 * time.Second)
		return nil
	case "oversize":
		_, err := fmt.Fprintln(os.Stdout, strings.Repeat("x", 65537))
		return err
	case "eof":
		return nil
	case "native-cancel":
		_ = enc.Encode(map[string]any{"error": map[string]any{"code": "user_canceled", "status": -128, "message": "synthetic consent canceled"}})
		return fmt.Errorf("synthetic cancellation")
	}
	review := make(map[string]any, len(binding)+1)
	for k, v := range binding {
		review[k] = v
	}
	review["phase"] = "confirmed"
	switch mode {
	case "digest-only":
		delete(review, "document")
	case "wrong-phase":
		review["phase"] = "ready"
	case "unknown-field":
		review["consent"] = true
	case "tamper":
		review["document"] = []byte("changed")
	}
	if err := enc.Encode(review); err != nil {
		return err
	}
	if mode == "post-timeout" || mode == "post-cancel" {
		time.Sleep(5 * time.Second)
		return nil
	}
	var dispatch map[string]any
	if err := read(&dispatch); err != nil {
		return err
	}
	if dispatch["phase"] != "dispatch" {
		return fmt.Errorf("missing dispatch phase")
	}
	delete(dispatch, "phase")
	if !reflect.DeepEqual(dispatch, binding) {
		return fmt.Errorf("dispatch binding changed")
	}
	if mode == "post-error" {
		_ = enc.Encode(map[string]any{"error": map[string]any{"code": "security", "status": -50, "message": "synthetic post-dispatch error"}})
		return fmt.Errorf("synthetic failure")
	}
	if err := enc.Encode(map[string]any{"der": []byte("synthetic-der"), "point": binding["point"]}); err != nil {
		return err
	}
	if mode == "trailing" {
		_, err := os.Stdout.WriteString("{}\n")
		return err
	}
	return nil
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--self-check" {
		return
	}
	// The filename selects the behavior without an interpreter or wrapper.
	mode := strings.TrimPrefix(os.Args[0][strings.LastIndexAny(os.Args[0], "/\\")+1:], "document-peer-")
	if err := run(mode); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

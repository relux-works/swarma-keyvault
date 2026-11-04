package grants

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// This child is the current Go test binary, never gh. Exact argv/stdin/env are
// checked before recording a single inert fixture call; no credential is read.
func runA2AProviderFixture(mode string) int {
	want := []string{"api", "--hostname", "github.com", "-X", "POST", "orgs/relux-works/repos", "--input", "-"}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1025))
	var body map[string]any
	if err != nil || len(raw) > 1024 || !reflect.DeepEqual(os.Args[1:], want) || json.Unmarshal(raw, &body) != nil || len(body) != 2 || body["name"] != A2ARepository || body["private"] != true || os.Getenv("GH_PROMPT_DISABLED") != "1" {
		return 92
	}
	f, err := os.OpenFile(os.Getenv("KEYVAULT_A2A_GH_CALLS"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return 93
	}
	_, err = f.WriteString("create\n")
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return 94
	}
	switch mode {
	case "success":
		b, _ := json.Marshal(map[string]any{"id": 42, "node_id": "R_fixture", "full_name": LocalOrganization + "/" + A2ARepository, "private": true, "extra": nil})
		_, _ = os.Stdout.Write(b)
	case "bad-receipt":
		_, _ = os.Stdout.WriteString("{}")
	case "process-failure":
		_, _ = os.Stderr.WriteString("inert diagnostic must not escape")
		return 17
	case "output-limit":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte{'x'}, localReceiptLimit+1))
	case "stderr-limit":
		_, _ = os.Stderr.Write(bytes.Repeat([]byte{'x'}, 8193))
	default:
		return 95
	}
	return 0
}

// The actual process adapter uses the fixed endpoint/private G2 target once.
// Bad receipts/process/output failures keep the reservation held as UNKNOWN;
// replay never starts a second fixture process or forwards its diagnostics.
func TestA2ADurableProviderProcessBoundary(t *testing.T) {
	for _, mode := range []string{"success", "bad-receipt", "process-failure", "output-limit", "stderr-limit"} {
		t.Run(mode, func(t *testing.T) {
			_, m, _, e := a2aMediatorFixture(t)
			calls := filepath.Join(t.TempDir(), "calls")
			t.Setenv("KEYVAULT_A2A_GH_FIXTURE", mode)
			t.Setenv("KEYVAULT_A2A_GH_CALLS", calls)
			m.provider = a2aGHProvider{path: m.providerPath}
			out, err := m.Execute(context.Background(), e)
			if mode == "success" {
				if err != nil || out == nil || out.State != "succeeded" {
					t.Fatal(mode, out, err)
				}
			} else if !errors.Is(err, ErrA2AUnknown) || out == nil || out.State != "unknown" {
				t.Fatal(mode, out, err)
			}
			if _, err := m.Execute(context.Background(), e); !errors.Is(err, ErrA2AUseHeld) {
				t.Fatal("process replay not held", err)
			}
			b, err := os.ReadFile(calls)
			if err != nil || string(b) != "create\n" {
				t.Fatal("wrong process count", err, string(b))
			}
		})
	}
}

// The same receipt predicates preserve each fixed profile's legitimate target
// while rejecting substitution in both directions and arbitrary repositories.
func TestA2AProviderReceiptScope(t *testing.T) {
	good := a2aReceiptFixture(t)
	if _, err := parseRepositoryProviderReceipt(good, A2ARepository); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{LocalRepository, "arbitrary"} {
		if _, err := parseRepositoryProviderReceipt(good, target); err == nil {
			t.Fatal("wrong receipt scope accepted", target)
		}
	}
	if _, err := parseLocalProviderReceipt(localGoodReceipt()); err != nil {
		t.Fatal("local positive changed", err)
	}
	if _, err := parseRepositoryProviderReceipt(localGoodReceipt(), A2ARepository); err == nil {
		t.Fatal("old local receipt accepted as G2")
	}
}

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
	"strings"
	"testing"
)

// The test binary acts as a Go-only gh fixture. It validates argv/stdin and
// records each process start, without opening credentials or making a network
// call. The external docking test uses this same process boundary.
func TestMain(m *testing.M) {
	if mode := os.Getenv("KEYVAULT_A2A_PROJECTION_FIXTURE"); mode != "" && len(os.Args) > 1 && os.Args[1] == "--profile" {
		os.Exit(runA2AProjectionFixture(mode))
	}
	if mode := os.Getenv("KEYVAULT_A2A_GH_FIXTURE"); mode != "" {
		os.Exit(runA2AProviderFixture(mode))
	}
	if mode := os.Getenv("KEYVAULT_LOCAL_GH_FIXTURE"); mode != "" {
		want := []string{"api", "--hostname", "github.com", "-X", "POST", "orgs/relux-works/repos", "--input", "-"}
		input, err := io.ReadAll(io.LimitReader(os.Stdin, 1024))
		var body map[string]any
		if err != nil || !reflect.DeepEqual(os.Args[1:], want) || json.Unmarshal(input, &body) != nil || len(body) != 2 || body["name"] != LocalRepository || body["private"] != true || os.Getenv("GH_PROMPT_DISABLED") != "1" {
			os.Exit(92)
		}
		f, err := os.OpenFile(os.Getenv("KEYVAULT_LOCAL_GH_CALLS"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			os.Exit(93)
		}
		_, err = f.WriteString("create\n")
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			os.Exit(94)
		}
		switch mode {
		case "success":
			_, _ = os.Stdout.Write(localGoodReceipt())
		case "invalid":
			_, _ = os.Stdout.WriteString(`{"id":42,"node_id":"R_fixture","full_name":"relux-works/wrong","private":true}`)
		case "stdout-limit":
			_, _ = os.Stdout.Write(bytes.Repeat([]byte{'x'}, localReceiptLimit+1))
		case "stderr-limit":
			_, _ = os.Stderr.Write(bytes.Repeat([]byte{'x'}, 8193))
		case "failure":
			_, _ = os.Stderr.WriteString("fixture private diagnostic must not escape")
			os.Exit(17)
		default:
			os.Exit(95)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func localGoodReceipt() []byte {
	return []byte(" {\n\"id\":42,\"node_id\":\"R_kgFixture\",\"full_name\":\"relux-works/matrix-grants-poc-261031\",\"private\":true,\"owner\":{\"login\":\"relux-works\"},\"topics\":[],\"description\":null}\n")
}

// Accept the provider's normal whitespace, extra/nested/null fields, legacy
// base64 and current opaque node ids. Reject ambiguous or mismatched receipts.
func TestLocalProviderReceipts(t *testing.T) {
	good := localGoodReceipt()
	for _, node := range []string{"R_kgFixture", "MDEwOlJlcG9zaXRvcnkxMjM=", "a-b_c/d+e="} {
		raw := bytes.ReplaceAll(good, []byte("R_kgFixture"), []byte(node))
		r, err := parseLocalProviderReceipt(raw)
		if err != nil || r.id != 42 || r.nodeID != node || !bytes.Equal(r.raw, raw) {
			t.Fatal("legitimate receipt", err)
		}
	}
	cases := map[string][]byte{
		"duplicate":        bytes.Replace(good, []byte(`"id":42`), []byte(`"id":42,"id":43`), 1),
		"nested-duplicate": bytes.Replace(good, []byte(`"login":"relux-works"`), []byte(`"login":"a","login":"b"`), 1),
		"wrong-name":       bytes.Replace(good, []byte(LocalRepository), []byte("other"), 1),
		"public":           bytes.Replace(good, []byte(`"private":true`), []byte(`"private":false`), 1),
		"private-string":   bytes.Replace(good, []byte(`"private":true`), []byte(`"private":"true"`), 1),
		"node-empty":       bytes.Replace(good, []byte("R_kgFixture"), nil, 1),
		"node-control":     bytes.Replace(good, []byte("R_kgFixture"), []byte(`bad\nnode`), 1),
		"node-unicode":     bytes.Replace(good, []byte("R_kgFixture"), []byte("ключ"), 1),
		"trailing":         append(bytes.Clone(good), []byte(`{}`)...),
		"array":            []byte(`[]`), "null": []byte(`null`), "missing": []byte(`{}`),
		"oversize": bytes.Repeat([]byte{' '}, localReceiptLimit+1),
		"depth":    []byte(`{"id":42,"x":` + strings.Repeat("[", 14) + `null` + strings.Repeat("]", 14) + `}`),
	}
	for _, number := range []string{`"42"`, "0", "-1", "42.0", "4.2e1", "18446744073709551616", "null", "true"} {
		cases["id-"+number] = bytes.Replace(good, []byte(`"id":42`), []byte(`"id":`+number), 1)
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseLocalProviderReceipt(good); err != nil {
				t.Fatal("valid neighbor", err)
			}
			if r, err := parseLocalProviderReceipt(raw); !errors.Is(err, errLocalProvider) || r != nil {
				t.Fatal("bad receipt accepted", err)
			}
		})
	}
}

// The production subprocess adapter sends exactly one structured CREATE;
// errors and bounded output failures never leak raw diagnostics or retry.
func TestLocalProviderProcess(t *testing.T) {
	for _, mode := range []string{"success", "failure", "stdout-limit", "stderr-limit", "missing-executable", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			f := localTestFixture(t)
			c, q := f.envelopes(t)
			e, err := ParseLocalEnrollment(requestTestBytes(t, f.config))
			if err != nil {
				t.Fatal(err)
			}
			checked, err := e.check(c, q, f.now)
			if err != nil {
				t.Fatal(err)
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			calls := filepath.Join(t.TempDir(), "calls")
			t.Setenv("KEYVAULT_LOCAL_GH_FIXTURE", mode)
			t.Setenv("KEYVAULT_LOCAL_GH_CALLS", calls)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			wantCalls := 1
			if mode == "missing-executable" {
				exe = filepath.Join(t.TempDir(), "absent")
				wantCalls = 0
			}
			if mode == "cancelled" {
				cancel()
				wantCalls = 0
			}
			raw, err := (localGHProvider{path: exe}).create(ctx, checked)
			if mode == "success" {
				if err != nil || !bytes.Equal(raw, localGoodReceipt()) {
					t.Fatal("process receipt", err)
				}
			} else if !errors.Is(err, errLocalProvider) || len(raw) != 0 {
				t.Fatal("uncontrolled process failure", err)
			}
			actual, readErr := os.ReadFile(calls)
			if wantCalls == 0 {
				if !os.IsNotExist(readErr) {
					t.Fatal("unexpected process", readErr)
				}
			} else if readErr != nil || string(actual) != "create\n" {
				t.Fatal("process count", readErr, string(actual))
			}
		})
	}
}

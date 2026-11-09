package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// This subprocess is test transport only. No actual node, route or credentials
// are accessible in the enclosing offline test namespace.
func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == "--owned-protocol" {
		// A bounded final message large enough to fill an unread receipt pipe.
		_, _ = os.Stdout.WriteString(`{"done":true,"padding":"` + strings.Repeat("x", 1<<20) + `"}` + "\n")
		return
	}
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "-conf=") {
		raw, err := os.ReadFile(strings.TrimPrefix(os.Args[1], "-conf="))
		if err != nil {
			os.Exit(3)
		}
		var fixture struct {
			Args     []string
			Reply    json.RawMessage
			Delay    bool
			Oversize bool
			Invalid  bool
			Text     string
		}
		if json.Unmarshal(raw, &fixture) != nil || !reflect.DeepEqual(fixture.Args, os.Args[1:]) {
			os.Exit(4)
		}
		if fixture.Delay {
			time.Sleep(5 * time.Second)
		}
		if fixture.Oversize {
			_, _ = os.Stdout.WriteString(strings.Repeat("x", maxReply+1))
			return
		}
		if fixture.Invalid {
			_, _ = os.Stdout.WriteString("broken")
			return
		}
		if fixture.Text != "" {
			_, _ = os.Stdout.WriteString(fixture.Text + "\n")
			return
		}
		_, _ = os.Stdout.Write(fixture.Reply)
		return
	}
	os.Exit(m.Run())
}

func TestCLIStringProjection(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	c := Config{Network: "main", NodeCLI: self, NodeConfig: filepath.Join(root, "node.conf"), NodeDataDir: root}
	params := []json.RawMessage{json.RawMessage(`0`)}
	args, err := nodeArgs(c, "getblockhash", params)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{strings.Repeat("a", 64), "not-a-hash", strings.Repeat("A", 64), strings.Repeat("a", 64) + "\n"} {
		raw, _ := json.Marshal(map[string]any{"Args": args, "Text": text})
		if os.WriteFile(c.NodeConfig, raw, 0600) != nil {
			t.Fatal("fixture write")
		}
		got, err := nodeCall(context.Background(), c, root, "getblockhash", params)
		if text == strings.Repeat("a", 64) {
			if err != nil || string(got) != `"`+text+`"` {
				t.Fatalf("bare CLI string: %s %v", got, err)
			}
		} else if !errors.Is(err, refused) || got != nil {
			t.Fatal("malformed CLI hash accepted")
		}
	}
}

func TestCLINullProjection(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	c := Config{Network: "main", NodeCLI: self, NodeConfig: filepath.Join(root, "node.conf"), NodeDataDir: root}
	for _, method := range []string{"gettxout", "getblockchaininfo", "getblockhash"} {
		args, err := nodeArgs(c, method, nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(map[string]any{"Args": args})
		if os.WriteFile(c.NodeConfig, raw, 0600) != nil {
			t.Fatal("fixture write")
		}
		got, err := nodeCall(context.Background(), c, root, method, nil)
		if method == "gettxout" {
			if err != nil || string(got) != "null" {
				t.Fatalf("null CLI result: %s %v", got, err)
			}
		} else if !errors.Is(err, refused) || got != nil {
			t.Fatal("empty non-null result accepted")
		}
	}
}

func TestBlockedReceiptLifetime(t *testing.T) {
	binary := os.Getenv("LAB_OWN_NODE")
	if binary == "" {
		t.Fatal("NOT RUN (missing fixture): LAB_OWN_NODE must name candidate supervisor; see docs/lab-testing.md")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	selfBytes, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("private root")
	}
	configPath, inputPath, nodePath := filepath.Join(root, "route.json"), filepath.Join(root, "input.json"), filepath.Join(root, "node.conf")
	c := Config{Network: "main", Genesis: "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770", NodeCLI: self, NodeCLISHA256: digest(selfBytes), NodeConfig: nodePath, NodeDataDir: root, Compose: self, ComposeSHA256: digest(selfBytes), PrivateRoot: root, RouteID: "offline-blocked-output-control"}
	raw, _ := json.Marshal(c)
	for path, data := range map[string][]byte{configPath: raw, inputPath: []byte(`{"Mode":"verify","Policy":{"Network":"main","Genesis":"000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770"}}`), nodePath: []byte(`{}`)} {
		if os.WriteFile(path, data, 0600) != nil {
			t.Fatal("fixture write")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 22*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, configPath, inputPath)
	cmd.Env = []string{"HOME=" + root, "TMPDIR=" + root, "PATH=/nonexistent"}
	var diag bytes.Buffer
	cmd.Stderr = &diag
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	start := time.Now()
	if cmd.Start() != nil {
		t.Fatal("start control")
	}
	err = cmd.Wait()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 124 || ctx.Err() != nil || time.Since(start) > 21*time.Second {
		t.Fatalf("blocked sink lifetime: error=%v elapsed=%s diagnostics=%s", err, time.Since(start), diag.String())
	}
}

func TestClosedInvocation(t *testing.T) {
	c := Config{Network: "main", NodeConfig: "/operator/node.conf", NodeDataDir: "/operator/node"}
	args, err := nodeArgs(c, "name_show", []json.RawMessage{json.RawMessage(`"id/example"`), json.RawMessage(`{"nameEncoding":"ascii","valueEncoding":"ascii","allowExpired":false}`)})
	want := []string{"-conf=/operator/node.conf", "-datadir=/operator/node", "-chain=main", "-rpcclienttimeout=2", "name_show", "id/example", `{"nameEncoding":"ascii","valueEncoding":"ascii","allowExpired":false}`}
	if err != nil || !reflect.DeepEqual(args, want) {
		t.Fatalf("unexpected invocation: %v %v", args, err)
	}
	for _, method := range []string{"sendrawtransaction", "signrawtransactionwithwallet", "generate", "name_update", "getwalletinfo", "help", "-rpcpassword=denied", ""} {
		if _, err := nodeArgs(c, method, nil); !errors.Is(err, refused) {
			t.Fatalf("method accepted: %s", method)
		}
	}
	if _, err := nodeArgs(c, "name_show", []json.RawMessage{json.RawMessage(`"-rpcconnect=denied"`)}); !errors.Is(err, refused) {
		t.Fatal("option-shaped string accepted")
	}
	if _, err := nodeArgs(c, "getblockhash", []json.RawMessage{json.RawMessage(`invalid`)}); !errors.Is(err, refused) {
		t.Fatal("invalid JSON accepted")
	}
}

func TestExactRouteSchema(t *testing.T) {
	valid := `{"Network":"main","Genesis":"g","NodeCLI":"n","NodeCLISHA256":"h","NodeConfig":"c","NodeDataDir":"d","Compose":"b","ComposeSHA256":"h","PrivateRoot":"p","RouteID":"r"}`
	if _, err := decodeConfig([]byte(valid)); err != nil {
		t.Fatal("schema positive refused")
	}
	for _, raw := range []string{
		strings.Replace(valid, `"Network":"main"`, `"Network":"main","Network":"regtest"`, 1),
		strings.Replace(valid, `"Network"`, `"NETWORK"`, 1),
		strings.Replace(valid, `"RouteID":"r"`, `"Unknown":"r"`, 1),
		strings.Replace(valid, `"RouteID":"r"`, `"RouteID":{}`, 1),
		strings.Replace(valid, `"RouteID":"r"`, `"RouteID":null`, 1),
		valid + ` {}`, `null`,
	} {
		if _, err := decodeConfig([]byte(raw)); !errors.Is(err, refused) {
			t.Fatal("ambiguous/unknown route accepted")
		}
	}
}

func TestBoundedReadSubprocess(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	c := Config{Network: "main", NodeCLI: self, NodeConfig: filepath.Join(root, "node.conf"), NodeDataDir: root}
	args, err := nodeArgs(c, "getblockchaininfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "invalid-json", "oversize", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			reply := json.RawMessage(`{"chain":"main"}`)
			fixture := map[string]any{"Args": args, "Reply": reply, "Delay": mode == "cancel", "Oversize": mode == "oversize", "Invalid": mode == "invalid-json"}
			raw, _ := json.Marshal(fixture)
			if os.WriteFile(c.NodeConfig, raw, 0600) != nil {
				t.Fatal("fixture write")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if mode != "cancel" {
				ctx = context.Background()
			}
			start := time.Now()
			got, err := nodeCall(ctx, c, root, "getblockchaininfo", nil)
			if mode == "valid" && (err != nil || string(got) != `{"chain":"main"}`) {
				t.Fatalf("positive read: %s %v", got, err)
			}
			if mode != "valid" && (!errors.Is(err, refused) || got != nil) {
				t.Fatal("failed read returned data")
			}
			if time.Since(start) > 3*time.Second {
				t.Fatal("subprocess cancellation/reap bound")
			}
		})
	}
}

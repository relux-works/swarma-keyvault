package namecoinwrapper

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Test-only CLI transport over the actual subprocess/stdio graph. The fixture
// is inert public data in the offline namespace, never external qualification.
func TestMain(m *testing.M) {
	if len(os.Args) > 5 && strings.HasPrefix(os.Args[1], "-conf=") {
		raw, err := os.ReadFile(strings.TrimPrefix(os.Args[1], "-conf="))
		if err != nil {
			os.Exit(3)
		}
		var fixture struct {
			Network     string
			Replies     map[string]json.RawMessage
			Counts      map[string]int
			Transitions []struct {
				Args       []string
				Occurrence int
				Replies    map[string]json.RawMessage
			}
		}
		if json.Unmarshal(raw, &fixture) != nil || os.Args[3] != "-chain="+fixture.Network || os.Args[4] != "-rpcclienttimeout=2" {
			os.Exit(4)
		}
		key, _ := json.Marshal(os.Args[5:])
		// Ordered, inert offline observations across actual one-shot CLI
		// children. Only this test fixture mutates its own private transcript.
		if len(fixture.Transitions) > 0 {
			if fixture.Counts == nil {
				fixture.Counts = map[string]int{}
			}
			fixture.Counts[string(key)]++
			for _, transition := range fixture.Transitions {
				args, _ := json.Marshal(transition.Args)
				if string(args) == string(key) && fixture.Counts[string(key)] == transition.Occurrence {
					for k, v := range transition.Replies {
						if v == nil {
							delete(fixture.Replies, k)
						} else {
							fixture.Replies[k] = v
						}
					}
				}
			}
			updated, err := json.Marshal(fixture)
			if err != nil || os.WriteFile(strings.TrimPrefix(os.Args[1], "-conf="), updated, 0600) != nil {
				os.Exit(7)
			}
		}
		reply, ok := fixture.Replies[string(key)]
		if !ok {
			os.Exit(5)
		}
		if os.Args[5] == "getblockhash" {
			var text string
			if json.Unmarshal(reply, &text) != nil {
				os.Exit(6)
			}
			_, _ = os.Stdout.WriteString(text + "\n")
			return
		}
		if os.Args[5] == "gettxout" && bytes.Equal(reply, []byte("null")) {
			return
		}
		_, _ = os.Stdout.Write(reply)
		return
	}
	os.Exit(m.Run())
}

func cliTranscript(t *testing.T, f *fixture) map[string]json.RawMessage {
	t.Helper()
	out := map[string]json.RawMessage{}
	for key, raw := range f.n.data {
		parts := strings.SplitN(key, ":", 2)
		var params []any
		if json.Unmarshal([]byte(parts[1]), &params) != nil {
			t.Fatal("invalid inert fixture")
		}
		args := []string{parts[0]}
		for _, p := range params {
			if s, ok := p.(string); ok {
				args = append(args, s)
			} else {
				args = append(args, string(marshal(t, p)))
			}
		}
		out[string(marshal(t, args))] = bytes.Clone(raw)
	}
	return out
}

func TestOwnNodeActualWrapperGraph(t *testing.T) {
	for _, mode := range []string{"main", "regtest", "default-cannot-follow-main", "rpc-network-mismatch", "wrong-genesis", "wrong-verifier-pin", "spend-restore-new-request"} {
		t.Run(mode, func(t *testing.T) {
			f := mainFixture(t)
			network, genesis := "main", MainnetGenesis
			want := mode == "main" || mode == "regtest" || mode == "spend-restore-new-request"
			switch mode {
			case "regtest":
				f = fresh(t)
				network, genesis = "regtest", RegtestGenesis
			case "default-cannot-follow-main":
				f.p.Network, f.p.Genesis = "", ""
			case "rpc-network-mismatch":
				f.n.set(t, "getblockchaininfo", tip{"regtest", f.best, 100, false})
			case "wrong-genesis":
				f.n.set(t, "getblockhash", RegtestGenesis, 0)
			case "wrong-verifier-pin":
				f.p.CLIHash = strings.Repeat("0", 64)
			}
			bridge, compose := os.Getenv("LAB_OWN_NODE"), os.Getenv("LAB_COMPOSE")
			if bridge == "" || compose == "" {
				t.Fatal("LAB_OWN_NODE and LAB_COMPOSE must name candidate executables")
			}
			// A separately built non-race copy avoids the race runtime's default
			// per-process exit sleep accumulating across a finite RPC observation.
			// The parent wrapper tests remain race-instrumented; bounds stay fixed.
			self := os.Getenv("LAB_NODE_FIXTURE_CLI")
			if self == "" {
				var err error
				self, err = os.Executable()
				if err != nil {
					t.Fatal(err)
				}
			}
			selfBytes, err := os.ReadFile(self)
			if err != nil {
				t.Fatal(err)
			}
			composeBytes, err := os.ReadFile(compose)
			if err != nil {
				t.Fatal(err)
			}
			root := f.p.PrivateRoot
			inputPath, routePath, nodeConfig := filepath.Join(root, "input.json"), filepath.Join(root, "route.json"), filepath.Join(root, "fake-node.json")
			certPath, requestPath := filepath.Join(root, "cert.json"), filepath.Join(root, "request.json")
			route := map[string]any{"Network": network, "Genesis": genesis, "NodeCLI": self, "NodeCLISHA256": hash(selfBytes), "NodeConfig": nodeConfig, "NodeDataDir": root, "Compose": compose, "ComposeSHA256": hash(composeBytes), "PrivateRoot": root, "RouteID": "offline-inert-test-transport"}
			observe := func(want bool) {
				t.Helper()
				files := map[string][]byte{
					inputPath: marshal(t, map[string]any{"Mode": "verify", "Policy": f.p, "Certificate": certPath, "Request": requestPath, "At": f.at}),
					routePath: marshal(t, route), nodeConfig: marshal(t, map[string]any{"Network": network, "Replies": cliTranscript(t, f)}), certPath: f.certificate, requestPath: f.request,
				}
				for path, raw := range files {
					if os.WriteFile(path, raw, 0600) != nil {
						t.Fatal("fixture write")
					}
				}
				cmd := exec.Command(bridge, routePath, inputPath)
				cmd.Env = []string{"HOME=" + root, "TMPDIR=" + root, "PATH=/nonexistent"}
				out, err := cmd.Output()
				if err != nil {
					if want {
						t.Fatalf("bridge positive failed: %v", err)
					}
					if len(out) != 0 {
						t.Fatal("startup refusal emitted observation")
					}
					return
				}
				var receipt struct {
					Network, Genesis string
					EffectAuthorized bool `json:"effect_authorized"`
					RouteQualified   bool `json:"node_route_qualified"`
					Result           struct {
						Verified bool `json:"verified"`
					}
				}
				if json.Unmarshal(out, &receipt) != nil || receipt.Network != network || receipt.Genesis != genesis || receipt.EffectAuthorized || receipt.RouteQualified || receipt.Result.Verified != want {
					t.Fatalf("unexpected receipt: %s", out)
				}
			}
			observe(want)
			if mode == "spend-restore-new-request" {
				key := callKey("gettxout", f.seal.TxID, f.seal.Vout, true)
				original := bytes.Clone(f.n.data[key])
				f.n.set(t, "gettxout", nil, f.seal.TxID, f.seal.Vout, true)
				observe(false)
				f.n.data[key] = original
				f.operation["request_id"] = "new-valid-request-through-actual-bridge"
				f.resign(t)
				observe(false)
			}
		})
	}
}

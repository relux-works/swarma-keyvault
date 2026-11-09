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

// Independent adjacent controls over the actual finite bridge/composer/verifier/
// signer graph. Consistent and inconsistent projections differ in one field.
func TestGenerationAndTipConsistency(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, mode := range []string{"replacement-consistent", "replacement-wrong-header-hash", "replacement-depth-mismatch", "replacement-tx-depth-mismatch", "tip-height-only", "tip-consistent", "tip-header-unavailable", "tip-header-hash", "tip-header-height", "tip-header-depth", "tip-canonical-mismatch", "tip-unstable"} {
			direction := "forward"
			if reverse {
				direction = "mirror"
			}
			t.Run(direction+"/"+mode, func(t *testing.T) {
				f := freshDirection(t, reverse)
				root := f.p.PrivateRoot
				bridge, compose, node := labFixture(t, "LAB_OWN_NODE"), labFixture(t, "LAB_COMPOSE"), labFixture(t, "LAB_NODE_FIXTURE_CLI")
				cb, err := os.ReadFile(compose)
				if err != nil {
					t.Fatal(err)
				}
				nb, err := os.ReadFile(node)
				if err != nil {
					t.Fatal(err)
				}
				routePath, inputPath, nodePath := filepath.Join(root, "route.json"), filepath.Join(root, "input.json"), filepath.Join(root, "node.json")
				certPath, reqPath := filepath.Join(root, "certificate.json"), filepath.Join(root, "request.json")
				route := map[string]any{"Network": "regtest", "Genesis": RegtestGenesis, "NodeCLI": node, "NodeCLISHA256": hash(nb), "NodeConfig": nodePath, "NodeDataDir": root, "Compose": compose, "ComposeSHA256": hash(cb), "PrivateRoot": root, "RouteID": "offline-independent-consistency"}
				var transitions []any
				observe := func(stage string, want bool) {
					t.Helper()
					fixture := map[string]any{"Network": "regtest", "Replies": cliTranscript(t, f), "Transitions": transitions}
					for path, raw := range map[string][]byte{routePath: marshal(t, route), inputPath: marshal(t, map[string]any{"Mode": "verify", "Policy": f.p, "Certificate": certPath, "Request": reqPath, "At": f.at}), nodePath: marshal(t, fixture), certPath: f.certificate, reqPath: f.request} {
						if err := os.WriteFile(path, raw, 0600); err != nil {
							t.Fatal(err)
						}
					}
					cmd := exec.Command(bridge, routePath, inputPath)
					cmd.Env = []string{"HOME=" + root, "TMPDIR=" + root, "PATH=/nonexistent"}
					raw, err := cmd.Output()
					if err != nil {
						t.Fatal(err)
					}
					var receipt struct {
						Effect    bool `json:"effect_authorized"`
						Qualified bool `json:"node_route_qualified"`
						Calls     int  `json:"read_calls"`
						Result    struct{ Verified bool }
					}
					if json.Unmarshal(raw, &receipt) != nil || receipt.Effect || receipt.Qualified {
						t.Fatal("invalid bounded observation receipt")
					}
					t.Logf("stage=%s verified=%v want=%v calls=%d", stage, receipt.Result.Verified, want, receipt.Calls)
					if receipt.Result.Verified != want {
						t.Errorf("incorrect lifecycle classification in %s", stage)
					}
				}
				observe("healthy", true)
				saved := map[string]json.RawMessage{}
				for k, v := range f.n.data {
					saved[k] = bytes.Clone(v)
				}
				permanent := mode == "replacement-consistent" || mode == "tip-consistent"
				if strings.HasPrefix(mode, "tip-") {
					args := []string{"getblockchaininfo"}
					key := string(marshal(t, args))
					// The same hash cannot identify blocks at heights 100 and 101. No new
					// canonical hash/height mapping or generation contradiction exists.
					next := strings.Repeat("8", 64)
					if mode == "tip-height-only" {
						next = f.best
					}
					header := map[string]any{"hash": next, "height": 101, "confirmations": 1}
					if mode == "tip-header-hash" {
						header["hash"] = strings.Repeat("7", 64)
					}
					if mode == "tip-header-height" {
						header["height"] = 100
					}
					if mode == "tip-header-depth" {
						header["confirmations"] = 77
					}
					headerArgs := []string{"getblockheader", next}
					heightArgs := []string{"getblockhash", "101"}
					replies := map[string]json.RawMessage{key: marshal(t, tip{"regtest", next, 101, false}), string(marshal(t, headerArgs)): marshal(t, header), string(marshal(t, heightArgs)): marshal(t, next)}
					if mode == "tip-header-unavailable" {
						replies[string(marshal(t, headerArgs))] = nil
					}
					if mode == "tip-canonical-mismatch" {
						replies[string(marshal(t, heightArgs))] = marshal(t, strings.Repeat("7", 64))
					}
					transitions = []any{map[string]any{"Args": args, "Occurrence": 2, "Replies": replies}}
					if mode == "tip-unstable" {
						transitions = append(transitions, map[string]any{"Args": args, "Occurrence": 3, "Replies": map[string]json.RawMessage{key: marshal(t, tip{"regtest", f.best, 100, false})}})
					}
				} else {
					newer := strings.Repeat("1", 64)
					f.ownerName.TxID = strings.Repeat("f", 64)
					f.ownerName.Height = 101
					f.refreshNames(t)
					f.anchor["blockhash"] = newer
					f.anchor["confirmations"] = 1
					h := map[string]any{"hash": newer, "height": 101, "confirmations": 1}
					if mode == "replacement-wrong-header-hash" {
						h["hash"] = strings.Repeat("2", 64)
					}
					if mode == "replacement-depth-mismatch" {
						h["confirmations"] = 77
					}
					if mode == "replacement-tx-depth-mismatch" {
						f.anchor["confirmations"] = 77
					}
					f.n.set(t, "getblockchaininfo", tip{"regtest", newer, 101, false})
					f.n.set(t, "getblockhash", newer, 101)
					f.n.set(t, "getblockheader", h, newer)
					f.n.set(t, "getrawtransaction", f.anchor, f.ownerName.TxID, true)
					f.n.data[callKey("getrawtransaction", f.requesterName.TxID, true)] = saved[callKey("getrawtransaction", f.requesterName.TxID, true)]
					f.n.data[callKey("getblockheader", f.p.AnchorBlock)] = marshal(t, map[string]any{"hash": f.p.AnchorBlock, "height": 99, "confirmations": 3})
				}
				observe("disturbed", false)
				raw, err := os.ReadFile(filepath.Join(root, "closed-"+hash(f.certificate)))
				t.Logf("persisted=%v expected=%v evidence=%s", err == nil, permanent, raw)
				if (err == nil) != permanent {
					t.Errorf("inconsistent projection produced persistent lifecycle closure")
				}
				f.n.data = saved
				transitions = nil
				f.operation["request_id"] = "fresh-independent-request-after-consistency-restoration"
				if reverse {
					f.request = signerRequest(t, f, root)
				} else {
					f.resign(t)
				}
				observe("restored-new-process-fresh-signature", !permanent)
			})
		}
	}
}

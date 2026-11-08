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

// Each observation crosses the real finite bridge, composer, verifier and
// signer in both directions. Restoration uses new processes and signatures.
func TestGenerationEvidenceActualGraph(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, caller := range []string{"initial-owner", "second-owner", "second-requester"} {
			for _, mode := range []string{"consistent", "wrong-header-hash", "header-depth", "tx-depth", "both-depth", "missing-header-height", "missing-tx-depth", "canonical-mismatch", "tip-height-mapping"} {
				direction := "forward"
				if reverse {
					direction = "mirror"
				}
				t.Run(direction+"/"+caller+"/"+mode, func(t *testing.T) {
					f := freshDirection(t, reverse)
					root := f.p.PrivateRoot
					bridge, compose, node := os.Getenv("LAB_OWN_NODE"), os.Getenv("LAB_COMPOSE"), os.Getenv("LAB_NODE_FIXTURE_CLI")
					cb, err := os.ReadFile(compose)
					if err != nil {
						t.Fatal(err)
					}
					nb, err := os.ReadFile(node)
					if err != nil {
						t.Fatal(err)
					}
					route := map[string]any{"Network": "regtest", "Genesis": RegtestGenesis, "NodeCLI": node, "NodeCLISHA256": hash(nb), "NodeConfig": filepath.Join(root, "node.json"), "NodeDataDir": root, "Compose": compose, "ComposeSHA256": hash(cb), "PrivateRoot": root, "RouteID": "offline-generation-evidence"}
					var transitions []any
					observe := func(stage string, want bool) {
						t.Helper()
						files := map[string][]byte{"route.json": marshal(t, route), "input.json": marshal(t, map[string]any{"Mode": "verify", "Policy": f.p, "Certificate": filepath.Join(root, "cert.json"), "Request": filepath.Join(root, "request.json"), "At": f.at}), "node.json": marshal(t, map[string]any{"Network": "regtest", "Replies": cliTranscript(t, f), "Transitions": transitions}), "cert.json": f.certificate, "request.json": f.request}
						for name, raw := range files {
							if err := os.WriteFile(filepath.Join(root, name), raw, 0600); err != nil {
								t.Fatal(err)
							}
						}
						cmd := exec.Command(bridge, filepath.Join(root, "route.json"), filepath.Join(root, "input.json"))
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
						if json.Unmarshal(raw, &receipt) != nil || receipt.Effect || receipt.Qualified || receipt.Calls > 256 {
							t.Fatal("invalid bounded receipt")
						}
						t.Logf("stage=%s receipt=%s", stage, raw)
						if receipt.Result.Verified != want {
							t.Errorf("verified=%v want=%v", receipt.Result.Verified, want)
						}
					}
					observe("healthy", true)
					saved := map[string]json.RawMessage{}
					for k, b := range f.n.data {
						saved[k] = bytes.Clone(b)
					}
					show := f.ownerName
					tx := f.anchor
					if caller == "second-requester" {
						show = f.requesterName
						tx = f.requesterTX
					}
					show.TxID = strings.Repeat("e", 64)
					show.Height = 100
					// Deliberately invalid value projection cannot hide a proven replacement.
					var fields map[string]any
					_ = json.Unmarshal(marshal(t, show), &fields)
					delete(fields, "value")
					fields["value_error"] = "invalid ascii"
					tx["txid"] = show.TxID
					tx["blockhash"] = strings.Repeat("1", 64)
					tx["confirmations"] = 2
					header := map[string]any{"hash": strings.Repeat("1", 64), "height": 100, "confirmations": 2}
					switch mode {
					case "wrong-header-hash":
						header["hash"] = strings.Repeat("2", 64)
					case "header-depth":
						header["confirmations"] = 77
					case "tx-depth":
						tx["confirmations"] = 77
					case "both-depth":
						header["confirmations"] = 77
						tx["confirmations"] = 77
					case "missing-header-height":
						delete(header, "height")
					case "missing-tx-depth":
						delete(tx, "confirmations")
					}
					best := strings.Repeat("3", 64)
					changes := map[string]json.RawMessage{
						callKey("name_show", show.Name, nameOptions()):     marshal(t, fields),
						callKey("getrawtransaction", show.TxID, true):      marshal(t, tx),
						callKey("getblockheader", strings.Repeat("1", 64)): marshal(t, header),
						callKey("getblockhash", 100):                       marshal(t, strings.Repeat("1", 64)),
						callKey("getblockchaininfo"):                       marshal(t, tip{"regtest", best, 101, false}),
						callKey("getblockheader", best):                    marshal(t, map[string]any{"hash": best, "height": 101, "confirmations": 1}),
						callKey("getblockhash", 101):                       marshal(t, best),
						callKey("getblockheader", f.block):                 marshal(t, map[string]any{"hash": f.block, "height": 99, "confirmations": 3}),
					}
					if mode == "canonical-mismatch" {
						changes[callKey("getblockhash", 100)] = marshal(t, strings.Repeat("4", 64))
					}
					if mode == "tip-height-mapping" {
						changes[callKey("getblockhash", 101)] = marshal(t, strings.Repeat("4", 64))
					}
					if caller == "initial-owner" {
						for k, b := range changes {
							f.n.data[k] = b
						}
					} else {
						cliChanges := map[string]json.RawMessage{}
						for key, b := range changes {
							parts := strings.SplitN(key, ":", 2)
							var params []any
							if json.Unmarshal([]byte(parts[1]), &params) != nil {
								t.Fatal("fixture key")
							}
							args := []string{parts[0]}
							for _, p := range params {
								if s, ok := p.(string); ok {
									args = append(args, s)
								} else {
									args = append(args, string(marshal(t, p)))
								}
							}
							cliChanges[string(marshal(t, args))] = b
						}
						args := []string{"name_show", show.Name, string(marshal(t, nameOptions()))}
						transitions = []any{map[string]any{"Args": args, "Occurrence": 2, "Replies": cliChanges}}
					}
					observe("disturbed", false)
					latch := filepath.Join(root, "closed-"+hash(f.certificate))
					first, err := os.ReadFile(latch)
					permanent := mode == "consistent"
					if (err == nil) != permanent {
						t.Fatalf("persisted=%v want=%v", err == nil, permanent)
					}
					f.n.data = saved
					transitions = nil
					f.operation["request_id"] = "fresh-request-after-generation-evidence"
					if reverse {
						f.request = signerRequest(t, f, root)
					} else {
						f.resign(t)
					}
					observe("restored-new-process-fresh-signature", !permanent)
					if permanent {
						last, err := os.ReadFile(latch)
						if err != nil || !bytes.Equal(first, last) {
							t.Fatal("first closure evidence changed")
						}
					}
				})
			}
		}
	}
}

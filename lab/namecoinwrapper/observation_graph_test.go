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

// Exercise lifecycle classification through the finite bridge, real composer,
// separate verifier and mirror signer. All children read inert offline replies.
func TestObservationLifecycleActualGraph(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, mode := range []string{"orphan-zero", "orphan-name-unavailable", "intercall-orphan", "replacement-value-error", "replacement-omitted", "replacement-malformed", "unconfirmed-replacement", "owner-value-error", "owner-value-mismatch", "requester-unavailable", "second-owner-unavailable", "second-requester-unavailable", "second-owner-value-error", "second-requester-value-error", "second-owner-replacement-value-error", "second-requester-replacement-value-error", "tip-unavailable", "tip-malformed", "tip-missing-ibd", "tip-change", "unknown-seal", "spent-seal"} {
			name := "forward/" + mode
			if reverse {
				name = "mirror/" + mode
			}
			t.Run(name, func(t *testing.T) {
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
				certPath, reqPath := filepath.Join(root, "cert.json"), filepath.Join(root, "req.json")
				route := map[string]any{"Network": "regtest", "Genesis": RegtestGenesis, "NodeCLI": node, "NodeCLISHA256": hash(nb), "NodeConfig": nodePath, "NodeDataDir": root, "Compose": compose, "ComposeSHA256": hash(cb), "PrivateRoot": root, "RouteID": "offline-lifecycle-control"}
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
						Effect    bool   `json:"effect_authorized"`
						Qualified bool   `json:"node_route_qualified"`
						Calls     int    `json:"read_calls"`
						Started   string `json:"started_at"`
						Finished  string `json:"finished_at"`
						Result    struct{ Verified bool }
					}
					if json.Unmarshal(raw, &receipt) != nil || receipt.Effect || receipt.Qualified {
						t.Fatal("invalid receipt")
					}
					t.Logf("stage=%s verified=%v want=%v calls=%d start=%s end=%s", stage, receipt.Result.Verified, want, receipt.Calls, receipt.Started, receipt.Finished)
					if receipt.Result.Verified != want {
						t.Errorf("incorrect lifecycle classification")
					}
				}
				observe("healthy", true)
				saved := map[string]json.RawMessage{}
				for k, v := range f.n.data {
					saved[k] = bytes.Clone(v)
				}
				permanent := false
				cliKey := func(args ...string) string { return string(marshal(t, args)) }
				transition := func(args []string, occurrence int, replies map[string]json.RawMessage) {
					transitions = []any{map[string]any{"Args": args, "Occurrence": occurrence, "Replies": replies}}
				}
				switch mode {
				case "orphan-zero", "orphan-name-unavailable", "intercall-orphan":
					permanent = true
					f.anchor["confirmations"] = 0
					orphan := marshal(t, f.anchor)
					changes := map[string]json.RawMessage{
						cliKey("getrawtransaction", f.p.AnchorTxID, "true"): orphan,
						cliKey("getblockheader", f.p.AnchorBlock):           marshal(t, map[string]any{"hash": f.p.AnchorBlock, "height": 99, "confirmations": -1}),
						cliKey("getblockhash", "99"):                        marshal(t, strings.Repeat("f", 64)),
						cliKey("getblockheader", strings.Repeat("f", 64)):   marshal(t, map[string]any{"hash": strings.Repeat("f", 64), "height": 99, "confirmations": 2}),
						cliKey("getblockhash", "100"):                       marshal(t, strings.Repeat("9", 64)),
						cliKey("getblockchaininfo"):                         marshal(t, tip{"regtest", strings.Repeat("9", 64), 100, false}),
					}
					if mode == "intercall-orphan" {
						transition([]string{"getblockheader", f.p.AnchorBlock}, 1, changes)
					} else {
						f.n.set(t, "getrawtransaction", f.anchor, f.p.AnchorTxID, true)
						setOrphanBranch(t, f)
						if mode == "orphan-name-unavailable" {
							delete(f.n.data, callKey("name_show", f.p.OwnerName, nameOptions()))
						}
					}
				case "replacement-value-error", "replacement-omitted", "replacement-malformed", "unconfirmed-replacement":
					permanent = mode != "unconfirmed-replacement"
					f.ownerName.TxID = strings.Repeat("f", 64)
					f.ownerName.Height = 101
					f.refreshNames(t)
					newer := strings.Repeat("1", 64)
					f.anchor["blockhash"] = newer
					f.anchor["confirmations"] = 1
					if !permanent {
						f.anchor["confirmations"] = 0
					}
					f.n.set(t, "getrawtransaction", f.anchor, f.ownerName.TxID, true)
					f.n.set(t, "getblockheader", map[string]any{"hash": newer, "height": 101, "confirmations": 1}, newer)
					f.n.set(t, "getblockhash", newer, 101)
					f.n.set(t, "getblockchaininfo", tip{"regtest", newer, 101, false})
					var fields map[string]any
					_ = json.Unmarshal(marshal(t, f.ownerName), &fields)
					delete(fields, "value")
					if mode == "replacement-value-error" {
						fields["value_error"] = "invalid ascii"
					}
					if mode == "replacement-malformed" {
						fields["value"] = map[string]any{"malformed": true}
					}
					f.n.set(t, "name_show", fields, f.p.OwnerName)
				case "owner-value-error", "owner-value-mismatch":
					op := f.anchor["vout"].([]any)[0].(map[string]any)["scriptPubKey"].(map[string]any)["nameOp"].(map[string]string)
					if mode == "owner-value-error" {
						delete(op, "value")
						op["value_error"] = "invalid ascii"
					} else {
						op["value"] = "malformed temporary projection"
					}
					f.n.set(t, "getrawtransaction", f.anchor, f.p.AnchorTxID, true)
				case "requester-unavailable":
					delete(f.n.data, callKey("getrawtransaction", f.requesterName.TxID, true))
				case "second-owner-unavailable", "second-requester-unavailable":
					name := f.p.OwnerName
					if mode == "second-requester-unavailable" {
						name = f.p.RequesterName
					}
					args := []string{"name_show", name, string(marshal(t, nameOptions()))}
					transition(args, 2, map[string]json.RawMessage{cliKey(args...): nil})
				case "second-owner-value-error", "second-requester-value-error", "second-owner-replacement-value-error", "second-requester-replacement-value-error":
					owner := strings.Contains(mode, "owner")
					permanent = strings.Contains(mode, "replacement")
					show := f.requesterName
					tx := f.requesterTX
					if owner {
						show = f.ownerName
						tx = f.anchor
					}
					newer := strings.Repeat("1", 64)
					if permanent {
						show.TxID = strings.Repeat("f", 64)
						show.Height = 101
						tx["txid"] = show.TxID
						tx["blockhash"] = newer
						tx["confirmations"] = 1
					}
					var fields map[string]any
					_ = json.Unmarshal(marshal(t, show), &fields)
					delete(fields, "value")
					fields["value_error"] = "invalid ascii"
					args := []string{"name_show", show.Name, string(marshal(t, nameOptions()))}
					changes := map[string]json.RawMessage{cliKey(args...): marshal(t, fields)}
					if permanent {
						changes[cliKey("getrawtransaction", show.TxID, "true")] = marshal(t, tx)
						changes[cliKey("getblockheader", newer)] = marshal(t, map[string]any{"hash": newer, "height": 101, "confirmations": 1})
						changes[cliKey("getblockhash", "101")] = marshal(t, newer)
						changes[cliKey("getblockchaininfo")] = marshal(t, tip{"regtest", newer, 101, false})
					}
					transition(args, 2, changes)
				case "tip-unavailable", "tip-malformed", "tip-missing-ibd", "tip-change":
					var raw json.RawMessage
					if mode == "tip-missing-ibd" {
						raw = marshal(t, map[string]any{"chain": "regtest", "bestblockhash": strings.Repeat("f", 64), "blocks": 101})
					}
					if mode == "tip-malformed" {
						raw = marshal(t, map[string]any{"blocks": "malformed"})
					}
					if mode == "tip-change" {
						permanent = true
						raw = marshal(t, tip{"regtest", strings.Repeat("f", 64), 101, false})
					}
					changes := map[string]json.RawMessage{cliKey("getblockchaininfo"): raw}
					if mode == "tip-change" {
						newer := strings.Repeat("f", 64)
						changes[cliKey("getblockheader", newer)] = marshal(t, map[string]any{"hash": newer, "height": 101, "confirmations": 1})
						changes[cliKey("getblockhash", "101")] = marshal(t, newer)
					}
					transition([]string{"getblockchaininfo"}, 2, changes)
				case "unknown-seal":
					permanent = true
					delete(f.n.data, callKey("gettxout", f.seal.TxID, f.seal.Vout, true))
				case "spent-seal":
					permanent = true
					f.n.set(t, "gettxout", nil, f.seal.TxID, f.seal.Vout, true)
				}
				observe("refusal", false)
				latch, err := os.ReadFile(filepath.Join(root, "closed-"+hash(f.certificate)))
				if (err == nil) != permanent {
					t.Fatalf("persisted=%v want=%v", err == nil, permanent)
				}
				if permanent {
					var evidence closureEvidence
					if json.Unmarshal(latch, &evidence) != nil || evidence.Reason == "" {
						t.Fatal("missing classified evidence")
					}
					t.Logf("closure reason=%s", evidence.Reason)
				}
				f.n.data = saved
				transitions = nil
				f.operation["request_id"] = "fresh-valid-after-observation-restoration"
				if reverse {
					f.request = signerRequest(t, f, root)
				} else {
					f.resign(t)
				}
				observe("restored-new-process-fresh-signed-request", !permanent)
			})
		}
	}
}

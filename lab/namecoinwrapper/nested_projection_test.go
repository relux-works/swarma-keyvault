package namecoinwrapper

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type projectionGraph struct {
	t           *testing.T
	f           *fixture
	transitions []any
}

// Exercise the same parser at every other shared generation caller through
// actual subprocesses. The initial requester remains unanchored; the two
// second-read callers must prove replacement before they can persist closure.
func TestNestedProjectionSharedCallers(t *testing.T) {
	type scenario struct{ caller, mode string }
	var cases []scenario
	for _, caller := range []string{"initial-requester", "second-owner", "second-requester"} {
		for _, mode := range []string{"N", "SCRIPTPUBKEY", "NAMEOP", "ADDRESS"} {
			cases = append(cases, scenario{caller, mode})
		}
	}
	for _, caller := range []string{"initial-owner", "second-owner", "second-requester"} {
		for _, mode := range []string{"value-error", "omitted-value", "malformed-value"} {
			cases = append(cases, scenario{caller, mode})
		}
	}
	for _, reverse := range []bool{false, true} {
		direction := "forward"
		if reverse {
			direction = "mirror"
		}
		for _, c := range cases {
			t.Run(direction+"/"+c.caller+"/"+c.mode, func(t *testing.T) {
				f := freshDirection(t, reverse)
				g := &projectionGraph{t: t, f: f}
				g.observe("healthy", true)
				saved := projectionSave(f)
				show, source := f.ownerName, f.anchor
				if strings.Contains(c.caller, "requester") {
					show, source = f.requesterName, f.requesterTX
				}
				var tx map[string]any
				if json.Unmarshal(marshal(t, source), &tx) != nil {
					t.Fatal("fixture")
				}
				output := tx["vout"].([]any)[0].(map[string]any)
				sp := output["scriptPubKey"].(map[string]any)
				op := sp["nameOp"].(map[string]any)
				permanent := strings.Contains(c.mode, "value")
				switch c.mode {
				case "N":
					output["N"] = output["n"]
					delete(output, "n")
				case "SCRIPTPUBKEY":
					output["SCRIPTPUBKEY"] = sp
					delete(output, "scriptPubKey")
				case "NAMEOP":
					sp["NAMEOP"] = op
					delete(sp, "nameOp")
				case "ADDRESS":
					sp["ADDRESS"] = sp["address"]
					delete(sp, "address")
				case "value-error":
					delete(op, "value")
					op["value_error"] = "invalid ascii"
				case "omitted-value":
					delete(op, "value")
				case "malformed-value":
					op["value"] = map[string]any{"invalid": true}
					op["value_encoding"] = 7
				}
				if c.caller != "initial-requester" {
					show.TxID, show.Height = strings.Repeat("7", 64), 100
					tx["txid"], tx["blockhash"], tx["confirmations"] = show.TxID, strings.Repeat("1", 64), 2
					best := strings.Repeat("3", 64)
					f.n.set(t, "getblockchaininfo", tip{"regtest", best, 101, false})
					f.n.set(t, "getblockheader", map[string]any{"hash": best, "height": 101, "confirmations": 1}, best)
					f.n.set(t, "getblockhash", best, 101)
					f.n.set(t, "getblockheader", map[string]any{"hash": strings.Repeat("1", 64), "height": 100, "confirmations": 2}, strings.Repeat("1", 64))
					f.n.set(t, "getblockhash", strings.Repeat("1", 64), 100)
					f.n.set(t, "getblockheader", map[string]any{"hash": f.block, "height": 99, "confirmations": 3}, f.block)
				}
				var fields map[string]any
				_ = json.Unmarshal(marshal(t, show), &fields)
				if permanent {
					delete(fields, "value")
					if c.mode == "value-error" {
						fields["value_error"] = "invalid ascii"
					}
					if c.mode == "malformed-value" {
						fields["value"] = []any{1}
					}
				}
				f.n.set(t, "name_show", fields, show.Name)
				f.n.set(t, "getrawtransaction", tx, show.TxID, true)
				if strings.HasPrefix(c.caller, "second-") {
					changes := cliTranscript(t, f)
					g.transitions = []any{map[string]any{"Args": []string{"name_show", show.Name, string(marshal(t, nameOptions()))}, "Occurrence": 2, "Replies": changes}}
					f.n.data = saved
				}
				g.observe("disturbed", false)
				g.restore(saved, reverse, permanent)
			})
		}
	}
}

// Small parser controls cover each used nested identity field's absence, alias,
// conflict, duplicate and malformed type without repeating the process matrix.
func TestNestedIdentityProjectionBoundaries(t *testing.T) {
	f := fresh(t)
	original := bytes.Clone(f.n.data[callKey("getrawtransaction", f.ownerName.TxID, true)])
	for _, field := range []string{"n", "scriptPubKey", "address", "nameOp", "op", "name", "name_encoding"} {
		for _, mode := range []string{"missing", "alias", "conflict", "duplicate", "malformed", "null"} {
			t.Run(field+"/"+mode, func(t *testing.T) {
				var tx map[string]any
				_ = json.Unmarshal(original, &tx)
				output := tx["vout"].([]any)[0].(map[string]any)
				sp := output["scriptPubKey"].(map[string]any)
				op := sp["nameOp"].(map[string]any)
				parent := op
				if field == "n" || field == "scriptPubKey" {
					parent = output
				}
				if field == "address" || field == "nameOp" {
					parent = sp
				}
				alias := strings.ToUpper(field)
				switch mode {
				case "missing":
					delete(parent, field)
				case "alias":
					parent[alias] = parent[field]
					delete(parent, field)
				case "conflict":
					parent[alias] = []any{"conflict"}
				case "malformed":
					parent[field] = []any{"wrong type"}
				case "null":
					parent[field] = nil
				}
				raw := marshal(t, tx)
				if mode == "duplicate" {
					key := append(marshal(t, field), ':')
					member := append(append(bytes.Clone(key), marshal(t, parent[field])...), ',')
					raw = bytes.Replace(raw, key, append(member, key...), 1)
				}
				f.n.data[callKey("getrawtransaction", f.ownerName.TxID, true)] = raw
				if _, err := checkedGeneration(context.Background(), f.n, f.ownerName); err == nil {
					t.Fatal("ambiguous identity proved a generation")
				}
			})
		}
	}
	f.n.data[callKey("getrawtransaction", f.ownerName.TxID, true)] = original
	if _, err := checkedGeneration(context.Background(), f.n, f.ownerName); err != nil {
		t.Fatal("official neighbor", err)
	}
}

func (g *projectionGraph) observe(stage string, want bool) {
	t, f := g.t, g.f
	t.Helper()
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
	route := map[string]any{"Network": "regtest", "Genesis": RegtestGenesis, "NodeCLI": node, "NodeCLISHA256": hash(nb), "NodeConfig": filepath.Join(root, "node.json"), "NodeDataDir": root, "Compose": compose, "ComposeSHA256": hash(cb), "PrivateRoot": root, "RouteID": "offline-projection-adjacent"}
	files := map[string][]byte{"route.json": marshal(t, route), "input.json": marshal(t, map[string]any{"Mode": "verify", "Policy": f.p, "Certificate": filepath.Join(root, "cert.json"), "Request": filepath.Join(root, "request.json"), "At": f.at}), "node.json": marshal(t, map[string]any{"Network": "regtest", "Replies": cliTranscript(t, f), "Transitions": g.transitions}), "cert.json": f.certificate, "request.json": f.request}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(root, n), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(bridge, filepath.Join(root, "route.json"), filepath.Join(root, "input.json"))
	cmd.Env = []string{"HOME=" + root, "TMPDIR=" + root, "XDG_CACHE_HOME=" + root, "PATH=/nonexistent"}
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("bridge: %v", err)
	}
	var r struct {
		Effect    bool `json:"effect_authorized"`
		Qualified bool `json:"node_route_qualified"`
		Calls     int  `json:"read_calls"`
		Result    struct{ Verified bool }
	}
	if json.Unmarshal(raw, &r) != nil || r.Effect || r.Qualified || r.Calls > 256 {
		t.Fatal("invalid bounded receipt")
	}
	t.Logf("stage=%s want=%v receipt=%s", stage, want, raw)
	if r.Result.Verified != want {
		t.Errorf("stage=%s verified=%v want=%v", stage, r.Result.Verified, want)
	}
}
func projectionSave(f *fixture) map[string]json.RawMessage {
	r := map[string]json.RawMessage{}
	for k, v := range f.n.data {
		r[k] = bytes.Clone(v)
	}
	return r
}
func (g *projectionGraph) restore(saved map[string]json.RawMessage, reverse bool, permanent bool) {
	t, f := g.t, g.f
	t.Helper()
	p := filepath.Join(f.p.PrivateRoot, "closed-"+hash(f.certificate))
	first, err := os.ReadFile(p)
	t.Logf("persisted=%v want=%v evidence=%s", err == nil, permanent, first)
	if (err == nil) != permanent {
		t.Errorf("persisted=%v want=%v", err == nil, permanent)
	}
	f.n.data = saved
	g.transitions = nil
	f.operation["request_id"] = "fresh-projection-restoration"
	if reverse {
		f.request = signerRequest(t, f, f.p.PrivateRoot)
	} else {
		f.resign(t)
	}
	g.observe("restored-new-process-fresh-signature", !permanent)
	if permanent {
		last, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(last, first) {
			t.Error("first reason changed")
		}
	}
}

// Replace one official output identity spelling at a time. The independent
// original block remains canonical throughout, so it cannot excuse a latch.
func TestNestedOutputProjection(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, mode := range []string{"canonical", "N", "SCRIPTPUBKEY", "NAMEOP", "ADDRESS"} {
			direction := "forward"
			if reverse {
				direction = "mirror"
			}
			t.Run(direction+"/"+mode, func(t *testing.T) {
				f := freshDirection(t, reverse)
				g := &projectionGraph{t: t, f: f}
				g.observe("healthy", true)
				saved := projectionSave(f)
				f.ownerName.TxID = strings.Repeat("7", 64)
				f.ownerName.Height = 100
				f.refreshNames(t)
				f.anchor["blockhash"] = strings.Repeat("1", 64)
				f.anchor["confirmations"] = 2
				output := f.anchor["vout"].([]any)[0].(map[string]any)
				sp := output["scriptPubKey"].(map[string]any)
				switch mode {
				case "N":
					output["N"] = output["n"]
					delete(output, "n")
				case "SCRIPTPUBKEY":
					output["SCRIPTPUBKEY"] = sp
					delete(output, "scriptPubKey")
				case "NAMEOP":
					sp["NAMEOP"] = sp["nameOp"]
					delete(sp, "nameOp")
				case "ADDRESS":
					sp["ADDRESS"] = sp["address"]
					delete(sp, "address")
				}
				best := strings.Repeat("3", 64)
				f.n.set(t, "getrawtransaction", f.anchor, f.ownerName.TxID, true)
				f.n.set(t, "getblockheader", map[string]any{"hash": strings.Repeat("1", 64), "height": 100, "confirmations": 2}, strings.Repeat("1", 64))
				f.n.set(t, "getblockhash", strings.Repeat("1", 64), 100)
				f.n.set(t, "getblockchaininfo", tip{"regtest", best, 101, false})
				f.n.set(t, "getblockheader", map[string]any{"hash": best, "height": 101, "confirmations": 1}, best)
				f.n.set(t, "getblockhash", best, 101)
				f.n.set(t, "getblockheader", map[string]any{"hash": f.block, "height": 99, "confirmations": 3}, f.block)
				g.observe("disturbed", false)
				g.restore(saved, reverse, mode == "canonical")
			})
		}
	}
}

// A contradictory block projection in a claimed name transaction is not an
// independent policy anchor. Adjacent owner/requester controls keep the actual
// issuance block and its canonical mapping unchanged.
func TestUnprovenRequesterDisplacement(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, who := range []string{"owner", "requester"} {
			direction := "forward"
			if reverse {
				direction = "mirror"
			}
			t.Run(direction+"/"+who, func(t *testing.T) {
				f := freshDirection(t, reverse)
				g := &projectionGraph{t: t, f: f}
				g.observe("healthy", true)
				saved := projectionSave(f)
				tx, show := f.anchor, f.ownerName
				if who == "requester" {
					tx, show = f.requesterTX, f.requesterName
				}
				claimed := strings.Repeat("7", 64)
				tx["blockhash"] = claimed
				f.n.set(t, "getrawtransaction", tx, show.TxID, true)
				f.n.set(t, "getblockheader", map[string]any{"hash": claimed, "height": 99, "confirmations": 2}, claimed)
				// getblockhash(99) is still the independently pinned original block.
				g.observe("contradictory-claimed-block", false)
				g.restore(saved, reverse, false)
			})
		}
	}
}

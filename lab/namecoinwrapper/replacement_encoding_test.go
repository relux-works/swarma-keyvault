package namecoinwrapper

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Each restart retains the same private root and exact certificate envelope.
// The restored request is newly signed by the separate fixture signer.
func TestReplacementEncodingRestoration(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, projection := range []string{"ascii", "value-error", "omitted-value", "malformed-value", "malformed-record", "header-only", "unconfirmed", "wrong-name", "name-error", "malformed-outpoint", "wrong-outpoint", "missing-tx-outpoint", "wrong-tx-name", "noncanonical", "header-height", "unavailable"} {
			name := "forward"
			if reverse {
				name = "mirror"
			}
			name += "/" + projection
			t.Run(name, func(t *testing.T) {
				canonical := projection == "ascii" || projection == "value-error" || projection == "omitted-value" || projection == "malformed-value" || projection == "malformed-record" || projection == "header-only"
				f := freshDirection(t, reverse)
				f.p.Network, f.p.Genesis = "main", MainnetGenesis
				f.n.set(t, "getblockchaininfo", tip{"main", f.best, 100, false})
				f.n.set(t, "getblockhash", MainnetGenesis, 0)
				f.verify(t, new(Verifier), true)
				original := map[string]json.RawMessage{}
				for k, b := range f.n.data {
					original[k] = bytes.Clone(b)
				}
				newer := strings.Repeat("1", 64)
				f.ownerName.TxID = strings.Repeat("f", 64)
				if projection == "header-only" {
					f.ownerName.TxID = f.p.AnchorTxID
				}
				f.ownerName.Height = 101
				f.refreshNames(t)
				f.anchor["blockhash"] = newer
				f.n.set(t, "getblockheader", map[string]any{"height": 101, "confirmations": 1}, newer)
				f.n.set(t, "getblockhash", newer, 101)
				f.n.set(t, "getblockchaininfo", tip{"main", newer, 101, false})
				// Keep the unrelated original requester transaction unchanged.
				f.n.data[callKey("getrawtransaction", f.requesterName.TxID, true)] = original[callKey("getrawtransaction", f.requesterName.TxID, true)]
				if projection != "ascii" {
					var show map[string]any
					if json.Unmarshal(marshal(t, f.ownerName), &show) != nil {
						t.Fatal("decode test fixture")
					}
					delete(show, "value")
					if projection == "value-error" {
						show["value_error"] = "invalid data for ascii"
					}
					if projection == "malformed-value" {
						show["value"] = map[string]any{"invalid": "value"}
					}
					if projection == "malformed-record" {
						show["value"] = "not-json"
					}
					if projection == "wrong-name" {
						show["name"] = "id/unrelated"
					}
					if projection == "name-error" {
						show["name_error"] = "invalid data for ascii"
					}
					if projection == "malformed-outpoint" {
						show["vout"] = -1
					}
					if projection == "wrong-outpoint" {
						show["vout"] = 1
					}
					f.n.set(t, "name_show", show, f.p.OwnerName)
					op := f.anchor["vout"].([]any)[0].(map[string]any)["scriptPubKey"].(map[string]any)["nameOp"].(map[string]string)
					delete(op, "value")
					op["value_error"] = "invalid data for ascii"
					if projection == "wrong-tx-name" {
						op["name"] = "id/unrelated"
					}
					if projection == "missing-tx-outpoint" {
						delete(f.anchor["vout"].([]any)[0].(map[string]any), "n")
					}
					if projection == "unconfirmed" {
						f.anchor["confirmations"] = 0
					}
					if projection == "noncanonical" {
						f.n.set(t, "getblockhash", strings.Repeat("2", 64), 101)
					}
					if projection == "header-height" {
						f.n.set(t, "getblockheader", map[string]any{"height": 100, "confirmations": 1}, newer)
					}
				}
				f.n.set(t, "getrawtransaction", f.anchor, f.ownerName.TxID, true)
				if projection == "unavailable" {
					delete(f.n.data, callKey("getrawtransaction", f.ownerName.TxID, true))
				}
				f.verify(t, new(Verifier), false)
				_, err := os.Stat(filepath.Join(f.p.PrivateRoot, "closed-"+hash(f.certificate)))
				t.Logf("confirmed replacement refused; persisted latch=%v", err == nil)
				if (err == nil) != canonical {
					t.Fatalf("persisted canonical closure=%v want %v", err == nil, canonical)
				}
				f.n.data = original
				f.operation["request_id"] = "independent-fresh-valid-request-after-restoration"
				if reverse {
					f.request = signerRequest(t, f, f.p.PrivateRoot)
				} else {
					f.resign(t)
				}
				observation, err := new(Verifier).Verify(context.Background(), f.n, f.p, f.certificate, f.request, f.at)
				t.Logf("restored original branch with fresh valid request: observation=%v error=%v", observation != nil, err)
				if canonical {
					if observation != nil || err == nil {
						t.Error("canonical replacement reopened after restoration")
					}
				} else if observation == nil || err != nil {
					t.Error("uncertain/unrelated claim wrongly persisted closure")
				}
			})
		}
	}
}

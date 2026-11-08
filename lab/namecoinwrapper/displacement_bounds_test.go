package namecoinwrapper

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An independently pinned block can be displaced; an orphan/error projection
// alone cannot establish that displacement. Inter-call instability is refusal.
func TestOriginalDisplacementRequiresConsistentPositiveEvidence(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, mode := range []string{"unchanged-canonical", "canonical-unavailable", "canonical-malformed", "header-unavailable", "header-height-missing", "height-beyond-tip", "hash-restored-between-reads", "tip-changes-between-reads", "canonical-header-unavailable", "canonical-header-height", "canonical-header-depth", "tip-height-unavailable", "tip-height-mismatch", "same-hash-at-two-heights"} {
			name := "forward/" + mode
			if reverse {
				name = "mirror/" + mode
			}
			t.Run(name, func(t *testing.T) {
				f := freshDirection(t, reverse)
				f.verify(t, new(Verifier), true)
				saved := map[string]json.RawMessage{}
				for k, v := range f.n.data {
					saved[k] = bytes.Clone(v)
				}
				f.anchor["confirmations"] = 0
				f.n.set(t, "getrawtransaction", f.anchor, f.p.AnchorTxID, true)
				setOrphanBranch(t, f)
				switch mode {
				case "unchanged-canonical":
					f.n.set(t, "getblockhash", f.p.AnchorBlock, 99)
				case "canonical-unavailable":
					delete(f.n.data, callKey("getblockhash", 99))
				case "canonical-malformed":
					f.n.set(t, "getblockhash", map[string]any{"bad": true}, 99)
				case "header-unavailable":
					delete(f.n.data, callKey("getblockheader", f.p.AnchorBlock))
				case "header-height-missing":
					f.n.set(t, "getblockheader", map[string]any{"confirmations": -1}, f.p.AnchorBlock)
				case "height-beyond-tip":
					f.n.set(t, "getblockheader", map[string]any{"height": 101, "confirmations": -1}, f.p.AnchorBlock)
				case "canonical-header-unavailable":
					delete(f.n.data, callKey("getblockheader", strings.Repeat("f", 64)))
				case "canonical-header-height":
					f.n.set(t, "getblockheader", map[string]any{"hash": strings.Repeat("f", 64), "height": 98, "confirmations": 2}, strings.Repeat("f", 64))
				case "canonical-header-depth":
					f.n.set(t, "getblockheader", map[string]any{"hash": strings.Repeat("f", 64), "height": 99, "confirmations": 1}, strings.Repeat("f", 64))
				case "tip-height-unavailable":
					delete(f.n.data, callKey("getblockhash", 100))
				case "tip-height-mismatch":
					f.n.set(t, "getblockhash", strings.Repeat("8", 64), 100)
				case "same-hash-at-two-heights":
					f.n.set(t, "getblockchaininfo", tip{"regtest", strings.Repeat("f", 64), 100, false})
				case "hash-restored-between-reads":
					reads := 0
					f.n.mutate = func(method string, args []any) {
						if method == "getblockhash" && args[0] == 99 {
							reads++
							if reads == 2 {
								f.n.set(t, method, f.p.AnchorBlock, 99)
							}
						}
					}
				case "tip-changes-between-reads":
					reads := 0
					f.n.mutate = func(method string, args []any) {
						if method == "getblockchaininfo" {
							reads++
							if reads == 3 {
								f.n.set(t, method, tip{"regtest", strings.Repeat("f", 64), 101, false})
							}
						}
					}
				}
				f.verify(t, new(Verifier), false)
				if _, err := os.Stat(filepath.Join(f.p.PrivateRoot, "closed-"+hash(f.certificate))); !os.IsNotExist(err) {
					t.Fatalf("uncertain displacement persisted: %v", err)
				}
				f.n.data = saved
				f.n.mutate = nil
				f.operation["request_id"] = "fresh-after-uncertain-displacement"
				if reverse {
					f.request = signerRequest(t, f, f.p.PrivateRoot)
				} else {
					f.resign(t)
				}
				f.verify(t, new(Verifier), true)
			})
		}
	}
}

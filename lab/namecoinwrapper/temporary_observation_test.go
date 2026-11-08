package namecoinwrapper

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Supplemental controls: malformed replies about the SAME pinned issuance
// establish no canonical generation change. A new valid observation must recover.
func TestTemporaryObservationRestoration(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, mode := range []string{"owner-value-error", "owner-value-mismatch", "requester-unavailable", "after-owner-unavailable"} {
			name := mode
			if reverse {
				name = "mirror/" + name
			} else {
				name = "forward/" + name
			}
			t.Run(name, func(t *testing.T) {
				f := freshDirection(t, reverse)
				f.verify(t, new(Verifier), true)
				saved := map[string]json.RawMessage{}
				for k, v := range f.n.data {
					saved[k] = bytes.Clone(v)
				}
				switch mode {
				case "owner-value-error", "owner-value-mismatch":
					op := f.anchor["vout"].([]any)[0].(map[string]any)["scriptPubKey"].(map[string]any)["nameOp"].(map[string]string)
					if mode == "owner-value-error" {
						delete(op, "value")
						op["value_error"] = "invalid ascii"
					} else {
						op["value"] = "malformed-transient-RPC-projection"
					}
					f.n.set(t, "getrawtransaction", f.anchor, f.p.AnchorTxID, true)
				case "requester-unavailable":
					delete(f.n.data, callKey("getrawtransaction", f.requesterName.TxID, true))
				case "after-owner-unavailable":
					count := 0
					f.n.mutate = func(method string, args []any) {
						if method == "name_show" && args[0] == f.p.OwnerName {
							count++
							if count == 2 {
								delete(f.n.data, callKey("name_show", f.p.OwnerName, nameOptions()))
							}
						}
					}
				}
				f.verify(t, new(Verifier), false)
				_, staterr := os.Stat(filepath.Join(f.p.PrivateRoot, "closed-"+hash(f.certificate)))
				t.Logf("same issuance; no canonical generation changed; persisted_latch=%v", staterr == nil)
				f.n.data = saved
				f.n.mutate = nil
				f.operation["request_id"] = "review-new-valid-request-after-transient-error"
				if reverse {
					f.request = signerRequest(t, f, f.p.PrivateRoot)
				} else {
					f.resign(t)
				}
				got, err := new(Verifier).Verify(context.Background(), f.n, f.p, f.certificate, f.request, f.at)
				t.Logf("restored healthy exact issuance; newly signed request; verified=%v error=%v", got != nil, err)
				if staterr == nil || got == nil || err != nil {
					t.Errorf("malformed/unavailable reply permanently revoked unchanged canonical issuance")
				}
			})
		}
	}
}

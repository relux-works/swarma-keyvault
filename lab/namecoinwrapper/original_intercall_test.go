package namecoinwrapper

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

// Ordered snapshots emulate a reorg after a successful original-tx read, but
// before reading its pinned block header. No unconfirmed replacement is involved.
func TestOriginalIssuanceIntercallReorgRestoration(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		name := "forward"
		if reverse {
			name = "mirror"
		}
		t.Run(name, func(t *testing.T) {
			f := freshDirection(t, reverse)
			f.verify(t, new(Verifier), true)
			saved := map[string]json.RawMessage{}
			for k, v := range f.n.data {
				saved[k] = bytes.Clone(v)
			}
			changed := false
			f.n.calls = nil
			f.n.mutate = func(method string, args []any) {
				if !changed && method == "getblockheader" && args[0] == f.p.AnchorBlock {
					changed = true
					setOrphanBranch(t, f)
				}
			}
			f.verify(t, new(Verifier), false)
			if !changed {
				t.Fatal("did not reach reorg transition")
			}
			t.Logf("actual ordered reads=%v", f.n.calls)
			f.n.mutate = nil
			f.n.data = saved
			f.operation["request_id"] = "fresh-request-after-timed-original-reorg"
			if reverse {
				f.request = signerRequest(t, f, f.p.PrivateRoot)
			} else {
				f.resign(t)
			}
			got, err := new(Verifier).Verify(context.Background(), f.n, f.p, f.certificate, f.request, f.at)
			t.Logf("post-reorg restoration verified=%v error=%v", got != nil, err)
			if got != nil || err == nil {
				t.Error("original pinned block became orphaned during real read order, but persisted refusal was lost")
			}
		})
	}
}

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

// Distinct hashes at distinct heights, matching canonical confirmation depth
// and tip-height mapping. This is a new branch, not a simultaneous snapshot of
// an active and orphaned original block.
func setOrphanBranch(t *testing.T, f *fixture) {
	canonical, best := strings.Repeat("f", 64), strings.Repeat("9", 64)
	f.n.set(t, "getblockheader", map[string]any{"hash": f.p.AnchorBlock, "height": 99, "confirmations": -1}, f.p.AnchorBlock)
	f.n.set(t, "getblockheader", map[string]any{"hash": canonical, "height": 99, "confirmations": 2}, canonical)
	f.n.set(t, "getblockhash", canonical, 99)
	f.n.set(t, "getblockhash", best, 100)
	f.n.set(t, "getblockchaininfo", tip{"regtest", best, 100, false})
}

// The confirmation of a different block for the original issuance height is
// positive reorg evidence even if Core's orphan transaction has zero confirmations.
func TestOriginalIssuanceOrphanRestoration(t *testing.T) {
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
			f.anchor["confirmations"] = 0
			f.n.set(t, "getrawtransaction", f.anchor, f.p.AnchorTxID, true)
			setOrphanBranch(t, f)
			f.verify(t, new(Verifier), false)
			_, err := os.Stat(filepath.Join(f.p.PrivateRoot, "closed-"+hash(f.certificate)))
			t.Logf("original anchor contradicted at canonical height; rawtx confirmations=0; header confirmations=-1; persisted_latch=%v", err == nil)
			f.n.data = saved
			f.operation["request_id"] = "fresh-after-original-anchor-reorg"
			if reverse {
				f.request = signerRequest(t, f, f.p.PrivateRoot)
			} else {
				f.resign(t)
			}
			got, verifyErr := new(Verifier).Verify(context.Background(), f.n, f.p, f.certificate, f.request, f.at)
			t.Logf("restored original branch with fresh valid request: verified=%v error=%v", got != nil, verifyErr)
			if got != nil || verifyErr == nil {
				t.Error("original issuance reorg did not remain closed")
			}
		})
	}
}

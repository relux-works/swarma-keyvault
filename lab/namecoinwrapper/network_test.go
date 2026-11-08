package namecoinwrapper

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// These synthetic public RPC replies exercise the actual wrapper and separate
// cryptographic CLI; they are not external mainnet qualification.
func mainFixture(t *testing.T) *fixture {
	f := fresh(t)
	f.p.Network, f.p.Genesis = "main", MainnetGenesis
	f.n.set(t, "getblockchaininfo", tip{"main", f.best, 100, false})
	f.n.set(t, "getblockhash", MainnetGenesis, 0)
	return f
}

func TestIndependentNetworkPolicy(t *testing.T) {
	for _, mode := range []string{"default-regtest", "explicit-regtest", "explicit-main", "main-with-default", "regtest-with-main-policy", "wrong-main-genesis", "main-with-regtest-genesis", "unknown", "missing-genesis", "missing-network", "policy-genesis-mismatch"} {
		t.Run(mode, func(t *testing.T) {
			f := fresh(t)
			want := false
			switch mode {
			case "default-regtest":
				want = true
			case "explicit-regtest":
				f.p.Network, f.p.Genesis = "regtest", RegtestGenesis
				want = true
			case "explicit-main":
				f = mainFixture(t)
				want = true
			case "main-with-default":
				f.n.set(t, "getblockchaininfo", tip{"main", f.best, 100, false})
				f.n.set(t, "getblockhash", MainnetGenesis, 0)
			case "regtest-with-main-policy":
				f.p.Network, f.p.Genesis = "main", MainnetGenesis
			case "wrong-main-genesis":
				f = mainFixture(t)
				f.n.set(t, "getblockhash", strings.Repeat("a", 64), 0)
			case "main-with-regtest-genesis":
				f = mainFixture(t)
				f.n.set(t, "getblockhash", RegtestGenesis, 0)
			case "unknown":
				f.p.Network, f.p.Genesis = "test", MainnetGenesis
			case "missing-genesis":
				f.p.Network = "main"
			case "missing-network":
				f.p.Genesis = MainnetGenesis
			case "policy-genesis-mismatch":
				f.p.Network, f.p.Genesis = "main", RegtestGenesis
			}
			f.verify(t, &Verifier{}, want)
		})
	}
}

func TestMainnetPersistedRefusal(t *testing.T) {
	for _, state := range []string{"mempool-spend", "one-block-spend", "reorg", "issuance-replacement"} {
		t.Run(state, func(t *testing.T) {
			f := mainFixture(t)
			f.verify(t, &Verifier{}, true)
			original := map[string]json.RawMessage{}
			for key, raw := range f.n.data {
				original[key] = bytes.Clone(raw)
			}
			switch state {
			case "mempool-spend", "one-block-spend":
				f.n.set(t, "gettxout", nil, f.seal.TxID, f.seal.Vout, true)
				if state == "one-block-spend" {
					setExtendedTip(t, f, "main")
				}
			case "reorg":
				setOrphanBranch(t, f)
				f.n.set(t, "getblockchaininfo", tip{"main", strings.Repeat("9", 64), 100, false})
			case "issuance-replacement":
				f.ownerName.TxID = strings.Repeat("f", 64)
				f.refreshNames(t)
			}
			f.verify(t, &Verifier{}, false)
			f.n.data = original
			// A newly valid signature/request cannot undo the same certificate latch.
			f.operation["request_id"] = "new-valid-request-after-restoration"
			f.resign(t)
			f.verify(t, &Verifier{}, false)
		})
	}
}

func TestMainnetPreservesCryptographicAndPublicPins(t *testing.T) {
	for _, control := range []string{"bad-signature", "wrong-owner", "anchor", "full-certificate", "encoding-error", "full-spki", "seal"} {
		t.Run(control, func(t *testing.T) {
			f := mainFixture(t)
			f.verify(t, &Verifier{}, true)
			switch control {
			case "bad-signature":
				f.request = bytes.Replace(f.request, []byte(`"signature":"`), []byte(`"signature":"A`), 1)
			case "wrong-owner":
				f.p.ExpectedOwner = "@other:example.invalid"
			case "anchor":
				f.p.AnchorTxID = strings.Repeat("1", 64)
			case "full-certificate":
				f.certificate = append(f.certificate, '\n')
			case "encoding-error":
				var fields map[string]any
				_ = json.Unmarshal(f.n.data[callKey("name_show", f.p.OwnerName, nameOptions())], &fields)
				fields["name_error"] = nil
				f.n.set(t, "name_show", fields, f.p.OwnerName, nameOptions())
			case "full-spki":
				f.ownerRecord["swarma"].(map[string]any)["keyvault_owner_spki"] = strings.Repeat("A", 122)
				f.refreshNames(t)
			case "seal":
				f.p.SealVout++
			}
			f.verify(t, &Verifier{}, false)
		})
	}
}

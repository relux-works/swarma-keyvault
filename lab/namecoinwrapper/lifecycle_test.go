package namecoinwrapper

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Three coherent synthetic states: issuance, a confirmed owner update on an
// extending tip, and restoration of the original branch after a reorg.
func TestConfirmedGenerationReplacementCannotReopen(t *testing.T) {
	f := fresh(t)
	f.verify(t, &Verifier{}, true)
	original := map[string]json.RawMessage{}
	for key, value := range f.n.data {
		original[key] = bytes.Clone(value)
	}
	newer := strings.Repeat("1", 64)
	f.ownerName.TxID = strings.Repeat("f", 64)
	f.ownerName.Height = 101
	f.refreshNames(t)
	f.anchor["blockhash"] = newer
	f.anchor["confirmations"] = 1
	f.n.set(t, "getrawtransaction", f.anchor, f.ownerName.TxID, true)
	f.n.set(t, "getblockheader", map[string]any{"hash": newer, "height": 101, "confirmations": 1}, newer)
	f.n.set(t, "getblockhash", newer, 101)
	f.n.set(t, "getblockchaininfo", tip{"regtest", newer, 101, false})
	f.n.set(t, "gettxout", map[string]any{"bestblock": newer, "confirmations": 4, "scriptPubKey": map[string]string{"address": "LAB-OWNER"}}, f.seal.TxID, 0, true)
	f.n.data[callKey("getrawtransaction", f.requesterName.TxID, true)] = original[callKey("getrawtransaction", f.requesterName.TxID, true)]
	f.verify(t, &Verifier{}, false)
	f.n.data = original
	f.verify(t, &Verifier{}, false)
}

func TestCompleteASCIINameReplies(t *testing.T) {
	f := fresh(t)
	f.ownerName.NameEncoding = "ascii"
	f.ownerName.ValueEncoding = "ascii"
	f.requesterName.NameEncoding = "ascii"
	f.requesterName.ValueEncoding = "ascii"
	f.n.set(t, "name_show", f.ownerName, f.p.OwnerName)
	f.n.set(t, "name_show", f.requesterName, f.p.RequesterName)
	f.verify(t, &Verifier{}, true)
	want := callKey("name_show", f.p.OwnerName, map[string]any{"nameEncoding": "ascii", "valueEncoding": "ascii", "allowExpired": false})
	found := false
	for _, call := range f.n.calls {
		if call == want {
			found = true
		}
		if strings.HasPrefix(call, "name_show:") && !strings.Contains(call, `"allowExpired":false,"nameEncoding":"ascii","valueEncoding":"ascii"`) {
			t.Fatal("name_show did not use fixed official options", call)
		}
	}
	if !found {
		t.Fatal("owner lookup missing")
	}
}

func TestReplacementClosurePrecedesRecordAndRequesterErrors(t *testing.T) {
	for _, kind := range []string{"missing-seal", "different-certificate", "malformed-record", "bad-requester"} {
		t.Run(kind, func(t *testing.T) {
			f := fresh(t)
			f.verify(t, &Verifier{}, true)
			original := map[string]json.RawMessage{}
			for k, value := range f.n.data {
				original[k] = bytes.Clone(value)
			}
			f.ownerName.TxID = strings.Repeat("f", 64)
			switch kind {
			case "missing-seal":
				delete(f.ownerRecord["swarma"].(map[string]any), "keyvault_seal")
			case "different-certificate":
				f.ownerRecord["swarma"].(map[string]any)["keyvault_certificate_sha256"] = strings.Repeat("0", 64)
			case "bad-requester":
				f.requesterRecord = map[string]any{}
			}
			f.refreshNames(t)
			if kind == "malformed-record" {
				f.ownerName.Value = "not-json"
				f.n.set(t, "name_show", f.ownerName, f.p.OwnerName)
				f.anchor["vout"].([]any)[0].(map[string]any)["scriptPubKey"].(map[string]any)["nameOp"].(map[string]string)["value"] = f.ownerName.Value
				f.n.set(t, "getrawtransaction", f.anchor, f.ownerName.TxID, true)
			}
			f.verify(t, &Verifier{}, false)
			latch := filepath.Join(f.p.PrivateRoot, "closed-"+hash(f.certificate))
			st, err := os.Stat(latch)
			if err != nil || st.Mode().Perm() != 0600 {
				t.Fatalf("closure not persisted privately: %v", err)
			}
			f.n.data = original
			f.verify(t, &Verifier{}, false)
		})
	}
}

func TestPersistenceFailureStillClosesCurrentVerifier(t *testing.T) {
	f := fresh(t)
	v := &Verifier{}
	f.verify(t, v, true)
	original := map[string]json.RawMessage{}
	for k, value := range f.n.data {
		original[k] = bytes.Clone(value)
	}
	f.ownerName.TxID = strings.Repeat("f", 64)
	f.refreshNames(t)
	// Change permissions only after the private-root check, when the confirmed
	// canonical replacement is being established. This forces latch creation to
	// fail; no restart persistence is claimed after an unsuccessful write.
	f.n.mutate = func(method string, args []any) {
		if method == "getblockhash" && args[0] == 99 {
			if err := os.Chmod(f.p.PrivateRoot, 0500); err != nil {
				t.Fatal(err)
			}
		}
	}
	f.verify(t, v, false)
	if err := os.Chmod(f.p.PrivateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	f.n.mutate = nil
	f.n.data = original
	if _, err := os.Stat(filepath.Join(f.p.PrivateRoot, "closed-"+hash(f.certificate))); !os.IsNotExist(err) {
		t.Fatalf("persistence failure fixture did not fail: %v", err)
	}
	f.verify(t, v, false)
}

func TestObservationDoesNotReserveRequestOrImplementIdleStop(t *testing.T) {
	f := fresh(t)
	f.operation["expires_at"] = f.at.Add(45 * time.Minute).Format(time.RFC3339)
	f.resign(t)
	v := &Verifier{}
	first := f.verify(t, v, true)
	second := f.verify(t, v, true)
	if *first != *second {
		t.Fatal("repeat observation changed")
	}
	f.at = f.at.Add(31 * time.Minute)
	f.verify(t, &Verifier{}, true)
	raw := marshal(t, second)
	if bytes.Contains(raw, []byte(`"decision"`)) || bytes.Contains(raw, []byte("admit")) {
		t.Fatal("observation presented as admission", string(raw))
	}
}

func TestNameRPCEncodingControls(t *testing.T) {
	for _, target := range []string{"name_show", "nameOp"} {
		for _, kind := range []string{"missing-name-encoding", "missing-value-encoding", "wrong-name-encoding", "wrong-value-encoding", "name-error", "value-error", "null-error", "aliased-encoding", "non-ascii-name", "non-ascii-value"} {
			t.Run(target+"/"+kind, func(t *testing.T) {
				f := fresh(t)
				f.verify(t, &Verifier{}, true)
				var fields map[string]json.RawMessage
				key := callKey("name_show", f.p.OwnerName, nameOptions())
				if target == "name_show" {
					if err := json.Unmarshal(f.n.data[key], &fields); err != nil {
						t.Fatal(err)
					}
				} else {
					op := f.anchor["vout"].([]any)[0].(map[string]any)["scriptPubKey"].(map[string]any)["nameOp"]
					if err := json.Unmarshal(marshal(t, op), &fields); err != nil {
						t.Fatal(err)
					}
				}
				switch kind {
				case "missing-name-encoding":
					delete(fields, "name_encoding")
				case "missing-value-encoding":
					delete(fields, "value_encoding")
				case "wrong-name-encoding":
					fields["name_encoding"] = marshal(t, "hex")
				case "wrong-value-encoding":
					fields["value_encoding"] = marshal(t, "utf8")
				case "name-error":
					fields["name_error"] = marshal(t, "invalid data for ascii")
				case "value-error":
					fields["value_error"] = marshal(t, "invalid data for ascii")
				case "null-error":
					fields["value_error"] = json.RawMessage("null")
				case "aliased-encoding":
					fields["NAME_ENCODING"] = fields["name_encoding"]
					delete(fields, "name_encoding")
				case "non-ascii-name":
					fields["name"] = marshal(t, "d/é")
				case "non-ascii-value":
					fields["value"] = marshal(t, "é")
				}
				if target == "name_show" {
					f.n.data[key] = marshal(t, fields)
				} else {
					f.anchor["vout"].([]any)[0].(map[string]any)["scriptPubKey"].(map[string]any)["nameOp"] = fields
					f.n.set(t, "getrawtransaction", f.anchor, f.ownerName.TxID, true)
				}
				f.verify(t, &Verifier{}, false)
			})
		}
	}
}

func TestNameHeightMatchesConfirmedHistory(t *testing.T) {
	for _, kind := range []string{"missing", "mismatched"} {
		t.Run(kind, func(t *testing.T) {
			f := fresh(t)
			var fields map[string]json.RawMessage
			key := callKey("name_show", f.p.OwnerName, nameOptions())
			if err := json.Unmarshal(f.n.data[key], &fields); err != nil {
				t.Fatal(err)
			}
			if kind == "missing" {
				delete(fields, "height")
			} else {
				fields["height"] = json.RawMessage("98")
			}
			f.n.data[key] = marshal(t, fields)
			f.verify(t, &Verifier{}, false)
		})
	}
}

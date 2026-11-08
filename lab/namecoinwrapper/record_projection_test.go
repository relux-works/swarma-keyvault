package namecoinwrapper

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every known record member rejects aliases/conflicts/duplicates at its actual
// nesting level; small values keep even top-level duplicates below 520 bytes,
// so a bound rejection cannot masquerade as a projection regression witness.
func TestW7RecordExactProjection(t *testing.T) {
	official := []byte(`{"swarma":{"keyvault_owner_spki":"owner","keyvault_requester_spki":"requester","keyvault_certificate_sha256":"cert","keyvault_seal":{"txid":"tx","vout":0}}}`)
	for _, field := range []string{"swarma", "keyvault_owner_spki", "keyvault_requester_spki", "keyvault_certificate_sha256", "keyvault_seal", "txid", "vout"} {
		for _, mode := range []string{"official", "alias", "alias-last", "official-last", "duplicate"} {
			t.Run(field+"/"+mode, func(t *testing.T) {
				raw := official
				if mode != "official" {
					raw = sealProjectionMutation(t, raw, field, strings.ToUpper(field), mode)
				}
				if len(raw) > 520 {
					t.Fatal("fixture exceeds record bound")
				}
				r, err := parseRecord(nameShow{Value: string(raw)})
				if mode == "official" {
					if err != nil || r.Swarma.Owner != "owner" || r.Swarma.Requester != "requester" || r.Swarma.Certificate != "cert" || r.Swarma.Seal == nil || *r.Swarma.Seal != (point{"tx", 0}) {
						t.Fatal("official record", r, err)
					}
				} else if !errors.Is(err, ErrRefused) {
					t.Fatalf("ambiguous record parsed: %+v, %v", r, err)
				}
			})
		}
	}
}

// Unknown non-alias members at all three levels, whitespace, and member order
// stay compatible. A requester-only record does not acquire owner requirements.
func TestW7RecordExtensionsRemainIgnored(t *testing.T) {
	for _, raw := range []string{
		`{"extra":1,"swarma":{"extra":true,"keyvault_owner_spki":"owner","keyvault_seal":{"extra":{},"vout":0,"txid":"tx"}}}`,
		`{ "swarma" : { "keyvault_seal" : { "vout" : 0, "txid" : "tx" }, "keyvault_owner_spki" : "owner" }, "extra" : 1 }`,
	} {
		r, err := parseRecord(nameShow{Value: raw})
		if err != nil || r.Swarma.Owner != "owner" || r.Swarma.Seal == nil || *r.Swarma.Seal != (point{"tx", 0}) {
			t.Fatal(r, err)
		}
	}
	r, err := parseRecord(nameShow{Value: `{"swarma":{"keyvault_requester_spki":"requester"}}`})
	if err != nil || r.Swarma.Requester != "requester" || r.Swarma.Owner != "" || r.Swarma.Seal != nil {
		t.Fatal(r, err)
	}
}

// An alias of an otherwise unused known field cannot hide in a valid anchored
// record. Align name_show and transaction nameOp bytes so the full graph reaches
// parseRecord; rejection must leave no lifecycle latch, and restoration admits.
func TestW7RecordProjectionGraph(t *testing.T) {
	for _, role := range []string{"owner", "requester"} {
		t.Run(role, func(t *testing.T) {
			f := fresh(t)
			f.verify(t, new(Verifier), true)
			saved := projectionSave(f)
			name, tx := &f.ownerName, f.anchor
			alias := "KEYVAULT_REQUESTER_SPKI"
			if role == "requester" {
				name, tx = &f.requesterName, f.requesterTX
				alias = "KEYVAULT_OWNER_SPKI"
			}
			var outer map[string]json.RawMessage
			if json.Unmarshal([]byte(name.Value), &outer) != nil {
				t.Fatal("fixture")
			}
			var inner map[string]any
			if json.Unmarshal(outer["swarma"], &inner) != nil {
				t.Fatal("fixture")
			}
			inner[alias] = "ignored-alias"
			outer["swarma"] = marshal(t, inner)
			name.Value = string(marshal(t, outer))
			if len(name.Value) > 520 {
				t.Fatal("fixture exceeds record bound")
			}
			f.n.set(t, "name_show", *name, name.Name)
			tx["vout"].([]any)[0].(map[string]any)["scriptPubKey"].(map[string]any)["nameOp"].(map[string]string)["value"] = name.Value
			f.n.set(t, "getrawtransaction", tx, name.TxID, true)
			f.verify(t, new(Verifier), false)
			if _, err := os.Stat(filepath.Join(f.p.PrivateRoot, "closed-"+hash(f.certificate))); !os.IsNotExist(err) {
				t.Fatal("record alias latched", err)
			}
			f.n.data = saved
			f.verify(t, new(Verifier), true)
		})
	}
}

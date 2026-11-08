package namecoinwrapper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Replace exactly one known fixture member without parsing away duplicates or
// changing member order. Null conflicts have one otherwise valid alias value.
func sealProjectionMutation(t *testing.T, raw []byte, field, alias, mode string) []byte {
	t.Helper()
	tag := `"` + field + `":`
	i := bytes.Index(raw, []byte(tag))
	if i < 0 {
		t.Fatal("fixture field absent", field)
	}
	d := json.NewDecoder(bytes.NewReader(raw[i+len(tag):]))
	var value json.RawMessage
	if err := d.Decode(&value); err != nil {
		t.Fatal(err)
	}
	end := i + len(tag) + int(d.InputOffset())
	official := tag + string(value)
	alternate := `"` + alias + `":` + string(value)
	var replacement string
	switch mode {
	case "alias":
		replacement = alternate
	case "alias-last":
		replacement = tag + `null,` + alternate
	case "official-last":
		replacement = alternate + `,` + tag + `null`
	case "duplicate":
		replacement = official + `,` + official
	default:
		t.Fatal("unknown mutation")
	}
	return []byte(string(raw[:i]) + replacement + string(raw[end:]))
}

// Each used seal field requires its exact spelling at both the direct gate and
// the full Verify graph. Malformed seal evidence retains the existing durable
// spent-or-unknown refusal; restoring a reply cannot reopen that certificate.
func TestW7SealExactProjection(t *testing.T) {
	for _, field := range []string{"bestblock", "confirmations", "scriptPubKey", "address"} {
		for _, mode := range []string{"alias", "alias-last", "official-last", "duplicate"} {
			t.Run(field+"/"+mode, func(t *testing.T) {
				f := fresh(t)
				key := callKey("gettxout", f.seal.TxID, f.seal.Vout, true)
				official := bytes.Clone(f.n.data[key])
				if err := checkSeal(context.Background(), f.n, f.seal, f.ownerName.Address, f.best); err != nil {
					t.Fatal("official gate", err)
				}
				f.verify(t, new(Verifier), true)
				f.n.data[key] = sealProjectionMutation(t, official, field, strings.ToUpper(field), mode)
				if err := checkSeal(context.Background(), f.n, f.seal, f.ownerName.Address, f.best); !errors.Is(err, ErrRefused) {
					t.Errorf("ambiguous seal not refused: %v", err)
				}
				result, err := new(Verifier).Verify(context.Background(), f.n, f.p, f.certificate, f.request, f.at)
				if !errors.Is(err, ErrRefused) || result != nil {
					t.Errorf("ambiguous seal admitted: %v %+v", err, result)
				}
				path := filepath.Join(f.p.PrivateRoot, "closed-"+hash(f.certificate))
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal("missing refusal latch", err)
				}
				var evidence closureEvidence
				if json.Unmarshal(raw, &evidence) != nil || evidence.Reason != "seal-spent-or-unknown" {
					t.Fatal("wrong latch", string(raw))
				}
				f.n.data[key] = official
				f.verify(t, new(Verifier), false)
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(raw, after) {
					t.Fatal("restoration changed latch")
				}
			})
		}
	}
}

// The last seal read shares the strict gate, after CLI verification; an alias
// introduced only there must not turn the preceding valid reads into admission.
func TestW7FinalSealProjection(t *testing.T) {
	f := fresh(t)
	key := callKey("gettxout", f.seal.TxID, f.seal.Vout, true)
	official := bytes.Clone(f.n.data[key])
	reads := 0
	f.n.mutate = func(method string, _ []any) {
		if method == "gettxout" {
			reads++
			if reads == 2 {
				f.n.data[key] = sealProjectionMutation(t, official, "confirmations", "CONFIRMATIONS", "alias")
			}
		}
	}
	f.verify(t, new(Verifier), false)
	if reads != 2 {
		t.Fatalf("did not reach final gate: %d", reads)
	}
}

// Core null is still spent/unknown, and a zero official confirmation cannot be
// overridden by an alias in either order. The adjacent positive fixture admits.
func TestW7SealNullAndConfirmationConflict(t *testing.T) {
	for _, members := range []string{`"confirmations":0,"CONFIRMATIONS":3`, `"CONFIRMATIONS":3,"confirmations":0`, "null"} {
		t.Run(members, func(t *testing.T) {
			f := fresh(t)
			f.verify(t, new(Verifier), true)
			raw := []byte(`{"bestblock":"` + f.best + `",` + members + `,"scriptPubKey":{"address":"LAB-OWNER"}}`)
			if members == "null" {
				raw = []byte("null")
			}
			f.n.data[callKey("gettxout", f.seal.TxID, 0, true)] = raw
			f.verify(t, new(Verifier), false)
		})
	}
}

// Displacement may latch only from official header evidence. An alias or
// duplicate in either original or canonical header refuses with no latch, and
// restoring the original healthy branch admits again in the same private root.
func TestW7DisplacedHeaderProjection(t *testing.T) {
	for _, target := range []string{"original", "canonical"} {
		fields := []string{"hash", "height"}
		if target == "canonical" {
			fields = append(fields, "confirmations")
		}
		for _, field := range fields {
			for _, mode := range []string{"official", "alias", "alias-last", "official-last", "duplicate"} {
				t.Run(target+"/"+field+"/"+mode, func(t *testing.T) {
					f := fresh(t)
					f.verify(t, new(Verifier), true)
					saved := map[string]json.RawMessage{}
					for k, v := range f.n.data {
						saved[k] = bytes.Clone(v)
					}
					f.anchor["confirmations"] = 0
					f.n.set(t, "getrawtransaction", f.anchor, f.p.AnchorTxID, true)
					setOrphanBranch(t, f)
					id := f.p.AnchorBlock
					if target == "canonical" {
						id = strings.Repeat("f", 64)
					}
					key := callKey("getblockheader", id)
					if mode != "official" {
						f.n.data[key] = sealProjectionMutation(t, f.n.data[key], field, strings.ToUpper(field), mode)
					}
					f.verify(t, new(Verifier), false)
					path := filepath.Join(f.p.PrivateRoot, "closed-"+hash(f.certificate))
					raw, err := os.ReadFile(path)
					if mode == "official" {
						var e closureEvidence
						if err != nil || json.Unmarshal(raw, &e) != nil || e.Reason != "canonical-block-displacement" {
							t.Fatal("official displacement not latched", err)
						}
					} else {
						if !os.IsNotExist(err) {
							t.Fatalf("ambiguous header persisted closure: %s, %v", raw, err)
						}
						f.n.data = saved
						f.verify(t, new(Verifier), true)
					}
				})
			}
		}
	}
}

// Fold-equal duplicates are ambiguous at any depth, including unknown Core
// extension fields and Unicode folds that lowercasing alone does not merge.
func TestW7DuplicateFold(t *testing.T) {
	for _, raw := range []string{`{"extra":1,"EXTRA":2}`, `{"x":{"s":1,"ſ":2}}`, `{"k":1,"K":2}`} {
		var out any
		if uniqueJSON([]byte(raw), 1024, &out) == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	var out any
	if err := uniqueJSON([]byte(`{"extra":1,"different":2}`), 1024, &out); err != nil {
		t.Fatal(err)
	}
}

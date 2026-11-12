package namecoinwire

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Every frozen FORMAT-ONLY bundle has the closed public result syntax. This
// proves neither the synthetic journal fields nor a protected SIGNED outcome.
func TestFrozenResultSyntaxAndRefusals(t *testing.T) {
	for _, mode := range []string{"all-four-before-release", "two-stage"} {
		for _, slot := range []string{"A", "B", "C", "D"} {
			t.Run(mode+"/"+slot, func(t *testing.T) {
				raw := fixture(t, mode, slot+"-result.json")
				result, err := DecodeResult(raw)
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := EncodeResult(result)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = DecodeResult(encoded); err != nil {
					t.Fatal(err)
				}
				for _, mutate := range []func(*Result){func(r *Result) { r.Schema = "keyvault-namecoin-psbt-result/1" }, func(r *Result) { r.Receipt.JournalSequence = 0 }, func(r *Result) { r.Receipt.Status = "UNKNOWN" }, func(r *Result) { r.Receipt.InputSignatures[0].Index++ }, func(r *Result) { r.Receipt.InputSignatures[0].Sighash = "SINGLE" }, func(r *Result) { r.Receipt.SignedPSBTSHA256 = "00" }, func(r *Result) { r.SignedPSBT += "=" }} {
					bad, err := DecodeResult(raw)
					if err != nil {
						t.Fatal(err)
					}
					mutate(&bad)
					changed, err := json.Marshal(bad)
					if err != nil {
						t.Fatal(err)
					}
					if _, err = DecodeResult(changed); err == nil {
						t.Fatal("malformed public result admitted")
					}
				}
				if _, err = DecodeResult(bytes.Replace(encoded, []byte(`"status":`), []byte(`"Status":`), 1)); err == nil {
					t.Fatal("result case alias admitted")
				}
			})
		}
	}
}

package grants

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// Exact independently specified unsigned vectors exercise seven complete
// representation positives and eight specific refusals. No positive proves
// enrollment, signature authenticity, retained lifecycle state or an effect.
func TestOriginalTypedPayloadVectors(t *testing.T) {
	var vectors []struct {
		ID              string `json:"id"`
		Parser          string `json:"parser"`
		Want            string `json:"want"`
		PositiveControl string `json:"positive_control"`
		RawBase64       string `json:"raw_base64"`
		Bytes           int    `json:"bytes"`
		SHA256          string `json:"sha256"`
	}
	data, e := os.ReadFile("testdata/payload_vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	if e := json.Unmarshal(data, &vectors); e != nil || len(vectors) != 15 {
		t.Fatal("fixture set", e)
	}
	byID := make(map[string]int, len(vectors))
	decoded := make([][]byte, len(vectors))
	positiveCount := 0
	negativeCount := 0
	for i, v := range vectors {
		if _, exists := byID[v.ID]; exists {
			t.Fatal("duplicate fixture ID")
		}
		byID[v.ID] = i
		raw, e := base64.StdEncoding.DecodeString(v.RawBase64)
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(raw)
		if len(raw) != v.Bytes || hex.EncodeToString(sum[:]) != v.SHA256 {
			t.Fatal("original bytes changed", v.ID)
		}
		decoded[i] = raw
		if v.Want == "" {
			positiveCount++
		} else {
			negativeCount++
		}
	}
	if positiveCount != 7 || negativeCount != 8 {
		t.Fatal("positive/refusal fixture inventory")
	}
	parse := func(raw []byte, kind string) error {
		t.Helper()
		switch kind {
		case "certificate":
			v, e := parseCertificateProjection(raw)
			if (e == nil) != (v != nil) {
				t.Fatal("certificate partial/empty output")
			}
			return e
		case "request":
			v, e := parseRequestProjection(raw)
			if (e == nil) != (v != nil) {
				t.Fatal("request partial/empty output")
			}
			return e
		case "revocation":
			v, e := parseRevocationProjection(raw)
			if (e == nil) != (v != nil) {
				t.Fatal("revocation partial/empty output")
			}
			return e
		default:
			t.Fatal("unknown parser")
			return nil
		}
	}
	for i, v := range vectors {
		t.Run(v.ID, func(t *testing.T) {
			positive := func() {
				t.Helper()
				if v.Want == "" {
					return
				}
				j, ok := byID[v.PositiveControl]
				if !ok || vectors[j].Want != "" || vectors[j].Parser != v.Parser {
					t.Fatal("missing positive control")
				}
				if e := parse(decoded[j], v.Parser); e != nil {
					t.Fatal("valid neighboring vector", e)
				}
			}
			positive()
			e := parse(decoded[i], v.Parser)
			if v.Want == "" {
				if e != nil {
					t.Fatal("representation positive", e)
				}
			} else if e == nil || e.Error() != v.Want {
				t.Fatal("specific refusal", v.Want, e)
			}
			positive()
		})
	}
}

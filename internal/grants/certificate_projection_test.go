package grants

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
)

func certificateOriginalBytes(t *testing.T) []byte {
	t.Helper()
	data, e := os.ReadFile("testdata/envelope_payload_vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var vectors []struct {
		ID        string `json:"id"`
		RawBase64 string `json:"raw_base64"`
	}
	if e := json.Unmarshal(data, &vectors); e != nil {
		t.Fatal(e)
	}
	for _, v := range vectors {
		if v.ID == "certificate-unsigned-canonical" {
			raw, e := base64.StdEncoding.DecodeString(v.RawBase64)
			if e != nil {
				t.Fatal(e)
			}
			sum := sha256.Sum256(raw)
			if len(raw) != 1696 || hex.EncodeToString(sum[:]) != "264162256a1ddf7ce62a65c3b4b75873b3eac82a70d2e3f324977cab55e8a73a" {
				t.Fatal("original unsigned vector changed")
			}
			return raw
		}
	}
	t.Fatal("missing original unsigned certificate")
	return nil
}
func certificateTestObject(t *testing.T) map[string]any {
	t.Helper()
	var v map[string]any
	if e := json.Unmarshal(certificateOriginalBytes(t), &v); e != nil {
		t.Fatal(e)
	}
	return v
}
func certificateTestBytes(t *testing.T, v any) []byte {
	t.Helper()
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func certificateEntry(v map[string]any, index int) map[string]any {
	return v["entries"].([]any)[index].(map[string]any)
}
func certificateUse(entry map[string]any, index int) map[string]any {
	return entry["uses"].([]any)[index].(map[string]any)
}

// The independent unsigned R2 certificate is decoded with exact signed array
// order and owned raw bytes, without issuer/signature/state authority claims.
func TestCertificateProjectionOriginalAndOwnership(t *testing.T) {
	raw := certificateOriginalBytes(t)
	owned := append([]byte(nil), raw...)
	got, e := parseCertificateProjection(raw)
	if e != nil || got == nil {
		t.Fatal(e)
	}
	if got.certificateID != "cert-synthetic-1" || len(got.cycles) != 4 || len(got.entries) != 2 || len(got.supersedes) != 0 || got.cycles[0].cycleID != "claude-dm" || got.cycles[3].cycleID != "codex-group" || got.entries[0].entryID != "repo-create" || got.entries[1].entryID != "repo-delete" || got.entries[0].uses[3].operationUseID != "codex-group/create" {
		t.Fatal("decoded identity/order")
	}
	for i := range raw {
		raw[i] = 'x'
	}
	if !bytes.Equal(got.raw, owned) || got.issuer.ownerMXID != "@owner:example.invalid" || got.subject.deviceID != "SYNTHETIC" {
		t.Fatal("owned bytes/values")
	}
	v := certificateTestObject(t)
	cycles := v["cycles"].([]any)
	cycles[0], cycles[3] = cycles[3], cycles[0]
	entries := v["entries"].([]any)
	entries[0], entries[1] = entries[1], entries[0]
	uses := certificateEntry(v, 0)["uses"].([]any)
	uses[0], uses[3] = uses[3], uses[0]
	got, e = parseCertificateProjection(certificateTestBytes(t, v))
	if e != nil || got == nil || got.cycles[0].cycleID != "codex-group" || got.entries[0].entryID != "repo-delete" || got.entries[0].uses[0].cycleID != "codex-group" {
		t.Fatal("array order repaired/rejected", e)
	}
}

// Every required outer/entry field is closed and correctly typed. Limits and
// canonical encoding failures remain distinct from canonical schema refusals.
func TestCertificateProjectionClosedFields(t *testing.T) {
	good := func() {
		t.Helper()
		if got, e := parseCertificateProjection(certificateOriginalBytes(t)); e != nil || got == nil {
			t.Fatal("positive", e)
		}
	}
	original := certificateTestObject(t)
	for field := range original {
		for _, mode := range []string{"missing", "boolean", "integer", "wrong-container"} {
			t.Run(field+"/"+mode, func(t *testing.T) {
				good()
				v := certificateTestObject(t)
				switch mode {
				case "missing":
					delete(v, field)
				case "boolean":
					v[field] = true
				case "integer":
					v[field] = 1
				case "wrong-container":
					switch field {
					case "issuer", "subject", "audience", "cycles", "entries", "supersedes":
						v[field] = "container"
					default:
						v[field] = map[string]any{}
					}
				}
				if got, e := parseCertificateProjection(certificateTestBytes(t, v)); got != nil || !errors.Is(e, errBadSchema) {
					t.Fatal("closed outer", e)
				}
				good()
			})
		}
	}
	for _, index := range []int{0, 1} {
		for _, field := range []string{"entry_id", "action", "target", "uses"} {
			for _, mode := range []string{"missing", "integer", "wrong-container"} {
				t.Run(fmt.Sprint(index)+"/"+field+"/"+mode, func(t *testing.T) {
					good()
					v := certificateTestObject(t)
					entry := certificateEntry(v, index)
					switch mode {
					case "missing":
						delete(entry, field)
					case "integer":
						entry[field] = 1
					case "wrong-container":
						if field == "target" || field == "uses" {
							entry[field] = "container"
						} else {
							entry[field] = map[string]any{}
						}
					}
					if got, e := parseCertificateProjection(certificateTestBytes(t, v)); got != nil || !errors.Is(e, errBadSchema) {
						t.Fatal("closed entry", e)
					}
					good()
				})
			}
		}
	}
	v := certificateTestObject(t)
	v["extra"] = true
	if got, e := parseCertificateProjection(certificateTestBytes(t, v)); got != nil || !errors.Is(e, errBadSchema) {
		t.Fatal("extra", e)
	}
	good()
	for _, bad := range [][]byte{nil, []byte(`null`), append(certificateOriginalBytes(t), '\n')} {
		if got, e := parseCertificateProjection(bad); got != nil || !errors.Is(e, errBadEncoding) {
			t.Fatal("encoding", e)
		}
		good()
	}
	if got, e := parseCertificateProjection(bytes.Repeat([]byte{'x'}, 65537)); got != nil || !errors.Is(e, errInputLimit) {
		t.Fatal("payload65537", e)
	}
	good()
}

// Schedule structure resolves exact IDs, rejects duplicate/orphan references,
// and requires a same-resource same-cycle CREATE for every DELETE use. This
// proves no actual provider result, allowance reservation or lifecycle state.
func TestCertificateProjectionScheduleRefusals(t *testing.T) {
	cases := []struct {
		name   string
		change func(map[string]any)
		want   error
	}{
		{"empty cycles", func(v map[string]any) { v["cycles"] = []any{} }, errBadSchema},
		{"empty entries", func(v map[string]any) { v["entries"] = []any{} }, errBadSchema},
		{"empty uses", func(v map[string]any) { certificateEntry(v, 0)["uses"] = []any{} }, errBadSchema},
		{"duplicate cycle", func(v map[string]any) {
			c := v["cycles"].([]any)
			c[1].(map[string]any)["cycle_id"] = c[0].(map[string]any)["cycle_id"]
		}, errBadSchema},
		{"duplicate entry", func(v map[string]any) { certificateEntry(v, 1)["entry_id"] = "repo-create" }, errBadSchema},
		{"duplicate use ID", func(v map[string]any) {
			e := certificateEntry(v, 0)
			certificateUse(e, 1)["operation_use_id"] = certificateUse(e, 0)["operation_use_id"]
		}, errBadSchema},
		{"unknown cycle", func(v map[string]any) { certificateUse(certificateEntry(v, 0), 0)["cycle_id"] = "unknown" }, errBadSchema},
		{"orphan cycle", func(v map[string]any) {
			v["cycles"] = append(v["cycles"].([]any), map[string]any{"cycle_id": "orphan", "runtime": "codex", "channel": "encrypted-dm"})
		}, errBadSchema},
		{"duplicate entry cycle", func(v map[string]any) {
			e := certificateEntry(v, 0)
			e["uses"] = append(e["uses"].([]any), map[string]any{"cycle_id": "claude-dm", "operation_use_id": "different"})
		}, errBadSchema},
		{"unknown paired entry", func(v map[string]any) {
			certificateEntry(v, 1)["target"].(map[string]any)["paired_create_entry"] = "unknown"
		}, errBadSchema},
		{"paired delete entry", func(v map[string]any) {
			certificateEntry(v, 1)["target"].(map[string]any)["paired_create_entry"] = "repo-delete"
		}, errBadSchema},
		{"different organization", func(v map[string]any) { certificateEntry(v, 1)["target"].(map[string]any)["organization"] = "other" }, errBadSchema},
		{"different name", func(v map[string]any) { certificateEntry(v, 1)["target"].(map[string]any)["name"] = "other" }, errBadSchema},
		{"missing same-cycle create", func(v map[string]any) { e := certificateEntry(v, 0); e["uses"] = e["uses"].([]any)[1:] }, errBadSchema},
		{"duplicate predecessor", func(v map[string]any) { v["supersedes"] = []any{"old", "old"} }, errBadLifecycleReference},
		{"self predecessor", func(v map[string]any) { v["supersedes"] = []any{v["certificate_id"]} }, errBadLifecycleReference},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, e := parseCertificateProjection(certificateOriginalBytes(t)); e != nil || got == nil {
				t.Fatal("valid before", e)
			}
			v := certificateTestObject(t)
			c.change(v)
			if got, e := parseCertificateProjection(certificateTestBytes(t, v)); got != nil || !errors.Is(e, c.want) {
				t.Fatal("specific refusal", e)
			}
			if got, e := parseCertificateProjection(certificateOriginalBytes(t)); e != nil || got == nil {
				t.Fatal("valid after", e)
			}
		})
	}
}

// Count maxima compose with canonical byte/token bounds. The generated valid
// schedule reaches16 cycles/entries/uses-per-entry and256 total uses; it does
// not enlarge rights or prove a live deployment. Interval checks read no clock.
func TestCertificateProjectionLimitsAndInterval(t *testing.T) {
	v := certificateTestObject(t)
	cycles := []any{}
	entries := []any{}
	for i := 0; i < 16; i++ {
		cycles = append(cycles, map[string]any{"cycle_id": fmt.Sprint("c", i), "runtime": "codex", "channel": "encrypted-dm"})
	}
	for i := 0; i < 16; i++ {
		uses := []any{}
		for j := 0; j < 16; j++ {
			uses = append(uses, map[string]any{"cycle_id": fmt.Sprint("c", j), "operation_use_id": fmt.Sprint("u", j)})
		}
		entries = append(entries, map[string]any{"entry_id": fmt.Sprint("e", i), "action": "repository.create", "target": map[string]any{"organization": "O", "name": "N", "visibility": "private"}, "uses": uses})
	}
	v["cycles"] = cycles
	v["entries"] = entries
	pred := []any{}
	for i := 0; i < 16; i++ {
		pred = append(pred, fmt.Sprint("old", i))
	}
	v["supersedes"] = pred
	positive := certificateTestBytes(t, v)
	got, e := parseCertificateProjection(positive)
	if e != nil || got == nil || len(got.entries) != 16 || len(got.cycles) != 16 || len(got.supersedes) != 16 {
		t.Fatal("joint maximum", e)
	}
	total := 0
	for _, entry := range got.entries {
		total += len(entry.uses)
	}
	if total != 256 {
		t.Fatal("total uses", total)
	}
	for _, field := range []string{"cycles", "entries", "supersedes", "uses"} {
		t.Run(field+"17", func(t *testing.T) {
			var bad map[string]any
			if e := json.Unmarshal(positive, &bad); e != nil {
				t.Fatal(e)
			}
			if field == "uses" {
				entry := certificateEntry(bad, 0)
				values := entry["uses"].([]any)
				entry["uses"] = append(values, values[0])
			} else {
				values := bad[field].([]any)
				bad[field] = append(values, values[0])
			}
			if got, e := parseCertificateProjection(certificateTestBytes(t, bad)); got != nil || !errors.Is(e, errInputLimit) {
				t.Fatal("count limit", e)
			}
			if got, e := parseCertificateProjection(positive); got == nil || e != nil {
				t.Fatal("max neighbor", e)
			}
		})
	}
	for _, c := range []struct {
		begin, end string
		want       error
	}{
		{"2024-02-29T12:00:00Z", "2034-02-28T12:00:00Z", nil},
		{"2024-02-29T12:00:00Z", "2034-02-28T12:00:01Z", ErrLifetimeExceeded},
		{"2024-02-29T12:00:00Z", "2024-02-29T12:00:00Z", ErrInvalidInterval},
		{"2024-02-29T12:00:00Z", "2024-02-28T12:00:00Z", ErrInvalidInterval},
		{"9990-01-01T00:00:00Z", "9990-01-02T00:00:00Z", ErrLifetimeExceeded},
	} {
		v := certificateTestObject(t)
		v["not_before"] = c.begin
		v["expires_at"] = c.end
		got, e := parseCertificateProjection(certificateTestBytes(t, v))
		if c.want == nil {
			if e != nil || got == nil {
				t.Fatal("valid interval", e)
			}
		} else if got != nil || !errors.Is(e, c.want) {
			t.Fatal("interval refusal", e)
		}
	}
}

// Recursive container element types, entry/action target variants and nested
// extras are refused through the actual certificate path, with valid neighbors.
func TestCertificateProjectionNestedVariants(t *testing.T) {
	good := func() {
		t.Helper()
		if got, e := parseCertificateProjection(certificateOriginalBytes(t)); got == nil || e != nil {
			t.Fatal("valid neighbor", e)
		}
	}
	for _, array := range []string{"cycles", "entries", "supersedes", "uses"} {
		invalid := []any{true, 1, []any{}, map[string]any{}}
		if array != "supersedes" {
			invalid = append(invalid, "scalar")
		} else {
			invalid = append(invalid, "")
		}
		for i, bad := range invalid {
			t.Run(array+fmt.Sprint(i), func(t *testing.T) {
				good()
				v := certificateTestObject(t)
				if array == "uses" {
					certificateEntry(v, 0)["uses"] = []any{bad}
				} else if array == "supersedes" {
					v[array] = []any{bad}
				} else {
					values := v[array].([]any)
					values[0] = bad
				}
				if got, e := parseCertificateProjection(certificateTestBytes(t, v)); got != nil || !errors.Is(e, errBadSchema) {
					t.Fatal("element schema", e)
				}
				good()
			})
		}
	}
	for _, place := range []string{"cycle", "entry", "use", "target"} {
		good()
		v := certificateTestObject(t)
		var n map[string]any
		switch place {
		case "cycle":
			n = v["cycles"].([]any)[0].(map[string]any)
		case "entry":
			n = certificateEntry(v, 0)
		case "use":
			n = certificateUse(certificateEntry(v, 0), 0)
		case "target":
			n = certificateEntry(v, 0)["target"].(map[string]any)
		}
		n["extra"] = true
		if got, e := parseCertificateProjection(certificateTestBytes(t, v)); got != nil || !errors.Is(e, errBadSchema) {
			t.Fatal("nested extra", place, e)
		}
		good()
	}
	for i := 0; i < 2; i++ {
		good()
		v := certificateTestObject(t)
		certificateEntry(v, i)["action"] = "repository.update"
		if got, e := parseCertificateProjection(certificateTestBytes(t, v)); got != nil || !errors.Is(e, errBadSchema) {
			t.Fatal("entry action", e)
		}
		good()
		v = certificateTestObject(t)
		certificateEntry(v, i)["target"] = certificateEntry(v, 1-i)["target"]
		if got, e := parseCertificateProjection(certificateTestBytes(t, v)); got != nil || !errors.Is(e, errBadSchema) {
			t.Fatal("cross target", e)
		}
		good()
	}
	for field, bad := range map[string]string{"type": "grants-request-1", "certificate_id": "bad id", "not_before": "2026-02-30T00:00:00Z", "expires_at": "2026-11-01T00:00:00+00:00"} {
		good()
		v := certificateTestObject(t)
		v[field] = bad
		if got, e := parseCertificateProjection(certificateTestBytes(t, v)); got != nil || !errors.Is(e, errBadSchema) {
			t.Fatal("outer scalar", field, e)
		}
		good()
	}
	v := certificateTestObject(t)
	v["certificate_id"] = "A" + string(bytes.Repeat([]byte{'a'}, 127))
	if got, e := parseCertificateProjection(certificateTestBytes(t, v)); got == nil || e != nil {
		t.Fatal("certificate ID128", e)
	}
	v["certificate_id"] = "A" + string(bytes.Repeat([]byte{'a'}, 128))
	if got, e := parseCertificateProjection(certificateTestBytes(t, v)); got != nil || !errors.Is(e, errInputLimit) {
		t.Fatal("certificate ID129", e)
	}
	good()
}

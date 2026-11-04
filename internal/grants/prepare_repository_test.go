package grants

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Public generator points are fixtures only; preparation needs no private key.
func preparationPublic(t *testing.T, curve elliptic.Curve) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: curve, X: curve.Params().Gx, Y: curve.Params().Gy})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func preparationDraft(t *testing.T) map[string]any {
	t.Helper()
	certificate := certificateTestObject(t)
	target := certificateEntry(certificate, 0)["target"].(map[string]any)
	return map[string]any{
		"audience": certificate["audience"], "certificate_id": certificate["certificate_id"],
		"cycles": certificate["cycles"], "expires_at": certificate["expires_at"],
		"name": target["name"], "not_before": certificate["not_before"],
		"organization": target["organization"], "subject": certificate["subject"],
	}
}

// Authoring reconstructs the independently retained R2 fixture exactly except
// for its explicit public pin. One selected cycle is not expanded to four; cycle
// order, review fields and domain bytes are all checked independently.
func TestPrepareRepositoryCertificateExact(t *testing.T) {
	spki := preparationPublic(t, elliptic.P256())
	for _, mode := range []string{"four", "one", "reordered"} {
		t.Run(mode, func(t *testing.T) {
			want := certificateTestObject(t)
			draft := preparationDraft(t)
			if mode == "one" {
				draft["cycles"] = draft["cycles"].([]any)[2:3]
				want["cycles"] = want["cycles"].([]any)[2:3]
				for _, entry := range want["entries"].([]any) {
					e := entry.(map[string]any)
					e["uses"] = e["uses"].([]any)[2:3]
				}
			}
			if mode == "reordered" {
				for _, object := range []map[string]any{draft, want} {
					cycles := object["cycles"].([]any)
					cycles[0], cycles[3] = cycles[3], cycles[0]
				}
				for _, entry := range want["entries"].([]any) {
					uses := entry.(map[string]any)["uses"].([]any)
					uses[0], uses[3] = uses[3], uses[0]
				}
			}
			pin := sha256.Sum256(spki)
			want["issuer"].(map[string]any)["key_id"] = "sha256:" + hex.EncodeToString(pin[:])
			raw := certificateTestBytes(t, draft)
			before, keyBefore := bytes.Clone(raw), bytes.Clone(spki)
			got, err := PrepareRepositoryCertificate(raw, "@owner:example.invalid", spki)
			if err != nil || got == nil || !bytes.Equal(got.Payload, certificateTestBytes(t, want)) {
				t.Fatalf("exact unsigned certificate: %v", err)
			}
			digest := sha256.Sum256(append([]byte("swarma-grants/certificate/1\n"), got.Payload...))
			if got.Digest != digest || bytes.HasSuffix(got.Payload, []byte{'\n'}) {
				t.Fatal("wrong exact domain digest/payload suffix")
			}
			parts := strings.SplitN(got.Review, "\n", 4)
			if len(parts) != 4 || parts[0] != "UNSIGNED certificate; no rights are active." || parts[1] != "Domain: swarma-grants/certificate/1" || !strings.HasSuffix(parts[2], hex.EncodeToString(digest[:])) {
				t.Fatal("review status/domain/digest")
			}
			var compact bytes.Buffer
			if err := json.Compact(&compact, []byte(parts[3])); err != nil || !bytes.Equal(compact.Bytes(), got.Payload) {
				t.Fatal("review omits or substitutes signed fields", err)
			}
			if !bytes.Equal(raw, before) || !bytes.Equal(spki, keyBefore) {
				t.Fatal("preparation changed its inputs")
			}
		})
	}
}

// The authoring boundary preserves the accepted printable-ASCII representation
// (including literal HTML punctuation) and ordinary string maxima. It does not
// claim that these strings are admitted provider repository names.
func TestPrepareRepositoryCertificateText(t *testing.T) {
	for _, name := range []string{"a<&>b", strings.Repeat("a", 1024)} {
		draft := preparationDraft(t)
		draft["name"] = name
		var input bytes.Buffer
		encoder := json.NewEncoder(&input)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(draft); err != nil {
			t.Fatal(err)
		}
		got, err := PrepareRepositoryCertificate(bytes.TrimSuffix(input.Bytes(), []byte{'\n'}), "@owner:example.invalid", preparationPublic(t, elliptic.P256()))
		if err != nil || got == nil || !bytes.Contains(got.Payload, []byte(`"name":"`+name+`"`)) {
			t.Fatal("valid exact text was escaped or rejected", err)
		}
	}
}

// Invalid draft/schema/schedule/pin inputs return the specific refusal and no
// partial preparation. Every case is paired with a complete valid draft; these
// are authoring tests, never issuer enrollment or live signing evidence.
func TestPrepareRepositoryCertificateRefusals(t *testing.T) {
	spki := preparationPublic(t, elliptic.P256())
	for _, c := range []struct {
		name string
		edit func(map[string]any)
		want error
	}{
		{"missing-time", func(v map[string]any) { delete(v, "expires_at") }, errBadSchema},
		{"issuer-override", func(v map[string]any) { v["issuer"] = map[string]any{} }, errBadSchema},
		{"signature-placeholder", func(v map[string]any) { v["signature"] = "" }, errBadSchema},
		{"entry-override", func(v map[string]any) { v["entries"] = []any{} }, errBadSchema},
		{"empty-target", func(v map[string]any) { v["name"] = "" }, errBadSchema},
		{"bad-subject", func(v map[string]any) { v["subject"].(map[string]any)["device_id"] = true }, errBadSchema},
		{"empty-cycles", func(v map[string]any) { v["cycles"] = []any{} }, errBadSchema},
		{"duplicate-cycle", func(v map[string]any) { a := v["cycles"].([]any); a[1] = a[0] }, errBadSchema},
		{"unknown-runtime", func(v map[string]any) { v["cycles"].([]any)[0].(map[string]any)["runtime"] = "shell" }, errBadSchema},
		{"generated-use-overflow", func(v map[string]any) { v["cycles"].([]any)[0].(map[string]any)["cycle_id"] = strings.Repeat("c", 128) }, errInputLimit},
		{"cycle-overflow", func(v map[string]any) {
			cycles := make([]any, 17)
			for i := range cycles {
				cycles[i] = v["cycles"].([]any)[0]
			}
			v["cycles"] = cycles
		}, errInputLimit},
		{"time-alias", func(v map[string]any) { v["not_before"] = "2026-11-02T00:00:00+00:00" }, errBadSchema},
		{"invalid-interval", func(v map[string]any) { v["expires_at"] = v["not_before"] }, ErrInvalidInterval},
		{"lifetime-expansion", func(v map[string]any) { v["expires_at"] = "2046-01-01T00:00:00Z" }, ErrLifetimeExceeded},
	} {
		t.Run(c.name, func(t *testing.T) {
			good := certificateTestBytes(t, preparationDraft(t))
			if got, err := PrepareRepositoryCertificate(good, "@owner:example.invalid", spki); err != nil || got == nil {
				t.Fatal("valid neighbor", err)
			}
			draft := preparationDraft(t)
			c.edit(draft)
			if got, err := PrepareRepositoryCertificate(certificateTestBytes(t, draft), "@owner:example.invalid", spki); got != nil || !errors.Is(err, c.want) {
				t.Fatalf("got %#v %v, want %v", got, err, c.want)
			}
		})
	}
	good := certificateTestBytes(t, preparationDraft(t))
	for _, c := range []struct {
		name  string
		draft []byte
		owner string
		spki  []byte
		want  error
	}{
		{"duplicate-key", bytes.Replace(good, []byte(`"certificate_id":`), []byte(`"certificate_id":"x","certificate_id":`), 1), "@owner:example.invalid", spki, errBadEncoding},
		{"trailing-newline", append(bytes.Clone(good), '\n'), "@owner:example.invalid", spki, errBadEncoding},
		{"oversize-draft", bytes.Repeat([]byte{'x'}, 65537), "@owner:example.invalid", spki, errInputLimit},
		{"empty-owner", good, "", spki, errBadSchema},
		{"bad-pin", good, "@owner:example.invalid", []byte("not DER"), errIssuerUntrusted},
		{"wrong-curve", good, "@owner:example.invalid", preparationPublic(t, elliptic.P384()), errIssuerUntrusted},
		{"oversize-pin", good, "@owner:example.invalid", bytes.Repeat([]byte{1}, 1025), errIssuerUntrusted},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got, err := PrepareRepositoryCertificate(c.draft, c.owner, c.spki); got != nil || !errors.Is(err, c.want) {
				t.Fatalf("got %#v %v, want %v", got, err, c.want)
			}
		})
	}
}

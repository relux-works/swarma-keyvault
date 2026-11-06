package grants

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The two a2a framed-text request posts in testdata were produced by the a2a
// sender's actual-post test (synthetic users), with the HTML rendering it adds:
// format "org.matrix.custom.html" and formatted_body. The body carries an inert
// envelope; these posts test wrapper admission only, not a signature.
var a2aHTMLCaptures = []struct {
	file, sha256 string
	reply        bool
}{
	{"a2a-post-html-no-re.json", "41643bc1123d7e297e7a5a49675416b7d759436d4ba9f5d38fc9bf035ab9de7e", false},
	{"a2a-post-html-explicit-re.json", "73b69d8f4c29e0014df9b4024e71d27038111d6b024cba97b813f5ae69b1a97f", true},
}

func a2aHTMLCaptureContext() A2AObservationContext {
	return A2AObservationContext{Audience: "@alice:test.local", Topic: "alpha", ThreadRoot: "$ev001", DeclaredFrom: "bob", DeclaredTo: "alice"}
}

// Claim: both captured posts are admitted as they are, and extraction yields
// exactly the body's envelope bytes, never the HTML. Removing the pair still
// admits the same bytes (positive control for the 5-key form). Limit: the
// inert envelope is extracted, not verified.
func TestA2ACapturedHTMLPostsAdmitted(t *testing.T) {
	for _, c := range a2aHTMLCaptures {
		raw, err := os.ReadFile(filepath.Join("testdata", c.file))
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != c.sha256 {
			t.Fatal("captured post drifted", c.file)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		want := []byte(strings.SplitN(m["body"].(string), "\n\n", 2)[1])
		got, err := parseA2AWrapper(raw, a2aHTMLCaptureContext())
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("captured post refused or envelope changed", c.file, err)
		}
		delete(m, "format")
		delete(m, "formatted_body")
		plain, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := parseA2AWrapper(plain, a2aHTMLCaptureContext()); err != nil || !bytes.Equal(got, want) {
			t.Fatal("5-key form of the captured post refused", c.file, err)
		}
	}
}

// Claim: on the captured posts, a null formatted_body, an oversize
// formatted_body (the whole wrapper over the 65536-byte bound), a literally
// duplicated format key and a duplicate spelled with a JSON escape all refuse
// with ErrA2AContext. Each starts from a post that
// TestA2ACapturedHTMLPostsAdmitted admits.
func TestA2ACapturedHTMLPostsRefusals(t *testing.T) {
	for _, c := range a2aHTMLCaptures {
		raw, err := os.ReadFile(filepath.Join("testdata", c.file))
		if err != nil {
			t.Fatal(err)
		}
		const formatPair = `"format":"org.matrix.custom.html"`
		if !bytes.Contains(raw, []byte(formatPair)) {
			t.Fatal("captured post lacks the exact format member", c.file)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		null := map[string]any{}
		for k, v := range m {
			null[k] = v
		}
		null["formatted_body"] = nil
		nullRaw, _ := json.Marshal(null)
		big := map[string]any{}
		for k, v := range m {
			big[k] = v
		}
		big["formatted_body"] = strings.Repeat("x", 65536)
		bigRaw, _ := json.Marshal(big)
		cases := map[string][]byte{
			"null-formatted-body":    nullRaw,
			"oversize-wrapper":       bigRaw,
			"duplicate-format":       bytes.Replace(raw, []byte(formatPair), []byte(formatPair+","+formatPair), 1),
			"escaped-duplicate-name": bytes.Replace(raw, []byte(formatPair), []byte(formatPair+`,"form\u0061t":"org.matrix.custom.html"`), 1),
		}
		// The escaped spelling must really carry the JSON escape, so that a
		// check comparing raw key bytes instead of decoded names cannot pass.
		if escaped := cases["escaped-duplicate-name"]; !bytes.Contains(escaped, []byte(`"form\u0061t"`)) || bytes.Equal(escaped, cases["duplicate-format"]) {
			t.Fatal("escaped duplicate case is not escaped", c.file)
		}
		for name, bad := range cases {
			if bytes.Equal(bad, raw) {
				t.Fatal("refusal case did not change the post", name)
			}
			if _, err := parseA2AWrapper(bad, a2aHTMLCaptureContext()); !errors.Is(err, ErrA2AContext) {
				t.Error("refusal case admitted or refused for another reason", c.file, name, err)
			}
		}
	}
}

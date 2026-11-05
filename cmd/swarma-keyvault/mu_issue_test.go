package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

type muIssueFixture struct {
	t                 *testing.T
	owner, agent      *ecdsa.PrivateKey
	root, agentID     string
	ownerPin, subject string
	store             *cliIssueStore
	capture           func([]byte) string
	unboundPrompt     bool
}

// newMUIssueFixture installs a software stand-in for the owner root behind a
// fake manager; no vault, helper or Touch ID is touched.
func newMUIssueFixture(t *testing.T, mutate func(*keyvault.Record)) *muIssueFixture {
	t.Helper()
	f := &muIssueFixture{t: t}
	f.owner, f.root = muCLIKey(t)
	f.agent, f.agentID = muCLIKey(t)
	ownerDER := muSPKI(t, f.owner)
	f.ownerPin, f.subject = muCLIWrite(t, "owner.der", ownerDER), muCLIWrite(t, "agent.der", muSPKI(t, f.agent))
	rec := keyvault.Record{Schema: keyvault.SchemaVersion, Kind: keyvault.KindKey, Service: "alexis", Purpose: "grants-owner-v1", Version: 1,
		Algorithm: keyvault.AlgorithmECP256, Store: keyvault.StoreEnclave, UserPresence: true, Extraction: keyvault.ExtractionNone,
		Usages: []string{"sign", "verify"}, Format: keyvault.Format{Public: keyvault.FormatPublicSPKIDER, Signature: keyvault.FormatSignatureDERLowS},
		Created: keyvault.NewTime(time.Unix(1700000000, 0)), Origin: keyvault.Origin{User: "fixture", Host: "fixture", Tool: "fixture", Source: keyvault.SourceGenerated}, Meta: map[string]any{}}
	if mutate != nil {
		mutate(&rec)
	}
	tag, err := keyvault.EncodeRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	f.store = &cliIssueStore{key: f.owner, item: keyvault.Item{Label: rec.Label(), Tag: tag, SPKI: ownerDER}}
	previous := newIssueManager
	t.Cleanup(func() { newIssueManager = previous })
	newIssueManager = func(prompt func([]byte) string) *keyvault.Manager {
		f.store.factories++
		other := sha256.Sum256([]byte("another record"))
		if prompt(other[:]) != "" {
			f.unboundPrompt = true
		}
		f.capture = prompt
		return keyvault.NewManager(f.store, nil, keyvault.Origin{})
	}
	return f
}

func (f *muIssueFixture) run(kind string, spec map[string]any, subject bool) (int, string, string) {
	args := []string{"grants", "mu-issue", "--kind", kind, "--spec", muCLIWrite(f.t, "spec.json", spec), "--owner-spki-der", f.ownerPin}
	if subject {
		args = append(args, "--subject-spki-der", f.subject)
	}
	return muCLIRun(args...)
}

// verifyWire parses an emitted envelope and checks its single author
// signature under the owner root.
func (f *muIssueFixture) verifyWire(kind, wire string) map[string]any {
	f.t.Helper()
	parsed, err := record.Parse([]byte(wire), mugrant.MaxEnvelopeBytes, 16)
	if err != nil {
		f.t.Fatal(err)
	}
	e := parsed.(map[string]any)
	sig := e["signatures"].([]any)[0].(map[string]any)
	raw64, err := record.DecodeBase64(sig["sig"].(string), 64)
	if err != nil {
		f.t.Fatal(err)
	}
	pre, err := record.SigningPreimage(kind, f.root, "author", e["body"].(map[string]any))
	if err != nil || record.VerifySignature(f.root, raw64, pre) != nil {
		f.t.Fatal("emitted record does not verify under the owner root", err)
	}
	return e
}

// Claim: for each kind, mu-issue builds the record first, constructs the
// manager once with a reason bound to the exact digest (another digest gets
// none), signs once with the pinned enclave presence owner key, writes the
// full rendering and the decision-154 reason before the signature, and emits
// a record that verifies under the root. Limit: a software fixture stands in
// for the Secure Enclave key; the real dialog is exercised only at the sitting.
func TestMUIssue(t *testing.T) {
	cases := []struct {
		kind, recordKind, reasonPrefix string
		subject                        bool
	}{
		{"grant", "grant/1", "до срока · @meta-keeper.keeper-sirius:gr.relux.works · ", false},
		{"mac-agent", "attestation/1", "ключ агента · @meta-keeper.keeper-sirius:gr.relux.works · поколение 1 · ", true},
		{"publisher", "attestation/1", "ключ отзыва грантов · ", true},
	}
	for _, c := range cases {
		t.Run(c.kind, func(t *testing.T) {
			f := newMUIssueFixture(t, nil)
			spec := muAttestSpec(c.kind, f.root)
			if c.kind == "grant" {
				spec = muGrantSpecMap(f.root, f.agentID)
			}
			code, wire, review := f.run(c.kind, spec, c.subject)
			if code != 0 || f.store.factories != 1 || f.store.signs != 1 || f.unboundPrompt {
				t.Fatal("issue", code, review, f.store.factories, f.store.signs, f.unboundPrompt)
			}
			e := f.verifyWire(c.recordKind, wire)
			i := strings.Index(review, "Touch ID reason: ")
			if i < 0 || !strings.Contains(review[:i], "content id: "+e["id"].(string)) {
				t.Fatal("rendering missing before the reason", review)
			}
			reason := strings.TrimSuffix(review[i+len("Touch ID reason: "):], "\n")
			if !strings.HasPrefix(reason, c.reasonPrefix) || !strings.Contains(reason, " MSK · ") || !strings.Contains(reason, " · SHA256 ") || utf8.RuneCountInString(reason) > mugrant.ReasonLimit {
				t.Fatal("reason", reason)
			}
			if bound := f.capture(digestOf(t, c.recordKind, f.root, e)); bound != reason {
				t.Fatal("manager prompt differs from the displayed reason", bound)
			}
		})
	}
}

func digestOf(t *testing.T, kind, key string, e map[string]any) []byte {
	t.Helper()
	pre, err := record.SigningPreimage(kind, key, "author", e["body"].(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(pre)
	return d[:]
}

type muFailWriter struct{}

func (muFailWriter) Write([]byte) (int, error) { return 0, errors.New("sink closed") }

// Claim: refusals happen at the right point. Before any manager exists: an
// issuer that is not the given owner root, a reason over the limit, a spec
// kind that differs from --kind, and flag misuse (exit 2). At the key gate,
// with no private call: a keychain-store key, a key without presence, an
// extractable key, an owner DER that differs from the resolved key, and a
// review sink that cannot take the full rendering. After the single private
// call: a denied signature and a signature by another key emit nothing. The
// valid control above signs exactly once.
func TestMUIssueRefusals(t *testing.T) {
	t.Run("issuer-not-root", func(t *testing.T) {
		f := newMUIssueFixture(t, nil)
		code, out, _ := f.run("mac-agent", muAttestSpec("mac-agent", f.agentIDOther(t)), true)
		if code != 1 || out != "" || f.store.factories != 0 {
			t.Fatal(code, f.store.factories)
		}
	})
	t.Run("reason-overflow", func(t *testing.T) {
		f := newMUIssueFixture(t, nil)
		spec := muAttestSpec("mac-agent", f.root)
		spec["mxid"] = "@" + strings.Repeat("a", 180) + ":gr.relux.works"
		if code, out, _ := f.run("mac-agent", spec, true); code != 1 || out != "" || f.store.factories != 0 {
			t.Fatal(code, f.store.factories)
		}
	})
	t.Run("kind-differs", func(t *testing.T) {
		f := newMUIssueFixture(t, nil)
		if code, out, _ := f.run("publisher", muAttestSpec("mac-agent", f.root), true); code != 1 || out != "" || f.store.factories != 0 {
			t.Fatal(code, f.store.factories)
		}
	})
	t.Run("flag-misuse", func(t *testing.T) {
		f := newMUIssueFixture(t, nil)
		grant := muGrantSpecMap(f.root, f.agentID)
		for name, c := range map[string]func() (int, string, string){
			"grant-with-subject":     func() (int, string, string) { return f.run("grant", grant, true) },
			"attestation-no-subject": func() (int, string, string) { return f.run("publisher", muAttestSpec("publisher", f.root), false) },
			"unknown-kind":           func() (int, string, string) { return f.run("operator", grant, false) },
		} {
			if code, _, _ := c(); code != 2 {
				t.Error("usage not exit 2", name, code)
			}
		}
		if f.store.factories != 0 {
			t.Fatal("manager built on misuse")
		}
	})
	gate := map[string]func(*keyvault.Record){
		"keychain-store": func(r *keyvault.Record) { r.Store = keyvault.StoreKeychain; r.UserPresence = false },
		"no-presence":    func(r *keyvault.Record) { r.UserPresence = false },
		"extractable":    func(r *keyvault.Record) { r.Extraction = keyvault.ExtractionHuman },
	}
	for name, mutate := range gate {
		t.Run(name, func(t *testing.T) {
			f := newMUIssueFixture(t, mutate)
			if code, out, _ := f.run("grant", muGrantSpecMap(f.root, f.agentID), false); code != 1 || out != "" || f.store.signs != 0 {
				t.Fatal(code, f.store.signs)
			}
		})
	}
	t.Run("owner-der-differs", func(t *testing.T) {
		f := newMUIssueFixture(t, nil)
		other, otherID := muCLIKey(t)
		f.ownerPin = muCLIWrite(t, "other.der", muSPKI(t, other))
		if code, out, _ := f.run("grant", muGrantSpecMap(otherID, f.agentID), false); code != 1 || out != "" || f.store.signs != 0 {
			t.Fatal(code, f.store.signs)
		}
	})
	t.Run("short-review", func(t *testing.T) {
		f := newMUIssueFixture(t, nil)
		var out bytes.Buffer
		args := []string{"grants", "mu-issue", "--kind", "grant", "--spec", muCLIWrite(t, "spec.json", muGrantSpecMap(f.root, f.agentID)), "--owner-spki-der", f.ownerPin}
		if code := run(args, strings.NewReader(""), &out, muFailWriter{}); code != 1 || out.Len() != 0 || f.store.signs != 0 {
			t.Fatal(code, f.store.signs)
		}
	})
	t.Run("denied", func(t *testing.T) {
		f := newMUIssueFixture(t, nil)
		f.store.deny = true
		if code, out, _ := f.run("grant", muGrantSpecMap(f.root, f.agentID), false); code != 1 || out != "" || f.store.signs != 1 {
			t.Fatal(code, f.store.signs)
		}
	})
	t.Run("foreign-signature", func(t *testing.T) {
		f := newMUIssueFixture(t, nil)
		f.store.key = f.agent
		if code, out, _ := f.run("grant", muGrantSpecMap(f.root, f.agentID), false); code != 1 || out != "" || f.store.signs != 1 {
			t.Fatal(code, f.store.signs)
		}
	})
}

func (f *muIssueFixture) agentIDOther(t *testing.T) string {
	_, id := muCLIKey(t)
	return id
}

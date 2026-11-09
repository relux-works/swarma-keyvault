package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

type nostrCLIStore struct {
	records   []keyvault.NostrRecord
	calls     []string
	signError error
	wrongKey  bool
}

func nostrCLIPrivate(n byte) *btcec.PrivateKey {
	var scalar btcec.ModNScalar
	scalar.SetInt(uint32(n))
	defer scalar.Zero()
	return btcec.PrivKeyFromScalar(&scalar)
}
func (f *nostrCLIStore) Create(r keyvault.NostrRecord) (keyvault.NostrRecord, error) {
	f.calls = append(f.calls, "create")
	p := nostrCLIPrivate(3)
	defer p.Zero()
	pub := schnorr.SerializePubKey(p.PubKey())
	r.PublicKey = hex.EncodeToString(pub)
	r.NPub, _ = keyvault.NostrNPub(pub)
	f.records = append(f.records, r)
	return r, nil
}
func (f *nostrCLIStore) List() ([]keyvault.NostrRecord, error) {
	f.calls = append(f.calls, "list")
	return append([]keyvault.NostrRecord(nil), f.records...), nil
}
func (f *nostrCLIStore) Sign(_ keyvault.NostrRecord, digest []byte) ([]byte, error) {
	f.calls = append(f.calls, "sign")
	if f.signError != nil {
		return nil, f.signError
	}
	n := byte(3)
	if f.wrongKey {
		n = 4
	}
	p := nostrCLIPrivate(n)
	defer p.Zero()
	sig, err := schnorr.Sign(p, digest, schnorr.CustomNonce([32]byte{}))
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}

func nostrCLITest(t *testing.T) (*nostrCLIStore, *int) {
	t.Helper()
	oldBackend, oldLock := newNostrBackend, lockPath
	f := &nostrCLIStore{}
	constructed := new(int)
	newNostrBackend = func() keyvault.NostrBackend { *constructed++; return f }
	path := filepath.Join(t.TempDir(), "nostr.lock")
	lockPath = func() (string, error) { return path, nil }
	t.Cleanup(func() { newNostrBackend = oldBackend; lockPath = oldLock })
	return f, constructed
}
func nostrCLIInvoke(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, err bytes.Buffer
	code := run(args, &out, &err)
	return code, out.String() + err.String()
}

// Generation and every public read return only public records; signing returns
// 64-byte Schnorr output; offline verification never constructs a vault backend.
func TestNostrCLIPublicAndSign(t *testing.T) {
	f, constructed := nostrCLITest(t)
	code, raw := nostrCLIInvoke(t, "--json", "nostr", "generate", "--service", "test", "--purpose", "nostr")
	if code != 0 {
		t.Fatalf("generate: %s", raw)
	}
	var generated struct {
		OK     bool                 `json:"ok"`
		Result keyvault.NostrRecord `json:"result"`
	}
	if json.Unmarshal([]byte(raw), &generated) != nil || !generated.OK || generated.Result.PublicKey == "" || generated.Result.NPub == "" || generated.Result.Presence || generated.Result.PrivateExport {
		t.Fatal("invalid public result")
	}
	for _, args := range [][]string{{"list"}, {"describe", "test/nostr"}, {"pub", "test/nostr"}, {"pub", "test/nostr", "--format", "npub"}} {
		before := len(f.calls)
		code, output := nostrCLIInvoke(t, append([]string{"nostr"}, args...)...)
		if code != 0 || (!strings.Contains(output, generated.Result.PublicKey) && !strings.Contains(output, generated.Result.NPub)) {
			t.Fatal("public operation failed")
		}
		if strings.Contains(strings.Join(f.calls[before:], ","), "sign") {
			t.Fatal("public read used private signing")
		}
	}
	digest := strings.Repeat("00", 32)
	code, sigText := nostrCLIInvoke(t, "nostr", "sign", "test/nostr", "--digest", digest)
	if code != 0 || len(strings.TrimSpace(sigText)) != 128 {
		t.Fatal("invalid Schnorr signature output")
	}
	before := *constructed
	code, raw = nostrCLIInvoke(t, "--json", "nostr", "verify", "--pub", generated.Result.PublicKey, "--digest", digest, "--sig", strings.TrimSpace(sigText))
	if code != 0 || !strings.Contains(raw, "\"verified\": true") || *constructed != before {
		t.Fatal("offline verification touched custody or failed")
	}
	before = len(f.calls)
	code, _ = nostrCLIInvoke(t, "nostr", "generate", "--service", "test", "--purpose", "nostr")
	if code != 3 || strings.Contains(strings.Join(f.calls[before:], ","), "create") || len(f.records) != 1 {
		t.Fatal("duplicate generation reached write")
	}
	for _, output := range []string{raw, sigText} {
		if strings.Contains(output, "nsec1") || strings.Contains(output, "private_key") || strings.Contains(output, strings.Repeat("00", 31)+"03") {
			t.Fatal("private material in output")
		}
	}
}

// Unsupported import/export/seed formats and malformed inputs fail before even
// constructing a backend. Diagnostics do not repeat supplied secret-like data.
func TestNostrCLIRefusesBeforeCustody(t *testing.T) {
	_, constructed := nostrCLITest(t)
	for _, args := range [][]string{
		{"export", "private"}, {"import", "private"}, {"seed"}, {"pub", "test/nostr", "--format", "nsec"},
		{"pub", "test/nostr", "--format", "private"}, {"sign", "test/nostr", "--digest", "bad"},
		{"sign", "test/nostr", "--digest", strings.Repeat("00", 31)}, {"sign", "test/nostr", "--digest", strings.Repeat("00", 33)},
		{"sign", "test/nostr", "--digest", "@secret-file"}, {"sign", "test/nostr", "--stdin"}, {"sign", "test/nostr", "--data-file", "secret-file"},
		{"generate", "--service", "../foreign", "--purpose", "nostr"}, {"generate", "--service", "test", "--purpose", "nostr", "--enclave"},
		{"generate", "--service", "test", "--purpose", "nostr", "--user-presence"}, {"describe", "test/nostr", "--version", "0"},
		{"list", "unexpected-private-input"}, {"pub", "test/nostr", "--out", "secret-file"}, {"verify", "--pub", "bad", "--digest", strings.Repeat("00", 32), "--sig", "bad"},
	} {
		before := *constructed
		code, raw := nostrCLIInvoke(t, append([]string{"--json", "nostr"}, args...)...)
		if code != 2 || *constructed != before || !strings.Contains(raw, "\"ok\": false") {
			t.Fatalf("invalid operation reached custody or wrong exit: %s", args[0])
		}
		if strings.Contains(raw, "unexpected-private-input") || strings.Contains(raw, "@secret-file") {
			t.Fatal("diagnostic echoed sensitive input")
		}
	}
}

// Locked/untrusted native failures and a wrong-key backend produce no signature;
// refusing a signature never creates/replaces a key or selects another store.
func TestNostrCLIBackendRefusals(t *testing.T) {
	f, _ := nostrCLITest(t)
	code, _ := nostrCLIInvoke(t, "nostr", "generate", "--service", "test", "--purpose", "nostr")
	if code != 0 {
		t.Fatal("positive control failed")
	}
	for _, status := range []int{-25308, -25293, -67050} {
		f.signError = &keyvault.StatusError{Op: "nostr sign", Status: status}
		before := len(f.calls)
		code, raw := nostrCLIInvoke(t, "--json", "nostr", "sign", "test/nostr", "--digest", strings.Repeat("00", 32))
		if code == 0 || strings.Contains(raw, "\"signature\"") || strings.Contains(strings.Join(f.calls[before:], ","), "create") {
			t.Fatal("backend refusal leaked result or changed custody")
		}
	}
	f.signError = nil
	f.wrongKey = true
	code, raw := nostrCLIInvoke(t, "--json", "nostr", "sign", "test/nostr", "--digest", strings.Repeat("00", 32))
	if code != 3 || !strings.Contains(raw, "nostr_invalid_signature") || strings.Contains(raw, "\"signature\"") {
		t.Fatal("wrong-key signature escaped")
	}
}

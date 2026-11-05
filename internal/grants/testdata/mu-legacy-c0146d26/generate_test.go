package grants

// Copy this test into internal/grants at the historical revision; see README.md.
// It deliberately uses that revision's state writer, not a frame reimplementation.
import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateMULegacyC0146D26(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mu")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c := MUStateConfig{Directory: dir, Epoch: sha256.Sum256([]byte("mu-legacy-c0146d26-test-epoch"))}
	b := MUBinding{Audience: "synthetic-mu-legacy-receiver", GrantRoot: "p256:synthetic-legacy-root"}
	if err := InitializeMUState(c, b); err != nil {
		t.Fatal(err)
	}
	s, err := openMUState(context.Background(), c, b)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	for i, nonce := range []string{"synthetic-nonce-1", "synthetic-nonce-2"} {
		u := MUUse{Once: i == 0, GrantRoot: b.GrantRoot, GrantID: "synthetic-reserved-grant",
			Action: "work.assign", TargetKind: "product", TargetID: "synthetic-product",
			Requester: "p256:synthetic-requester", Nonce: nonce, Audience: b.Audience,
			RequestHash: sha256.Sum256([]byte("synthetic-request/" + nonce))}
		if _, err := s.reserve(u); err != nil {
			t.Fatal(err)
		}
	}
	// Separate calls produce two real kind-5 frames, one for each entry kind.
	for _, e := range []MURevocation{{"record", "synthetic-revoked-grant"}, {"key", "p256:synthetic-revoked-key"}} {
		if err := s.absorbRevocations([]MURevocation{e}); err != nil {
			t.Fatal(err)
		}
	}
	out := os.Getenv("MU_LEGACY_FIXTURE_OUT")
	if out == "" || !filepath.IsAbs(out) {
		t.Fatal("MU_LEGACY_FIXTURE_OUT must name an absolute output directory")
	}
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mu.journal", "mu.lock"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

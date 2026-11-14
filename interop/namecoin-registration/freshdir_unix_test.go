//go:build darwin || linux

package registration_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/namecoinfiles"
)

// Fixtures staged by freshDir are admitted by the strict public reader
// even when a shared sticky/writable temp root (the hosted-runner /tmp
// shape) is present, while an equivalent file under that shared root and
// a symlinked-directory alias into the private root are still refused.
// The helper changes fixture placement only, never reader policy.
func TestFreshDirUsesAdmittedAncestry(t *testing.T) {
	shared := filepath.Join(freshDir(t), "shared")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	legacy, err := os.MkdirTemp(shared, "legacy-")
	if err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(legacy, "fixture.json")
	write(t, legacyPath, []byte("public fixture"))
	if _, err := namecoinfiles.ReadInput(legacyPath, 64); !errors.Is(err, namecoinfiles.ErrUnsafe) {
		t.Fatalf("shared temp ancestry admitted: %v", err)
	}

	dir := freshDir(t)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("freshDir is not a private0700 directory: %v %v", info, err)
	}
	path := filepath.Join(dir, "fixture.json")
	write(t, path, []byte("public fixture"))
	raw, err := namecoinfiles.ReadInput(path, 64)
	if err != nil || !bytes.Equal(raw, []byte("public fixture")) {
		t.Fatalf("strict reader refused freshDir fixture: %v", err)
	}

	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(sub, "fixture.json")
	write(t, nested, []byte("public fixture"))
	if _, err := namecoinfiles.ReadInput(nested, 64); err != nil {
		t.Fatalf("strict reader refused nested freshDir fixture: %v", err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(sub, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := namecoinfiles.ReadInput(filepath.Join(alias, "fixture.json"), 64); !errors.Is(err, namecoinfiles.ErrUnsafe) {
		t.Fatalf("symlinked ancestry admitted: %v", err)
	}
}

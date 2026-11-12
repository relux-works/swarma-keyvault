//go:build darwin || linux

package rootqualification

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/codesignpolicy"
)

func artifactFixture(t *testing.T) (*ObservedCandidate, string) {
	t.Helper()
	files, dir := receiptFixture(t)
	o := &ObservedCandidate{files: files, candidate: candidateFixture()}
	for _, entry := range []struct {
		name string
		role codesignpolicy.Role
	}{{"mac-keyvault", codesignpolicy.Vault}, {"mac-keyvault-enclave", codesignpolicy.Helper}, {"public-foreign", codesignpolicy.Qualification}} {
		p := filepath.Join(dir, entry.name)
		if err := os.WriteFile(p, []byte("public fixture "+entry.name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0700); err != nil {
			t.Fatal(err)
		}
		if err := o.openArtifact(files.dirfd(), entry.name, p, entry.role); err != nil {
			t.Fatal(err)
		}
		i := len(o.artifacts) - 1
		h, err := o.hashArtifact(o.artifacts[i])
		if err != nil {
			t.Fatal(err)
		}
		a := Artifact{SHA256: h, CDHash: strings.Repeat(string(rune('0'+entry.role)), 40)}
		o.artifacts[i].pin = a
		switch entry.role {
		case codesignpolicy.Vault:
			o.candidate.Vault = a
		case codesignpolicy.Helper:
			o.candidate.Helper = a
		case codesignpolicy.Qualification:
			o.candidate.Foreign = a
		}
	}
	t.Cleanup(func() { _ = o.Close() })
	return o, dir
}

// Actual isolated descriptors/hashes admit the finite safe file forms and
// detect replacement/mutation. The fixture's CDHashes are synthetic: it does
// NOT run ObserveCandidate's certificate verifier or establish code trust.
func TestCandidateArtifactFilesystemBoundaries(t *testing.T) {
	for _, plant := range []string{"none", "same-content-replacement", "symlink", "changed-bytes", "mode", "hardlink"} {
		t.Run(plant, func(t *testing.T) {
			o, dir := artifactFixture(t)
			if _, err := o.Candidate(); err != nil {
				t.Fatal("valid file fixture refused")
			}
			if path, pin, err := o.Child(codesignpolicy.Helper); err != nil || path != filepath.Join(dir, "mac-keyvault-enclave") || pin != o.candidate.Helper.CDHash {
				t.Fatal("fixed child mapping lost")
			}
			if _, _, err := o.Child(codesignpolicy.Vault); !errors.Is(err, ErrReceipt) {
				t.Fatal("owning role selected as child")
			}
			path := filepath.Join(dir, "mac-keyvault")
			switch plant {
			case "same-content-replacement":
				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, b, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".original", path); err != nil {
					t.Fatal(err)
				}
			case "changed-bytes":
				if err := os.WriteFile(path, []byte("changed"), 0700); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(path, 0777); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".extra"); err != nil {
					t.Fatal(err)
				}
			}
			_, err := o.Candidate()
			if plant == "none" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrReceipt) {
				t.Fatal("changed artifact admitted")
			}
		})
	}
}

// Missing source/canceled context rejects before OS-home, process, signature
// or Keychain work. Captured code output has a real finite byte bound.
func TestCandidateInvalidEntryAndOutputBound(t *testing.T) {
	for _, pins := range [][2]string{{"unknown", strings.Repeat("a", 40)}, {strings.Repeat("A", 40), strings.Repeat("b", 40)}, {strings.Repeat("a", 40), ""}} {
		if _, err := ObserveCandidate(context.Background(), pins[0], pins[1]); !errors.Is(err, ErrReceipt) {
			t.Fatal("unbound source admitted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ObserveCandidate(ctx, strings.Repeat("a", 40), strings.Repeat("b", 40)); !errors.Is(err, ErrReceipt) {
		t.Fatal("canceled observation admitted")
	}
	var absent *ObservedCandidate
	if _, err := absent.Candidate(); !errors.Is(err, ErrReceipt) {
		t.Fatal("nil candidate admitted")
	}
	b := &codeOutput{limit: 4}
	if n, err := b.Write([]byte("abcd")); err != nil || n != 4 {
		t.Fatal("valid output refused")
	}
	if n, err := b.Write([]byte("e")); !errors.Is(err, ErrReceipt) || n != 0 || b.String() != "abcd" {
		t.Fatal("overflow modified/accepted code output")
	}
}

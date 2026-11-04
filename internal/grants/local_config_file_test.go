package grants

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Admission comes from a closed, private custodian file. Valid fixtures are
// accepted; malformed/extra fields, shared pins, relative paths and unsafe
// file types/permissions cannot turn caller JSON into a trust enrollment.
func TestLocalEnrollmentRefusals(t *testing.T) {
	for _, mode := range []string{"unknown", "same-key", "owner", "relative-state", "relative-gh", "target", "padded-pin", "newline", "duplicate", "permissions", "symlink", "fifo", "directory", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			f := localTestFixture(t)
			path := filepath.Join(t.TempDir(), "enrollment.json")
			good := requestTestBytes(t, f.config)
			if err := os.WriteFile(path, good, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadLocalEnrollment(path); err != nil {
				t.Fatal("valid neighbor", err)
			}
			var raw []byte
			switch mode {
			case "unknown":
				f.config["caller_pin"] = "x"
			case "same-key":
				f.config["requester_spki"] = f.config["owner_spki"]
			case "owner":
				f.config["owner_mxid"] = "@other:example.invalid"
			case "relative-state":
				f.config["state_dir"] = "relative"
			case "relative-gh":
				f.config["gh_path"] = "gh"
			case "target":
				f.config["name"] = "another-repository"
			case "padded-pin":
				f.config["owner_spki"] = f.config["owner_spki"].(string) + "="
			case "newline":
				raw = append(bytes.Clone(good), '\n')
			case "duplicate":
				raw = bytes.Replace(good, []byte(`{"audience":`), []byte(`{"audience":{},"audience":`), 1)
			case "oversize":
				raw = bytes.Repeat([]byte{'x'}, 8193)
			case "permissions":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				link := path + ".link"
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "fifo":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				path = t.TempDir()
			}
			if mode != "permissions" && mode != "symlink" && mode != "fifo" && mode != "directory" {
				if raw == nil {
					raw = requestTestBytes(t, f.config)
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if e, err := LoadLocalEnrollment(path); err == nil || e != nil {
				t.Fatal("unsafe enrollment accepted")
			}
		})
	}
}

// Invalid physical state cannot block on a FIFO, repair itself, or dispatch.
// Oversize is a sparse local fixture, not a real journal or private store.
func TestLocalStateFileTypesAndBudget(t *testing.T) {
	for _, mode := range []string{"journal-fifo", "lock-fifo", "journal-directory", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			_, m, p, c, q := localMediatorFixture(t)
			path := filepath.Join(m.enrollment.stateDir, "local.journal")
			if mode == "lock-fifo" {
				path = filepath.Join(m.enrollment.stateDir, "local.lock")
			}
			switch mode {
			case "journal-fifo", "lock-fifo":
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "journal-directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
				if err != nil {
					t.Fatal(err)
				}
				err = file.Truncate(journalScanMaxBytes + 1)
				closeErr := file.Close()
				if err != nil || closeErr != nil {
					t.Fatal(err, closeErr)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.Execute(context.Background(), c, q); !errors.Is(err, ErrLocalState) || p.calls != 0 {
				t.Fatal("unsafe state dispatched", err, p.calls)
			}
			after, err := os.Lstat(path)
			if err != nil || before.Mode() != after.Mode() || before.Size() != after.Size() {
				t.Fatal("refusal altered state", err)
			}
		})
	}
}

// A fully well-formed DELETE remains signed certificate data only. Neither the
// local requester signer nor mediator exposes a DELETE execution capability.
func TestLocalDeleteRefused(t *testing.T) {
	f, m, p, c, _ := localMediatorFixture(t)
	_, q := declaredMatchFixture("repository.delete", "codex-dm")
	q["target"].(map[string]any)["organization"] = LocalOrganization
	q["target"].(map[string]any)["name"] = LocalRepository
	f.request = q
	if _, err := PrepareLocalRequest(requestTestBytes(t, q), f.requesterDER); !errors.Is(err, errResourceMismatch) {
		t.Fatal("DELETE signing admitted", err)
	}
	_, signed := f.envelopes(t)
	if _, err := m.Execute(context.Background(), c, signed); !errors.Is(err, errResourceMismatch) || p.calls != 0 {
		t.Fatal("DELETE dispatch admitted", err, p.calls)
	}
	files, err := os.ReadDir(m.enrollment.stateDir)
	if err != nil || len(files) != 0 {
		t.Fatal("DELETE wrote state", err)
	}
}

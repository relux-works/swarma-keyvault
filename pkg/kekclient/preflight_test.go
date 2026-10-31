package kekclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func budgetDir(t *testing.T, n int, unicode bool) string {
	t.Helper()
	base := shortDir(t)
	prefix := ""
	if unicode {
		prefix = "é"
	}
	pad := n - len(base) - 1 - len(prefix)
	if pad < 1 {
		t.Fatalf("fixture base too long: %d", len(base))
	}
	dir := filepath.Join(base, prefix+strings.Repeat("x", pad))
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if len(dir) != n {
		t.Fatalf("fixture bytes=%d want%d", len(dir), n)
	}
	return dir
}

// A 103-byte socket can complete a synthetic exchange; the historical
// 104/107-byte cases must refuse before any broker child starts or file appears.
// The fake broker is this test executable and never touches a Keychain item.
func TestSocketBudgetExchangeAdmission(t *testing.T) {
	for _, tc := range []struct {
		name           string
		n              int
		unicode, valid bool
	}{
		{"direct72", 72, false, true}, {"boundary77", 77, false, true},
		{"first-over78", 78, false, false}, {"reported81", 81, false, false},
		{"utf8-valid77", 77, true, true}, {"utf8-over78", 78, true, false},
	} {
		for _, op := range []string{OpUnwrap, OpRebind} {
			t.Run(tc.name+"/"+op, func(t *testing.T) {
				sealed, env := testEnvelope(t)
				opts := fakeOptions(t, "echo-kek", "")
				opts.SocketDir = budgetDir(t, tc.n, tc.unicode)
				marker := filepath.Join(shortDir(t), "broker-started")
				t.Setenv(fakeStartedEnv, marker)
				if tc.valid {
					if op == OpUnwrap {
						got, err := Unwrap(context.Background(), opts, sealed)
						defer clear(got)
						if err != nil || !bytes.Equal(got, testKEK()) {
							t.Fatalf("valid unwrap control refused: %v", err)
						}
					} else {
						response, err := json.Marshal(Response{Contract: Contract, OK: true, Result: &Result{Address: env.Address, Generation: env.Generation, Fingerprint: env.Fingerprint, Envelope: sealed}})
						if err != nil {
							t.Fatal(err)
						}
						t.Setenv(fakeAnswerEnv, string(response))
						got, err := Rebind(context.Background(), opts, sealed)
						if err != nil || !bytes.Equal(got, sealed) {
							t.Fatalf("valid rebind control refused: %v", err)
						}
					}
					if _, err := os.Stat(marker); err != nil {
						t.Fatalf("valid control did not start fake broker: %v", err)
					}
				} else {
					if op == OpUnwrap {
						got, err := Unwrap(context.Background(), opts, sealed)
						defer clear(got)
						if err == nil || got != nil {
							t.Fatalf("overlong option accepted")
						}
					} else {
						got, err := Rebind(context.Background(), opts, sealed)
						if err == nil || got != nil {
							t.Fatalf("overlong rebind accepted")
						}
					}
					if pid, err := os.ReadFile(marker); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("broker started before overlong rejection: pid=%s err=%v", pid, err)
					}
				}
				entries, err := os.ReadDir(opts.SocketDir)
				if err != nil || len(entries) != 0 {
					t.Fatalf("socket directory changed: entries=%v error=%v", entries, err)
				}
			})
		}
	}
}

type countedNonce struct{ reads int }

func (r *countedNonce) Read(p []byte) (int, error) { r.reads++; clear(p); return len(p), nil }

// A local budget rejection must precede the nonce draw and cleanup registration.
// A pre-existing synthetic nonce-named file must survive this refused call.
func TestSocketBudgetRefusalPreservesNonceAndFile(t *testing.T) {
	sealed, _ := testEnvelope(t)
	opts := fakeOptions(t, "echo-kek", "")
	opts.SocketDir = budgetDir(t, 78, false)
	marker := filepath.Join(shortDir(t), "broker-started")
	t.Setenv(fakeStartedEnv, marker)
	path := filepath.Join(opts.SocketDir, "kek-0000000000000000.sock")
	original := []byte("synthetic fixture; preserve on rejection")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	saved := rand.Reader
	nonce := &countedNonce{}
	rand.Reader = nonce
	t.Cleanup(func() { rand.Reader = saved })
	got, err := Unwrap(context.Background(), opts, sealed)
	defer clear(got)
	if err == nil || got != nil {
		t.Fatal("expected local overlong option refusal")
	}
	if nonce.reads != 0 {
		t.Errorf("nonce drawn before budget rejection: %d", nonce.reads)
	}
	if actual, err := os.ReadFile(path); err != nil || !bytes.Equal(actual, original) {
		t.Errorf("refusal removed/changed existing fixture: %v", err)
	}
	if pid, err := os.ReadFile(marker); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("broker started before rejection: pid=%s err=%v", pid, err)
	}
	if n := len(path); n != 104 {
		t.Fatal(fmt.Sprintf("fixture socket bytes=%d", n))
	}
}

// Public preflight accepts the existing valid byte budgets and does not draw a
// nonce, start a child, write a socket or expose an overlong private path.
func TestPreflightSocketBudgetAndSideEffects(t *testing.T) {
	for _, tc := range []struct {
		name           string
		n              int
		unicode, valid bool
	}{
		{"direct72", 72, false, true}, {"boundary77", 77, false, true},
		{"first-over78", 78, false, false}, {"reported81", 81, false, false},
		{"utf8-valid77", 77, true, true}, {"utf8-over78", 78, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := fakeOptions(t, "echo-kek", "")
			opts.SocketDir = budgetDir(t, tc.n, tc.unicode)
			marker := filepath.Join(shortDir(t), "broker-started")
			t.Setenv(fakeStartedEnv, marker)
			saved := rand.Reader
			nonce := &countedNonce{}
			rand.Reader = nonce
			defer func() { rand.Reader = saved }()
			err := Preflight(opts)
			if tc.valid && err != nil {
				t.Fatalf("valid preflight refused: %v", err)
			}
			if !tc.valid && !errors.Is(err, ErrSocketPathTooLong) {
				t.Fatalf("wrong budget refusal: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), opts.SocketDir) {
				t.Fatal("budget error exposes private path")
			}
			if nonce.reads != 0 {
				t.Fatalf("preflight drew random nonce")
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("preflight started a child: %v", err)
			}
			if entries, err := os.ReadDir(opts.SocketDir); err != nil || len(entries) != 0 {
				t.Fatalf("preflight wrote state: %v %v", entries, err)
			}
		})
	}
}

// Existing unsafe directory and broker forms retain their intended refusals;
// a valid private directory remains accepted and is never repaired by preflight.
func TestPreflightUnsafeOptions(t *testing.T) {
	opts := fakeOptions(t, "echo-kek", "")
	if err := Preflight(opts); err != nil {
		t.Fatalf("valid control: %v", err)
	}
	open := shortDir(t)
	if err := os.Chmod(open, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(shortDir(t), "linked")
	if err := os.Symlink(opts.SocketDir, link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(shortDir(t), "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, dir, broker, want string }{
		{"relative broker", opts.SocketDir, "broker", "not absolute"},
		{"relative directory", "relative", opts.Broker, "not a clean absolute path"},
		{"unclean", opts.SocketDir + "/../" + filepath.Base(opts.SocketDir), opts.Broker, "not a clean absolute path"},
		{"missing", filepath.Join(opts.SocketDir, "missing"), opts.Broker, "no such file"},
		{"open", open, opts.Broker, "group or other permissions"},
		{"symlink", link, opts.Broker, "not a directory"},
		{"regular file", file, opts.Broker, "not a directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Preflight(Options{Broker: tc.broker, SocketDir: tc.dir})
			if err == nil || !strings.Contains(err.Error(), tc.want) || errors.Is(err, ErrSocketPathTooLong) {
				t.Fatalf("wrong unsafe-option refusal: %v", err)
			}
		})
	}
	if st, err := os.Lstat(open); err != nil || st.Mode().Perm() != 0755 {
		t.Fatal("preflight altered permissions")
	}
	if st, err := os.Lstat(link); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("preflight changed symlink")
	}
	if entries, err := os.ReadDir(opts.SocketDir); err != nil || len(entries) != 0 {
		t.Fatal("preflight changed valid directory")
	}
}

type socketDirInfo struct {
	mode os.FileMode
	stat any
}

func (s socketDirInfo) Name() string       { return "fixture" }
func (s socketDirInfo) Size() int64        { return 0 }
func (s socketDirInfo) Mode() os.FileMode  { return s.mode }
func (s socketDirInfo) ModTime() time.Time { return time.Time{} }
func (s socketDirInfo) IsDir() bool        { return s.mode.IsDir() }
func (s socketDirInfo) Sys() any           { return s.stat }

// Synthetic metadata exercises the real ownership predicate without chown,
// privilege changes or inspecting a foreign user's private directory.
func TestSocketDirectoryMetadataAdmission(t *testing.T) {
	for _, tc := range []struct {
		name string
		info socketDirInfo
		want string
	}{
		{"private owner", socketDirInfo{os.ModeDir | 0700, &syscall.Stat_t{Uid: 42}}, ""},
		{"private read-only existing form", socketDirInfo{os.ModeDir | 0500, &syscall.Stat_t{Uid: 42}}, ""},
		{"foreign owner", socketDirInfo{os.ModeDir | 0700, &syscall.Stat_t{Uid: 43}}, "not owned"},
		{"unknown owner", socketDirInfo{os.ModeDir | 0700, nil}, "not owned"},
		{"open", socketDirInfo{os.ModeDir | 0755, &syscall.Stat_t{Uid: 42}}, "group or other permissions"},
		{"file", socketDirInfo{0600, &syscall.Stat_t{Uid: 42}}, "not a directory"},
		{"symlink", socketDirInfo{os.ModeSymlink | 0700, &syscall.Stat_t{Uid: 42}}, "not a directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSocketDirMetadata("/fixture/data", tc.info, 42)
			if tc.want == "" && err != nil {
				t.Fatalf("valid metadata refused: %v", err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("wrong metadata refusal: %v", err)
			}
		})
	}
}

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) (settings, pinReader) {
	t.Helper()
	root := t.TempDir()
	s := settings{filepath.Join(root, "a"), filepath.Join(root, "b"), filepath.Join(root, "out"), filepath.Join(root, "supervisor")}
	for _, p := range []string{s.A, s.B} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(s.Supervisor, []byte("fixture only"), 0700); err != nil {
		t.Fatal(err)
	}
	return s, func(p string) (string, error) {
		if p == s.A {
			return sourceA, nil
		}
		if p == s.B {
			return sourceB, nil
		}
		return "", errors.New("unexpected source")
	}
}

func witness(r request, w io.Writer) {
	fmt.Fprintf(w, "synthetic collection %d/%s\n", r.Index, r.Label)
	_ = os.WriteFile(filepath.Join(r.Directory, "supervisor.json"), []byte(`{"fixture":true}`), 0600)
	_ = os.WriteFile(filepath.Join(r.Directory, "verifier-attribution.trace"), []byte("synthetic trace bytes, not a runtime trace"), 0600)
}

// Every selected process is attempted in ABBA order after a first failure,
// no-start or missing evidence. Exit/status witnesses survive; zero with all
// required files is a byte-retention control, never product qualification.
func TestAllCollectionsAfterFailure(t *testing.T) {
	for _, mode := range []string{"positive", "exit7", "not-started", "canceled", "missing-trace", "missing-report"} {
		t.Run(mode, func(t *testing.T) {
			s, pin := fixture(t)
			var seen []string
			var output bytes.Buffer
			run := func(r request, w io.Writer) (bool, int, error) {
				seen = append(seen, r.Label)
				witness(r, w)
				if r.Index == 0 {
					switch mode {
					case "exit7":
						return true, 7, errors.New("fixture failure")
					case "not-started":
						return false, -1, errors.New("fixture no-start")
					case "canceled":
						return true, 130, errors.New("fixture canceled")
					case "missing-trace":
						_ = os.Remove(filepath.Join(r.Directory, "verifier-attribution.trace"))
					case "missing-report":
						_ = os.Remove(filepath.Join(r.Directory, "supervisor.json"))
					}
				}
				return true, 0, nil
			}
			code, err := collect(s, run, pin, &output)
			if err != nil || strings.Join(seen, "") != "ABBA" {
				t.Fatalf("lanes lost: %v %v", seen, err)
			}
			if (code == 0) != (mode == "positive") {
				t.Fatalf("wrong overall verdict: %d", code)
			}
			raw, err := os.ReadFile(filepath.Join(s.Out, "collections.json"))
			if err != nil {
				t.Fatal(err)
			}
			var got receipt
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			if !got.DiagnosticOnly || got.Order != "ABBA" || len(got.Collections) != 4 {
				t.Fatal("invalid receipt")
			}
			if mode == "exit7" && got.Collections[0].ExitCode != 7 {
				t.Fatal("original exit lost")
			}
			if mode == "canceled" && got.Collections[0].ExitCode != 130 {
				t.Fatal("cancellation exit lost")
			}
			if mode == "not-started" && got.Collections[0].Started {
				t.Fatal("no-start promoted to execution")
			}
			for i, r := range got.Collections {
				if r.Index != i || r.Source != seen[i] {
					t.Fatal("order changed")
				}
			}
			info, _ := os.Stat(s.Out)
			if info.Mode().Perm() != 0700 {
				t.Fatal("private directory mode lost")
			}
		})
	}
}

// A known pin/path setup passes; wrong/unavailable pins, aliases, symlinks,
// existing evidence and writable/nonexecutable supervisors refuse before any
// executor call or new evidence directory. No live subprocess is launched.
func TestPreparationRefusals(t *testing.T) {
	cases := []string{"wrong-pin", "pin-error", "same-source", "relative", "symlink-source", "inside-source", "existing-output", "writable-supervisor", "nonexecutable-supervisor", "symlink-supervisor"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			s, pin := fixture(t)
			if err := validate(s, pin); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "wrong-pin":
				pin = func(string) (string, error) { return sourceB, nil }
			case "pin-error":
				pin = func(string) (string, error) { return "", errors.New("fixture") }
			case "same-source":
				s.B = s.A
			case "relative":
				s.A = "relative"
			case "symlink-source":
				p := s.A + "-link"
				if err := os.Symlink(s.A, p); err != nil {
					t.Fatal(err)
				}
				s.A = p
			case "inside-source":
				s.Out = filepath.Join(s.A, "evidence")
			case "existing-output":
				if err := os.Mkdir(s.Out, 0700); err != nil {
					t.Fatal(err)
				}
			case "writable-supervisor":
				if err := os.Chmod(s.Supervisor, 0777); err != nil {
					t.Fatal(err)
				}
			case "nonexecutable-supervisor":
				if err := os.Chmod(s.Supervisor, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink-supervisor":
				p := s.Supervisor + "-link"
				if err := os.Symlink(s.Supervisor, p); err != nil {
					t.Fatal(err)
				}
				s.Supervisor = p
			}
			before, statErr := os.Stat(s.Out)
			calls := 0
			code, err := collect(s, func(request, io.Writer) (bool, int, error) { calls++; return true, 0, nil }, pin, io.Discard)
			want := map[string]string{
				"wrong-pin": "source pin mismatch", "pin-error": "source pin mismatch",
				"same-source": "distinct source directories required", "relative": "absolute clean paths required",
				"symlink-source": "regular source directories required", "inside-source": "evidence must be outside source",
				"existing-output":          "evidence destination already exists or is unavailable",
				"writable-supervisor":      "regular executable without group/other writes required",
				"nonexecutable-supervisor": "regular executable without group/other writes required",
				"symlink-supervisor":       "regular executable without group/other writes required",
			}[name]
			if code != 64 || err == nil || err.Error() != want || calls != 0 {
				t.Fatalf("wrong preparation refusal: %d %v calls%d want %s", code, err, calls, want)
			}
			if statErr != nil {
				if _, err := os.Lstat(s.Out); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failed preparation wrote output")
				}
			} else {
				after, err := os.Stat(s.Out)
				if err != nil || !os.SameFile(before, after) {
					t.Fatal("existing evidence changed")
				}
			}
		})
	}
}

// Encoded telemetry round-trips exact bytes/hash. Empty, oversized or symlink
// inputs and a failed destination writer are intended capture refusals.
func TestTraceRetention(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "trace")
	raw := bytes.Repeat([]byte("synthetic runtime byte fixture\n"), 100)
	if err := os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	sum, err := emitTrace(p, 0, "A", &out)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	if sum != hex.EncodeToString(h[:]) {
		t.Fatal("trace hash changed")
	}
	start := "VERIFIER_TRACE_GZIP_BASE64_BEGIN\n"
	end := "VERIFIER_TRACE_GZIP_BASE64_END"
	_, payload, ok := strings.Cut(out.String(), start)
	if !ok {
		t.Fatal("missing evidence start")
	}
	payload, _, ok = strings.Cut(payload, end)
	if !ok {
		t.Fatal("missing evidence end")
	}
	compressed, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(payload, "\n", ""))
	if err != nil {
		t.Fatal(err)
	}
	z, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	_ = z.Close()
	if !bytes.Equal(got, raw) {
		t.Fatal("trace bytes changed")
	}
	for _, name := range []string{"empty", "oversized", "symlink", "writer"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			var writer io.Writer = io.Discard
			switch name {
			case "empty":
				_ = os.WriteFile(path, nil, 0600)
			case "oversized":
				f, err := os.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				_ = f.Truncate((64 << 20) + 1)
				_ = f.Close()
			case "symlink":
				if err := os.Symlink(p, path); err != nil {
					t.Fatal(err)
				}
			case "writer":
				path = p
				writer = brokenWriter{}
			}
			if sum, err := emitTrace(path, 0, "A", writer); err == nil || sum != "" {
				t.Fatal("invalid capture accepted")
			}
		})
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("fixture output failure") }

func TestMain(m *testing.M) {
	if version := os.Getenv("VERIFIER_DIAG_GO_VERSION_FIXTURE"); version != "" {
		if len(os.Args) != 3 || os.Args[1] != "env" || os.Args[2] != "GOVERSION" {
			os.Exit(64)
		}
		if err := os.WriteFile(os.Getenv("VERIFIER_DIAG_GO_CALL_FIXTURE"), []byte("env GOVERSION\n"), 0600); err != nil {
			os.Exit(65)
		}
		fmt.Fprintln(os.Stdout, version)
		os.Exit(0)
	}
	if os.Getenv("VERIFIER_DIAG_SUPERVISOR_FIXTURE") == "1" {
		args := os.Args[1:]
		if len(args) != 5 || args[0] != "--timeout=5m" || !strings.HasPrefix(args[1], "--report=") || args[2] != "--" || args[3] != "bash" || args[4] != "scripts/verifier-latency-confined.sh" {
			os.Exit(64)
		}
		cwd, err := os.Getwd()
		actual, actualErr := os.Stat(cwd)
		expected, expectedErr := os.Stat(os.Getenv("VERIFIER_DIAG_SOURCE_FIXTURE"))
		if err != nil || actualErr != nil || expectedErr != nil || !os.SameFile(actual, expected) {
			os.Exit(65)
		}
		report := strings.TrimPrefix(args[1], "--report=")
		dir := filepath.Dir(report)
		if os.Getenv("RUNNER_TEMP") != dir || os.Getenv("GITHUB_WORKSPACE") != os.Getenv("VERIFIER_DIAG_SOURCE_FIXTURE") {
			os.Exit(66)
		}
		if os.WriteFile(report, []byte(`{"fixture":true}`), 0600) != nil {
			os.Exit(67)
		}
		if os.WriteFile(filepath.Join(dir, "verifier-attribution.trace"), []byte("synthetic fixture bytes"), 0600) != nil {
			os.Exit(68)
		}
		fmt.Fprintln(os.Stdout, "fixture stdout")
		fmt.Fprintln(os.Stderr, "fixture stderr")
		if os.Getenv("VERIFIER_DIAG_EXIT_FIXTURE") == "7" {
			os.Exit(7)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// A real bounded Go subprocess checks executor argv, CWD, RUNNER_TEMP, both
// output streams and exact exit mapping. It does not test Linux subreaping;
// that remains the reviewed suite supervisor's separate custody contract.
func TestProcessInvocation(t *testing.T) {
	for _, exit := range []int{0, 7} {
		t.Run(fmt.Sprint(exit), func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("VERIFIER_DIAG_SUPERVISOR_FIXTURE", "1")
			t.Setenv("VERIFIER_DIAG_SOURCE_FIXTURE", dir)
			t.Setenv("GITHUB_WORKSPACE", "wrong ambient checkout")
			t.Setenv("RUNNER_TEMP", "wrong ambient scratch")
			t.Setenv("VERIFIER_DIAG_EXIT_FIXTURE", fmt.Sprint(exit))
			var out bytes.Buffer
			started, code, err := runCollection(request{Label: "A", Source: dir, Directory: dir, Supervisor: os.Args[0]}, &out)
			if !started || code != exit || (err == nil) != (exit == 0) {
				t.Fatalf("wrong child result %v/%d/%v", started, code, err)
			}
			if !strings.Contains(out.String(), "fixture stdout") || !strings.Contains(out.String(), "fixture stderr") {
				t.Fatal("child output lost")
			}
			for _, name := range []string{"supervisor.json", "verifier-attribution.trace"} {
				if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// Legitimate parent-directory aliases preserve the same known source pins.
// Aliasing A as B or putting evidence inside an aliased source still refuses.
func TestParentAliases(t *testing.T) {
	s, _ := fixture(t)
	alias := filepath.Join(t.TempDir(), "parent-link")
	if err := os.Symlink(filepath.Dir(s.A), alias); err != nil {
		t.Fatal(err)
	}
	realA, _ := filepath.EvalSymlinks(s.A)
	realB, _ := filepath.EvalSymlinks(s.B)
	pin := func(p string) (string, error) {
		r, err := filepath.EvalSymlinks(p)
		if err != nil {
			return "", err
		}
		if r == realA {
			return sourceA, nil
		}
		if r == realB {
			return sourceB, nil
		}
		return "", errors.New("unknown fixture")
	}
	valid := settings{filepath.Join(alias, "a"), filepath.Join(alias, "b"), filepath.Join(alias, "out"), s.Supervisor}
	if err := validate(valid, pin); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		s    settings
		want string
	}{
		{"source-alias", settings{s.A, valid.A, s.Out, s.Supervisor}, "distinct source directories required"},
		{"output-alias", settings{s.A, s.B, filepath.Join(alias, "a", "evidence"), s.Supervisor}, "evidence must be outside source"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			code, err := collect(tc.s, func(request, io.Writer) (bool, int, error) { calls++; return true, 0, nil }, pin, io.Discard)
			if code != 64 || err == nil || err.Error() != tc.want || calls != 0 {
				t.Fatalf("wrong alias refusal %d %v calls%d", code, err, calls)
			}
		})
	}
}

// The exact bounded status bytes survive encoding. Missing/empty, oversized,
// symlink and failed-output reports refuse capture; no JSON validity is claimed.
func TestReportRetention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	raw := []byte("{\n  \"fixture\": true\n}\n")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	sum, err := emitReport(path, 1, "B", &out)
	expected := sha256.Sum256(raw)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if err != nil || sum != hex.EncodeToString(expected[:]) || len(lines) < 4 || lines[1] != "VERIFIER_REPORT_BASE64_BEGIN" || lines[len(lines)-1] != "VERIFIER_REPORT_BASE64_END" {
		t.Fatal("report witness lost", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.Join(lines[2:len(lines)-1], ""))
	if err != nil || !bytes.Equal(decoded, raw) {
		t.Fatal("report bytes changed")
	}
	for _, name := range []string{"missing", "empty", "oversized", "symlink", "writer"} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "bad.json")
			var w io.Writer = io.Discard
			switch name {
			case "empty":
				_ = os.WriteFile(p, nil, 0600)
			case "oversized":
				_ = os.WriteFile(p, bytes.Repeat([]byte("x"), (64<<10)+1), 0600)
			case "symlink":
				_ = os.Symlink(path, p)
			case "writer":
				p, w = path, brokenWriter{}
			}
			if got, err := emitReport(p, 0, "A", w); err == nil || got != "" {
				t.Fatal("invalid report capture accepted")
			}
		})
	}
}

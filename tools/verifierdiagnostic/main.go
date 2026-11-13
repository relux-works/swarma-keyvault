// Command verifierdiagnostic retains four instrumented laboratory collections.
// Its output never qualifies a product head.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const sourceA = "fcaf645a6efce742a9778202873d8a7be69f172b"
const sourceB = "82886f1d90e3136e1708699036f7990d12385cb2"

type settings struct{ A, B, Out, Supervisor string }
type request struct {
	Label, Source, Directory, Supervisor string
	Index                                int
}
type collection struct {
	Index      int    `json:"index"`
	Source     string `json:"source"`
	Base       string `json:"base"`
	ExitCode   int    `json:"process_exit"`
	Started    bool   `json:"supervisor_started"`
	EvidenceOK bool   `json:"evidence_files_present"`
	Error      string `json:"error,omitempty"`
	LogSHA     string `json:"log_sha256,omitempty"`
	ReportSHA  string `json:"supervisor_report_sha256,omitempty"`
	TraceSHA   string `json:"trace_sha256,omitempty"`
}
type receipt struct {
	DiagnosticOnly bool         `json:"diagnostic_only"`
	Order          string       `json:"order"`
	Collections    []collection `json:"collections"`
}
type executor func(request, io.Writer) (bool, int, error)
type pinReader func(string) (string, error)

func main() {
	var s settings
	flag.StringVar(&s.A, "a", "", "instrumented checkout of fixed source A")
	flag.StringVar(&s.B, "b", "", "instrumented checkout of fixed source B")
	flag.StringVar(&s.Out, "out", "", "new private evidence directory")
	flag.StringVar(&s.Supervisor, "supervisor", "", "reviewed Linux suite supervisor")
	flag.Parse()
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "diagnostic execution requires Linux")
		os.Exit(125)
	}
	if flag.NArg() != 0 {
		os.Exit(64)
	}
	code, err := collect(s, runCollection, readPin, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "diagnostic preparation/recording refused:", err)
	}
	os.Exit(code)
}

func readPin(dir string) (string, error) {
	b, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	return strings.TrimSpace(string(b)), err
}

func validate(s settings, pin pinReader) error {
	for _, p := range []string{s.A, s.B, s.Out, s.Supervisor} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return errors.New("absolute clean paths required")
		}
	}
	resolved := make(map[string]string)
	for _, p := range []string{s.A, s.B} {
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() {
			return errors.New("regular source directories required")
		}
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			return errors.New("source path unavailable")
		}
		resolved[p] = real
	}
	if resolved[s.A] == resolved[s.B] {
		return errors.New("distinct source directories required")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(s.Out))
	if err != nil {
		return errors.New("evidence parent unavailable")
	}
	out := filepath.Join(parent, filepath.Base(s.Out))
	for _, pair := range [][2]string{{s.A, sourceA}, {s.B, sourceB}} {
		got, err := pin(pair[0])
		if err != nil || got != pair[1] {
			return errors.New("source pin mismatch")
		}
		rel, err := filepath.Rel(resolved[pair[0]], out)
		if err != nil || rel == "." || (!strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && rel != "..") {
			return errors.New("evidence must be outside source")
		}
	}
	info, err := os.Lstat(s.Supervisor)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("regular executable without group/other writes required")
	}
	if _, err := os.Lstat(s.Out); !errors.Is(err, os.ErrNotExist) {
		return errors.New("evidence destination already exists or is unavailable")
	}
	return nil
}

// Attempt all four selected collections after a red execution or missing
// telemetry. Preparation failure starts none; incomplete evidence never passes.
func collect(s settings, run executor, pin pinReader, output io.Writer) (int, error) {
	if err := validate(s, pin); err != nil {
		return 64, err
	}
	if err := os.Mkdir(s.Out, 0700); err != nil {
		return 64, err
	}
	result := receipt{DiagnosticOnly: true, Order: "ABBA", Collections: make([]collection, 0, 4)}
	failed := false
	for i, label := range []string{"A", "B", "B", "A"} {
		src, base := s.A, sourceA
		if label == "B" {
			src, base = s.B, sourceB
		}
		r := collection{Index: i, Source: label, Base: base, ExitCode: -1}
		dir := filepath.Join(s.Out, fmt.Sprintf("%d-%s", i, label))
		if err := os.Mkdir(dir, 0700); err != nil {
			r.Error = "collection-directory-unavailable"
		} else {
			log, err := os.OpenFile(filepath.Join(dir, "collection.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				r.Error = "collection-log-unavailable"
			} else {
				fmt.Fprintf(output, "diagnostic collection=%d source=%s base=%s\n", i, label, base)
				r.Started, r.ExitCode, err = run(request{label, src, dir, s.Supervisor, i}, io.MultiWriter(log, output))
				closeErr := log.Close()
				if err != nil {
					r.Error = "collection-process-failed"
				}
				if closeErr != nil {
					r.Error = "collection-log-close-failed"
				}
				var logErr, reportErr, traceErr error
				r.LogSHA, logErr = hashFile(filepath.Join(dir, "collection.log"))
				r.ReportSHA, reportErr = hashFile(filepath.Join(dir, "supervisor.json"))
				r.TraceSHA, traceErr = hashFile(filepath.Join(dir, "verifier-attribution.trace"))
				r.EvidenceOK = logErr == nil && reportErr == nil && traceErr == nil && closeErr == nil
				if !r.EvidenceOK && r.Error == "" {
					r.Error = "collection-evidence-incomplete"
				}
			}
		}
		if !r.Started || r.ExitCode != 0 || r.Error != "" || !r.EvidenceOK {
			failed = true
		}
		result.Collections = append(result.Collections, r)
	}
	// Compress/emit traces only after all timed child collections; parent-side
	// compression must not contend with a later collection's measured work.
	for i := range result.Collections {
		r := &result.Collections[i]
		reportSum, reportErr := emitReport(filepath.Join(s.Out, fmt.Sprintf("%d-%s", r.Index, r.Source), "supervisor.json"), r.Index, r.Source, output)
		if reportErr != nil || reportSum != r.ReportSHA {
			r.EvidenceOK = false
			failed = true
			if r.Error == "" {
				r.Error = "report-capture-incomplete-or-changed"
			}
		}
		sum, err := emitTrace(filepath.Join(s.Out, fmt.Sprintf("%d-%s", r.Index, r.Source), "verifier-attribution.trace"), r.Index, r.Source, output)
		if err != nil || sum != r.TraceSHA {
			r.EvidenceOK = false
			failed = true
			if r.Error == "" {
				r.Error = "trace-capture-incomplete-or-changed"
			}
		}
	}
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return 1, err
	}
	f, err := os.OpenFile(filepath.Join(s.Out, "collections.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return 1, err
	}
	_, writeErr := f.Write(append(raw, '\n'))
	closeErr := f.Close()
	if writeErr != nil {
		return 1, writeErr
	}
	if closeErr != nil {
		return 1, closeErr
	}
	if _, err := fmt.Fprintf(output, "DIAGNOSTIC_COLLECTIONS %s\n", raw); err != nil {
		return 1, err
	}
	if failed {
		return 1, nil
	}
	return 0, nil
}

func runCollection(r request, output io.Writer) (bool, int, error) {
	args := []string{"--timeout=5m", "--report=" + filepath.Join(r.Directory, "supervisor.json"), "--", "bash", "scripts/verifier-latency-confined.sh"}
	cmd := exec.Command(r.Supervisor, args...)
	cmd.Dir = r.Source
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "RUNNER_TEMP=") && !strings.HasPrefix(v, "GITHUB_WORKSPACE=") {
			cmd.Env = append(cmd.Env, v)
		}
	}
	cmd.Env = append(cmd.Env, "RUNNER_TEMP="+r.Directory, "GITHUB_WORKSPACE="+r.Source)
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		return false, -1, err
	}
	err := cmd.Wait()
	if err == nil {
		return true, 0, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return true, exit.ExitCode(), err
	}
	return true, -1, err
}

func hashFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("regular evidence file required")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Retain exact trace bytes via a bounded encoded log witness. Overflow or an
// absent/symlink trace refuses evidence; no truncated trace is called complete.
func emitTrace(path string, index int, label string, out io.Writer) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 64<<20 {
		return "", errors.New("trace missing or outside evidence bound")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(z, h), io.LimitReader(f, (64<<20)+1))
	closeErr := z.Close()
	if err != nil || closeErr != nil || n != info.Size() || compressed.Len() > 4<<20 {
		return "", errors.New("trace capture incomplete or outside evidence bound")
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if _, err := fmt.Fprintf(out, "trace collection=%d source=%s sha256=%s\nVERIFIER_TRACE_GZIP_BASE64_BEGIN\n", index, label, sum); err != nil {
		return "", err
	}
	text := base64.StdEncoding.EncodeToString(compressed.Bytes())
	for len(text) > 0 {
		n := min(len(text), 76)
		if _, err := fmt.Fprintln(out, text[:n]); err != nil {
			return "", err
		}
		text = text[n:]
	}
	if _, err := fmt.Fprintln(out, "VERIFIER_TRACE_GZIP_BASE64_END"); err != nil {
		return "", err
	}
	return sum, nil
}

// Retain the supervisor's exact public process-status bytes; presence and a
// checksum do not certify semantic validity of its cleanup or exit fields.
func emitReport(path string, index int, label string, out io.Writer) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 64<<10 {
		return "", errors.New("report missing or outside evidence bound")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || int64(len(raw)) != info.Size() {
		return "", errors.New("report capture incomplete")
	}
	sum := sha256.Sum256(raw)
	value := hex.EncodeToString(sum[:])
	if _, err := fmt.Fprintf(out, "report collection=%d source=%s sha256=%s\nVERIFIER_REPORT_BASE64_BEGIN\n", index, label, value); err != nil {
		return "", err
	}
	text := base64.StdEncoding.EncodeToString(raw)
	for len(text) > 0 {
		n := min(len(text), 76)
		if _, err := fmt.Fprintln(out, text[:n]); err != nil {
			return "", err
		}
		text = text[n:]
	}
	if _, err := fmt.Fprintln(out, "VERIFIER_REPORT_BASE64_END"); err != nil {
		return "", err
	}
	return value, nil
}

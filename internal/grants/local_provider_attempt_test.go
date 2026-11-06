package grants

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const localEvidenceSecret = "SYNTHETIC_PRIVATE_SENTINEL_303"
const localEvidenceID = "ABCD:123456:ABCDEF:123456:ABCDEF01"

func localEvidenceResponse(status, newline, id string, body []byte) []byte {
	header := "HTTP/2.0 " + status + newline + "Content-Type: application/json; charset=utf-8" + newline
	if id != "" {
		header += "X-Github-Request-Id: " + id + newline
	}
	// These legitimate extra headers are intentionally never diagnostic fields.
	header += "Set-Cookie: " + localEvidenceSecret + newline + "X-Private: opaque-é-" + localEvidenceSecret + newline + newline
	return append([]byte(header), body...)
}

// Run only as the existing Go fake provider after argv/stdin validation and its
// single CREATE marker. Every payload is synthetic, with no network or accounts.
func runLocalEvidenceFixture(mode string) int {
	switch mode {
	case "evidence-http-success", "evidence-http-outcome-write":
		_, _ = os.Stdout.Write(localEvidenceResponse("201 Created", "\r\n", localEvidenceID, localGoodReceipt()))
	case "evidence-http-failure":
		_, _ = os.Stdout.Write(localEvidenceResponse("403 Forbidden", "\n", localEvidenceID, []byte(localEvidenceSecret)))
		_, _ = os.Stderr.WriteString("gh: " + localEvidenceSecret + "\nAuthorization: Bearer " + localEvidenceSecret)
		return 17
	case "evidence-http-nonzero-receipt":
		_, _ = os.Stdout.Write(localEvidenceResponse("201 Created", "\n", localEvidenceID, localGoodReceipt()))
		return 17
	case "evidence-http-invalid-body":
		_, _ = os.Stdout.Write(localEvidenceResponse("201 Created", "\n", localEvidenceID, []byte(`{"id":42`)))
	case "evidence-http-error-receipt":
		_, _ = os.Stdout.Write(localEvidenceResponse("403 Forbidden", "\n", localEvidenceID, localGoodReceipt()))
	case "evidence-partial":
		_, _ = os.Stdout.WriteString("HTTP/2.0 403 Forbidden\r\nX-Github-Request-Id: " + localEvidenceID)
		return 17
	case "evidence-hostile":
		_, _ = os.Stdout.Write(localEvidenceResponse("403 Forbidden", "\n", "\x1b[31m"+localEvidenceSecret, nil))
		_, _ = os.Stderr.WriteString("\x1b[2J\nAuthorization: " + localEvidenceSecret)
		return 17
	case "evidence-unknown":
		_, _ = os.Stderr.WriteString("unknown: " + localEvidenceSecret)
	case "evidence-oversize":
		_, _ = os.Stdout.Write(localEvidenceResponse("201 Created", "\n", localEvidenceID, nil))
		_, _ = os.Stdout.Write(bytes.Repeat([]byte{'x'}, localReceiptLimit+localHTTPHeaderLimit+1))
	case "evidence-timeout", "evidence-cancel":
		time.Sleep(time.Minute)
	default:
		return 95
	}
	return 0
}

// Preserve supported gh header spellings/status/IDs exactly; ignore all other
// headers and retain the original body bytes, including normal receipt extras.
func TestLocalProviderHTTPCompatibility(t *testing.T) {
	for _, protocol := range []string{"HTTP/1.0", "HTTP/1.1", "HTTP/2.0"} {
		for _, newline := range []string{"\n", "\r\n"} {
			for _, id := range []string{"", localEvidenceID, "abcd:12:ab:abcdef", "a:B:12:Cd:ef"} {
				raw := bytes.Replace(localEvidenceResponse("201 Created", newline, id, localGoodReceipt()), []byte("HTTP/2.0"), []byte(protocol), 1)
				body, a := parseLocalHTTPResponse(raw)
				if a == nil || a.Classification != "http-response" || a.HTTPStatus != 201 || a.RequestID != id || a.Diagnostic != "http-response" || !bytes.Equal(body, localGoodReceipt()) {
					t.Fatal("legitimate HTTP metadata/body not preserved")
				}
				safe, err := json.Marshal(a)
				if err != nil || bytes.Contains(safe, []byte(localEvidenceSecret)) || len(safe) > 512 {
					t.Fatal("unsafe diagnostic projection")
				}
			}
		}
	}
	for _, status := range []string{"200 OK", "201 Created", "204 No Content", "301 Moved Permanently", "401 Unauthorized", "403 Forbidden", "422 Unprocessable Entity", "429 Too Many Requests", "500 Internal Server Error"} {
		_, a := parseLocalHTTPResponse(localEvidenceResponse(status, "\n", localEvidenceID, nil))
		if a == nil || a.HTTPStatus != mustLocalStatus(t, status) {
			t.Fatal("actual status lost")
		}
	}
	body, a := parseLocalHTTPResponse(localGoodReceipt())
	if a != nil || !bytes.Equal(body, localGoodReceipt()) {
		t.Fatal("body-only receipt invented HTTP evidence")
	}
}

func mustLocalStatus(t *testing.T, status string) int {
	t.Helper()
	n := int(status[0]-'0')*100 + int(status[1]-'0')*10 + int(status[2]-'0')
	return n
}

// Unsupported or ambiguous framing fails closed; forbidden request-ID forms
// never escape even when an otherwise complete response establishes status.
func TestLocalProviderHTTPPrivacy(t *testing.T) {
	good := localEvidenceResponse("403 Forbidden", "\r\n", localEvidenceID, []byte(localEvidenceSecret))
	bad := map[string][]byte{
		"partial":           good[:bytes.Index(good, []byte("\r\n\r\n"))],
		"duplicate-id":      bytes.Replace(good, []byte("Set-Cookie:"), []byte("x-github-request-id: "+localEvidenceID+"\r\nSet-Cookie:"), 1),
		"folded-header":     bytes.Replace(good, []byte("Set-Cookie:"), []byte(" Set-Cookie:"), 1),
		"ansi":              bytes.Replace(good, []byte("Content-Type:"), []byte("\x1b[31mContent-Type:"), 1),
		"bare-cr":           bytes.Replace(good, []byte("Content-Type:"), []byte("X-Test: bad\rContent-Type:"), 1),
		"newline-injection": bytes.Replace(good, []byte(localEvidenceID), []byte(localEvidenceID+"\r\n"+localEvidenceSecret), 1),
		"bad-status":        bytes.Replace(good, []byte("403"), []byte("+43"), 1),
		"unknown-protocol":  bytes.Replace(good, []byte("HTTP/2.0"), []byte("HTTP/9.9"), 1),
		"informational":     bytes.Replace(good, []byte("403"), []byte("100"), 1),
		"header-limit":      []byte("HTTP/2.0 403 Forbidden\nX: " + strings.Repeat("x", localHTTPHeaderLimit) + "\n\n"),
		"header-count":      []byte("HTTP/2.0 403 Forbidden\n" + strings.Repeat("X: a\n", 129) + "\n"),
	}
	for name, raw := range bad {
		t.Run(name, func(t *testing.T) {
			_, neighbor := parseLocalHTTPResponse(good)
			if neighbor == nil || neighbor.HTTPStatus != 403 || neighbor.RequestID != localEvidenceID {
				t.Fatal("valid HTTP neighbor refused")
			}
			body, a := parseLocalHTTPResponse(raw)
			if a != nil || body != nil {
				t.Fatal("ambiguous/hostile HTTP framing accepted")
			}
		})
	}
	for _, id := range []string{localEvidenceSecret, "Bearer " + localEvidenceSecret, "ghp_" + localEvidenceSecret, "abcd:1:2", "abcd::1:2", "ABCD:1:2:3:4:5", strings.Repeat("A", 129), "ABCD:1:2:3 extra", "ABCD:1:2:３", "ABCD:1:2:3\tsecret"} {
		_, a := parseLocalHTTPResponse(localEvidenceResponse("403 Forbidden", "\n", id, nil))
		if a == nil || a.HTTPStatus != 403 || a.RequestID != "" {
			t.Fatal("forbidden request ID escaped or established status lost")
		}
		safe, _ := json.Marshal(a)
		if bytes.Contains(safe, []byte(localEvidenceSecret)) {
			t.Fatal("private diagnostic escaped")
		}
	}
}

// Exercise real Start/Wait boundaries with only the fake executable. Every
// classification has a nearby positive and a bounded, credential-free result.
func TestLocalProviderAttemptProcess(t *testing.T) {
	for _, mode := range []string{"success", "failure", "missing-executable", "invalid-executable", "cancelled", "evidence-http-success", "evidence-http-failure", "evidence-http-nonzero-receipt", "evidence-http-invalid-body", "evidence-http-error-receipt", "evidence-partial", "evidence-hostile", "evidence-unknown", "evidence-oversize", "stderr-limit", "evidence-timeout", "evidence-cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := localTestFixture(t)
			c, q := f.envelopes(t)
			e, err := ParseLocalEnrollment(requestTestBytes(t, f.config))
			if err != nil {
				t.Fatal("fixture enrollment", err)
			}
			checked, err := e.check(c, q, f.now)
			if err != nil {
				t.Fatal("fixture authority", err)
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			calls := filepath.Join(t.TempDir(), "calls")
			t.Setenv("KEYVAULT_LOCAL_GH_FIXTURE", mode)
			t.Setenv("KEYVAULT_LOCAL_GH_CALLS", calls)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			wantCalls := 1
			wantClass := "transport-or-unknown"
			wantStatus := 0
			wantID := ""
			if mode == "missing-executable" {
				exe = filepath.Join(t.TempDir(), "absent")
				wantCalls = 0
			}
			if mode == "invalid-executable" {
				exe = localExecutableMetadataFixture(t)
				wantCalls = 0
			}
			if mode == "cancelled" {
				cancel()
				wantCalls = 0
			}
			if wantCalls == 0 {
				wantClass = "process-start-failure"
			}
			if strings.HasPrefix(mode, "evidence-http-") {
				wantClass = "http-response"
				wantStatus = 201
				wantID = localEvidenceID
			}
			if mode == "evidence-oversize" {
				wantClass, wantStatus, wantID = "http-response", 201, localEvidenceID
			}
			if mode == "evidence-http-failure" || mode == "evidence-http-error-receipt" {
				wantStatus = 403
			}
			if mode == "evidence-timeout" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 500*time.Millisecond)
				defer stop()
			}
			done := make(chan bool, 1)
			if mode == "evidence-cancel" {
				go func() {
					deadline := time.NewTimer(5 * time.Second)
					defer deadline.Stop()
					tick := time.NewTicker(time.Millisecond)
					defer tick.Stop()
					for {
						select {
						case <-tick.C:
							if _, err := os.Stat(calls); err == nil {
								cancel()
								done <- true
								return
							}
						case <-deadline.C:
							cancel()
							done <- false
							return
						}
					}
				}()
			}
			raw, a, err := (localGHProvider{path: exe}).createWithAttempt(ctx, checked)
			if mode == "evidence-cancel" && !<-done {
				t.Fatal("cancel fixture did not reach process boundary")
			}
			if a == nil || a.Classification != wantClass || a.HTTPStatus != wantStatus || a.RequestID != wantID {
				t.Fatal("incorrect causal attempt classification")
			}
			switch mode {
			case "success", "evidence-http-success":
				if err != nil || !bytes.Equal(raw, localGoodReceipt()) {
					t.Fatal("valid receipt neighbor refused")
				}
			case "evidence-http-invalid-body", "evidence-unknown":
				if err != nil {
					t.Fatal("successful subprocess error changed")
				}
				if _, err := parseLocalProviderReceipt(raw); !errors.Is(err, errLocalProvider) {
					t.Fatal("invalid receipt accepted")
				}
			default:
				if !errors.Is(err, errLocalProvider) || len(raw) != 0 {
					t.Fatal("uncontrolled provider failure")
				}
			}
			if mode == "evidence-timeout" && a.Diagnostic != "deadline-exceeded" {
				t.Fatal("timeout classification")
			}
			if mode == "evidence-cancel" && a.Diagnostic != "context-cancelled" {
				t.Fatal("cancel classification")
			}
			safe, marshalErr := json.Marshal(a)
			if marshalErr != nil || bytes.Contains(safe, []byte(localEvidenceSecret)) || bytes.Contains(safe, []byte("Authorization")) || len(safe) > 512 {
				t.Fatal("unsafe bounded process evidence")
			}
			actual, readErr := os.ReadFile(calls)
			if wantCalls == 0 {
				if !os.IsNotExist(readErr) {
					t.Fatal("unexpected fake process start")
				}
			} else if readErr != nil || string(actual) != "create\n" {
				t.Fatal("fake process count mismatch")
			}
		})
	}
}

// Detailed attempt observations never change durable receipt or allowance semantics.
func TestLocalProviderAttemptDurability(t *testing.T) {
	for _, mode := range []string{"success", "evidence-http-success", "evidence-http-failure", "evidence-http-invalid-body", "evidence-http-error-receipt", "evidence-partial", "evidence-hostile", "evidence-unknown", "evidence-oversize", "invalid-executable", "evidence-http-outcome-write"} {
		t.Run(mode, func(t *testing.T) {
			f := localTestFixture(t)
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			if mode == "invalid-executable" {
				exe = localExecutableMetadataFixture(t)
			}
			f.config["gh_path"] = exe
			e, err := ParseLocalEnrollment(requestTestBytes(t, f.config))
			if err != nil {
				t.Fatal("fixture enrollment", err)
			}
			m := NewLocalMediator(e)
			m.now = func() time.Time { return f.now }
			if mode == "evidence-http-outcome-write" {
				original := m.open
				m.open = func(ctx context.Context, e *LocalEnrollment) (*localState, error) {
					s, err := original(ctx, e)
					if err != nil {
						return nil, err
					}
					write := s.write
					writes := 0
					s.write = func(file *os.File, raw []byte) (int, error) {
						writes++
						if writes == 3 {
							return 0, io.ErrClosedPipe
						}
						return write(file, raw)
					}
					return s, nil
				}
			}
			c, q := f.envelopes(t)
			calls := filepath.Join(t.TempDir(), "calls")
			t.Setenv("KEYVAULT_LOCAL_GH_FIXTURE", mode)
			t.Setenv("KEYVAULT_LOCAL_GH_CALLS", calls)
			outcome, err := m.Execute(context.Background(), c, q)
			succeeded := mode == "success" || mode == "evidence-http-success"
			if outcome == nil || outcome.Attempt == nil {
				t.Fatal("attempt observation absent")
			}
			if mode == "evidence-http-outcome-write" && (outcome.Attempt.Classification != "http-response" || outcome.Attempt.HTTPStatus != 201 || outcome.Attempt.RequestID != localEvidenceID) {
				t.Fatal("outcome-write uncertainty discarded established HTTP metadata")
			}
			if succeeded {
				if err != nil || outcome.State != "succeeded" || outcome.RepositoryID != "42" {
					t.Fatal("valid receipt behavior changed")
				}
			} else if !errors.Is(err, ErrLocalUnknown) || outcome.State != "unknown" {
				t.Fatal("uncertainty did not hold use")
			}
			safe, marshalErr := json.Marshal(outcome)
			if marshalErr != nil || bytes.Contains(safe, []byte(localEvidenceSecret)) || bytes.Contains(safe, []byte("Set-Cookie")) || len(safe) > 1024 {
				t.Fatal("outcome leaked private provider content")
			}
			journal := filepath.Join(e.stateDir, "local.journal")
			before, err := os.ReadFile(journal)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(before, []byte(localEvidenceSecret)) || bytes.Contains(before, []byte("HTTP/")) {
				t.Fatal("diagnostics changed durable receipt bytes")
			}
			state, err := openLocalState(context.Background(), e)
			if err != nil {
				t.Fatal(err)
			}
			wantSequence := uint64(3)
			if succeeded {
				wantSequence = 4
			}
			if state.link.sequence != wantSequence || len(state.uses) != 1 {
				state.close()
				t.Fatal("durable reservation/intent frame count changed")
			}
			for _, held := range state.uses {
				if !held.intent || (held.receipt != nil) != succeeded {
					state.close()
					t.Fatal("held use/receipt semantics changed")
				}
				if succeeded && !bytes.Equal(held.receipt.raw, localGoodReceipt()) {
					state.close()
					t.Fatal("original receipt not preserved")
				}
			}
			state.close()
			fresh := NewLocalMediator(e)
			fresh.now = m.now
			if out, err := fresh.Execute(context.Background(), c, q); out != nil || !errors.Is(err, ErrLocalUseHeld) {
				t.Fatal("fresh mediator retried held use")
			}
			f.request["request_id"] = "new-observation-request"
			_, q = f.envelopes(t)
			if out, err := fresh.Execute(context.Background(), c, q); out != nil || !errors.Is(err, ErrLocalUseHeld) {
				t.Fatal("new request ID released use")
			}
			after, err := os.ReadFile(journal)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("held-use refusal rewrote journal")
			}
			actual, readErr := os.ReadFile(calls)
			if mode == "invalid-executable" {
				if !os.IsNotExist(readErr) || outcome.Attempt.Classification != "process-start-failure" {
					t.Fatal("start failure claimed dispatch")
				}
			} else if readErr != nil || string(actual) != "create\n" {
				t.Fatal("provider repeated effect or changed action")
			}
		})
	}
}

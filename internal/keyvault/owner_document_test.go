package keyvault

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var documentPeerBuild struct {
	sync.Once
	path string
	dir  string
	err  error
}

// These executables are private synthetic protocol peers, never the native
// helper. No UI/presence or real custody success follows from these tests.
func documentPeer(t *testing.T, mode string) string {
	t.Helper()
	documentPeerBuild.Do(func() {
		// Compile once, outside every production protocol deadline. The peer is
		// intentionally non-race: only the inert transport is outside the race
		// runtime; CallDocument and its controls run in the parent race suite.
		dir, err := os.MkdirTemp("", "document-peer-build-")
		if err != nil {
			documentPeerBuild.err = err
			return
		}
		documentPeerBuild.dir = dir
		binary := filepath.Join(dir, "document-peer")
		cmd := exec.Command("go", "build", "-race=false", "-o", binary, "./testdata/documentpeer")
		if out, err := cmd.CombinedOutput(); err != nil {
			documentPeerBuild.err = fmt.Errorf("build document peer: %w: %s", err, out)
			return
		}
		// Prepare the one executable path before entering any protocol deadline.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, binary, "--self-check").CombinedOutput(); err != nil {
			documentPeerBuild.err = fmt.Errorf("probe document peer: %w: %s", err, out)
			return
		}
		documentPeerBuild.path = binary
	})
	if documentPeerBuild.err != nil {
		t.Fatal(documentPeerBuild.err)
	}
	// Tests are serial; Setenv restores the selector after each case and
	// disallows parallel use. Every mode executes the same prepared file.
	t.Setenv("KEYVAULT_TEST_DOCUMENT_PEER_MODE", mode)
	return documentPeerBuild.path
}

func TestDocumentHelperPipeBindingAndRefusals(t *testing.T) {
	for _, mode := range []string{"success", "tamper", "digest-only", "wrong-phase", "unknown-field", "native-cancel", "oversize", "eof", "timeout", "post-timeout", "post-cancel", "final-refusal", "final-cancel", "post-error", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			binding := DocumentBinding{Document: []byte("Complete exact text\n"), Digest: bytes.Repeat([]byte{7}, 32), Point: bytes.Repeat([]byte{4}, 65), Label: "synthetic-label", Reason: "synthetic reason"}
			helper := ExecEnclaveHelper{Path: documentPeer(t, mode), InteractiveTimeout: 250 * time.Millisecond}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			checks := 0
			sourceChanged := errors.New("source changed")
			started := time.Now()
			response, err := helper.CallDocument(ctx, EnclaveRequest{Op: "review-document", Blob: []byte("synthetic-blob"), Presence: "required", Document: &binding}, func(review DocumentBinding) error {
				checks++
				if !sameDocument(review, binding) {
					t.Fatal("altered handoff reached final gate")
				}
				if mode == "final-refusal" {
					return sourceChanged
				}
				if mode == "post-cancel" {
					timer := time.AfterFunc(30*time.Millisecond, cancel)
					t.Cleanup(func() { timer.Stop() })
				}
				if mode == "final-cancel" {
					cancel()
				}
				return nil
			})
			t.Logf("mode=%s elapsed=%s gates=%d error=%v", mode, time.Since(started), checks, err)
			if mode == "timeout" || mode == "post-timeout" {
				if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
					t.Fatalf("stalled peer escaped deadline: %v", err)
				}
			} else if mode == "final-cancel" || mode == "post-cancel" {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("lost cancellation: %v", err)
				}
			} else if mode != "success" && errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("refusal was masked by startup timeout: %v", err)
			}
			// Require the intended refusal, so an unrelated peer crash or timeout
			// cannot substitute for a planted invalid handoff.
			switch mode {
			case "tamper", "digest-only", "wrong-phase":
				if err == nil || !strings.Contains(err.Error(), "invalid native confirmation") {
					t.Fatalf("wrong confirmation refusal: %v", err)
				}
			case "unknown-field":
				if err == nil || !strings.Contains(err.Error(), `unknown field "consent"`) {
					t.Fatalf("wrong strict JSON refusal: %v", err)
				}
			case "oversize":
				if !errors.Is(err, bufio.ErrBufferFull) {
					t.Fatalf("wrong frame-bound refusal: %v", err)
				}
			case "eof":
				if !errors.Is(err, io.EOF) {
					t.Fatalf("wrong EOF refusal: %v", err)
				}
			case "final-refusal":
				if !errors.Is(err, sourceChanged) {
					t.Fatalf("lost final gate refusal: %v", err)
				}
			case "trailing":
				if err == nil || !strings.Contains(err.Error(), "trailing helper output") {
					t.Fatalf("wrong trailing-frame refusal: %v", err)
				}
			}
			if mode == "success" {
				if err != nil || string(response.DER) != "synthetic-der" || !bytes.Equal(response.Point, binding.Point) || checks != 1 {
					t.Fatal(response, err, checks)
				}
			} else if err == nil || len(response.DER) != 0 {
				t.Fatal("unsafe result", response, checks)
			}
			switch mode {
			case "tamper", "digest-only", "wrong-phase", "unknown-field", "native-cancel", "oversize", "eof", "timeout":
				if checks != 0 {
					t.Fatal("bad handoff reached dispatch gate", checks)
				}
			default:
				if checks != 1 {
					t.Fatal("expected exactly one final gate", checks)
				}
			}
			if mode == "native-cancel" || mode == "post-error" {
				var native *EnclaveHelperError
				if !errors.As(err, &native) {
					t.Fatal("lost native failure", err)
				}
				wantCode, wantStatus := "user_canceled", -128
				if mode == "post-error" {
					wantCode, wantStatus = "security", -50
				}
				if native.Code != wantCode || native.Status != wantStatus {
					t.Fatal("lost native failure", err)
				}
			}
		})
	}
}

func TestDocumentHelperRejectsMissingProtocolAndRelativePath(t *testing.T) {
	for _, path := range []string{"relative", filepath.Join(t.TempDir(), "absent")} {
		_, err := (ExecEnclaveHelper{Path: path}).CallDocument(context.Background(), EnclaveRequest{Op: "review-document", Document: &DocumentBinding{}}, func(DocumentBinding) error { t.Fatal("missing helper dispatched"); return nil })
		if err == nil {
			t.Fatal("invalid helper allowed")
		}
	}
}

func TestDocumentHelperFinalGateDoesNotAliasRequest(t *testing.T) {
	binding := DocumentBinding{Document: []byte("Exact"), Digest: bytes.Repeat([]byte{1}, 32), Point: bytes.Repeat([]byte{4}, 65), Label: "synthetic", Reason: "synthetic"}
	helper := ExecEnclaveHelper{Path: documentPeer(t, "success"), InteractiveTimeout: time.Second}
	_, err := helper.CallDocument(context.Background(), EnclaveRequest{Op: "review-document", Document: &binding}, func(review DocumentBinding) error {
		// Mutating caller-owned data after confirmation must not mutate dispatch.
		binding.Document[0] = 'X'
		binding.Reason = "changed"
		return nil
	})
	if err != nil {
		t.Fatal("caller buffer altered immutable dispatch", err)
	}
	if strings.HasPrefix(string(binding.Document), "Exact") {
		t.Fatal("control did not mutate caller buffer")
	}
}

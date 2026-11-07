package keyvault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These executables are private synthetic protocol peers, never the native
// helper. No UI/presence or real custody success follows from these tests.
func documentPeer(t *testing.T, mode string) string {
	t.Helper()
	script := `#!/usr/bin/python3
import base64, json, sys, time
mode = %q
req=json.loads(sys.stdin.readline())
binding=req['review']
if mode=='timeout':
    time.sleep(5)
    sys.exit(0)
if mode=='oversize':
    print('x'*65537,flush=True)
    sys.exit(0)
if mode=='eof':
    sys.exit(0)
if mode=='native-cancel':
    print(json.dumps({'error':{'code':'user_canceled','status':-128,'message':'synthetic consent canceled'}}),flush=True)
    sys.exit(1)
review=dict(binding,phase='confirmed')
if mode=='digest-only': review.pop('document')
if mode=='wrong-phase': review['phase']='ready'
if mode=='unknown-field': review['consent']=True
if mode=='tamper': review['document']=base64.b64encode(b'changed').decode()
print(json.dumps(review),flush=True)
line=sys.stdin.readline()
if not line:
    sys.exit(0)
dispatch=json.loads(line)
assert dispatch.pop('phase')=='dispatch'
assert dispatch==binding
if mode=='trailing':
    print(json.dumps({'der':base64.b64encode(b'synthetic-der').decode(),'point':binding['point']}),flush=True)
    print('{}',flush=True)
    sys.exit(0)
if mode=='post-error':
    print(json.dumps({'error':{'code':'security','status':-50,'message':'synthetic post-dispatch error'}}),flush=True)
    sys.exit(1)
print(json.dumps({'der':base64.b64encode(b'synthetic-der').decode(),'point':binding['point']}),flush=True)
`
	path := filepath.Join(t.TempDir(), "synthetic-document-peer")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(script, mode)), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDocumentHelperPipeBindingAndRefusals(t *testing.T) {
	for _, mode := range []string{"success", "tamper", "digest-only", "wrong-phase", "unknown-field", "native-cancel", "oversize", "eof", "timeout", "final-refusal", "final-cancel", "post-error", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			binding := DocumentBinding{Document: []byte("Complete exact text\n"), Digest: bytes.Repeat([]byte{7}, 32), Point: bytes.Repeat([]byte{4}, 65), Label: "synthetic-label", Reason: "synthetic reason"}
			helper := ExecEnclaveHelper{Path: documentPeer(t, mode), InteractiveTimeout: 250 * time.Millisecond}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			checks := 0
			response, err := helper.CallDocument(ctx, EnclaveRequest{Op: "review-document", Blob: []byte("synthetic-blob"), Presence: "required", Document: &binding}, func(review DocumentBinding) error {
				checks++
				if !sameDocument(review, binding) {
					t.Fatal("altered handoff reached final gate")
				}
				if mode == "final-refusal" {
					return errors.New("source changed")
				}
				if mode == "final-cancel" {
					cancel()
				}
				return nil
			})
			if mode == "success" {
				if err != nil || string(response.DER) != "synthetic-der" || checks != 1 {
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

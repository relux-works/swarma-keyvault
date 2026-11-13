package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/codesignpolicy"
	"github.com/relux-works/swarma-keyvault/internal/rootqualification"
)

type qualificationInput struct {
	bytes.Buffer
	closed               bool
	failWrite, failClose bool
}

func (w *qualificationInput) Write(b []byte) (int, error) {
	if w.failWrite || w.closed {
		return 0, io.ErrClosedPipe
	}
	return w.Buffer.Write(b)
}
func (w *qualificationInput) Close() error {
	w.closed = true
	if w.failClose {
		return io.ErrClosedPipe
	}
	return nil
}

type qualificationOutput struct {
	reader        *bytes.Reader
	input         *qualificationInput
	readBeforeEOF bool
}

func (r *qualificationOutput) Read(b []byte) (int, error) {
	if !r.input.closed {
		r.readBeforeEOF = true
		return 0, io.ErrUnexpectedEOF
	}
	return r.reader.Read(b)
}

// Public transport requires one canonical request plus stdin EOF before
// reading a bounded finite response. This proves framing only; synthetic
// statuses do not establish child identity, a marker read or ACL refusal.
func TestRootQualificationParentExchange(t *testing.T) {
	request, err := rootqualification.NewRequest([]byte{1, 2, 3}, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	defer request.Clear()
	for status, want := range map[string]rootqualification.Result{"access-refused": rootqualification.AccessRefused, "unexpected-access": rootqualification.UnexpectedAccess, "unqualified": rootqualification.Unqualified} {
		input := &qualificationInput{}
		output := &qualificationOutput{reader: bytes.NewReader([]byte(`{"schema":"keyvault-root-acl-qualification/1","result":"` + status + `"}` + "\n")), input: input}
		got, err := rootQualificationExchange(input, output, request)
		if err != nil || got != want || !input.closed || output.readBeforeEOF {
			t.Fatalf("valid %s protocol refused", status)
		}
		parsed, err := rootqualification.ReadRequest(bytes.NewReader(input.Bytes()))
		if err != nil {
			t.Fatal("sent invalid request")
		}
		defer parsed.Clear()
		if !bytes.Equal(parsed.Reference(), []byte{1, 2, 3}) || parsed.ReceiptSHA256() != strings.Repeat("a", 64) {
			t.Fatal("request binding changed")
		}
	}
	for _, bad := range []string{"", `{"schema":"keyvault-root-acl-qualification/1","result":"access-refused"}`, `{"schema":"other","result":"access-refused"}` + "\n", `{"schema":"keyvault-root-acl-qualification/1","result":"access-refused","extra":true}` + "\n", `{"schema":"keyvault-root-acl-qualification/1","result":"access-refused"}` + "\nextra", strings.Repeat("x", 257)} {
		input := &qualificationInput{}
		if _, err := rootQualificationExchange(input, strings.NewReader(bad), request); err == nil {
			t.Fatal("malformed control accepted")
		}
	}
	for _, input := range []*qualificationInput{{failWrite: true}, {failClose: true}} {
		if got, err := rootQualificationExchange(input, strings.NewReader(""), request); err == nil || got != rootqualification.Unqualified {
			t.Fatal("transport failure passed control")
		}
	}
}

// Neither an ordinary in-process dispatcher nor the foreign linker mark can
// invoke owning native qualification. Invalid code/source/context facts fail
// before signature/Keychain work; no test enters a valid native branch or
// arms a process watchdog against its runner.
func TestRootQualificationParentRefusesUntimedAndInvalidEntry(t *testing.T) {
	before := recoveryQualificationOnly
	defer func() { recoveryQualificationOnly = before }()
	for _, mark := range []string{"", "1", "unknown"} {
		recoveryQualificationOnly = mark
		var out, errout bytes.Buffer
		code := run([]string{"--json", "root-grants", "qualify-storage", "--case", "create-project"}, &out, &errout)
		if code == exitOK {
			t.Fatal("in-process owning operation admitted")
		}
		if mark == "" && (code != exitRefused || !strings.Contains(out.String(), `"schema":"keyvault-root-acl-qualification-result/1"`) || !strings.Contains(out.String(), `"result":"unqualified"`)) {
			t.Fatal("owning dispatcher lost its explicit untimed refusal")
		}
	}
	for _, ctx := range []context.Context{nil, canceledQualificationContext()} {
		result, digest, code := rootQualificationParentCase(ctx, rootQualificationArguments{operation: rootQualificationCreate}, io.Discard)
		if result != "unqualified" || digest != "" || code != exitFailure {
			t.Fatal("invalid context admitted")
		}
	}
	if _, err := rootqualification.ObserveCandidate(context.Background(), "unknown", "unknown"); !errors.Is(err, rootqualification.ErrReceipt) {
		t.Fatal("missing source pins admitted")
	}
	for _, role := range []codesignpolicy.Role{0, codesignpolicy.Vault, codesignpolicy.Seed, 255} {
		if _, err := rootQualificationControl(context.Background(), nil, role, rootqualification.Request{}); !errors.Is(err, errRootQualification) {
			t.Fatal("non-child role admitted")
		}
	}
}
func canceledQualificationContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// Parent output is public finite status/digest only; no item reference/native
// error is serialized. Partial/failed writes refuse success. This formatter
// does not decide whether an actual native operation or control passed.
func TestRootQualificationParentResponse(t *testing.T) {
	var out bytes.Buffer
	if code := writeRootQualificationParent(&out, "create-project", "unknown", strings.Repeat("a", 64), exitFailure); code != exitFailure {
		t.Fatal("formatter changed failure")
	}
	want := `{"schema":"keyvault-root-acl-qualification-result/1","case":"create-project","result":"unknown","receipt_sha256":"` + strings.Repeat("a", 64) + `"}` + "\n"
	if out.String() != want {
		t.Fatal("public response changed")
	}
	if code := writeRootQualificationParent(&qualificationInput{failWrite: true}, "create-project", "created", "", exitOK); code != exitFailure {
		t.Fatal("failed output reported success")
	}
}

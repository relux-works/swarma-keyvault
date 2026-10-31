package signerclient_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
	"github.com/relux-works/swarma-keyvault/internal/keyvault/testguard"
)

// TestMain hands the process to fakeServer (fake_test.go) when
// SIGNERCLIENT_FAKE_SERVER names a scenario.
func TestMain(m *testing.M) {
	if scenario := os.Getenv("SIGNERCLIENT_FAKE_SERVER"); scenario != "" {
		os.Exit(fakeServer(scenario))
	}
	os.Exit(m.Run())
}

// envelopeShape is one combination of {ok, result present, error member}
// a server could write; response builds it around the op's result.
type envelopeShape struct {
	ok     bool
	result bool
	null   bool   // result member present as the literal null
	err    string // "" absent, otherwise the code carried (declared or not)
}

func (e envelopeShape) response(result json.RawMessage) signerclient.Response {
	resp := signerclient.Response{OK: e.ok}
	if e.result {
		resp.Result = result
	}
	if e.null {
		resp.Result = json.RawMessage("null")
	}
	if e.err != "" {
		resp.Error = &signerclient.Error{Code: e.err, Message: "shape " + e.err, Hint: "h"}
	}
	return resp
}

// envelopeShapes enumerates every combination of ok x result-present x
// error-member {absent, declared stream code, undeclared code}, plus the
// one edge of "present": ok with result literally null; the declared code
// is signature_invalid so the one documented shape with a result next to
// a refusal (verify's false verdict) is in the table.
var envelopeShapes = map[string]envelopeShape{
	"ok-result-noerr":          {ok: true, result: true},
	"ok-null-noerr":            {ok: true, null: true},
	"ok-result-declared":       {ok: true, result: true, err: signerclient.CodeSignatureInvalid},
	"ok-result-undeclared":     {ok: true, result: true, err: "self_minted"},
	"ok-noresult-noerr":        {ok: true},
	"ok-noresult-declared":     {ok: true, err: signerclient.CodeSignatureInvalid},
	"ok-noresult-undeclared":   {ok: true, err: "self_minted"},
	"fail-result-noerr":        {result: true},
	"fail-result-declared":     {result: true, err: signerclient.CodeSignatureInvalid},
	"fail-result-undeclared":   {result: true, err: "self_minted"},
	"fail-noresult-noerr":      {},
	"fail-noresult-declared":   {err: signerclient.CodeSignatureInvalid},
	"fail-noresult-undeclared": {err: "self_minted"},
}

// rawEnvelopeVerdict is what the client must do with one raw line.
type rawEnvelopeVerdict int

const (
	rawProtocol rawEnvelopeVerdict = iota // ErrProtocol, server killed, client unusable
	rawSuccess                            // nil error
	rawRefusal                            // *Error with the declared code, session usable
	rawContract                           // ErrContract (hello only: the contract member is absent or foreign)
	rawSkip                               // the row does not apply at this entry
)

// rawEnvelopeRow is one stdout line written verbatim by the fake server.
// $HEAD is `"contract":1` on the hello and `"id":<request id>` on a
// response, $ID the bare request id, $RESULT the op's documented result
// object; a row that names the head member explicitly (id/contract rows)
// applies to one entry only. hello / call are the verdicts at Start and
// at Call (pub, or verify when verifyOp is set — the one op that documents
// a result next to its refusal).
type rawEnvelopeRow struct {
	line     string
	hello    rawEnvelopeVerdict
	call     rawEnvelopeVerdict
	verifyOp bool
	code     string // the declared code a rawRefusal must carry
}

// rawEnvelopeRows is the rev5 review F1 corpus: every row is raw JSON so
// the absent/null/wrong-type distinctions a typed Response erases are on
// the wire. Controls (rawSuccess / rawRefusal) prove the gate admits the
// documented shapes; every other row must be refused before ok is read.
var rawEnvelopeRows = map[string]rawEnvelopeRow{
	// controls
	"control-success":           {line: `{$HEAD,"ok":true,"result":$RESULT}`, hello: rawSuccess, call: rawSuccess},
	"control-refusal":           {line: `{$HEAD,"ok":false,"error":{"code":"not_found","message":"m","hint":"h"}}`, hello: rawRefusal, call: rawRefusal, code: "not_found"},
	"control-refusal-os-status": {line: `{$HEAD,"ok":false,"error":{"code":"security","message":"m","hint":"h","os_status":-25300}}`, hello: rawRefusal, call: rawRefusal, code: "security"},
	"control-verify-verdict":    {line: `{$HEAD,"ok":false,"result":$RESULT,"error":{"code":"signature_invalid","message":"m","hint":"h"}}`, hello: rawProtocol, call: rawRefusal, verifyOp: true, code: "signature_invalid"},
	"control-string-id":         {line: `{"id":"$ID","ok":true,"result":$RESULT}`, hello: rawSkip, call: rawProtocol}, // the client sent a number; a string spelling of it is another id
	// ok: presence and type
	"ok-missing":            {line: `{$HEAD,"result":$RESULT}`, hello: rawProtocol, call: rawProtocol},
	"ok-missing-with-error": {line: `{$HEAD,"error":{"code":"not_found","message":"m","hint":"h"}}`, hello: rawProtocol, call: rawProtocol},
	"ok-null":               {line: `{$HEAD,"ok":null,"result":$RESULT}`, hello: rawProtocol, call: rawProtocol},
	"ok-null-with-error":    {line: `{$HEAD,"ok":null,"error":{"code":"not_found","message":"m","hint":"h"}}`, hello: rawProtocol, call: rawProtocol},
	"ok-string":             {line: `{$HEAD,"ok":"true","result":$RESULT}`, hello: rawProtocol, call: rawProtocol},
	"ok-number":             {line: `{$HEAD,"ok":1,"result":$RESULT}`, hello: rawProtocol, call: rawProtocol},
	// error: null on either branch, wrong type
	"error-null-on-ok":          {line: `{$HEAD,"ok":true,"result":$RESULT,"error":null}`, hello: rawProtocol, call: rawProtocol},
	"error-null-on-fail":        {line: `{$HEAD,"ok":false,"error":null}`, hello: rawProtocol, call: rawProtocol},
	"error-null-on-fail-result": {line: `{$HEAD,"ok":false,"result":$RESULT,"error":null}`, hello: rawProtocol, call: rawProtocol, verifyOp: true},
	"error-string":              {line: `{$HEAD,"ok":false,"error":"not_found"}`, hello: rawProtocol, call: rawProtocol},
	"error-array":               {line: `{$HEAD,"ok":false,"error":[]}`, hello: rawProtocol, call: rawProtocol},
	// error object: mandatory members present, non-null, typed; no extras
	"error-code-missing":     {line: `{$HEAD,"ok":false,"error":{"message":"m","hint":"h"}}`, hello: rawProtocol, call: rawProtocol},
	"error-code-null":        {line: `{$HEAD,"ok":false,"error":{"code":null,"message":"m","hint":"h"}}`, hello: rawProtocol, call: rawProtocol},
	"error-code-number":      {line: `{$HEAD,"ok":false,"error":{"code":1,"message":"m","hint":"h"}}`, hello: rawProtocol, call: rawProtocol},
	"error-message-missing":  {line: `{$HEAD,"ok":false,"error":{"code":"not_found","hint":"h"}}`, hello: rawProtocol, call: rawProtocol},
	"error-message-null":     {line: `{$HEAD,"ok":false,"error":{"code":"not_found","message":null,"hint":"h"}}`, hello: rawProtocol, call: rawProtocol},
	"error-message-number":   {line: `{$HEAD,"ok":false,"error":{"code":"not_found","message":1,"hint":"h"}}`, hello: rawProtocol, call: rawProtocol},
	"error-hint-missing":     {line: `{$HEAD,"ok":false,"error":{"code":"not_found","message":"m"}}`, hello: rawProtocol, call: rawProtocol},
	"error-hint-null":        {line: `{$HEAD,"ok":false,"error":{"code":"not_found","message":"m","hint":null}}`, hello: rawProtocol, call: rawProtocol},
	"error-code-only":        {line: `{$HEAD,"ok":false,"error":{"code":"not_found"}}`, hello: rawProtocol, call: rawProtocol},
	"error-os-status-string": {line: `{$HEAD,"ok":false,"error":{"code":"security","message":"m","hint":"h","os_status":"-25300"}}`, hello: rawProtocol, call: rawProtocol},
	"error-os-status-null":   {line: `{$HEAD,"ok":false,"error":{"code":"security","message":"m","hint":"h","os_status":null}}`, hello: rawProtocol, call: rawProtocol},
	"error-extra-member":     {line: `{$HEAD,"ok":false,"error":{"code":"not_found","message":"m","hint":"h","detail":"x"}}`, hello: rawProtocol, call: rawProtocol},
	// result: null is not absent; must be an object
	"result-null-on-ok":          {line: `{$HEAD,"ok":true,"result":null}`, hello: rawProtocol, call: rawProtocol},
	"result-null-on-fail":        {line: `{$HEAD,"ok":false,"result":null,"error":{"code":"not_found","message":"m","hint":"h"}}`, hello: rawProtocol, call: rawProtocol},
	"result-null-on-verify-fail": {line: `{$HEAD,"ok":false,"result":null,"error":{"code":"signature_invalid","message":"m","hint":"h"}}`, hello: rawProtocol, call: rawProtocol, verifyOp: true},
	"result-array":               {line: `{$HEAD,"ok":true,"result":[]}`, hello: rawProtocol, call: rawProtocol},
	"result-string":              {line: `{$HEAD,"ok":true,"result":"x"}`, hello: rawProtocol, call: rawProtocol},
	// envelope members: nothing beyond the contract
	"extra-member":         {line: `{$HEAD,"ok":true,"result":$RESULT,"extra":1}`, hello: rawProtocol, call: rawProtocol},
	"extra-member-on-fail": {line: `{$HEAD,"ok":false,"error":{"code":"not_found","message":"m","hint":"h"},"extra":1}`, hello: rawProtocol, call: rawProtocol},
	"id-on-hello":          {line: `{"contract":1,"id":1,"ok":true,"result":$RESULT}`, hello: rawProtocol, call: rawSkip},
	"contract-on-response": {line: `{"id":$ID,"contract":1,"ok":true,"result":$RESULT}`, hello: rawSkip, call: rawProtocol},
	// head member: id presence and type on a response; contract absence is ErrContract on the hello
	"id-missing":         {line: `{"ok":true,"result":$RESULT}`, hello: rawContract, call: rawProtocol},
	"id-null":            {line: `{"id":null,"ok":true,"result":$RESULT}`, hello: rawSkip, call: rawProtocol},
	"id-null-with-error": {line: `{"id":null,"ok":false,"error":{"code":"missing_id","message":"m","hint":"h"}}`, hello: rawSkip, call: rawProtocol}, // the server's answer to a request without id; the client always sends one
	"id-object":          {line: `{"id":{"a":1},"ok":true,"result":$RESULT}`, hello: rawSkip, call: rawProtocol},
	"contract-null":      {line: `{"contract":null,"ok":true,"result":$RESULT}`, hello: rawContract, call: rawSkip},
	"contract-string":    {line: `{"contract":"1","ok":true,"result":$RESULT}`, hello: rawProtocol, call: rawSkip},
	// not an object at all
	"top-array":    {line: `[]`, hello: rawProtocol, call: rawProtocol},
	"top-null":     {line: `null`, hello: rawProtocol, call: rawProtocol},
	"top-string":   {line: `"ok"`, hello: rawProtocol, call: rawProtocol},
	"top-trailing": {line: `{$HEAD,"ok":true,"result":$RESULT} {}`, hello: rawProtocol, call: rawProtocol},
}

func mustJSON(v any) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

func startFake(t *testing.T, scenario string) (*signerclient.Client, error) {
	return startFakeVersion(t, scenario, 0)
}

func startFakeVersion(t *testing.T, scenario string, version int) (*signerclient.Client, error) {
	return startFakeOptions(t, scenario, signerclient.Options{Address: "test/fake", Version: version})
}

func startFakeOptions(t *testing.T, scenario string, opts signerclient.Options) (*signerclient.Client, error) {
	t.Helper()
	t.Setenv("SIGNERCLIENT_FAKE_SERVER", scenario)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	opts.Binary = os.Args[0]
	client, err := signerclient.Start(ctx, opts)
	if err == nil {
		t.Cleanup(func() { _ = client.Close() })
	}
	return client, err
}

// Start refuses a hello that announces contract 2 or no contract at all
// with ErrContract, a hello that is not JSON with ErrProtocol, and a
// startup failure hello (ok=false) with the server's *Error and code; a
// scenario that speaks contract 1 starts (positive control). None of
// these leaves a running process: Close after a failed Start is not
// reachable, so the process is reaped inside Start.
func TestStartRefusesForeignContractAndSurfacesStartupErrors(t *testing.T) {
	for _, scenario := range []string{"contract-2", "no-contract"} {
		if _, err := startFake(t, scenario); !errors.Is(err, signerclient.ErrContract) {
			t.Errorf("%s: %v, want ErrContract", scenario, err)
		}
	}
	if _, err := startFake(t, "garbage"); !errors.Is(err, signerclient.ErrProtocol) {
		t.Errorf("garbage: %v, want ErrProtocol", err)
	}
	var remote *signerclient.Error
	if _, err := startFake(t, "startup-error"); !errors.As(err, &remote) || remote.Code != "not_found" {
		t.Errorf("startup-error: %v, want *Error not_found", err)
	}
	client, err := startFake(t, "ok")
	if err != nil {
		t.Fatalf("positive control: %v", err)
	}
	if client.Hello().Label != "works.relux.mac-keyvault.key.test.fake.v1" || len(client.Hello().Ops) != 4 {
		t.Fatalf("hello: %+v", client.Hello())
	}
}

// The hello must pin a generation the consumer can attest: a hello with
// version 0 (the pre-rev1 "newest at each request" shape) is ErrProtocol,
// a hello whose version is not the one Options.Version requested is
// ErrProtocol, while a hello with version 1 starts both unpinned
// (positive control, above) and when version 1 is requested. Guards
// signerclient.Start; the server side is TestSignerServePinsGeneration.
func TestStartRefusesUnpinnedOrMismatchedGeneration(t *testing.T) {
	if _, err := startFake(t, "unpinned"); !errors.Is(err, signerclient.ErrProtocol) || !strings.Contains(err.Error(), "pin") {
		t.Errorf("unpinned: %v, want ErrProtocol", err)
	}
	if _, err := startFakeVersion(t, "version-3", 1); !errors.Is(err, signerclient.ErrProtocol) || !strings.Contains(err.Error(), "requested version 1") {
		t.Errorf("version-3 for requested 1: %v, want ErrProtocol", err)
	}
	if client, err := startFakeVersion(t, "ok", 1); err != nil || client.Hello().Version != 1 {
		t.Fatalf("requested version 1 against a version-1 hello: %v", err)
	}
}

// Review rev3 F2 regression, through signerclient.Start (the production
// entry kvctl calls): the hello is accepted only as one coherent
// contract-1 binding. Each row is the valid hello with exactly one member
// changed or removed — tool not mac-keyvault, address not the requested
// one, kind not the requested one (key when omitted), label or
// fingerprint missing, ops empty, missing, a subset, a superset or a
// renamed member — and every one is ErrProtocol whose text names the
// member, with the fake process reaped. Controls: the unchanged hello
// starts; a kind-certificate hello starts when Kind certificate is
// requested and is refused when kind was omitted. The generation rows
// (version 0 / mismatch) are TestStartRefusesUnpinnedOrMismatchedGeneration.
func TestStartRefusesHelloBoundToAnotherIdentity(t *testing.T) {
	rows := []struct{ scenario, want string }{
		{"binding-tool", "tool"},
		{"binding-tool-missing", "tool"},
		{"binding-address", "address"},
		{"binding-address-missing", "address"},
		{"binding-kind", "kind"},
		{"binding-kind-missing", "kind"},
		{"binding-label-missing", "label"},
		{"binding-fp-missing", "fingerprint"},
		{"binding-ops-empty", "ops"},
		{"binding-ops-missing", "ops"},
		{"binding-ops-subset", "ops"},
		{"binding-ops-extra", "ops"},
		{"binding-ops-renamed", "ops"},
	}
	for _, row := range rows {
		client, err := startFake(t, row.scenario)
		if !errors.Is(err, signerclient.ErrProtocol) || !strings.Contains(err.Error(), row.want) {
			t.Errorf("%s: Start returned (%v, %v), want ErrProtocol naming %q", row.scenario, client, err, row.want)
		}
		if client != nil {
			t.Errorf("%s: a client was returned for a mismatched hello", row.scenario)
		}
	}
	client, err := startFake(t, "binding-ok")
	if err != nil {
		t.Fatalf("positive control: %v", err)
	}
	if h := client.Hello(); h.Tool != signerclient.Tool || h.Address != "test/fake" || h.Kind != signerclient.KindKey || h.Version != 1 {
		t.Fatalf("control hello: %+v", h)
	}
	if _, err := startFakeOptions(t, "binding-kind-certificate", signerclient.Options{Address: "test/fake", Kind: "certificate"}); err != nil {
		t.Fatalf("kind certificate requested against a certificate hello: %v", err)
	}
	if _, err := startFakeOptions(t, "binding-kind-certificate", signerclient.Options{Address: "test/fake"}); !errors.Is(err, signerclient.ErrProtocol) {
		t.Fatalf("kind omitted against a certificate hello: %v, want ErrProtocol", err)
	}
	// The e2e test binds the built binary with a real hello; the fake
	// above is byte-shaped like it (tool, address, kind, version, label,
	// fingerprint, ops) so the control exercises the same members.
}

// Review rev3 F1 regression, through Start and Call: the client enforces
// the closed error surface (StreamErrorCodes) it documents. A startup
// hello with ok:false whose code is undeclared ("self_minted") or empty is
// ErrProtocol, not a *Error; a mid-stream refusal with an undeclared code
// is ErrProtocol, the process is reaped (Close returns the kill status,
// not nil) and the next call fails with the same ErrProtocol without
// writing; a response with ok:false and no error object is likewise
// ErrProtocol. Controls: a declared startup code (not_found) is a *Error
// and a declared mid-stream code (unknown_op) is a *Error after which the
// session is still usable — proven in
// TestStartRefusesForeignContractAndSurfacesStartupErrors and
// TestCallProtocolViolationsAndRemoteErrors, and re-asserted here on
// every declared code the fake can produce so the check cannot be
// satisfied by refusing all codes.
func TestClientFailsClosedOnUndeclaredErrorCode(t *testing.T) {
	var remote *signerclient.Error
	for _, scenario := range []string{"startup-undeclared-code", "startup-empty-code"} {
		client, err := startFake(t, scenario)
		if !errors.Is(err, signerclient.ErrProtocol) || errors.As(err, &remote) || client != nil {
			t.Errorf("%s: (%v, %v), want ErrProtocol and no *Error", scenario, client, err)
		}
	}
	if _, err := startFake(t, "startup-error"); !errors.As(err, &remote) || remote.Code != signerclient.CodeNotFound || errors.Is(err, signerclient.ErrProtocol) {
		t.Errorf("declared startup code control: %v", err)
	}

	client, err := startFake(t, "undeclared-code")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Call(context.Background(), signerclient.Request{Op: signerclient.OpPub})
	if !errors.Is(err, signerclient.ErrProtocol) || errors.As(err, &remote) || !strings.Contains(err.Error(), "self_minted") {
		t.Fatalf("undeclared code: %v, want ErrProtocol naming the code and no *Error", err)
	}
	if _, err := client.Call(context.Background(), signerclient.Request{Op: signerclient.OpPub}); !errors.Is(err, signerclient.ErrProtocol) {
		t.Fatalf("client usable after an undeclared code: %v", err)
	}
	if err := client.Close(); err == nil {
		t.Fatal("Close returned nil: the fake was not killed on the undeclared code")
	}

	client, err = startFake(t, "no-error-object")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Call(context.Background(), signerclient.Request{Op: signerclient.OpPub}); !errors.Is(err, signerclient.ErrProtocol) {
		t.Fatalf("ok:false without error: %v, want ErrProtocol", err)
	}

	// Declared-code control across the whole registry: every Stream code
	// is accepted as a *Error (Lookup agrees), no undeclared one is, so
	// the gate is the registry and not a shorter private list.
	for _, code := range signerclient.StreamErrorCodes() {
		if !signerclient.IsStreamCode(code) {
			t.Errorf("declared stream code %q refused by IsStreamCode", code)
		}
	}
	for _, code := range []string{"", "self_minted", "SECURITY", "not-found", signerclient.CodeDuplicate, signerclient.CodeInvalidSchema} {
		if signerclient.IsStreamCode(code) {
			t.Errorf("%q accepted as a stream code", code)
		}
	}
	client, err = startFake(t, "ok")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Describe(context.Background()); !errors.As(err, &remote) || remote.Code != signerclient.CodeUnknownOp {
		t.Fatalf("declared mid-stream code control: %v", err)
	}
	if _, _, err := client.PublicKey(context.Background()); err != nil {
		t.Fatalf("session unusable after a declared code: %v", err)
	}
}

// Review rev4 F1 regression (repeat-of rev3 F1): the envelope is judged
// as one shape before ok is read, so a server cannot keep a foreign error
// code and flip ok to true past the closed-set gate. The table drives
// every combination of {ok, result present, error absent/declared/
// undeclared} (plus ok with result null) through the production entry
// points signerclient.Start
// (startup hello) and (*Client).Call (mid-stream, once as pub and once as
// verify). Exactly three shapes are admitted: ok+result+no error
// (success), fail+no result+declared (refusal, session usable), and
// fail+result+declared only for verify (the documented false verdict);
// startup admits the first two only. Every other row is ErrProtocol with
// no client at startup, and mid-stream an unusable client whose Close
// reports the kill (the fake would otherwise exit 0 on EOF). Controls:
// the admitted rows return a client / nil error / a *Error and the
// session answers the next request.
func TestClientRefusesMalformedEnvelopeBeforeReadingOK(t *testing.T) {
	type verdict int
	const (
		protocol verdict = iota // ErrProtocol, reaped, unusable
		success                 // nil error
		refusal                 // *Error with the declared code, session usable
	)
	// want[shape] = {hello, pub, verify}
	want := map[string][3]verdict{
		"ok-result-noerr":          {success, success, success},
		"ok-null-noerr":            {protocol, protocol, protocol},
		"ok-result-declared":       {protocol, protocol, protocol},
		"ok-result-undeclared":     {protocol, protocol, protocol},
		"ok-noresult-noerr":        {protocol, protocol, protocol},
		"ok-noresult-declared":     {protocol, protocol, protocol},
		"ok-noresult-undeclared":   {protocol, protocol, protocol},
		"fail-result-noerr":        {protocol, protocol, protocol},
		"fail-result-declared":     {protocol, protocol, refusal},
		"fail-result-undeclared":   {protocol, protocol, protocol},
		"fail-noresult-noerr":      {protocol, protocol, protocol},
		"fail-noresult-declared":   {refusal, refusal, protocol}, // verify: signature_invalid documents a verdict; none carried
		"fail-noresult-undeclared": {protocol, protocol, protocol},
	}
	if len(want) != len(envelopeShapes) {
		t.Fatalf("table covers %d of %d shapes", len(want), len(envelopeShapes))
	}
	shapes := make([]string, 0, len(want))
	for shape := range want {
		if _, ok := envelopeShapes[shape]; !ok {
			t.Fatalf("shape %q is not one the fake can write", shape)
		}
		shapes = append(shapes, shape)
	}
	sort.Strings(shapes)
	var remote *signerclient.Error
	judge := func(t *testing.T, err error, expect verdict) {
		t.Helper()
		switch expect {
		case protocol:
			if !errors.Is(err, signerclient.ErrProtocol) || errors.As(err, &remote) {
				t.Fatalf("%v, want ErrProtocol and no *Error", err)
			}
		case success:
			if err != nil {
				t.Fatalf("%v, want success", err)
			}
		case refusal:
			if !errors.As(err, &remote) || remote.Code != signerclient.CodeSignatureInvalid || errors.Is(err, signerclient.ErrProtocol) {
				t.Fatalf("%v, want *Error signature_invalid", err)
			}
		}
	}
	for _, shape := range shapes {
		expect := want[shape]
		t.Run("hello/"+shape, func(t *testing.T) {
			client, err := startFake(t, "envelope-hello-"+shape)
			judge(t, err, expect[0])
			if (client != nil) != (expect[0] == success) {
				t.Fatalf("client %v returned for %v", client, err)
			}
		})
		for i, op := range []string{signerclient.OpPub, signerclient.OpVerify} {
			t.Run(op+"/"+shape, func(t *testing.T) {
				scenario := "envelope-" + shape
				if op == signerclient.OpVerify {
					scenario = "envelope-verify-" + shape // pub and sign stay honest
				}
				client, err := startFake(t, scenario)
				if err != nil {
					t.Fatal(err)
				}
				req := signerclient.Request{Op: op}
				if op == signerclient.OpVerify {
					// A signature the hello key made, so the honest verdict
					// is true for the ok shapes; tampered for the others,
					// so the honest verdict is the documented false one.
					digest := sha256.Sum256([]byte("envelope " + shape))
					der, _, err := client.Sign(context.Background(), digest[:], signerclient.FormatDERLowS)
					if err != nil {
						t.Fatal(err)
					}
					if !envelopeShapes[shape].ok {
						der[len(der)-1] ^= 0x01
					}
					req.Digest = hex.EncodeToString(digest[:])
					req.Signature = hex.EncodeToString(der)
				}
				resp, err := client.Call(context.Background(), req)
				judge(t, err, expect[1+i])
				if expect[1+i] == protocol {
					if len(resp.Result) != 0 || resp.Error != nil {
						t.Fatalf("a refused envelope leaked its members: %+v", resp)
					}
					if _, err := client.Call(context.Background(), signerclient.Request{Op: signerclient.OpPub}); !errors.Is(err, signerclient.ErrProtocol) {
						t.Fatalf("client usable after a malformed envelope: %v", err)
					}
					if err := client.Close(); err == nil {
						t.Fatal("Close returned nil: the fake was not killed on the malformed envelope")
					}
					return
				}
				if _, err := client.Call(context.Background(), req); err != nil && !errors.As(err, &remote) {
					t.Fatalf("session unusable after an admitted envelope: %v", err)
				}
				if expect[1+i] == refusal && op == signerclient.OpVerify && shape == "fail-result-declared" {
					var v signerclient.Verdict
					if err := json.Unmarshal(resp.Result, &v); err != nil || v.Verified {
						t.Fatalf("documented false verdict not returned next to the refusal: %v %+v", err, v)
					}
				}
				if err := client.Close(); err != nil {
					t.Fatalf("Close after an admitted envelope: %v", err)
				}
			})
		}
	}
}

// Review rev5 F1 regression (repeat-of rev4 F1, rev3 F1): the envelope
// gate judges the RAW line — member presence, null, JSON type, unknown
// members — before the typed Response exists, because a typed decode
// erases the difference between an absent ok and false, an absent error
// and null, a missing error.message and "". Every row of rawEnvelopeRows
// is written verbatim by the fake server (never through Response) and
// driven through the production entry points signerclient.Start (hello)
// and (*Client).Call (mid-stream). Claims: the rows the contract
// documents are admitted (controls: success, refusal, refusal with
// os_status, verify's false verdict next to signature_invalid); every
// presence/null/type/extra-member row is ErrProtocol with no *Error, the
// server is killed (Close reports the kill mid-stream; at startup no
// client is returned), and the client is unusable afterwards; the two
// contract-member rows are ErrContract as documented on Start. Coverage
// is logged as a ratio over the corpus. Bound: the fake is the test
// binary, so this proves the client gate, not the server's emission (the
// goldens do that).
func TestClientRefusesEnvelopeMissingOrNullMembers(t *testing.T) {
	rows := make([]string, 0, len(rawEnvelopeRows))
	for name := range rawEnvelopeRows {
		rows = append(rows, name)
	}
	sort.Strings(rows)
	var remote *signerclient.Error
	judge := func(t *testing.T, err error, expect rawEnvelopeVerdict, code string) {
		t.Helper()
		switch expect {
		case rawProtocol:
			if !errors.Is(err, signerclient.ErrProtocol) || errors.As(err, &remote) {
				t.Fatalf("%v, want ErrProtocol and no *Error", err)
			}
		case rawContract:
			if !errors.Is(err, signerclient.ErrContract) || errors.As(err, &remote) {
				t.Fatalf("%v, want ErrContract and no *Error", err)
			}
		case rawSuccess:
			if err != nil {
				t.Fatalf("%v, want success", err)
			}
		case rawRefusal:
			if !errors.As(err, &remote) || remote.Code != code || remote.Message != "m" || remote.Hint != "h" || errors.Is(err, signerclient.ErrProtocol) {
				t.Fatalf("%v, want *Error %s with message m and hint h", err, code)
			}
		}
	}
	driven, applicable := 0, 0
	for _, name := range rows {
		row := rawEnvelopeRows[name]
		if row.hello != rawSkip {
			applicable++
			t.Run("hello/"+name, func(t *testing.T) {
				client, err := startFake(t, "raw-hello-"+name)
				judge(t, err, row.hello, row.code)
				if (client != nil) != (row.hello == rawSuccess) {
					t.Fatalf("client %v returned for %v", client, err)
				}
				driven++
			})
		}
		if row.call != rawSkip {
			applicable++
			t.Run("call/"+name, func(t *testing.T) {
				client, err := startFake(t, "raw-"+name)
				if err != nil {
					t.Fatal(err)
				}
				req := signerclient.Request{Op: signerclient.OpPub}
				if row.verifyOp {
					req = signerclient.Request{Op: signerclient.OpVerify, Digest: strings.Repeat("ab", signerclient.DigestSize), Signature: "3006020101020101"}
				}
				resp, err := client.Call(context.Background(), req)
				judge(t, err, row.call, row.code)
				if row.call == rawProtocol {
					if len(resp.Result) != 0 || resp.Error != nil {
						t.Fatalf("a refused envelope leaked its members: %+v", resp)
					}
					if _, err := client.Call(context.Background(), req); !errors.Is(err, signerclient.ErrProtocol) {
						t.Fatalf("client usable after a refused envelope: %v", err)
					}
					if err := client.Close(); err == nil {
						t.Fatal("Close returned nil: the fake was not killed on the refused envelope")
					}
					driven++
					return
				}
				if row.verifyOp && row.call == rawRefusal {
					var v signerclient.Verdict
					if err := json.Unmarshal(resp.Result, &v); err != nil || v.Verified || v.Digest != req.Digest {
						t.Fatalf("documented false verdict not returned next to the refusal: %v %+v", err, v)
					}
				}
				if _, err := client.Call(context.Background(), req); err != nil && !errors.As(err, &remote) {
					t.Fatalf("session unusable after an admitted envelope: %v", err)
				}
				if err := client.Close(); err != nil {
					t.Fatalf("Close after an admitted envelope: %v", err)
				}
				driven++
			})
		}
	}
	t.Logf("raw envelope corpus: %d of %d applicable rows driven (%d rows)", driven, applicable, len(rows))
	if driven != applicable {
		t.Errorf("raw envelope corpus: %d of %d applicable rows driven", driven, applicable)
	}
}

// A response whose id is not the pending request's is ErrProtocol and
// the client stays broken (the next call fails without writing); a server
// that ends the stream after the hello is ErrProtocol on the first call;
// a server that never answers is ended by the context (ctx.Err() is
// returned and the process is killed); a remote refusal (unknown_op from
// the fake) is a *Error and the client stays usable.
func TestCallProtocolViolationsAndRemoteErrors(t *testing.T) {
	client, err := startFake(t, "id-mismatch")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Call(context.Background(), signerclient.Request{Op: signerclient.OpPub}); !errors.Is(err, signerclient.ErrProtocol) {
		t.Fatalf("id mismatch: %v", err)
	}
	if _, err := client.Call(context.Background(), signerclient.Request{Op: signerclient.OpPub}); !errors.Is(err, signerclient.ErrProtocol) {
		t.Fatalf("broken client accepted a call: %v", err)
	}

	client, err = startFake(t, "exit-early")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Call(context.Background(), signerclient.Request{Op: signerclient.OpPub}); !errors.Is(err, signerclient.ErrProtocol) {
		t.Fatalf("exit-early: %v", err)
	}

	client, err = startFake(t, "silent")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := client.Call(ctx, signerclient.Request{Op: signerclient.OpPub}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("silent: %v, want DeadlineExceeded", err)
	}

	client, err = startFake(t, "ok")
	if err != nil {
		t.Fatal(err)
	}
	var remote *signerclient.Error
	if _, err := client.Describe(context.Background()); !errors.As(err, &remote) || remote.Code != signerclient.CodeUnknownOp {
		t.Fatalf("remote error: %v", err)
	}
	if _, _, err := client.PublicKey(context.Background()); err != nil {
		t.Fatalf("client unusable after a remote error: %v", err)
	}
}

// The typed calls decode the contract's result shapes: PublicKey parses
// the SPKI, Sign returns DER that crypto/ecdsa verifies under it, and
// CryptoSigner signs an x509 certificate that checks against itself;
// CryptoSigner refuses a non-SHA-256 SignerOpts and a mis-sized digest
// before any request is sent.
func TestTypedCallsAgainstFake(t *testing.T) {
	client, err := startFake(t, "ok")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, pub, err := client.PublicKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("typed calls"))
	der, sig, err := client.Sign(ctx, digest[:], signerclient.FormatDERLowS)
	if err != nil || sig.Digest != hex.EncodeToString(digest[:]) || !ecdsa.VerifyASN1(pub, digest[:], der) {
		t.Fatalf("sign: %v %+v", err, sig)
	}
	signer, err := client.CryptoSigner(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !signer.Public().(*ecdsa.PublicKey).Equal(pub) {
		t.Fatal("CryptoSigner public key differs from pub")
	}
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA512); err == nil {
		t.Fatal("CryptoSigner accepted SHA-512 opts")
	}
	if _, err := signer.Sign(rand.Reader, digest[:31], crypto.SHA256); err == nil {
		t.Fatal("CryptoSigner accepted a 31-byte digest")
	}
	certDER := selfSign(t, signer)
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("self-signed certificate does not verify: %v", err)
	}
}

func selfSign(t *testing.T, signer crypto.Signer) []byte {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "signerclient test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatalf("CreateCertificate through the vault signer: %v", err)
	}
	return certDER
}

// buildBinary compiles cmd/mac-keyvault into a temp dir: the e2e test
// drives the real executable, not the package.
func buildBinary(t *testing.T) string {
	t.Helper()
	testguard.Require(t)
	binary := filepath.Join(t.TempDir(), "mac-keyvault")
	build := exec.Command("go", "build", "-o", binary, "../../../cmd/mac-keyvault")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return binary
}

func fingerprintOf(spki []byte) string {
	sum := sha256.Sum256(spki)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func runCLI(t *testing.T, binary string, args ...string) (int, map[string]any) {
	t.Helper()
	testguard.Require(t)
	cmd := exec.Command(binary, append([]string{"--json"}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("%v: not an envelope: %s / %s", args, stdout.String(), stderr.String())
	}
	return code, envelope
}

// End to end through the built mac-keyvault binary on this Mac: a key
// under service test is created by the CLI, the client starts `signer
// serve` against it and the hello names a test label; Describe returns
// the record, PublicKey parses, Sign (DER and raw) verifies with
// crypto/ecdsa under that key, Verify returns true, a tampered signature
// is a *Error signature_invalid with Verdict.Verified false and the
// session stays usable, CryptoSigner produces a self-signed X.509
// certificate that checks against itself, Close returns nil (exit 0 on
// EOF). Starting against a raw label is a *Error foreign_label from the
// binary. The key is deleted afterwards. Stated bound: kvctl is not
// code yet, so this Go client is the only consumer the contract is
// proven against.
func TestClientAgainstBuiltBinaryAndLoginKeychain(t *testing.T) {
	binary := buildBinary(t)
	purpose := fmt.Sprintf("signerclient-e2e-%d", os.Getpid())
	address := "test/" + purpose
	if code, env := runCLI(t, binary, "init", "--service", "test", "--purpose", purpose, "--usages", "sign,verify", "--title", "signerclient e2e"); code != 0 {
		t.Fatalf("init: %v", env)
	}
	// Both generations (v1 from init, v2 from the rotate below) are
	// deleted by version so no other item is ever addressed.
	t.Cleanup(func() {
		for _, version := range []string{"2", "1"} {
			if code, env := runCLI(t, binary, "delete", address, "--confirm", "--version", version); code != 0 {
				t.Errorf("cleanup delete v%s: %v", version, env)
			}
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var remote *signerclient.Error
	if _, err := signerclient.Start(ctx, signerclient.Options{Binary: binary, Address: "works.relux.mac-keyvault.key.test." + purpose + ".v1"}); !errors.As(err, &remote) || remote.Code != "foreign_label" {
		t.Fatalf("raw label: %v, want foreign_label", err)
	}
	if _, err := signerclient.Start(ctx, signerclient.Options{Binary: binary, Address: "test/" + purpose + "-absent"}); !errors.As(err, &remote) || remote.Code != "not_found" {
		t.Fatalf("absent: %v, want not_found", err)
	}

	client, err := signerclient.Start(ctx, signerclient.Options{Binary: binary, Address: address, Stderr: os.Stderr})
	if err != nil {
		t.Fatal(err)
	}
	hello := client.Hello()
	if !strings.HasPrefix(hello.Label, "works.relux.mac-keyvault.key.test.") || hello.Label != "works.relux.mac-keyvault.key.test."+purpose+".v1" || hello.Version != 1 || hello.Tool != "mac-keyvault" || strings.Join(hello.Ops, ",") != strings.Join(signerclient.Ops, ",") {
		t.Fatalf("hello: %+v", hello)
	}
	// Review rev1 F1 regression, through the built binary: a rotate
	// between the hello and the first request must not move the session
	// to v2 — pub, describe and sign keep answering with the v1
	// fingerprint the hello attested. Controls: a fresh unpinned session
	// binds v2 (newest at its hello) with a different fingerprint, and a
	// session started with Version 1 binds v1 again.
	if code, env := runCLI(t, binary, "rotate", address); code != 0 {
		t.Fatalf("rotate: %v", env)
	}
	if _, pubV1, err := client.PublicKey(ctx); err != nil {
		t.Fatal(err)
	} else if spkiV1, _ := x509.MarshalPKIXPublicKey(pubV1); fingerprintOf(spkiV1) != hello.Fingerprint {
		t.Fatalf("pub after rotate: fingerprint %s, hello attested %s (unversioned session followed the newest generation)", fingerprintOf(spkiV1), hello.Fingerprint)
	}
	if view, err := client.Describe(ctx); err != nil || view.Label != hello.Label {
		t.Fatalf("describe after rotate: %v %v", err, view.Label)
	}
	rotated, err := signerclient.Start(ctx, signerclient.Options{Binary: binary, Address: address})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Hello().Version != 2 || rotated.Hello().Fingerprint == hello.Fingerprint {
		t.Fatalf("fresh session after rotate: %+v", rotated.Hello())
	}
	_ = rotated.Close()
	pinned, err := signerclient.Start(ctx, signerclient.Options{Binary: binary, Address: address, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	if pinned.Hello().Version != 1 || pinned.Hello().Fingerprint != hello.Fingerprint {
		t.Fatalf("--version 1 session: %+v", pinned.Hello())
	}
	_ = pinned.Close()
	view, err := client.Describe(ctx)
	if err != nil || view.Label != hello.Label || view.Title != "signerclient e2e" || view.Fingerprint != hello.Fingerprint || view.Schema != signerclient.SchemaVersion || view.Version != hello.Version {
		t.Fatalf("describe: %v %+v", err, view)
	}
	spki, pub, err := client.PublicKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spki)
	if base64.RawURLEncoding.EncodeToString(sum[:]) != hello.Fingerprint {
		t.Fatal("fingerprint is not SHA-256 of the streamed SPKI")
	}
	pem, err := client.PublicKeyPEM(ctx)
	if err != nil || !strings.HasPrefix(pem, "-----BEGIN PUBLIC KEY-----") {
		t.Fatalf("pem: %v %q", err, pem)
	}
	digest := sha256.Sum256([]byte("e2e " + purpose))
	der, sig, err := client.Sign(ctx, digest[:], "")
	if err != nil || sig.Format != signerclient.FormatDERLowS || !sig.LowS || sig.Fingerprint != hello.Fingerprint || !ecdsa.VerifyASN1(pub, digest[:], der) {
		t.Fatalf("sign: %v %+v", err, sig)
	}
	raw, sigRaw, err := client.Sign(ctx, digest[:], signerclient.FormatRaw)
	if err != nil || sigRaw.Format != signerclient.FormatRaw || len(raw) != 64 || !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])) {
		t.Fatalf("sign raw: %v %+v", err, sigRaw)
	}
	verdict, err := client.Verify(ctx, digest[:], der, signerclient.FormatDERLowS, false)
	if err != nil || !verdict.Verified {
		t.Fatalf("verify: %v %+v", err, verdict)
	}
	tampered := append([]byte(nil), der...)
	tampered[len(tampered)-1] ^= 0x01
	verdict, err = client.Verify(ctx, digest[:], tampered, signerclient.FormatDERLowS, false)
	if !errors.As(err, &remote) || remote.Code != "signature_invalid" || verdict.Verified {
		t.Fatalf("tampered: %v %+v", err, verdict)
	}
	if _, err := client.Verify(ctx, digest[:31], der, signerclient.FormatDERLowS, false); !errors.As(err, &remote) || remote.Code != "invalid_digest" {
		t.Fatalf("short digest: %v", err)
	}
	signer, err := client.CryptoSigner(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(selfSign(t, signer))
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("certificate signed through the vault does not verify: %v", err)
	}
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(pub) {
		t.Fatal("certificate carries another public key")
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close (exit on EOF): %v", err)
	}
}

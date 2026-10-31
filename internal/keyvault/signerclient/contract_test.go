package signerclient_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"sort"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
)

// verdict is what the client must do with one shaped line.
type verdict int

const (
	protocol verdict = iota // ErrProtocol, server killed, client unusable
	success                 // nil error
	refusal                 // *Error with the named code, session usable
)

// dupRow is one line with a member repeated. The CONTRADICTORY value is
// written first and the honest one last, the order a map or struct
// decode collapses to the honest value — so a client whose gate runs
// after such a decode admits every one of these rows (review rev6 F1).
// hello builds the hello line; call builds the response to the request
// the row's op names (every other request is answered honestly).
type dupRow struct {
	op    string
	hello func(k *fakeKey) string
	call  func(k *fakeKey, req signerclient.Request) string
	want  verdict
	code  string // refusal rows: the declared code
}

// withFirst renders result with one extra member written FIRST, spelt
// as given (so an escape-spelt name can be injected verbatim).
func withFirst(result map[string]any, spelling string, value any) string {
	return `{"` + spelling + `":` + string(mustJSON(value)) + `,` + rawObject(result) + `}`
}

// nestedFirst renders result and injects one extra member, spelt as
// given, as the FIRST member of the nested object (or first array
// element's object) that opens right after anchor, e.g. `"format":{` or
// `"operations":[{`.
func nestedFirst(result map[string]any, anchor, spelling string, value any) string {
	rendered := string(mustJSON(result))
	i := strings.Index(rendered, anchor)
	if i < 0 {
		panic("nestedFirst: anchor " + anchor + " not in " + rendered)
	}
	i += len(anchor)
	return rendered[:i] + `"` + spelling + `":` + string(mustJSON(value)) + `,` + rendered[i:]
}

func helloLine(k *fakeKey, head string) string {
	return `{` + head + `"ok":true,"result":` + string(mustJSON(k.hello())) + `}`
}

func okLine(k *fakeKey, req signerclient.Request, head, result string) string {
	return `{` + head + `"ok":true,"result":` + result + `}`
}

func honestResult(k *fakeKey, req signerclient.Request) map[string]any {
	result, _ := k.answer(req)
	return result
}

const foreignFingerprint = "foreign-fingerprint"

var duplicateRows = map[string]dupRow{
	// envelope members, verbatim and escape-spelt
	"envelope-contract": {
		hello: func(k *fakeKey) string { return helloLine(k, `"contract":2,"contract":1,`) },
		op:    signerclient.OpPub,
		call: func(k *fakeKey, req signerclient.Request) string {
			return okLine(k, req, `"id":999,"id":`+string(req.ID)+`,`, string(mustJSON(honestResult(k, req))))
		},
	},
	"envelope-contract-escaped": {
		hello: func(k *fakeKey) string { return helloLine(k, `"co\u006etract":2,"contract":1,`) },
		op:    signerclient.OpPub,
		call: func(k *fakeKey, req signerclient.Request) string {
			return okLine(k, req, `"i\u0064":999,"id":`+string(req.ID)+`,`, string(mustJSON(honestResult(k, req))))
		},
	},
	"envelope-ok": {
		hello: func(k *fakeKey) string {
			return `{"contract":1,"ok":false,` + strings.TrimPrefix(helloLine(k, ""), "{")
		},
		op: signerclient.OpPub,
		call: func(k *fakeKey, req signerclient.Request) string {
			return `{"id":` + string(req.ID) + `,"ok":false,"ok":true,"result":` + string(mustJSON(honestResult(k, req))) + `}`
		},
	},
	"envelope-ok-escaped": {
		hello: func(k *fakeKey) string {
			return `{"contract":1,"\u006fk":false,` + strings.TrimPrefix(helloLine(k, ""), "{")
		},
		op: signerclient.OpPub,
		call: func(k *fakeKey, req signerclient.Request) string {
			return `{"id":` + string(req.ID) + `,"\u006fk":false,"ok":true,"result":` + string(mustJSON(honestResult(k, req))) + `}`
		},
	},
	// the nested error object: an undeclared code first, a declared one last
	"error-code": {
		hello: func(k *fakeKey) string {
			return `{"contract":1,"ok":false,"error":{"code":"self_minted","code":"not_found","message":"m","hint":"h"}}`
		},
		op: signerclient.OpPub,
		call: func(k *fakeKey, req signerclient.Request) string {
			return `{"id":` + string(req.ID) + `,"ok":false,"error":{"code":"self_minted","code":"not_found","message":"m","hint":"h"}}`
		},
	},
	"error-code-escaped": {
		hello: func(k *fakeKey) string {
			return `{"contract":1,"ok":false,"error":{"c\u006fde":"self_minted","code":"not_found","message":"m","hint":"h"}}`
		},
		op: signerclient.OpPub,
		call: func(k *fakeKey, req signerclient.Request) string {
			return `{"id":` + string(req.ID) + `,"ok":false,"error":{"c\u006fde":"self_minted","code":"not_found","message":"m","hint":"h"}}`
		},
	},
	// the hello result
	"hello-tool": {
		hello: func(k *fakeKey) string {
			return `{"contract":1,"ok":true,"result":` + withFirst(k.hello(), "tool", "impostor") + `}`
		},
	},
	"hello-tool-escaped": {
		hello: func(k *fakeKey) string {
			return `{"contract":1,"ok":true,"result":` + withFirst(k.hello(), `t\u006fol`, "impostor") + `}`
		},
	},
	"hello-fingerprint": {
		hello: func(k *fakeKey) string {
			return `{"contract":1,"ok":true,"result":` + withFirst(k.hello(), "fingerprint", foreignFingerprint) + `}`
		},
	},
	// op results
	"pub-fingerprint": {
		op: signerclient.OpPub,
		call: func(k *fakeKey, req signerclient.Request) string {
			return okLine(k, req, `"id":`+string(req.ID)+`,`, withFirst(honestResult(k, req), "fingerprint", foreignFingerprint))
		},
	},
	"pub-fingerprint-escaped": {
		op: signerclient.OpPub,
		call: func(k *fakeKey, req signerclient.Request) string {
			return okLine(k, req, `"id":`+string(req.ID)+`,`, withFirst(honestResult(k, req), `fingerpr\u0069nt`, foreignFingerprint))
		},
	},
	"sign-digest": {
		op: signerclient.OpSign,
		call: func(k *fakeKey, req signerclient.Request) string {
			return okLine(k, req, `"id":`+string(req.ID)+`,`, withFirst(honestResult(k, req), "digest", "00"))
		},
	},
	"sign-signature-escaped": {
		op: signerclient.OpSign,
		call: func(k *fakeKey, req signerclient.Request) string {
			return okLine(k, req, `"id":`+string(req.ID)+`,`, withFirst(honestResult(k, req), `sign\u0061ture`, "00"))
		},
	},
	"verify-verified": { // the request carries a tampered signature: the honest verdict is false
		op: signerclient.OpVerify,
		call: func(k *fakeKey, req signerclient.Request) string {
			return `{"id":` + string(req.ID) + `,"ok":false,"result":` + withFirst(honestResult(k, req), "verified", true) + `,"error":{"code":"signature_invalid","message":"m","hint":"h"}}`
		},
	},
	"describe-label": {
		op: signerclient.OpDescribe,
		call: func(k *fakeKey, req signerclient.Request) string {
			return okLine(k, req, `"id":`+string(req.ID)+`,`, withFirst(honestResult(k, req), "label", "foreign-label"))
		},
	},
	// nested objects of the describe result (review rev8 F1, repeat-of
	// rev6 F1): a closed struct at depth 1 of the result (format, origin,
	// validity), the open meta map, and an operation entry inside the
	// operations ARRAY. Each carries the contradictory value first, the
	// honest one last, verbatim or escape-spelt; a gate that judges only
	// the object it is handed and lets encoding/json materialise the rest
	// admits every one of them with the honest value.
	"describe-format-public": {
		op: signerclient.OpDescribe,
		call: func(k *fakeKey, req signerclient.Request) string {
			return okLine(k, req, `"id":`+string(req.ID)+`,`, nestedFirst(honestResult(k, req), `"format":{`, "public", "wrong"))
		},
	},
	"describe-format-public-escaped": {
		op: signerclient.OpDescribe,
		call: func(k *fakeKey, req signerclient.Request) string {
			return okLine(k, req, `"id":`+string(req.ID)+`,`, nestedFirst(honestResult(k, req), `"format":{`, `publ\u0069c`, "wrong"))
		},
	},
	"describe-origin-user-escaped": {
		op: signerclient.OpDescribe,
		call: func(k *fakeKey, req signerclient.Request) string {
			return okLine(k, req, `"id":`+string(req.ID)+`,`, nestedFirst(honestResult(k, req), `"origin":{`, `u\u0073er`, "attacker"))
		},
	},
	"describe-validity-not-before": {
		op: signerclient.OpDescribe,
		call: func(k *fakeKey, req signerclient.Request) string {
			return okLine(k, req, `"id":`+string(req.ID)+`,`, nestedFirst(honestResult(k, req), `"validity":{`, "not_before", "2020-01-01T00:00:00Z"))
		},
	},
	"describe-meta-owner": {
		op: signerclient.OpDescribe,
		call: func(k *fakeKey, req signerclient.Request) string {
			return okLine(k, req, `"id":`+string(req.ID)+`,`, nestedFirst(honestResult(k, req), `"meta":{`, "owner", "attacker"))
		},
	},
	"describe-meta-owner-escaped": {
		op: signerclient.OpDescribe,
		call: func(k *fakeKey, req signerclient.Request) string {
			return okLine(k, req, `"id":`+string(req.ID)+`,`, nestedFirst(honestResult(k, req), `"meta":{`, `own\u0065r`, "attacker"))
		},
	},
	"describe-operations-name": {
		op: signerclient.OpDescribe,
		call: func(k *fakeKey, req signerclient.Request) string {
			return okLine(k, req, `"id":`+string(req.ID)+`,`, nestedFirst(honestResult(k, req), `"operations":[{`, "name", "forged"))
		},
	},
	"describe-operations-name-escaped": {
		op: signerclient.OpDescribe,
		call: func(k *fakeKey, req signerclient.Request) string {
			return okLine(k, req, `"id":`+string(req.ID)+`,`, nestedFirst(honestResult(k, req), `"operations":[{`, `na\u006de`, "forged"))
		},
	},
	"describe-operations-last-via": { // not the first array element: the walk must not stop at [0]
		op: signerclient.OpDescribe,
		call: func(k *fakeKey, req signerclient.Request) string {
			result := string(mustJSON(honestResult(k, req)))
			i := strings.LastIndex(result, `"via":"pub"`)
			return okLine(k, req, `"id":`+string(req.ID)+`,`, result[:i]+`"via":"sign",`+result[i:])
		},
	},
	// hello result nested? the hello carries no object below the result,
	// so the depth-1 hello rows above are its whole surface.
	// controls: the honest line, an escape-spelt SINGLE member (decoded
	// names are compared, escapes as such are not refused), and a
	// declared refusal
	"control-honest": {
		hello: func(k *fakeKey) string { return helloLine(k, `"contract":1,`) },
		op:    signerclient.OpPub,
		call: func(k *fakeKey, req signerclient.Request) string {
			return okLine(k, req, `"id":`+string(req.ID)+`,`, string(mustJSON(honestResult(k, req))))
		},
		want: success,
	},
	"control-escaped-single": {
		hello: func(k *fakeKey) string { return helloLine(k, `"co\u006etract":1,`) },
		op:    signerclient.OpSign,
		call: func(k *fakeKey, req signerclient.Request) string {
			result := honestResult(k, req)
			sig := result["signature"]
			delete(result, "signature")
			return okLine(k, req, `"i\u0064":`+string(req.ID)+`,`, withFirst(result, `sign\u0061ture`, sig))
		},
		want: success,
	},
	"control-describe-honest": { // operations[0..2] each carry name/via: one name in sibling objects is not a repeat
		op: signerclient.OpDescribe,
		call: func(k *fakeKey, req signerclient.Request) string {
			return okLine(k, req, `"id":`+string(req.ID)+`,`, string(mustJSON(honestResult(k, req))))
		},
		want: success,
	},
	"control-describe-escaped-single-nested": { // an escape-spelt SINGLE nested member is admitted under its decoded name
		op: signerclient.OpDescribe,
		call: func(k *fakeKey, req signerclient.Request) string {
			result := honestResult(k, req)
			format := result["format"].(map[string]any)
			result["format"] = map[string]any{"signature": format["signature"]}
			line := nestedFirst(result, `"format":{`, `publ\u0069c`, format["public"])
			return okLine(k, req, `"id":`+string(req.ID)+`,`, strings.Replace(line, `"operations":[{"name"`, `"operations":[{"na\u006de"`, 1))
		},
		want: success,
	},
	"control-refusal": {
		hello: func(k *fakeKey) string {
			return `{"contract":1,"ok":false,"error":{"code":"not_found","message":"m","hint":"h"}}`
		},
		op: signerclient.OpPub,
		call: func(k *fakeKey, req signerclient.Request) string {
			return `{"id":` + string(req.ID) + `,"ok":false,"error":{"code":"not_found","message":"m","hint":"h"}}`
		},
		want: refusal,
		code: "not_found",
	},
}

// driveOp sends the row's op through the typed helper a consumer uses
// and returns its error; for verify it first obtains a signature from
// the (honest) sign op and tampers or re-forms it as asked.
func driveOp(t *testing.T, client *signerclient.Client, op, format string, tamper, highS, allowHighS bool) error {
	t.Helper()
	ctx := context.Background()
	digest := sha256.Sum256([]byte("contract test"))
	switch op {
	case signerclient.OpDescribe:
		_, err := client.Describe(ctx)
		return err
	case signerclient.OpPub:
		if format == signerclient.FormatSPKIPEM {
			_, err := client.PublicKeyPEM(ctx)
			return err
		}
		_, _, err := client.PublicKey(ctx)
		return err
	case signerclient.OpSign:
		_, _, err := client.Sign(ctx, digest[:], format)
		return err
	case signerclient.OpVerify:
		sig, _, err := client.Sign(ctx, digest[:], format)
		if err != nil {
			t.Fatalf("sign before verify: %v", err)
		}
		effective := format
		if effective == "" {
			effective = signerclient.FormatDERLowS
		}
		r, s, err := signerclient.ParseSignature(sig, effective)
		if err != nil {
			t.Fatal(err)
		}
		if tamper {
			r = new(big.Int).Add(r, big.NewInt(1))
		}
		if highS {
			s = new(big.Int).Sub(elliptic.P256().Params().N, s)
		}
		_, err = client.Verify(ctx, digest[:], encodeSignature(r, s, effective), format, allowHighS)
		return err
	}
	t.Fatalf("op %q", op)
	return nil
}

// judgeLine asserts the verdict a shaped line must get, and for a
// protocol verdict that the session is dead: no *Error, the next call
// ErrProtocol, Close reporting the kill.
func judgeLine(t *testing.T, client *signerclient.Client, err error, want verdict, code string) {
	t.Helper()
	var remote *signerclient.Error
	switch want {
	case protocol:
		if !errors.Is(err, signerclient.ErrProtocol) || errors.As(err, &remote) {
			t.Fatalf("%v, want ErrProtocol and no *Error", err)
		}
		if client == nil {
			return
		}
		if _, err := client.Call(context.Background(), signerclient.Request{Op: signerclient.OpPub}); !errors.Is(err, signerclient.ErrProtocol) {
			t.Fatalf("client usable after a protocol violation: %v", err)
		}
		if err := client.Close(); err == nil {
			t.Fatal("Close returned nil: the fake was not killed")
		}
	case success:
		if err != nil {
			t.Fatalf("%v, want success", err)
		}
	case refusal:
		if !errors.As(err, &remote) || remote.Code != code || errors.Is(err, signerclient.ErrProtocol) {
			t.Fatalf("%v, want *Error %s", err, code)
		}
	}
	if client != nil && want != protocol {
		if _, err := client.Call(context.Background(), signerclient.Request{Op: signerclient.OpPub}); err != nil && !errors.As(err, &remote) {
			t.Fatalf("session unusable after an admitted line: %v", err)
		}
		if err := client.Close(); err != nil {
			t.Fatalf("Close after an admitted line: %v", err)
		}
	}
}

// Review rev6 F1 regression (repeat-of rev5 F1): every contract-bearing
// object the client reads — the envelope, its error member, the hello
// result, each op result — is read token by token, and a second member
// of one DECODED name is refused before any value is trusted, whether
// the repeat is spelt verbatim or with a JSON escape ("co\u006etract").
// Each row writes the contradictory value first and the honest one last,
// so a map or struct decode would collapse it to the honest value and
// admit the line; through signerclient.Start (hello) and (*Client).Call
// via the typed helpers (call) every such row is ErrProtocol naming the
// duplicate, no *Error, the fake reaped. Controls: the honest line, a
// single escape-spelt member (admitted: escapes are decoded, not
// refused) and a declared refusal are admitted.
//
// Rev8 F1 (repeat-of rev6 F1) extends the corpus BELOW the top level of
// the result: the describe-* rows repeat a member inside format, origin,
// validity, the open meta map and an operation entry inside the
// operations array (first and last element), verbatim and escape-spelt.
// These reach the client through the same production path
// (Start → Describe → Call → readResponse → decodeEnvelope →
// DecodeObject → CheckDocument) and prove the gate is the recursive
// document walk, not a per-object check: a walk limited to depth 0 or
// one that skips array elements admits them (mutants M1/M2). Controls:
// the honest describe (sibling operation entries legitimately share
// member names) and a nested escape-spelt single member. Bound: the fake
// is the test binary, so this proves the client gate; the server's
// request gate is TestSignerServeRefusesDuplicateMembers and the goldens.
func TestClientRefusesDuplicateMembers(t *testing.T) {
	names := make([]string, 0, len(duplicateRows))
	for name := range duplicateRows {
		names = append(names, name)
	}
	sort.Strings(names)
	driven, entries := 0, 0
	for _, name := range names {
		row := duplicateRows[name]
		if row.hello != nil {
			entries++
			t.Run("hello/"+name, func(t *testing.T) {
				client, err := startFake(t, "dup-hello-"+name)
				t.Logf("%v", err)
				if row.want == protocol && (err == nil || !strings.Contains(err.Error(), "duplicate member")) {
					t.Fatalf("%v does not name the duplicate", err)
				}
				judgeLine(t, nil, err, row.want, row.code)
				if (client != nil) != (row.want == success) {
					t.Fatalf("client %v returned for %v", client, err)
				}
				driven++
			})
		}
		if row.call != nil {
			entries++
			t.Run("call/"+name, func(t *testing.T) {
				client, err := startFake(t, "dup-"+name)
				if err != nil {
					t.Fatal(err)
				}
				err = driveOp(t, client, row.op, "", row.op == signerclient.OpVerify, false, false)
				t.Logf("%v", err)
				if row.want == protocol && (err == nil || !strings.Contains(err.Error(), "duplicate member")) {
					t.Fatalf("%v does not name the duplicate", err)
				}
				judgeLine(t, client, err, row.want, row.code)
				driven++
			})
		}
	}
	t.Logf("duplicate-member corpus: %d of %d entries driven (%d rows)", driven, entries, len(names))
	if driven != entries {
		t.Errorf("duplicate-member corpus: %d of %d entries driven", driven, entries)
	}
}

// resultRow is one op result that differs from the honest answer in one
// stated way: a member overridden (nil deletes it; json null is the
// literal null; a $-sentinel substitutes material from another key or
// another digest), the envelope code forced ("ok" forces success), the
// result dropped. want is what the typed helper must return.
type resultRow struct {
	op         string
	format     string
	tamper     bool // verify: send a signature that does not verify
	highS      bool // verify: send the high-S form
	allowHighS bool
	override   map[string]any
	code       string // force this code on the envelope ("ok": force ok)
	dropResult bool
	want       verdict
	wantCode   string
}

var jsonNull = json.RawMessage("null")

// shape is the fake's answer for the row: the honest result re-shaped.
func (r resultRow) shape(k *fakeKey, req signerclient.Request) signerclient.Response {
	result, code := k.answer(req)
	switch r.code {
	case "":
	case "ok":
		code = ""
	default:
		code = r.code
	}
	if r.dropResult {
		result = nil
	}
	digest, _ := hex.DecodeString(req.Digest)
	format := req.Format
	if format == "" {
		format = signerclient.FormatDERLowS
	}
	setSignature := func(sig []byte) {
		result["signature"] = hex.EncodeToString(sig)
		result["signature_base64"] = base64.StdEncoding.EncodeToString(sig)
	}
	for name, v := range r.override {
		switch v {
		case nil:
			delete(result, name)
		case "$FOREIGN_SIGNATURE":
			foreign, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			setSignature(k.sign(foreign, digest, format, false))
		case "$HIGH_S_SIGNATURE":
			setSignature(k.sign(nil, digest, format, true))
		case "$OTHER_DIGEST_SIGNATURE":
			other := sha256.Sum256([]byte("another payload"))
			setSignature(k.sign(nil, other[:], format, false))
		case "$FOREIGN_KEY_DER":
			result["der_base64"] = base64.StdEncoding.EncodeToString(newFakeKey().spki)
		case "$OWN_FINGERPRINT":
			result[name] = k.fingerprint()
		case "$FOREIGN_KEY_PEM":
			result["pem"] = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: newFakeKey().spki}))
		default:
			result[name] = v
		}
	}
	return response(req.ID, result, code)
}

var resultRows = map[string]resultRow{
	// describe (review rev7 F1): the result is the closed schema-2 record
	// decoded and judged by the vault's own rows, plus the derived
	// members, bound to the hello. One row per required member with the
	// WRONG JSON TYPE (the reviewer's probe: kind {}, version {}, service
	// [], purpose false, schema "two"), one per member with a wrong VALUE,
	// the invariant/finding mirror in both directions, and controls.
	"describe-control":                {op: signerclient.OpDescribe, want: success},
	"describe-control-invalid-record": {op: signerclient.OpDescribe, override: map[string]any{"usages": []any{}, "findings": []any{"record_invalid:invalid_usages"}}, want: success}, // the vault reports a violated row as a finding; the client agrees
	"describe-control-expired":        {op: signerclient.OpDescribe, override: map[string]any{"validity": map[string]any{"not_before": nil, "not_after": "2020-01-01T00:00:00Z"}, "findings": []any{"validity_expired"}}, want: success},
	"describe-control-no-primitive":   {op: signerclient.OpDescribe, override: map[string]any{"store": "enclave", "exposure": "unknown", "operations": []any{}, "findings": []any{"unsupported_primitive"}}, want: success},
	"describe-control-user-presence":  {op: signerclient.OpDescribe, override: map[string]any{"user_presence": true}, want: success}, // a schema field the view omits when false
	"describe-label-foreign":          {op: signerclient.OpDescribe, override: map[string]any{"label": "foreign-label"}},
	"describe-fingerprint-foreign":    {op: signerclient.OpDescribe, override: map[string]any{"fingerprint": foreignFingerprint}},
	"describe-label-missing":          {op: signerclient.OpDescribe, override: map[string]any{"label": nil}},
	"describe-fingerprint-null":       {op: signerclient.OpDescribe, override: map[string]any{"fingerprint": jsonNull}},
	"describe-findings-missing":       {op: signerclient.OpDescribe, override: map[string]any{"findings": nil}},
	"describe-operations-string":      {op: signerclient.OpDescribe, override: map[string]any{"operations": "sign"}},
	"describe-exposure-missing":       {op: signerclient.OpDescribe, override: map[string]any{"exposure": nil}},
	"describe-version-missing":        {op: signerclient.OpDescribe, override: map[string]any{"version": nil}},
	// wrong JSON type per required record member (the rev7 probe, one member at a time)
	"describe-kind-object":            {op: signerclient.OpDescribe, override: map[string]any{"kind": map[string]any{}}},
	"describe-version-object":         {op: signerclient.OpDescribe, override: map[string]any{"version": map[string]any{}}},
	"describe-version-string":         {op: signerclient.OpDescribe, override: map[string]any{"version": "1"}},
	"describe-version-float":          {op: signerclient.OpDescribe, override: map[string]any{"version": 1.5}},
	"describe-service-array":          {op: signerclient.OpDescribe, override: map[string]any{"service": []any{}}},
	"describe-purpose-bool":           {op: signerclient.OpDescribe, override: map[string]any{"purpose": false}},
	"describe-schema-string":          {op: signerclient.OpDescribe, override: map[string]any{"schema": "two"}},
	"describe-exposure-number":        {op: signerclient.OpDescribe, override: map[string]any{"exposure": 1}},
	"describe-findings-object":        {op: signerclient.OpDescribe, override: map[string]any{"findings": map[string]any{}}},
	"describe-findings-number":        {op: signerclient.OpDescribe, override: map[string]any{"findings": []any{1}}},
	"describe-label-number":           {op: signerclient.OpDescribe, override: map[string]any{"label": 7}},
	"describe-title-array":            {op: signerclient.OpDescribe, override: map[string]any{"title": []any{"x"}}},
	"describe-usages-string":          {op: signerclient.OpDescribe, override: map[string]any{"usages": "sign"}},
	"describe-format-string":          {op: signerclient.OpDescribe, override: map[string]any{"format": "spki-der"}},
	"describe-created-number":         {op: signerclient.OpDescribe, override: map[string]any{"created": 1700000000}},
	"describe-origin-string":          {op: signerclient.OpDescribe, override: map[string]any{"origin": "generated"}},
	"describe-validity-array":         {op: signerclient.OpDescribe, override: map[string]any{"validity": []any{}}},
	"describe-meta-array":             {op: signerclient.OpDescribe, override: map[string]any{"meta": []any{}}},
	"describe-store-object":           {op: signerclient.OpDescribe, override: map[string]any{"store": map[string]any{}}},
	"describe-operation-entry-string": {op: signerclient.OpDescribe, override: map[string]any{"operations": []any{"sign"}}},
	"describe-operation-name-number":  {op: signerclient.OpDescribe, override: map[string]any{"operations": []any{map[string]any{"name": 1, "input": "", "output": "", "via": "sign"}}}},
	// wrong VALUE per required member: not the identity the hello bound, or outside the model grammar
	"describe-schema-3":               {op: signerclient.OpDescribe, override: map[string]any{"schema": 3}},
	"describe-schema-0":               {op: signerclient.OpDescribe, override: map[string]any{"schema": 0}},
	"describe-kind-certificate":       {op: signerclient.OpDescribe, override: map[string]any{"kind": "certificate"}},
	"describe-kind-unknown":           {op: signerclient.OpDescribe, override: map[string]any{"kind": "unknown"}},
	"describe-version-2":              {op: signerclient.OpDescribe, override: map[string]any{"version": 2}},
	"describe-version-0":              {op: signerclient.OpDescribe, override: map[string]any{"version": 0}},
	"describe-service-other":          {op: signerclient.OpDescribe, override: map[string]any{"service": "prod"}},
	"describe-service-uppercase":      {op: signerclient.OpDescribe, override: map[string]any{"service": "TEST"}},
	"describe-purpose-other":          {op: signerclient.OpDescribe, override: map[string]any{"purpose": "other"}},
	"describe-purpose-empty":          {op: signerclient.OpDescribe, override: map[string]any{"purpose": ""}},
	"describe-label-other-generation": {op: signerclient.OpDescribe, override: map[string]any{"label": "works.relux.mac-keyvault.key.test.fake.v2"}},
	"describe-undefined-member":       {op: signerclient.OpDescribe, override: map[string]any{"colour": "red"}}, // DisallowUnknownFields, as the vault's own tag decode
	"describe-exposure-other":         {op: signerclient.OpDescribe, override: map[string]any{"exposure": "public"}},
	"describe-exposure-empty":         {op: signerclient.OpDescribe, override: map[string]any{"exposure": ""}},
	// invariant rows and findings must agree, in both directions, exactly as the vault reports them
	"describe-invalid-record-unreported":    {op: signerclient.OpDescribe, override: map[string]any{"usages": []any{}}},                                                     // row fails, no finding
	"describe-invalid-record-wrong-code":    {op: signerclient.OpDescribe, override: map[string]any{"usages": []any{}, "findings": []any{"record_invalid:invalid_format"}}}, // row fails, another code reported
	"describe-invalid-finding-clean-record": {op: signerclient.OpDescribe, override: map[string]any{"findings": []any{"record_invalid:invalid_usages"}}},                    // finding on a record that passes every row
	"describe-algorithm-ed25519":            {op: signerclient.OpDescribe, override: map[string]any{"algorithm": "ed25519"}},
	"describe-store-other":                  {op: signerclient.OpDescribe, override: map[string]any{"store": "cloud"}},
	"describe-extraction-other":             {op: signerclient.OpDescribe, override: map[string]any{"extraction": "always"}},
	"describe-issuer-on-key":                {op: signerclient.OpDescribe, override: map[string]any{"issuer": map[string]any{"dn": "CN=x", "fingerprint": "f"}}},
	"describe-not-before-on-key":            {op: signerclient.OpDescribe, override: map[string]any{"validity": map[string]any{"not_before": "2020-01-01T00:00:00Z", "not_after": nil}}},
	"describe-created-null":                 {op: signerclient.OpDescribe, override: map[string]any{"created": jsonNull}},
	"describe-origin-empty":                 {op: signerclient.OpDescribe, override: map[string]any{"origin": map[string]any{"user": "", "host": "", "tool": "", "source": "generated"}}},
	"describe-meta-reserved":                {op: signerclient.OpDescribe, override: map[string]any{"meta": map[string]any{"label": "x"}}},
	"describe-title-too-long":               {op: signerclient.OpDescribe, override: map[string]any{"title": strings.Repeat("x", 81)}},
	"describe-finding-unknown":              {op: signerclient.OpDescribe, override: map[string]any{"findings": []any{"looks_fine"}}},
	"describe-finding-duplicate":            {op: signerclient.OpDescribe, override: map[string]any{"validity": map[string]any{"not_before": nil, "not_after": "2020-01-01T00:00:00Z"}, "findings": []any{"validity_expired", "validity_expired"}}},
	"describe-expired-without-not-after":    {op: signerclient.OpDescribe, override: map[string]any{"findings": []any{"validity_expired"}}},
	"describe-exposure-unknown-with-row":    {op: signerclient.OpDescribe, override: map[string]any{"exposure": "unknown"}},
	"describe-no-primitive-with-exposure":   {op: signerclient.OpDescribe, override: map[string]any{"operations": []any{}, "findings": []any{"unsupported_primitive"}}},
	"describe-no-primitive-with-operations": {op: signerclient.OpDescribe, override: map[string]any{"exposure": "unknown", "findings": []any{"unsupported_primitive"}}},
	"describe-operation-without-via":        {op: signerclient.OpDescribe, override: map[string]any{"operations": []any{map[string]any{"name": "ecdsa-sha256-sign", "input": "", "output": ""}}}},
	"describe-operation-undefined-member":   {op: signerclient.OpDescribe, override: map[string]any{"operations": []any{map[string]any{"name": "ecdsa-sha256-sign", "input": "", "output": "", "via": "sign", "cost": 1}}}},
	"describe-refusal":                      {op: signerclient.OpDescribe, code: signerclient.CodeMetadataUnknown, dropResult: true, want: refusal, wantCode: signerclient.CodeMetadataUnknown},
	// pub: identity, format, one encoding that parses and fingerprints as the hello
	"pub-control-der":         {op: signerclient.OpPub, want: success},
	"pub-control-pem":         {op: signerclient.OpPub, format: signerclient.FormatSPKIPEM, want: success},
	"pub-label-foreign":       {op: signerclient.OpPub, override: map[string]any{"label": "foreign-label"}},
	"pub-fingerprint-foreign": {op: signerclient.OpPub, override: map[string]any{"fingerprint": foreignFingerprint}},
	"pub-fingerprint-missing": {op: signerclient.OpPub, override: map[string]any{"fingerprint": nil}},
	"pub-format-pem-for-der":  {op: signerclient.OpPub, override: map[string]any{"format": signerclient.FormatSPKIPEM}},
	"pub-format-unknown":      {op: signerclient.OpPub, override: map[string]any{"format": "jwk"}},
	"pub-der-foreign-key":     {op: signerclient.OpPub, override: map[string]any{"der_base64": "$FOREIGN_KEY_DER"}},
	"pub-der-garbage":         {op: signerclient.OpPub, override: map[string]any{"der_base64": "AAAA"}},
	"pub-der-not-base64":      {op: signerclient.OpPub, override: map[string]any{"der_base64": "*"}},
	"pub-der-missing":         {op: signerclient.OpPub, override: map[string]any{"der_base64": nil}},
	"pub-der-null":            {op: signerclient.OpPub, override: map[string]any{"der_base64": jsonNull}},
	"pub-both-encodings":      {op: signerclient.OpPub, override: map[string]any{"pem": "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n"}},
	"pub-extra-member":        {op: signerclient.OpPub, override: map[string]any{"jwk": "{}"}},
	"pub-pem-foreign-key":     {op: signerclient.OpPub, format: signerclient.FormatSPKIPEM, override: map[string]any{"pem": "$FOREIGN_KEY_PEM"}},
	"pub-pem-garbage":         {op: signerclient.OpPub, format: signerclient.FormatSPKIPEM, override: map[string]any{"pem": "not pem"}},
	"pub-pem-der-for-pem":     {op: signerclient.OpPub, format: signerclient.FormatSPKIPEM, override: map[string]any{"pem": nil, "der_base64": "AAAA"}},
	"pub-refusal":             {op: signerclient.OpPub, code: signerclient.CodeSecurity, dropResult: true, want: refusal, wantCode: signerclient.CodeSecurity},
	// sign: identity, hash, digest, format, encodings, low-S, and the signature verifies under the attested key
	"sign-control-default":        {op: signerclient.OpSign, want: success},
	"sign-control-der":            {op: signerclient.OpSign, format: signerclient.FormatDERLowS, want: success},
	"sign-control-raw":            {op: signerclient.OpSign, format: signerclient.FormatRaw, want: success},
	"sign-label-foreign":          {op: signerclient.OpSign, override: map[string]any{"label": "foreign-label"}},
	"sign-fingerprint-foreign":    {op: signerclient.OpSign, override: map[string]any{"fingerprint": foreignFingerprint}},
	"sign-hash-sha512":            {op: signerclient.OpSign, override: map[string]any{"hash": "sha512"}},
	"sign-digest-other":           {op: signerclient.OpSign, override: map[string]any{"digest": "00"}},
	"sign-format-raw-for-der":     {op: signerclient.OpSign, format: signerclient.FormatDERLowS, override: map[string]any{"format": signerclient.FormatRaw}},
	"sign-format-unknown":         {op: signerclient.OpSign, override: map[string]any{"format": "wrong-format"}},
	"sign-signature-foreign-key":  {op: signerclient.OpSign, override: map[string]any{"signature": "$FOREIGN_SIGNATURE"}},
	"sign-signature-other-digest": {op: signerclient.OpSign, override: map[string]any{"signature": "$OTHER_DIGEST_SIGNATURE"}},
	"sign-signature-high-s":       {op: signerclient.OpSign, override: map[string]any{"signature": "$HIGH_S_SIGNATURE"}},
	"sign-signature-raw-for-der":  {op: signerclient.OpSign, format: signerclient.FormatRaw, override: map[string]any{"format": signerclient.FormatDERLowS}}, // raw bytes announced as DER
	"sign-signature-not-hex":      {op: signerclient.OpSign, override: map[string]any{"signature": "zz"}},
	"sign-signature-00":           {op: signerclient.OpSign, override: map[string]any{"signature": "00", "signature_base64": "AA=="}},
	"sign-signature-base64-other": {op: signerclient.OpSign, override: map[string]any{"signature_base64": "AA=="}},
	"sign-signature-missing":      {op: signerclient.OpSign, override: map[string]any{"signature": nil}},
	"sign-low-s-false":            {op: signerclient.OpSign, override: map[string]any{"low_s": false}},
	"sign-low-s-null":             {op: signerclient.OpSign, override: map[string]any{"low_s": jsonNull}},
	"sign-normalized-missing":     {op: signerclient.OpSign, override: map[string]any{"normalized": nil}},
	"sign-extra-member":           {op: signerclient.OpSign, override: map[string]any{"key_id": 1}},
	"sign-refusal":                {op: signerclient.OpSign, code: signerclient.CodeUsageRefused, dropResult: true, want: refusal, wantCode: signerclient.CodeUsageRefused},
	// verify: the verdict is re-derived under the attested key and must agree
	"verify-control-true":                 {op: signerclient.OpVerify, want: success},
	"verify-control-raw":                  {op: signerclient.OpVerify, format: signerclient.FormatRaw, want: success},
	"verify-control-false":                {op: signerclient.OpVerify, tamper: true, want: refusal, wantCode: signerclient.CodeSignatureInvalid},
	"verify-control-high-s":               {op: signerclient.OpVerify, highS: true, want: refusal, wantCode: signerclient.CodeHighSRefused},
	"verify-control-high-s-allowed":       {op: signerclient.OpVerify, highS: true, allowHighS: true, want: success},
	"verify-control-refusal":              {op: signerclient.OpVerify, code: signerclient.CodeNotFound, dropResult: true, want: refusal, wantCode: signerclient.CodeNotFound},
	"verify-true-on-tampered":             {op: signerclient.OpVerify, tamper: true, code: "ok", override: map[string]any{"verified": true}},
	"verify-false-on-valid":               {op: signerclient.OpVerify, code: signerclient.CodeSignatureInvalid, override: map[string]any{"verified": false}},
	"verify-ok-verified-false":            {op: signerclient.OpVerify, override: map[string]any{"verified": false}},
	"verify-invalid-verified-true":        {op: signerclient.OpVerify, tamper: true, override: map[string]any{"verified": true}},
	"verify-label-foreign":                {op: signerclient.OpVerify, override: map[string]any{"label": "foreign-label"}},
	"verify-fingerprint-foreign":          {op: signerclient.OpVerify, override: map[string]any{"fingerprint": foreignFingerprint}},
	"verify-label-missing":                {op: signerclient.OpVerify, override: map[string]any{"label": nil}},
	"verify-label-on-high-s":              {op: signerclient.OpVerify, highS: true, override: map[string]any{"label": fakeLabel}},
	"verify-hash-sha512":                  {op: signerclient.OpVerify, override: map[string]any{"hash": "sha512"}},
	"verify-digest-other":                 {op: signerclient.OpVerify, override: map[string]any{"digest": "00"}},
	"verify-format-raw-for-der":           {op: signerclient.OpVerify, override: map[string]any{"format": signerclient.FormatRaw}},
	"verify-high-s-allowed-flipped":       {op: signerclient.OpVerify, override: map[string]any{"high_s_allowed": true}},
	"verify-low-s-flipped":                {op: signerclient.OpVerify, override: map[string]any{"low_s": false}},
	"verify-high-s-refused-on-low-s":      {op: signerclient.OpVerify, code: signerclient.CodeHighSRefused, override: map[string]any{"label": nil, "fingerprint": nil, "verified": false}},
	"verify-high-s-verdict-without-allow": {op: signerclient.OpVerify, highS: true, code: "ok", override: map[string]any{"label": fakeLabel, "fingerprint": "$OWN_FINGERPRINT", "verified": true}},
	"verify-result-on-not-found":          {op: signerclient.OpVerify, code: signerclient.CodeNotFound},
	"verify-invalid-without-verdict":      {op: signerclient.OpVerify, tamper: true, dropResult: true},
	"verify-ok-without-verdict":           {op: signerclient.OpVerify, dropResult: true},
	"verify-extra-member":                 {op: signerclient.OpVerify, override: map[string]any{"reason": "x"}},
	"verify-verified-null":                {op: signerclient.OpVerify, override: map[string]any{"verified": jsonNull}},
}

// Review rev6 F2 regression (repeat-of rev3 F2): every op result is
// judged by one owner (checkResult, inside Call) against the pending
// request and the accepted hello before a typed helper returns. Each row
// is the honest answer of the fake's key with exactly one thing changed
// — another label or fingerprint, a member missing or null, a foreign
// or undefined member, the wrong hash, digest or format, a signature
// another key made or made over another digest, a high-S signature
// announced low-S, mismatched encodings, a verdict crypto/ecdsa under the
// attested key does not give, a verdict where the op documents none or
// none where it documents one — and every one is ErrProtocol through the
// typed helpers Describe / PublicKey / PublicKeyPEM / Sign / Verify with
// the fake reaped and the client unusable. Controls: the honest answer
// of every op in every format is admitted; declared refusals without a
// result stay *Error; describe admits record fields beyond the required
// ones (stated bound: the record vocabulary is the record model's).
func TestClientRefusesResultNotBoundToRequestOrHello(t *testing.T) {
	names := make([]string, 0, len(resultRows))
	for name := range resultRows {
		names = append(names, name)
	}
	sort.Strings(names)
	driven := 0
	for _, name := range names {
		row := resultRows[name]
		t.Run(name, func(t *testing.T) {
			client, err := startFake(t, "result-"+name)
			if err != nil {
				t.Fatal(err)
			}
			err = driveOp(t, client, row.op, row.format, row.tamper, row.highS, row.allowHighS)
			t.Logf("%v", err)
			if row.want == protocol && (err == nil || !strings.Contains(err.Error(), "result")) {
				t.Fatalf("%v does not name the result", err)
			}
			judgeLine(t, client, err, row.want, row.wantCode)
			driven++
		})
	}
	t.Logf("result corpus: %d of %d rows driven", driven, len(names))
	if driven != len(names) {
		t.Errorf("result corpus: %d of %d rows driven", driven, len(names))
	}
}

// Sign and Verify reach the attested key through one pub request per
// session (the key is cached), and the fingerprint the hello announced
// is the one every signature is checked under: a signature made by the
// hello key verifies with crypto/ecdsa under the key PublicKey returns,
// and Fingerprint of that SPKI is the hello fingerprint.
func TestSignVerifiesUnderTheHelloKey(t *testing.T) {
	client, err := startFake(t, "ok")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	digest := sha256.Sum256([]byte("attested"))
	der, sig, err := client.Sign(ctx, digest[:], signerclient.FormatDERLowS)
	if err != nil {
		t.Fatal(err)
	}
	spki, pub, err := client.PublicKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if signerclient.Fingerprint(spki) != client.Hello().Fingerprint || sig.Fingerprint != client.Hello().Fingerprint {
		t.Fatalf("fingerprints: spki %s, sign %s, hello %s", signerclient.Fingerprint(spki), sig.Fingerprint, client.Hello().Fingerprint)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], der) {
		t.Fatal("signature does not verify under the hello key")
	}
	if v, err := client.Verify(ctx, digest[:], der, signerclient.FormatDERLowS, false); err != nil || !v.Verified {
		t.Fatalf("verify: %v %+v", err, v)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

// DecodeObject is the one reader every contract-bearing object passes:
// it keeps members in source order, refuses a repeated decoded name
// (verbatim or escape-spelt, at any position), refuses anything but one
// object and anything after it, and admits an escape-spelt single member
// under its decoded name.
func TestDecodeObject(t *testing.T) {
	obj, err := signerclient.DecodeObject([]byte(` {"b":1,"a":{"x":[1,{"x":2}]},"c\u0064":"d"} `))
	if err != nil || strings.Join(obj.Names(), ",") != "b,a,cd" {
		t.Fatalf("%v %v", obj.Names(), err)
	}
	if v, ok := obj.Get("a"); !ok || string(v) != `{"x":[1,{"x":2}]}` {
		t.Fatalf("a = %s %v", v, ok)
	}
	if _, ok := obj.Get("x"); ok {
		t.Fatal("a nested member is not a member of the outer object")
	}
	for _, bad := range []string{
		`{"a":1,"a":2}`, `{"a":1,"\u0061":2}`, `{"\u0061":1,"a":2}`, `{"a":1,"b":2,"a":1}`,
		`[]`, `null`, `"s"`, `1`, ``, ` `, `{"a":1} {}`, `{"a":1} x`, `{"a":1`, `{"a":}`, `{1:2}`, `{"a":1,}`,
	} {
		if _, err := signerclient.DecodeObject([]byte(bad)); err == nil {
			t.Errorf("%s admitted", bad)
		}
	}
	for _, dup := range []string{`{"a":1,"a":2}`, `{"a":1,"\u0061":2}`, `{"o":{"a":1,"a":2}}`, `{"l":[{"a":1,"\u0061":2}]}`} {
		if _, err := signerclient.DecodeObject([]byte(dup)); !errors.Is(err, signerclient.ErrDuplicateMember) || !strings.Contains(err.Error(), `"a"`) {
			t.Errorf("%s: %v, want ErrDuplicateMember naming a", dup, err)
		}
	}
}

// CheckDocument is the one recursive strict pass: a repeated decoded
// member name is refused in the top-level object, in an object nested at
// depth 1, 2 and 3, and in objects inside arrays (first and later
// elements, arrays of arrays), verbatim and escape-spelt, naming the
// member and its path; exactly one document is required. Controls: one
// name in sibling objects, at different depths, an escape-spelt single
// member, surrounding whitespace, scalars and arrays as documents (they
// are documents; whether they are objects is DecodeObject's rule) are
// admitted. DecodeSingleJSON, the typed reader of the record tag and
// the --meta-json input, takes the same pass and refuses a nested repeat
// the struct decode would collapse.
func TestCheckDocument(t *testing.T) {
	refused := []struct{ doc, want string }{
		{`{"a":1,"a":2}`, `duplicate member "a"`},
		{`{"a":1,"\u0061":2}`, `duplicate member "a"`},
		{`{"o":{"a":1,"a":2}}`, `duplicate member "a" at o`},
		{`{"o":{"a":1,"\u0061":2}}`, `duplicate member "a" at o`},
		{`{"o":{"\u0061":1,"a":2}}`, `duplicate member "a" at o`},
		{`{"o":{"p":{"a":1,"a":2}}}`, `duplicate member "a" at o.p`},
		{`{"o":{"p":{"q":{"a":1,"a":2}}}}`, `duplicate member "a" at o.p.q`},
		{`{"l":[{"a":1,"a":2}]}`, `duplicate member "a" at l[0]`},
		{`{"l":[{"a":1},{"a":1,"a":2}]}`, `duplicate member "a" at l[1]`},
		{`{"l":[{"a":1},{"a":1,"\u0061":2}]}`, `duplicate member "a" at l[1]`},
		{`{"l":[[{"a":1,"a":2}]]}`, `duplicate member "a" at l[0][0]`},
		{`{"l":[1,"s",null,{"o":[{"a":1,"a":2}]}]}`, `duplicate member "a" at l[3].o[0]`},
		{`[{"a":1,"a":2}]`, `duplicate member "a" at [0]`},
		{`{"a":{"b":1},"c":{"b":2},"d":{"b":3,"b":4}}`, `duplicate member "b" at d`},
		{`{"a":1,"o":{"a":1},"a":2}`, `duplicate member "a"`},
		{`{"a":1} {"b":2}`, "unexpected data after the JSON document"},
		{`{"a":1} 1`, "unexpected data after the JSON document"},
		{`1 2`, "unexpected data after the JSON document"},
		{``, "empty input"},
		{`   `, "empty input"},
	}
	for _, row := range refused {
		err := signerclient.CheckDocument([]byte(row.doc))
		if err == nil || !strings.Contains(err.Error(), row.want) {
			t.Errorf("CheckDocument(%s) = %v, want %q", row.doc, err, row.want)
		}
		if strings.HasPrefix(row.want, "duplicate") && !errors.Is(err, signerclient.ErrDuplicateMember) {
			t.Errorf("CheckDocument(%s) = %v, want ErrDuplicateMember", row.doc, err)
		}
		if strings.HasPrefix(row.want, "unexpected data") && !errors.Is(err, signerclient.ErrMultipleDocuments) {
			t.Errorf("CheckDocument(%s) = %v, want ErrMultipleDocuments", row.doc, err)
		}
	}
	for _, bad := range []string{`{"a":1`, `{"a":}`, `{1:2}`, `{"a":1,}`, `[1,]`, `{"o":{"a":1}`, `x`, `{"a":1}}`, `{"a":1}]`} {
		if err := signerclient.CheckDocument([]byte(bad)); err == nil {
			t.Errorf("CheckDocument(%s) admitted malformed JSON", bad)
		}
	}
	for _, good := range []string{
		`{"a":1,"b":2}`, ` {"a":1} `, "{\"a\":1}\n", `{"\u0061":1}`, `{"o":{"\u0061":1}}`,
		`{"a":{"b":1},"c":{"b":2}}`, `{"a":1,"o":{"a":1,"p":{"a":1}}}`, `{"l":[{"a":1},{"a":2},{"a":3}]}`,
		`{"l":[[{"a":1}],[{"a":1}]]}`, `{"o":{}}`, `{"l":[]}`, `{}`, `[]`, `[{"a":1},[{"a":1}]]`, `1`, `"s"`, `null`, `true`,
	} {
		if err := signerclient.CheckDocument([]byte(good)); err != nil {
			t.Errorf("CheckDocument(%s) = %v, want admitted", good, err)
		}
	}
	// the typed reader: a nested repeat the struct decode would collapse
	type nested struct {
		A int `json:"a"`
	}
	type doc struct {
		O nested   `json:"o"`
		L []nested `json:"l"`
	}
	var d doc
	for _, dup := range []string{`{"o":{"a":1,"a":2}}`, `{"o":{"a":1,"\u0061":2}}`, `{"l":[{"a":1},{"a":1,"a":2}]}`} {
		if err := signerclient.DecodeSingleJSON([]byte(dup), &d); !errors.Is(err, signerclient.ErrDuplicateMember) {
			t.Errorf("DecodeSingleJSON(%s) = %v, want ErrDuplicateMember", dup, err)
		}
	}
	if err := signerclient.DecodeSingleJSON([]byte(`{"o":{"\u0061":1},"l":[{"a":1},{"a":2}]}`), &d); err != nil || d.O.A != 1 || len(d.L) != 2 {
		t.Errorf("DecodeSingleJSON control: %v %+v", err, d)
	}
}

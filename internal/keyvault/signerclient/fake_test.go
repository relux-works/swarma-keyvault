package signerclient_test

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
)

// The test binary doubles as a scripted fake server when
// SIGNERCLIENT_FAKE_SERVER names a scenario, so the client's own gates
// (contract check, hello binding, envelope shape and presence, duplicate
// members, result binding, id match, stream end, cancellation) are
// driven through the production entry points without a keychain. The
// fake owns one P-256 key per process: its hello carries that key's real
// fingerprint and every HONEST answer (fakeKey.answer) is what
// mac-keyvault would write for the key — so the client's result gate
// admits the honest answers and each negative scenario differs from an
// honest answer in exactly the way its row states.

// fakeLabel and fakeAddress are the identity the fake announces.
const (
	fakeAddress = "test/fake"
	fakeLabel   = "works.relux.mac-keyvault.key.test.fake.v1"
)

type fakeKey struct {
	priv *ecdsa.PrivateKey
	spki []byte
}

func newFakeKey() *fakeKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		panic(err)
	}
	return &fakeKey{priv: priv, spki: spki}
}

func (k *fakeKey) fingerprint() string { return signerclient.Fingerprint(k.spki) }

// hello is the valid contract-1 hello binding: tool mac-keyvault, address
// test/fake, kind key, version 1, the real fingerprint, full op set.
func (k *fakeKey) hello() map[string]any {
	return map[string]any{"tool": signerclient.Tool, "tool_version": "0", "address": fakeAddress, "kind": "key", "version": 1, "label": fakeLabel, "fingerprint": k.fingerprint(), "ops": signerclient.Ops}
}

// describe is the honest describe result: a complete, valid schema-2 key
// record (every invariant row passes, the label is the one the record
// derives) plus the derived members the vault prints for a keychain
// ec-p256 key with usages sign,verify and no validity bound.
func (k *fakeKey) describe() map[string]any {
	return map[string]any{
		"schema": 2, "kind": "key", "service": "test", "purpose": "fake", "version": 1,
		"title": "fake", "description": "fake signer record", "algorithm": "ec-p256", "store": "keychain", "extraction": "none",
		"usages": []any{"sign", "verify"}, "format": map[string]any{"public": "spki-der", "signature": "ecdsa-der-low-s"},
		"created": "2023-11-14T22:13:20Z", "origin": map[string]any{"user": "tester", "host": "testhost", "tool": "mac-keyvault/test", "source": "generated"},
		"issuer": nil, "validity": map[string]any{"not_before": nil, "not_after": nil}, "meta": map[string]any{"owner": "fake"},
		"label": fakeLabel, "fingerprint": k.fingerprint(), "exposure": "never",
		"operations": []any{
			map[string]any{"name": "ecdsa-sha256-sign", "input": "sha256-digest", "output": "ecdsa-der-low-s|ecdsa-raw", "via": "sign"},
			map[string]any{"name": "ecdsa-sha256-verify", "input": "sha256-digest+signature", "output": "verdict", "via": "verify"},
			map[string]any{"name": "export-public", "input": "", "output": "spki-der|spki-pem|jwk", "via": "pub"},
		},
		"findings": []any{},
	}
}

// sign returns the low-S signature of digest in format, made by priv
// (the fake's own key unless another is given).
func (k *fakeKey) sign(priv *ecdsa.PrivateKey, digest []byte, format string, highS bool) []byte {
	if priv == nil {
		priv = k.priv
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		panic(err)
	}
	n := elliptic.P256().Params().N
	if signerclient.IsLowS(s) == highS { // flip into the half asked for
		s = new(big.Int).Sub(n, s)
	}
	return encodeSignature(r, s, format)
}

func encodeSignature(r, s *big.Int, format string) []byte {
	if format == signerclient.FormatRaw {
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		panic(err)
	}
	return der
}

// answer is the honest contract-1 answer to req for the fake's key: the
// result and, for a refusal, the error code (the result is then the
// documented partial verdict, or nil).
func (k *fakeKey) answer(req signerclient.Request) (result map[string]any, code string) {
	switch req.Op {
	case signerclient.OpDescribe:
		return k.describe(), ""
	case signerclient.OpPub:
		format := req.Format
		if format == "" {
			format = signerclient.FormatSPKIDER
		}
		result := map[string]any{"label": fakeLabel, "fingerprint": k.fingerprint(), "format": format}
		if format == signerclient.FormatSPKIPEM {
			result["pem"] = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: k.spki}))
		} else {
			result["der_base64"] = base64.StdEncoding.EncodeToString(k.spki)
		}
		return result, ""
	case signerclient.OpSign:
		digest, err := hex.DecodeString(req.Digest)
		if err != nil || len(digest) != signerclient.DigestSize {
			return nil, signerclient.CodeInvalidDigest
		}
		format := req.Format
		if format == "" {
			format = signerclient.FormatDERLowS
		}
		sig := k.sign(nil, digest, format, false)
		return map[string]any{"label": fakeLabel, "fingerprint": k.fingerprint(), "hash": signerclient.Hash, "digest": req.Digest, "format": format, "signature": hex.EncodeToString(sig), "signature_base64": base64.StdEncoding.EncodeToString(sig), "low_s": true, "normalized": false}, ""
	case signerclient.OpVerify:
		digest, err := hex.DecodeString(req.Digest)
		if err != nil || len(digest) != signerclient.DigestSize {
			return nil, signerclient.CodeInvalidDigest
		}
		format := req.Format
		if format == "" {
			format = signerclient.FormatDERLowS
		}
		sigBytes, err := hex.DecodeString(req.Signature)
		if err != nil {
			return nil, signerclient.CodeBadRequest
		}
		r, s, err := signerclient.ParseSignature(sigBytes, format)
		if err != nil {
			return nil, signerclient.CodeInvalidSignature
		}
		verdict := map[string]any{"hash": signerclient.Hash, "digest": req.Digest, "format": format, "low_s": signerclient.IsLowS(s), "high_s_allowed": req.AllowHighS, "verified": false}
		if !signerclient.IsLowS(s) && !req.AllowHighS {
			return verdict, signerclient.CodeHighSRefused
		}
		verdict["label"], verdict["fingerprint"] = fakeLabel, k.fingerprint()
		if !ecdsa.Verify(&k.priv.PublicKey, digest, r, s) {
			return verdict, signerclient.CodeSignatureInvalid
		}
		verdict["verified"] = true
		return verdict, ""
	}
	return nil, signerclient.CodeUnknownOp
}

// response wraps an honest answer as the envelope the server writes.
func response(id json.RawMessage, result map[string]any, code string) signerclient.Response {
	resp := signerclient.Response{ID: id, OK: code == ""}
	if result != nil {
		resp.Result = mustJSON(result)
	}
	if code != "" {
		resp.Error = &signerclient.Error{Code: code, Message: "m", Hint: "h"}
	}
	return resp
}

func fakeServer(scenario string) int {
	key := newFakeKey()
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	write := func(v any) {
		data, _ := json.Marshal(v)
		out.Write(append(data, '\n'))
		out.Flush()
	}
	writeRaw := func(line string) {
		fmt.Fprintln(out, line)
		out.Flush()
	}
	// helloWith writes the valid hello with the named members overridden
	// — the negative hello-binding scenarios differ from the valid hello
	// in exactly one member each.
	helloWith := func(override map[string]any) {
		result := key.hello()
		for k, v := range override {
			if v == nil {
				delete(result, k)
			} else {
				result[k] = v
			}
		}
		write(signerclient.Response{Contract: signerclient.Contract, OK: true, Result: mustJSON(result)})
	}
	helloVersion := func(version int) { helloWith(map[string]any{"version": version}) }
	hello := func() { helloVersion(1) }
	in := bufio.NewReader(os.Stdin)
	// serve answers every request line through answer until EOF; answer
	// returns the response to write, or nil to stay silent.
	serve := func(answer func(req signerclient.Request, line []byte) *signerclient.Response) int {
		for {
			line, err := in.ReadBytes('\n')
			if err != nil {
				return 0
			}
			var req signerclient.Request
			_ = json.Unmarshal(line, &req)
			if resp := answer(req, line); resp != nil {
				write(*resp)
			}
		}
	}
	honest := func(req signerclient.Request) signerclient.Response {
		result, code := key.answer(req)
		return response(req.ID, result, code)
	}
	if override, ok := helloBindingScenarios[scenario]; ok {
		helloWith(override)
		return 0
	}
	// raw-hello-<row> / raw-<row>: the line is written VERBATIM from
	// rawEnvelopeRows — never through Response, whose typed members
	// cannot express an absent-vs-null distinction — with $HEAD, $ID and
	// $RESULT substituted (see rawEnvelopeRows). A verify row answers the
	// pub request the client makes first (to fetch the attested key)
	// honestly and shapes the verify answer.
	if row, ok := strings.CutPrefix(scenario, "raw-hello-"); ok {
		r := strings.NewReplacer("$HEAD", `"contract":1`, "$RESULT", string(mustJSON(key.hello())))
		writeRaw(r.Replace(rawEnvelopeRows[row].line))
		return 0
	}
	if row, ok := strings.CutPrefix(scenario, "raw-"); ok {
		hello()
		return serve(func(req signerclient.Request, _ []byte) *signerclient.Response {
			if rawEnvelopeRows[row].verifyOp && req.Op != signerclient.OpVerify {
				resp := honest(req)
				return &resp
			}
			result, _ := key.answer(req)
			r := strings.NewReplacer("$HEAD", `"id":`+string(req.ID), "$ID", string(req.ID), "$RESULT", string(mustJSON(result)))
			writeRaw(r.Replace(rawEnvelopeRows[row].line))
			return nil
		})
	}
	// envelope-hello-<shape>: the hello is the valid binding re-shaped;
	// envelope-<shape>: a valid hello, then every request is answered in
	// that shape around its honest result; envelope-verify-<shape>: only
	// the verify request is re-shaped, pub and sign stay honest so the
	// test can obtain a signature and the client its attested key. See
	// envelopeShapes.
	if shape, ok := strings.CutPrefix(scenario, "envelope-hello-"); ok {
		resp := envelopeShapes[shape].response(mustJSON(key.hello()))
		resp.Contract = signerclient.Contract
		write(resp)
		return 0
	}
	if rest, ok := strings.CutPrefix(scenario, "envelope-"); ok {
		shape, verifyOnly := strings.CutPrefix(rest, "verify-")
		hello()
		return serve(func(req signerclient.Request, _ []byte) *signerclient.Response {
			if verifyOnly && req.Op != signerclient.OpVerify {
				resp := honest(req)
				return &resp
			}
			result, _ := key.answer(req)
			resp := envelopeShapes[shape].response(mustJSON(result))
			resp.ID = req.ID
			return &resp
		})
	}
	// dup-hello-<row> / dup-<row>: one line built by duplicateRows[row]
	// from the honest answer, with a member repeated (verbatim or
	// escape-spelt); requests the row does not shape are honest.
	if row, ok := strings.CutPrefix(scenario, "dup-hello-"); ok {
		writeRaw(duplicateRows[row].hello(key))
		return 0
	}
	if row, ok := strings.CutPrefix(scenario, "dup-"); ok {
		hello()
		return serve(func(req signerclient.Request, _ []byte) *signerclient.Response {
			if req.Op != duplicateRows[row].op {
				resp := honest(req)
				return &resp
			}
			writeRaw(duplicateRows[row].call(key, req))
			return nil
		})
	}
	// result-<row>: the honest answer to the row's op with resultRows[row]
	// applied (member overrides, another signer, a forced error code);
	// every other request is honest.
	if row, ok := strings.CutPrefix(scenario, "result-"); ok {
		hello()
		return serve(func(req signerclient.Request, _ []byte) *signerclient.Response {
			r := resultRows[row]
			if req.Op != r.op {
				resp := honest(req)
				return &resp
			}
			resp := r.shape(key, req)
			return &resp
		})
	}
	switch scenario {
	case "unpinned":
		helloVersion(0)
		return 0
	case "version-3":
		helloVersion(3)
		return 0
	case "startup-undeclared-code":
		write(signerclient.Response{Contract: signerclient.Contract, Error: &signerclient.Error{Code: "self_minted", Message: "not a contract code", Hint: "h"}})
		return 1
	case "startup-empty-code":
		write(signerclient.Response{Contract: signerclient.Contract, Error: &signerclient.Error{Message: "no code at all", Hint: "h"}})
		return 1
	case "undeclared-code":
		// Contract-1 hello, then every request is refused with a code the
		// contract does not declare; a client that treats it as a
		// recoverable *Error would keep the session (the rev3 finding).
		hello()
		return serve(func(req signerclient.Request, _ []byte) *signerclient.Response {
			return &signerclient.Response{ID: req.ID, Error: &signerclient.Error{Code: "self_minted", Message: "not a contract code", Hint: "h"}}
		})
	case "no-error-object":
		hello()
		return serve(func(req signerclient.Request, _ []byte) *signerclient.Response {
			return &signerclient.Response{ID: req.ID, OK: false}
		})
	case "contract-2":
		write(signerclient.Response{Contract: 2, OK: true, Result: json.RawMessage(`{}`)})
		return 0
	case "no-contract":
		write(signerclient.Response{OK: true, Result: json.RawMessage(`{}`)})
		return 0
	case "startup-error":
		write(signerclient.Response{Contract: signerclient.Contract, Error: &signerclient.Error{Code: "not_found", Message: "key not found: test/fake", Hint: "list shows every record"}})
		return 1
	case "garbage":
		writeRaw("mac-keyvault: something that is not JSON")
		return 0
	case "id-mismatch":
		hello()
		return serve(func(signerclient.Request, []byte) *signerclient.Response {
			return &signerclient.Response{ID: json.RawMessage("999"), OK: true, Result: json.RawMessage(`{}`)}
		})
	case "exit-early":
		hello()
		return 0
	case "silent":
		hello()
		return serve(func(signerclient.Request, []byte) *signerclient.Response { return nil })
	case "ok":
		// Honest for pub, sign and verify; describe is refused with
		// unknown_op so a declared mid-stream refusal is on hand.
		hello()
		return serve(func(req signerclient.Request, line []byte) *signerclient.Response {
			var probe map[string]json.RawMessage
			if err := json.Unmarshal(line, &probe); err != nil {
				return &signerclient.Response{ID: json.RawMessage("null"), Error: &signerclient.Error{Code: signerclient.CodeBadRequest, Message: err.Error(), Hint: "h"}}
			}
			if req.Op == signerclient.OpDescribe {
				return &signerclient.Response{ID: req.ID, Error: &signerclient.Error{Code: signerclient.CodeUnknownOp, Message: req.Op, Hint: "h"}}
			}
			resp := honest(req)
			return &resp
		})
	}
	fmt.Fprintln(os.Stderr, "unknown scenario", scenario)
	return 2
}

// helloBindingScenarios: fake-server scenarios whose hello is the valid
// binding with exactly one member changed (nil deletes the member). Every
// one must be refused by Start with ErrProtocol; "binding-ok" is the
// unchanged control.
var helloBindingScenarios = map[string]map[string]any{
	"binding-ok":               {},
	"binding-tool":             {"tool": "impostor"},
	"binding-tool-missing":     {"tool": nil},
	"binding-address":          {"address": "other/key"},
	"binding-address-missing":  {"address": nil},
	"binding-kind":             {"kind": "certificate"},
	"binding-kind-missing":     {"kind": nil},
	"binding-label-missing":    {"label": nil},
	"binding-fp-missing":       {"fingerprint": nil},
	"binding-ops-empty":        {"ops": []string{}},
	"binding-ops-missing":      {"ops": nil},
	"binding-ops-subset":       {"ops": []string{"describe", "pub", "sign"}},
	"binding-ops-extra":        {"ops": []string{"describe", "pub", "sign", "verify", "export"}},
	"binding-ops-renamed":      {"ops": []string{"describe", "pub", "sign", "verifi"}},
	"binding-kind-certificate": {"kind": "certificate"}, // valid only when Kind certificate is requested
}

// rawObject renders an honest result as `"a":1,"b":2` (no braces) so a
// row can wrap it with extra members before or after.
func rawObject(v map[string]any) string {
	return strings.TrimSuffix(strings.TrimPrefix(string(mustJSON(v)), "{"), "}")
}

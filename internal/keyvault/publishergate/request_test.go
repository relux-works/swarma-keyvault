package publishergate

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

const closedRequest = `{"version":"publisher-call/1","op":"publish-current","scope_id":"synthetic-scope","policy_epoch":7,"request_nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`

func requireCode(t *testing.T, err error, want Code) {
	t.Helper()
	var refused *Refusal
	if !errors.As(err, &refused) || refused.Code != want || err.Error() != string(want) {
		t.Fatalf("refusal = %v, want %s", err, want)
	}
}

func TestDecodeClosedRequestBoundaries(t *testing.T) {
	for _, raw := range []string{
		closedRequest,
		closedRequest + strings.Repeat(" ", MaxRequestBytes-len(closedRequest)),
		strings.Replace(closedRequest, "synthetic-scope", strings.Repeat("s", 64), 1),
		strings.Replace(closedRequest, `"policy_epoch":7`, `"policy_epoch":18446744073709551615`, 1),
	} {
		r, err := DecodeRequest([]byte(raw))
		if err != nil || r.ScopeID() == "" || r.PolicyEpoch() == 0 || r.RequestNonce() != [32]byte{} {
			t.Fatalf("valid closed request refused: %v", err)
		}
	}
	// Returned nonce is a value; changing it cannot alter the parsed request.
	r, err := DecodeRequest([]byte(closedRequest))
	if err != nil {
		t.Fatal(err)
	}
	nonce := r.RequestNonce()
	nonce[0] = 1
	if r.RequestNonce()[0] != 0 {
		t.Fatal("request nonce was mutable")
	}
}

func TestDecodeRefusesAmbiguousOrOpenMessages(t *testing.T) {
	tests := map[string]string{
		"empty":             "",
		"array":             "[]",
		"missing":           `{"version":"publisher-call/1"}`,
		"wrong-version":     strings.Replace(closedRequest, "publisher-call/1", "publisher-call/2", 1),
		"wrong-operation":   strings.Replace(closedRequest, "publish-current", "sign", 1),
		"empty-scope":       strings.Replace(closedRequest, "synthetic-scope", "", 1),
		"scope-too-long":    strings.Replace(closedRequest, "synthetic-scope", strings.Repeat("s", 65), 1),
		"scope-non-ascii":   strings.Replace(closedRequest, "synthetic-scope", "scopeé", 1),
		"scope-surrogate":   strings.Replace(closedRequest, "synthetic-scope", `\ud800`, 1),
		"null-version":      strings.Replace(closedRequest, `"publisher-call/1"`, "null", 1),
		"null-scope":        strings.Replace(closedRequest, `"synthetic-scope"`, "null", 1),
		"null-epoch":        strings.Replace(closedRequest, `"policy_epoch":7`, `"policy_epoch":null`, 1),
		"string-epoch":      strings.Replace(closedRequest, `"policy_epoch":7`, `"policy_epoch":"7"`, 1),
		"zero-epoch":        strings.Replace(closedRequest, `"policy_epoch":7`, `"policy_epoch":0`, 1),
		"negative-epoch":    strings.Replace(closedRequest, `"policy_epoch":7`, `"policy_epoch":-7`, 1),
		"fractional-epoch":  strings.Replace(closedRequest, `"policy_epoch":7`, `"policy_epoch":7.0`, 1),
		"exponential-epoch": strings.Replace(closedRequest, `"policy_epoch":7`, `"policy_epoch":7e0`, 1),
		"overflow-epoch":    strings.Replace(closedRequest, `"policy_epoch":7`, `"policy_epoch":18446744073709551616`, 1),
		"nonce-padding":     strings.Replace(closedRequest, `AAA"}`, `AAA="}`, 1),
		"nonce-pad-bits":    strings.Replace(closedRequest, `AAA"}`, `AAB"}`, 1),
		"nonce-too-short":   strings.Replace(closedRequest, `AAA"}`, `AA"}`, 1),
		"nonce-wrong-type":  strings.Replace(closedRequest, `"request_nonce":"`+strings.Repeat("A", 43)+`"`, `"request_nonce":[]`, 1),
		"nested-value":      strings.Replace(closedRequest, `"synthetic-scope"`, `{"scope":"synthetic-scope"}`, 1),
		"deep-value":        strings.Replace(closedRequest, `"synthetic-scope"`, strings.Repeat("[", 17)+`"s"`+strings.Repeat("]", 17), 1),
		"duplicate":         strings.TrimSuffix(closedRequest, "}") + `,"scope_id":"synthetic-scope"}`,
		"escaped-duplicate": strings.TrimSuffix(closedRequest, "}") + `,"\u0073cope_id":"foreign"}`,
		"trailing-message":  closedRequest + closedRequest,
		"trailing-junk":     closedRequest + "x",
		"truncated":         strings.TrimSuffix(closedRequest, "}"),
		"invalid-utf8":      strings.Replace(closedRequest, "synthetic-scope", string([]byte{0xff}), 1),
	}
	for _, field := range []string{"pid", "path", "hash", "audit_token", "parent", "env", "digest", "blob", "key", "entries", "out", "fd", "endpoint"} {
		tests["extra-"+field] = strings.TrimSuffix(closedRequest, "}") + `,"` + field + `":"spoof"}`
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			r, err := DecodeRequest([]byte(raw))
			requireCode(t, err, OperationRefused)
			if r != (Request{}) {
				t.Fatal("refused parser exposed partial request")
			}
		})
	}
	_, err := DecodeRequest([]byte(closedRequest + strings.Repeat(" ", MaxRequestBytes+1-len(closedRequest))))
	requireCode(t, err, ResourceLimit)
}

func FuzzDecodeRequest(f *testing.F) {
	f.Add([]byte(closedRequest))
	f.Add([]byte(`{"version":null}`))
	f.Add([]byte(strings.TrimSuffix(closedRequest, "}") + `,"pid":1}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		before := bytes.Clone(raw)
		r, err := DecodeRequest(raw)
		if !bytes.Equal(before, raw) {
			t.Fatal("parser mutated its input")
		}
		if err != nil {
			if r != (Request{}) {
				t.Fatal("partial request on refusal")
			}
			return
		}
		nonce := r.RequestNonce()
		if len(raw) > MaxRequestBytes || !validScope(r.ScopeID()) || r.PolicyEpoch() == 0 || len(base64.RawURLEncoding.EncodeToString(nonce[:])) != 43 {
			t.Fatal("accepted request violates bounds")
		}
	})
}

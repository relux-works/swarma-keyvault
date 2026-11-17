package keyvault

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// Claim: create-wrap accepts the paired helper's sorted, complete wrap result
// and rejects altered field order, omitted false, unknown fields and trailers.
// Limit: public byte fixtures do not establish authenticated child identity or
// native Secure Enclave behavior.
func TestAgentNostrCanonicalWrapResponse(t *testing.T) {
	point, err := testP256Point(1)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{
		"blob": []byte("public-marker"), "point": point, "fingerprint": sha256Hex(point),
		"policy": "none", "silent_refused": false,
	}
	valid, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseAgentNostrWrapResponse(valid)
	if err != nil {
		t.Fatalf("valid sorted wrap response was refused: %v", err)
	}
	if err := validateAgentNostrWrap(got); err != nil || !bytes.Equal(got.Blob, []byte("public-marker")) || !bytes.Equal(got.Point, point) ||
		got.Fingerprint != sha256Hex(point) || got.Policy != "none" || got.SilentRefused {
		t.Fatalf("valid sorted wrap response was refused: result=%+v err=%v", got, err)
	}
	clear(got.Blob)
	clear(got.Point)

	unsortedOrder, err := json.Marshal(struct {
		Blob          []byte `json:"blob"`
		Point         []byte `json:"point"`
		Fingerprint   string `json:"fingerprint"`
		Policy        string `json:"policy"`
		SilentRefused bool   `json:"silent_refused"`
	}{[]byte("public-marker"), point, sha256Hex(point), "none", false})
	if err != nil {
		t.Fatal(err)
	}
	missingFalse := bytes.Replace(valid, []byte(`,"silent_refused":false`), nil, 1)
	unknownField := bytes.Replace(valid, []byte(`{"blob":`), []byte(`{"extra":true,"blob":`), 1)
	for name, raw := range map[string][]byte{
		"unsorted-field-order": unsortedOrder,
		"missing-false-field":  missingFalse,
		"unknown-field":        unknownField,
		"trailing-byte":        append(bytes.Clone(valid), ' '),
		"over-limit":           bytes.Repeat([]byte{'x'}, 24577),
	} {
		t.Run(name, func(t *testing.T) {
			result, err := parseAgentNostrWrapResponse(raw)
			var privateErr *AgentNostrPrivateError
			if err == nil || !errors.As(err, &privateErr) || privateErr.Code != "unknown" || !privateErr.Dispatched ||
				len(result.Blob) != 0 || len(result.Point) != 0 {
				t.Fatalf("malformed wrap response accepted or leaked fields: result=%+v err=%v", result, err)
			}
		})
	}
}

type agentNostrNoEOFReader struct{ *bytes.Reader }

func (r agentNostrNoEOFReader) Read(p []byte) (int, error) {
	if r.Len() == 0 {
		return 0, nil
	}
	return r.Reader.Read(p)
}

func agentNostrTestResponse(status byte, payload []byte) []byte {
	frame := make([]byte, 5+len(payload))
	frame[0] = status
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	return frame
}

// Claim: the new private route accepts only the seven complete authenticated
// refusal codes and a successful status-0 frame; limit: this does not prove
// signed child identity, socket peer tokens or Secure Enclave behavior.
func TestAgentNostrPrivateProtocolExactStatuses(t *testing.T) {
	for _, code := range []string{"bad_request", "invalid_blob", "policy_refused", "presence_required", "auth_refused", "enclave_unavailable", "parent_not_admitted"} {
		t.Run(code, func(t *testing.T) {
			payload, err := receiveAgentNostrResult(bytes.NewReader(agentNostrTestResponse(1, []byte(code))), nil, 128,
				func() (int, error) { return 1, errors.New("exit status 1") }, func() {}, func() bool { return false })
			var privateErr *AgentNostrPrivateError
			if payload != nil || !errors.As(err, &privateErr) || privateErr.Code != code || !privateErr.Dispatched || strings.Contains(err.Error(), code) {
				t.Fatal("authenticated refusal was not returned as its fixed private status")
			}
		})
	}
	payload, err := receiveAgentNostrResult(bytes.NewReader(agentNostrTestResponse(0, []byte("public-payload"))), nil, 128,
		func() (int, error) { return 0, nil }, func() {}, func() bool { return false })
	if err != nil || string(payload) != "public-payload" {
		t.Fatal("complete status-0 response did not return its payload")
	}
}

// Claim: malformed, ambiguous and phase-lost frames become UNKNOWN and stop
// exactly once; limit: process kill timing remains a native subprocess check.
func TestAgentNostrPrivateProtocolAmbiguousFrames(t *testing.T) {
	validSuccess := agentNostrTestResponse(0, []byte("ok"))
	validRefusal := agentNostrTestResponse(1, []byte("invalid_blob"))
	oversizeSuccess := agentNostrTestResponse(0, bytes.Repeat([]byte{'x'}, 9))
	oversizeRefusal := agentNostrTestResponse(1, bytes.Repeat([]byte{'x'}, 65))
	truncatedHeader := []byte{0, 0, 0}
	truncatedPayload := agentNostrTestResponse(0, []byte("abc"))[:6]
	unknownStatus := agentNostrTestResponse(2, []byte("bad_request"))
	unknownCode := agentNostrTestResponse(1, []byte("unknown_private_code"))
	trailing := append(bytes.Clone(validSuccess), 0)
	for _, tc := range []struct {
		name   string
		reader io.Reader
		frame  []byte
		exit   int
		wait   error
		late   bool
	}{
		{"truncated-header", bytes.NewReader(truncatedHeader), nil, 0, nil, false},
		{"truncated-payload", bytes.NewReader(truncatedPayload), nil, 0, nil, false},
		{"oversize-success", bytes.NewReader(oversizeSuccess), nil, 0, nil, false},
		{"oversize-refusal", bytes.NewReader(oversizeRefusal), nil, 1, errors.New("exit status 1"), false},
		{"unknown-status", bytes.NewReader(unknownStatus), nil, 2, errors.New("exit status 2"), false},
		{"unknown-code", bytes.NewReader(unknownCode), nil, 1, errors.New("exit status 1"), false},
		{"trailing-bytes", bytes.NewReader(trailing), nil, 0, nil, false},
		{"missing-eof", nil, validSuccess, 0, nil, false},
		{"success-exit-mismatch", bytes.NewReader(validSuccess), nil, 1, errors.New("exit status 1"), false},
		{"refusal-exit-mismatch", bytes.NewReader(validRefusal), nil, 0, nil, false},
		{"deadline", bytes.NewReader(validSuccess), nil, 0, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := tc.reader
			if tc.name == "missing-eof" {
				reader = agentNostrNoEOFReader{bytes.NewReader(tc.frame)}
			}
			waits, closes, cancels := 0, 0, 0
			payload, err := receiveAgentNostrResult(reader, func() error { closes++; return nil }, 8,
				func() (int, error) { waits++; return tc.exit, tc.wait }, func() { cancels++ }, func() bool { return tc.late })
			var privateErr *AgentNostrPrivateError
			if payload != nil || !errors.As(err, &privateErr) || privateErr.Code != "unknown" || !privateErr.Dispatched || waits != 1 || closes != 1 || cancels != 1 {
				t.Fatal("ambiguous response was accepted or process cleanup was not bounded to one attempt")
			}
		})
	}
}

// Claim: private refusal vocabulary is a positive allowlist; limit: helper
// process admission is outside this platform-independent protocol predicate.
func TestAgentNostrPrivateStatusAllowlist(t *testing.T) {
	for _, code := range []string{"bad_request", "invalid_blob", "policy_refused", "presence_required", "auth_refused", "enclave_unavailable", "parent_not_admitted"} {
		if !validAgentNostrPrivateCode(code) {
			t.Fatalf("contract status %q was not admitted", code)
		}
	}
	for _, code := range []string{"", "helper_refused", "unknown", "parent-not-admitted", "parent_not_admitted\n", "bad_request ", "invalid_blob\x00"} {
		if validAgentNostrPrivateCode(code) {
			t.Fatalf("uncontracted status %q was admitted", code)
		}
	}
}

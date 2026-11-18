package keyvault

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const agentNostrMaxPrivateRequest = 32768

func agentNostrPrivateRequestWithinLimit(request []byte) bool {
	return len(request) > 0 && len(request) <= agentNostrMaxPrivateRequest
}

func agentNostrCreateWrapRequest() ([]byte, error) {
	return json.Marshal(struct {
		Op      string `json:"op"`
		Purpose string `json:"purpose"`
	}{"create-wrap", "nostr"})
}

func agentNostrUnwrapRequest(envelope AgentNostrEnvelope) ([]byte, error) {
	blob, err := decodeAgentNostrBase64(envelope.EnclaveBlob)
	if err != nil {
		return nil, err
	}
	defer clear(blob)
	point, err := decodeAgentNostrBase64(envelope.Point)
	if err != nil {
		return nil, err
	}
	defer clear(point)
	ciphertext, err := decodeAgentNostrBase64(envelope.Ciphertext)
	if err != nil {
		return nil, err
	}
	defer clear(ciphertext)
	request, err := json.Marshal(struct {
		Op         string `json:"op"`
		Blob       []byte `json:"blob"`
		Point      []byte `json:"point"`
		Ciphertext []byte `json:"ciphertext"`
	}{"unwrap-agent-nostr", blob, point, ciphertext})
	if err != nil || !agentNostrPrivateRequestWithinLimit(request) {
		clear(request)
		return nil, errors.New("agent Nostr private request exceeds its bound")
	}
	return request, nil
}

func parseAgentNostrWrapResponse(response []byte) (AgentNostrWrap, error) {
	var result struct {
		Blob          []byte `json:"blob"`
		Fingerprint   string `json:"fingerprint"`
		Point         []byte `json:"point"`
		Policy        string `json:"policy"`
		SilentRefused bool   `json:"silent_refused"`
	}
	if len(response) > 24576 || DecodeSingleJSON(response, &result) != nil {
		clear(result.Blob)
		clear(result.Point)
		return AgentNostrWrap{}, &AgentNostrPrivateError{Code: "unknown", Dispatched: true}
	}
	canonical, err := json.Marshal(map[string]any{
		"blob": result.Blob, "point": result.Point, "fingerprint": result.Fingerprint,
		"policy": result.Policy, "silent_refused": result.SilentRefused,
	})
	defer clear(canonical)
	if err != nil || !bytes.Equal(response, canonical) {
		clear(result.Blob)
		clear(result.Point)
		return AgentNostrWrap{}, &AgentNostrPrivateError{Code: "unknown", Dispatched: true}
	}
	return AgentNostrWrap{Blob: result.Blob, Fingerprint: result.Fingerprint, Point: result.Point, Policy: result.Policy, SilentRefused: result.SilentRefused}, nil
}

// receiveAgentNostrResult authenticates the complete one-frame response and
// retained process completion. Its cleanup callbacks are owned by the caller.
func receiveAgentNostrResult(reader io.Reader, closeEndpoint func() error, maxSuccess int,
	wait func() (int, error), cancel func(), deadlineExpired func() bool) ([]byte, error) {
	waited := false
	stop := func() {
		if closeEndpoint != nil {
			_ = closeEndpoint()
		}
		if cancel != nil {
			cancel()
		}
		if !waited && wait != nil {
			_, _ = wait()
			waited = true
		}
	}
	unknown := func() ([]byte, error) {
		stop()
		return nil, &AgentNostrPrivateError{Code: "unknown", Dispatched: true}
	}
	if reader == nil || maxSuccess < 1 || wait == nil {
		return unknown()
	}
	var header [5]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return unknown()
	}
	status := header[0]
	length := int(binary.BigEndian.Uint32(header[1:]))
	limit := maxSuccess
	if status == 1 {
		limit = 64
	}
	if status > 1 || length < 1 || length > limit {
		return unknown()
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		clear(payload)
		return unknown()
	}
	var extra [1]byte
	more, readErr := reader.Read(extra[:])
	if more != 0 || !errors.Is(readErr, io.EOF) {
		clear(payload)
		return unknown()
	}
	exitCode, waitErr := wait()
	waited = true
	deadlineElapsed := deadlineExpired != nil && deadlineExpired()
	if cancel != nil {
		cancel()
	}
	if closeEndpoint != nil {
		_ = closeEndpoint()
	}
	if deadlineElapsed || exitCode != int(status) {
		clear(payload)
		return nil, &AgentNostrPrivateError{Code: "unknown", Dispatched: true}
	}
	if status == 0 {
		if waitErr != nil {
			clear(payload)
			return nil, &AgentNostrPrivateError{Code: "unknown", Dispatched: true}
		}
		return payload, nil
	}
	if waitErr == nil {
		clear(payload)
		return nil, &AgentNostrPrivateError{Code: "unknown", Dispatched: true}
	}
	code := string(payload)
	clear(payload)
	if !validAgentNostrPrivateCode(code) {
		return nil, &AgentNostrPrivateError{Code: "unknown", Dispatched: true}
	}
	return nil, &AgentNostrPrivateError{Code: code, Dispatched: true}
}

func validAgentNostrPrivateCode(code string) bool {
	switch code {
	case "bad_request", "invalid_blob", "policy_refused", "presence_required", "auth_refused", "enclave_unavailable", "parent_not_admitted":
		return true
	default:
		return false
	}
}

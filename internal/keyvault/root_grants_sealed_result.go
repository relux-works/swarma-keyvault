package keyvault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// Pure public validation, deliberately without opening a private session/engine.
func rootGrantsHelperRequest(raw []byte) (rootGrantsPrivateRequest, error) {
	var q rootGrantsPrivateRequest
	if len(raw) > 262144 {
		return q, recoveryRefuse("limit_exceeded")
	}
	if len(raw) == 0 || DecodeSingleJSON(raw, &q) != nil {
		return q, recoveryRefuse("invalid_arguments")
	}
	canonical, err := json.Marshal(q)
	if err != nil || !bytes.Equal(raw, canonical) || len(q.PairMetadata) == 0 || q.Protocol == "" || q.Engine == "" || q.Profile == "" || q.Mode == "" {
		return rootGrantsPrivateRequest{}, recoveryRefuse("invalid_arguments")
	}
	if q.Protocol != "keyvault-root-grants-private/1" || q.Engine != "namecoin-root-grants-engine/1" || q.Profile != rootGrantsProfile {
		return rootGrantsPrivateRequest{}, recoveryRefuse("unsupported_version")
	}
	if q.Mode != "attach" {
		return rootGrantsPrivateRequest{}, recoveryRefuse("unsupported_operation")
	}
	if validateRootGrantsPair(q.Pair) != nil || rootGrantsMatchPair(q.PairMetadata, q.Pair) != nil {
		return rootGrantsPrivateRequest{}, recoveryRefuse("retained_record_mismatch")
	}
	if _, err := (RootGrantsAddress{Service: q.Service, Version: q.Version}).Account(); err != nil {
		return rootGrantsPrivateRequest{}, recoveryRefuse("invalid_arguments")
	}
	created, err := time.Parse(time.RFC3339, q.Created)
	if err != nil || len(q.Created) != 20 || created.UTC().Format(time.RFC3339) != q.Created {
		return rootGrantsPrivateRequest{}, recoveryRefuse("invalid_arguments")
	}
	return q, nil
}

// Pure shape/binding checking returns no plan or authenticity certificate. The
// request contains no independently known root K: K/02K/script consistency is
// checked here; actual private-key correspondence remains the pinned helper's
// qualified operation. No seed, scalar or consumed preparation is reconstructed.
func rootGrantsCheckSealed(rawRequest, rawSealed []byte) (rootGrantsSealedItem, RootGrantsProjection, error) {
	var empty rootGrantsSealedItem
	var projection RootGrantsProjection
	q, err := rootGrantsHelperRequest(rawRequest)
	if err != nil {
		return empty, projection, err
	}
	if len(rawSealed) == 0 || len(rawSealed) > 131072 {
		return empty, projection, recoveryRefuse("private_protocol_error")
	}
	var result RootGrantsPrivateSealed
	if DecodeSingleJSON(rawSealed, &result) != nil {
		return empty, projection, recoveryRefuse("private_protocol_error")
	}
	canonical, err := json.Marshal(result)
	if err != nil || !bytes.Equal(rawSealed, canonical) {
		return empty, projection, recoveryRefuse("private_protocol_error")
	}
	r, err := ParseRootGrantsRecord(result.Record)
	if err != nil || r.Service != q.Service || r.Version != q.Version || r.Created != q.Created || r.Profile != q.Profile || r.Pair != q.Pair || rootGrantsMatchPair(q.PairMetadata, r.Pair) != nil {
		return empty, projection, recoveryRefuse("binding_mismatch")
	}
	if _, err := ParseRootGrantsEnvelope(result.Envelope, r); err != nil {
		return empty, projection, recoveryRefuse("invalid_envelope")
	}
	pair, err := parseRecoveryRecord(q.PairMetadata)
	if err != nil || bytes.Equal(r.WrappingPoint, pair.Nostr.WrappingPoint) || bytes.Equal(r.WrappingPoint, pair.Namecoin.WrappingPoint) {
		return empty, projection, recoveryRefuse("wrapping_policy_refused")
	}
	return rootGrantsSealedItem{address: RootGrantsAddress{Service: q.Service, Version: q.Version}, metadata: string(result.Record), envelope: string(result.Envelope)}, rootGrantsProject(r), nil
}

// This package-private completion is minted ONLY by the fixed native caller
// after full bindings/live PID/code, exact v2 ACK/EOF and successful exit.
// Package-local test fixtures can model it but do not prove code admission.
// It is not a public approval wrapper, ciphertext import or native certificate.
type rootGrantsHelperResult struct{ completion *rootGrantsHelperCompletion }
type rootGrantsHelperCompletion struct {
	mu      sync.Mutex
	pid     int
	request []byte
	sealed  []byte
}

func (rootGrantsHelperResult) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "<root-grants-helper-result>")
}
func (rootGrantsHelperResult) MarshalJSON() ([]byte, error) {
	return nil, recoveryRefuse("private_protocol_error")
}

// Admission consumes this invocation once, including on validation failure.
// Zero/external public result objects cannot enter this path. There is no
// approved/qualified Boolean or exported constructor; trust includes all code
// in this internal package, not hostile code added to that same package.
func (r *rootGrantsHelperResult) plan() (*rootGrantsAttachment, error) {
	if r == nil || r.completion == nil {
		return nil, recoveryRefuse("code_not_admitted")
	}
	c := r.completion
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() { clear(c.request); clear(c.sealed); c.request = nil; c.sealed = nil; c.pid = 0 }()
	if c.pid <= 0 || len(c.request) == 0 || len(c.sealed) == 0 {
		return nil, recoveryRefuse("code_not_admitted")
	}
	item, public, err := rootGrantsCheckSealed(c.request, c.sealed)
	if err != nil {
		return nil, err
	}
	return &rootGrantsAttachment{state: &rootGrantsAttachmentState{item: item, public: public}}, nil
}

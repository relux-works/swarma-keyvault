package keyvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

var errRootTrustTestBinding = errors.New("synthetic binding refusal")

type rootTrustExchangeFailure struct {
	code    string
	outcome string
}

func (f *rootTrustExchangeFailure) Error() string { return f.code }

type rootTrustExchangeConfig struct {
	stages              []byte
	refusalCode         uint32
	returnedRefusalCode uint32
	ignoreRefusal       bool
	extraOutput         bool
	truncateStage       bool
	truncateSignature   bool
	inputCloseErr       error
	outputCloseErr      error
	waitErr             error
}

type rootTrustExchangeWriter struct {
	*io.PipeWriter
	closeErr error
	closes   atomic.Int32
}

func (w *rootTrustExchangeWriter) Close() error {
	w.closes.Add(1)
	err := w.PipeWriter.Close()
	if err != nil {
		return err
	}
	return w.closeErr
}

type rootTrustExchangeReader struct {
	*io.PipeReader
	closeErr error
	closes   atomic.Int32
}

func (r *rootTrustExchangeReader) Close() error {
	r.closes.Add(1)
	err := r.PipeReader.Close()
	if err != nil {
		return err
	}
	return r.closeErr
}

type rootTrustExchangeHost struct {
	request    []byte
	signature  []byte
	config     rootTrustExchangeConfig
	starts     atomic.Int32
	checks     atomic.Int32
	waits      atomic.Int32
	signed     atomic.Bool
	deadlineMu sync.Mutex
	deadlines  []time.Time
	childDone  chan error
	parentIn   *rootTrustExchangeWriter
	parentOut  *rootTrustExchangeReader
}

type rootTrustIncompleteExchangeHost struct {
	starts      atomic.Int32
	terms       atomic.Int32
	kills       atomic.Int32
	waits       atomic.Int32
	missingWait bool
}

func (*rootTrustIncompleteExchangeHost) verify(pid int, pin []byte) error {
	if pid == 0 && len(pin) == 0 || pid == 9417 && bytes.Equal(pin, bytes.Repeat([]byte{0x7a}, 20)) {
		return nil
	}
	return errors.New("test admission mismatch")
}

func (h *rootTrustIncompleteExchangeHost) start() (*rootGrantsHelperChild, error) {
	h.starts.Add(1)
	child := &rootGrantsHelperChild{
		pid: 9417,
		term: func() error {
			h.terms.Add(1)
			return nil
		},
		kill: func() error { h.kills.Add(1); return nil },
	}
	if !h.missingWait {
		child.wait = func() error { h.waits.Add(1); return nil }
	}
	return child, nil
}

func (h *rootTrustExchangeHost) recordDeadline(ctx context.Context) bool {
	deadline, ok := ctx.Deadline()
	if !ok {
		return false
	}
	h.deadlineMu.Lock()
	h.deadlines = append(h.deadlines, deadline)
	h.deadlineMu.Unlock()
	return true
}

func (h *rootTrustExchangeHost) observedDeadlines() []time.Time {
	h.deadlineMu.Lock()
	defer h.deadlineMu.Unlock()
	return append([]time.Time(nil), h.deadlines...)
}

// This proves the shared helper accepts only exact C1 parent-control frames and still admits both valid success/refusal controls.
func TestRootGrantsValidPrivateSigningControl(t *testing.T) {
	validRefusal := rootGrantsFrame46(1, binary.BigEndian.AppendUint32(nil, 13))
	for _, tc := range []struct {
		name string
		wire []byte
		want bool
	}{
		{name: "success", wire: []byte{0, 0, 0, 0, 0}, want: true},
		{name: "existing status refusal", wire: validRefusal, want: true},
		{name: "wrong tag", wire: []byte{2, 0, 0, 0, 0}, want: false},
		{name: "wrong success length", wire: []byte{0, 0, 0, 0, 4}, want: false},
		{name: "missing refusal code", wire: []byte{1, 0, 0, 0, 4}, want: false},
		{name: "zero refusal code", wire: rootGrantsFrame46(1, binary.BigEndian.AppendUint32(nil, 0)), want: false},
		{name: "unknown refusal code", wire: rootGrantsFrame46(1, binary.BigEndian.AppendUint32(nil, 25)), want: false},
		{name: "extra refusal bytes", wire: append(bytes.Clone(validRefusal), 0), want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := rootGrantsValidPrivateSigningControl(tc.wire); got != tc.want {
				t.Fatalf("control validity=%v, want %v", got, tc.want)
			}
		})
	}
}

func (h *rootTrustExchangeHost) verify(pid int, pin []byte) error {
	if pid == 0 && len(pin) == 0 {
		return nil
	}
	if pid == 9417 && bytes.Equal(pin, bytes.Repeat([]byte{0x7a}, 20)) {
		return nil
	}
	return errors.New("test admission mismatch")
}

func (h *rootTrustExchangeHost) start() (*rootGrantsHelperChild, error) {
	h.starts.Add(1)
	childIn, parentIn := io.Pipe()
	parentOut, childOut := io.Pipe()
	h.parentIn = &rootTrustExchangeWriter{PipeWriter: parentIn, closeErr: h.config.inputCloseErr}
	h.parentOut = &rootTrustExchangeReader{PipeReader: parentOut, closeErr: h.config.outputCloseErr}
	h.childDone = make(chan error, 1)
	go func() {
		h.childDone <- h.run(childIn, childOut)
	}()
	return &rootGrantsHelperChild{
		pid:    9417,
		input:  h.parentIn,
		output: h.parentOut,
		term:   func() error { return nil },
		kill:   func() error { return nil },
		wait: func() error {
			h.waits.Add(1)
			childErr := <-h.childDone
			if childErr != nil {
				return childErr
			}
			return h.config.waitErr
		},
	}, nil
}

func (h *rootTrustExchangeHost) run(input *io.PipeReader, output *io.PipeWriter) error {
	defer output.Close()
	var length [4]byte
	if _, err := io.ReadFull(input, length[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(length[:])
	if n == 0 || n > 262144 {
		return io.ErrUnexpectedEOF
	}
	request := make([]byte, int(n))
	defer clear(request)
	if _, err := io.ReadFull(input, request); err != nil || !bytes.Equal(request, h.request) {
		return io.ErrUnexpectedEOF
	}
	stages := h.config.stages
	if stages == nil {
		stages = []byte{1, 2}
	}
	for _, stage := range stages {
		frame, err := rootGrantsGrantV3RecheckFrame(stage, rootGrantsGrantV3AttemptLimit)
		if err != nil {
			return io.ErrClosedPipe
		}
		if h.config.truncateStage {
			_, _ = output.Write(frame[:len(frame)-1])
			return nil
		}
		if rootGrantsWriteRaw(output, frame) != nil {
			return io.ErrClosedPipe
		}
		var header [5]byte
		if _, err := io.ReadFull(input, header[:]); err != nil {
			return err
		}
		payloadLength := binary.BigEndian.Uint32(header[1:])
		if header[0] == 0 && payloadLength != 0 || header[0] == 1 && payloadLength != 4 || header[0] > 1 {
			return io.ErrUnexpectedEOF
		}
		var code uint32
		if payloadLength == 4 {
			var payload [4]byte
			if _, err := io.ReadFull(input, payload[:]); err != nil {
				return err
			}
			code = binary.BigEndian.Uint32(payload[:])
		}
		if header[0] == 1 {
			if h.config.ignoreRefusal {
				continue
			}
			responseCode := code
			if h.config.refusalCode != 0 {
				if code != h.config.refusalCode {
					return io.ErrUnexpectedEOF
				}
				responseCode = h.config.refusalCode
			}
			if h.config.returnedRefusalCode != 0 {
				responseCode = h.config.returnedRefusalCode
			}
			if rootGrantsWriteRaw(output, rootGrantsFrame46(1, binary.BigEndian.AppendUint32(nil, responseCode))) != nil {
				return io.ErrClosedPipe
			}
			var trailing [1]byte
			read, readErr := input.Read(trailing[:])
			if read != 0 || readErr != io.EOF {
				return io.ErrUnexpectedEOF
			}
			return nil
		}
		if code != 0 {
			return io.ErrUnexpectedEOF
		}
	}
	if len(stages) != 2 {
		// The caller under test must refuse this response before it can ACK.
	}
	h.signed.Store(true)
	signatureFrame := rootGrantsFrame46(0, h.signature)
	if h.config.truncateSignature {
		_, _ = output.Write(signatureFrame[:len(signatureFrame)-1])
		return nil
	}
	if rootGrantsWriteRaw(output, signatureFrame) != nil {
		return io.ErrClosedPipe
	}
	var ack [36]byte
	if _, err := io.ReadFull(input, ack[:]); err != nil {
		return err
	}
	want := rootGrantsCompletionACK(request, h.signature)
	if !bytes.Equal(ack[:], want[:]) {
		return io.ErrUnexpectedEOF
	}
	if h.config.extraOutput {
		if rootGrantsWriteRaw(output, []byte{0x55}) != nil {
			return io.ErrClosedPipe
		}
	}
	var trailing [1]byte
	read, readErr := input.Read(trailing[:])
	if read != 0 || readErr != io.EOF {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func rootTrustExchangeCallbacks(host *rootTrustExchangeHost, checkErr error) rootGrantsPrivateSigningPurpose {
	return rootGrantsPrivateSigningPurpose{
		requireOutputClose: true,
		validateRequest: func(raw []byte) error {
			if !bytes.Equal(raw, host.request) {
				return &rootTrustExchangeFailure{code: "invalid_arguments", outcome: "not_applied"}
			}
			return nil
		},
		verifySignature: func(raw, signature []byte) error {
			if !bytes.Equal(raw, host.request) || !bytes.Equal(signature, host.signature) {
				return errors.New("synthetic signature mismatch")
			}
			return nil
		},
		check: func(ctx context.Context, raw []byte) error {
			host.checks.Add(1)
			if !host.recordDeadline(ctx) || !bytes.Equal(raw, host.request) {
				return errors.New("synthetic recheck mismatch")
			}
			return checkErr
		},
		controlResponse: func(err error) []byte {
			if err == nil {
				return []byte{0, 0, 0, 0, 0}
			}
			code := uint32(16)
			if errors.Is(err, errRootTrustTestBinding) {
				code = 13
			} else if errors.Is(err, context.Canceled) {
				code = 14
			} else if errors.Is(err, context.DeadlineExceeded) {
				code = 15
			}
			return rootGrantsFrame46(1, binary.BigEndian.AppendUint32(nil, code))
		},
		refusalFailure: func(code uint32) error {
			if code == 13 {
				return &rootTrustExchangeFailure{code: "binding_mismatch", outcome: "not_applied"}
			}
			return &rootTrustExchangeFailure{code: "private_protocol_error", outcome: "unknown"}
		},
		refusalCode: func(err error) string {
			if errors.Is(err, errRootTrustTestBinding) {
				return "binding_mismatch"
			}
			return "private_protocol_error"
		},
		uncertainRefusal: func(code uint32) string {
			switch code {
			case 14:
				return "canceled"
			case 15:
				return "timeout"
			default:
				return "private_protocol_error"
			}
		},
		contextCode: func(err error) string {
			if errors.Is(err, context.DeadlineExceeded) {
				return "timeout"
			}
			return "canceled"
		},
		verificationCode: func(error) string { return "private_protocol_error" },
		failure: func(code, _ string, attempted bool) error {
			outcome := "unknown"
			if code == "binding_mismatch" && !attempted {
				outcome = "not_applied"
			}
			return &rootTrustExchangeFailure{code: code, outcome: outcome}
		},
	}
}

func rootTrustCountersignWireFixture(t *testing.T) []byte {
	t.Helper()
	return rootTrustCountersignWireFixtureForIssuer(t, grantV3TestK)
}

func rootTrustCountersignWireFixtureForIssuer(t *testing.T, issuer string) []byte {
	t.Helper()
	return rootTrustCountersignWireFixtureForScopeText(t, issuer, []byte("synthetic scope"), true)
}

func rootTrustCountersignTestContract(t *testing.T, scopeText []byte, scopeTextAvailable bool) []byte {
	t.Helper()
	contract := trustContractTestRoot()
	if scopeTextAvailable {
		digest := sha256.Sum256(scopeText)
		contract.ScopeTextSHA256 = hex.EncodeToString(digest[:])
	}
	return trustContractTestCanonical(t, contract)
}

func rootTrustCountersignAuthorityFixture(t *testing.T, record RootGrantsRecord, contract RootGrantsTrustContract,
	contractBytes []byte, seal RootGrantsGrantPoint) []byte {
	t.Helper()
	recordJSON, err := CanonicalRootGrantsRecord(record)
	if err != nil {
		t.Fatal("could not encode canonical full root record for authority fixture")
	}
	authority := rootGrantsTrustAuthorityV2{
		Schema: rootGrantsTrustAuthorityV2Schema, OwnerPrincipal: "owner:id/root",
		LandlordName: contract.LandlordName, Network: contract.Network,
		Genesis: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		Record: RootGrantsAuthorityRecord{Service: record.Service, Version: record.Version,
			MetadataSHA256: rootGrantsHashHex(recordJSON), PublicKey: record.PublicKey, SealScript: record.SealScript},
		RootGeneration: int64(record.Version),
		Operations:     []string{rootGrantsTrustContractCountersignOperation, rootGrantsGrantV3Operation},
		AgentName:      contract.AgentName, AgentKey: grantV3TestK,
		GranteeKey: contract.GranteeKey, GranteeName: "id/grantee",
		Scope: rootGrantsTrustDerivedGrantV3Scope(contract.Actions), NotBefore: contract.NotBefore,
		NotAfter: contract.NotAfter, MaxGrantSeconds: contract.NotAfter - contract.NotBefore,
		MaxBudgetSat: 0, Seal: seal,
		ApprovedContract: rootGrantsTrustAuthorityV2ApprovedContract{
			Profile: contract.Profile, ContractBytesBase64: base64.StdEncoding.EncodeToString(contractBytes),
			ContractSHA256: rootGrantsHashHex(contractBytes),
		},
		ObservationPolicy: RootGrantsOfflineReview,
	}
	authorityJSON, err := json.Marshal(authority)
	if err != nil {
		t.Fatal("could not encode canonical synthetic authority/2")
	}
	if _, err := rootGrantsParseTrustAuthorityV2(authorityJSON); err != nil {
		t.Fatalf("synthetic authority/2 fixture is not internally consistent: %v", err)
	}
	return authorityJSON
}

func rootTrustCountersignWireFixtureForScopeText(t *testing.T, issuer string, scopeText []byte, scopeTextAvailable bool) []byte {
	t.Helper()
	contractModel := trustContractTestRoot()
	if scopeTextAvailable {
		digest := sha256.Sum256(scopeText)
		contractModel.ScopeTextSHA256 = hex.EncodeToString(digest[:])
	}
	contract := trustContractTestCanonical(t, contractModel)
	contractHash := sha256.Sum256(contract)
	record, _ := rootGrantsRecordFixture13(t, "keyvault-root-grants/1")
	if record.PublicKey != issuer {
		t.Fatal("full root-record fixture does not match synthetic issuer")
	}
	recordJSON, err := CanonicalRootGrantsRecord(record)
	if err != nil {
		t.Fatal("could not encode canonical full root record")
	}
	recordPin := RootGrantsAuthorityRecord{
		Service: record.Service, Version: record.Version, MetadataSHA256: rootGrantsHashHex(recordJSON),
		PublicKey: record.PublicKey, SealScript: record.SealScript,
	}
	issuance := RootGrantsTrustContractCountersignIssuanceContext{
		RootRecord: recordPin, RootGeneration: 1, LandlordName: contractModel.LandlordName, Network: "regtest",
		Genesis:   "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		IssuerKey: issuer, AgentName: contractModel.AgentName, AgentKey: grantV3TestK, GranteeKey: contractModel.GranteeKey,
		GranteeName: "id/grantee", NotBefore: contractModel.NotBefore, NotAfter: contractModel.NotAfter, MaxGrantSeconds: 99, MaxBudgetSat: 0,
		Seal:    RootGrantsGrantPoint{TxID: strings.Repeat("4", 64), Vout: 0},
		Actions: slices.Clone(contractModel.Actions), Repos: slices.Clone(contractModel.Repos),
		SpendBudget: contractModel.SpendBudget, DerivedV3Scope: []string{},
	}
	issuanceJSON, err := rootGrantsTrustContractCountersignIssuanceContextJSON(issuance)
	if err != nil {
		t.Fatal("could not encode synthetic issuance context")
	}
	seal := issuance.Seal
	authorityJSON := rootTrustCountersignAuthorityFixture(t, record, contractModel, contract, seal)
	authorityHash := sha256.Sum256(authorityJSON)
	recordHash := sha256.Sum256(recordJSON)
	scopeTextHash := ""
	if scopeTextAvailable {
		digest := sha256.Sum256(scopeText)
		scopeTextHash = hex.EncodeToString(digest[:])
	}
	reviewJSON, err := json.Marshal(rootGrantsTrustContractCountersignReviewWire{
		Operation: rootGrantsTrustContractCountersignOperation, Profile: rootGrantsTrustContractCountersignProfile,
		ContractProfile: rootGrantsTrustContractProfile, ContractBase64: base64.StdEncoding.EncodeToString(contract),
		ContractBytes: len(contract), ContractSHA256: hex.EncodeToString(contractHash[:]),
		ScopeTextBase64: base64.StdEncoding.EncodeToString(scopeText), ScopeTextBytes: len(scopeText),
		ScopeTextSHA256: scopeTextHash, IssuanceContextJSON: issuanceJSON,
		AuthorityJSON: authorityJSON, RecordJSON: recordJSON, AuthoritySHA256: hex.EncodeToString(authorityHash[:]),
		RecordSHA256: hex.EncodeToString(recordHash[:]),
	})
	clear(issuanceJSON)
	if err != nil {
		t.Fatal("could not encode synthetic countersign review")
	}
	request, err := rootGrantsTrustContractCountersignHelperRequest(reviewJSON, []byte(`{"fixture":"envelope"}`), []byte{1})
	clear(reviewJSON)
	if err != nil {
		t.Fatal("could not encode synthetic helper request")
	}
	return request
}

func rootTrustRewriteCountersignReview(t *testing.T, raw []byte, edit func(*rootGrantsTrustContractCountersignReviewWire)) []byte {
	t.Helper()
	var outer rootGrantsGrantV3HelperRequest
	if DecodeSingleJSON(raw, &outer) != nil {
		t.Fatal("could not decode synthetic outer request")
	}
	var review rootGrantsTrustContractCountersignReviewWire
	if DecodeSingleJSON(outer.Review, &review) != nil {
		t.Fatal("could not decode synthetic review")
	}
	edit(&review)
	reviewJSON, err := json.Marshal(review)
	if err != nil {
		t.Fatal("could not encode edited synthetic review")
	}
	outer.Review = reviewJSON
	request, err := json.Marshal(outer)
	clear(reviewJSON)
	if err != nil {
		t.Fatal("could not encode edited synthetic request")
	}
	return request
}

func rootTrustReplaceCountersignReviewBytes(t *testing.T, raw, old, replacement []byte) []byte {
	t.Helper()
	var outer rootGrantsGrantV3HelperRequest
	if DecodeSingleJSON(raw, &outer) != nil || !bytes.Contains(outer.Review, old) {
		t.Fatal("could not locate synthetic review bytes")
	}
	outer.Review = bytes.Replace(outer.Review, old, replacement, 1)
	request, err := json.Marshal(outer)
	if err != nil {
		t.Fatal("could not encode edited synthetic request")
	}
	return request
}

func rootTrustRewriteCountersignOuter(t *testing.T, raw []byte, edit func(*rootGrantsGrantV3HelperRequest)) []byte {
	t.Helper()
	var outer rootGrantsGrantV3HelperRequest
	if DecodeSingleJSON(raw, &outer) != nil {
		t.Fatal("could not decode synthetic outer request")
	}
	edit(&outer)
	request, err := json.Marshal(outer)
	if err != nil {
		t.Fatal("could not encode edited synthetic outer request")
	}
	return request
}

func rootTrustAppendCountersignReviewMember(t *testing.T, raw []byte) []byte {
	t.Helper()
	var outer rootGrantsGrantV3HelperRequest
	if DecodeSingleJSON(raw, &outer) != nil || len(outer.Review) == 0 || outer.Review[len(outer.Review)-1] != '}' {
		t.Fatal("could not decode synthetic review object")
	}
	outer.Review = append(bytes.TrimSuffix(outer.Review, []byte("}")), []byte(`,"unexpected":true}`)...)
	request, err := json.Marshal(outer)
	if err != nil {
		t.Fatal("could not encode synthetic review with an extra member")
	}
	return request
}

func rootTrustCountersignPaddedJSONObject(size int) []byte {
	const prefix = `{"pad":"`
	const suffix = `"}`
	if size < len(prefix)+len(suffix) {
		return nil
	}
	return []byte(prefix + strings.Repeat("x", size-len(prefix)-len(suffix)) + suffix)
}

func rootTrustCountersignPaddedJSONObjectWithEscapes(size int, escaped bool) []byte {
	plain := rootTrustCountersignPaddedJSONObject(size)
	if len(plain) == 0 || !escaped {
		return plain
	}
	const prefixLength = 8
	const suffixLength = 2
	bodyBytes := size - prefixLength - suffixLength
	body := strings.Repeat(string([]byte{92, 92}), bodyBytes/2) + strings.Repeat("x", bodyBytes%2)
	raw := bytes.Clone(plain[:prefixLength])
	raw = append(raw, body...)
	return append(raw, plain[len(plain)-suffixLength:]...)
}

func rootTrustCountersignIssuanceJSONAtSize(t *testing.T, raw []byte, want int, escaped bool) []byte {
	t.Helper()
	var outer rootGrantsGrantV3HelperRequest
	if DecodeSingleJSON(raw, &outer) != nil {
		t.Fatal("could not decode synthetic outer request")
	}
	var review rootGrantsTrustContractCountersignReviewWire
	if DecodeSingleJSON(outer.Review, &review) != nil {
		t.Fatal("could not decode synthetic review")
	}
	var issuance RootGrantsTrustContractCountersignIssuanceContext
	if DecodeSingleJSON(review.IssuanceContextJSON, &issuance) != nil {
		t.Fatal("could not decode synthetic issuance context")
	}
	base, err := json.Marshal(issuance)
	if err != nil {
		t.Fatal("could not encode synthetic issuance context", err)
	}
	oldName, err := json.Marshal(issuance.AgentName)
	if err != nil {
		t.Fatal("could not encode synthetic agent name", err)
	}
	bodyBytes := want - len(base) + len(oldName) - 2
	if bodyBytes < 0 {
		t.Fatal("requested issuance size is smaller than fixed fields")
	}
	if escaped {
		issuance.AgentName = strings.Repeat("\\", bodyBytes/2) + strings.Repeat("x", bodyBytes%2)
	} else {
		issuance.AgentName = strings.Repeat("x", bodyBytes)
	}
	encoded, err := json.Marshal(issuance)
	if err != nil || len(encoded) != want {
		t.Fatalf("synthetic issuance context has %d bytes, want exactly %d (err=%v)", len(encoded), want, err)
	}
	return encoded
}

func rootTrustCountersignNestedJSONAtSize(t *testing.T, raw []byte, field string, want int, escaped bool) []byte {
	t.Helper()
	var outer rootGrantsGrantV3HelperRequest
	if DecodeSingleJSON(raw, &outer) != nil {
		t.Fatal("could not decode synthetic outer request")
	}
	var review rootGrantsTrustContractCountersignReviewWire
	if DecodeSingleJSON(outer.Review, &review) != nil {
		t.Fatal("could not decode synthetic review")
	}
	switch field {
	case "issuance":
		return rootTrustCountersignIssuanceJSONAtSize(t, raw, want, escaped)
	case "authority":
		var authority rootGrantsTrustAuthorityV2
		if DecodeSingleJSON(review.AuthorityJSON, &authority) != nil {
			t.Fatal("could not decode synthetic authority/2 fixture")
		}
		base, err := json.Marshal(authority)
		if err != nil || !bytes.Equal(base, review.AuthorityJSON) {
			t.Fatal("synthetic authority/2 fixture is not canonical")
		}
		oldValue, err := json.Marshal(authority.ObservationPolicy)
		if err != nil {
			t.Fatal("could not encode synthetic authority observation policy")
		}
		bodyBytes := want - len(base) + len(oldValue) - 2
		if bodyBytes < 0 {
			t.Fatal("requested authority size is smaller than the fixed fixture")
		}
		if escaped {
			authority.ObservationPolicy = strings.Repeat("\\", bodyBytes/2) + strings.Repeat("x", bodyBytes%2)
		} else {
			authority.ObservationPolicy = strings.Repeat("x", bodyBytes)
		}
		encoded, err := json.Marshal(authority)
		if err != nil || len(encoded) != want {
			t.Fatalf("synthetic typed authority has %d bytes, want exactly %d (err=%v)", len(encoded), want, err)
		}
		return encoded
	case "record":
		var record RootGrantsRecord
		if DecodeSingleJSON(review.RecordJSON, &record) != nil {
			t.Fatal("could not decode synthetic record")
		}
		base, err := json.Marshal(record)
		if err != nil {
			t.Fatal("could not encode synthetic record", err)
		}
		oldValue, err := json.Marshal(record.SealScript)
		if err != nil {
			t.Fatal("could not encode synthetic record seal script", err)
		}
		bodyBytes := want - len(base) + len(oldValue) - 2
		if bodyBytes < 0 {
			t.Fatal("requested record size is smaller than fixed fields")
		}
		if escaped {
			record.SealScript = strings.Repeat("\\", bodyBytes/2) + strings.Repeat("x", bodyBytes%2)
		} else {
			record.SealScript = strings.Repeat("x", bodyBytes)
		}
		encoded, err := json.Marshal(record)
		if err != nil || len(encoded) != want {
			t.Fatalf("synthetic record has %d bytes, want exactly %d (err=%v)", len(encoded), want, err)
		}
		return encoded
	default:
		t.Fatalf("unknown synthetic nested field %q", field)
		return nil
	}
}

// Claim: a contract window must fit inside the authority window and maximum duration, with exact bounds accepted; this check has no wall-clock input.
func TestRootGrantsTrustContractCountersignWindowWithinAuthority(t *testing.T) {
	for _, tc := range []struct {
		name       string
		contract   RootGrantsTrustContract
		authority  [2]int64
		maxSeconds int64
		want       bool
	}{
		{name: "exact authority bounds", contract: RootGrantsTrustContract{NotBefore: 100, NotAfter: 250}, authority: [2]int64{100, 250}, maxSeconds: 150, want: true},
		{name: "nested positive", contract: RootGrantsTrustContract{NotBefore: 150, NotAfter: 250}, authority: [2]int64{100, 300}, maxSeconds: 150, want: true},
		{name: "starts before authority", contract: RootGrantsTrustContract{NotBefore: 99, NotAfter: 250}, authority: [2]int64{100, 300}, maxSeconds: 200},
		{name: "ends after authority", contract: RootGrantsTrustContract{NotBefore: 100, NotAfter: 301}, authority: [2]int64{100, 300}, maxSeconds: 250},
		{name: "exceeds maximum duration", contract: RootGrantsTrustContract{NotBefore: 100, NotAfter: 251}, authority: [2]int64{100, 400}, maxSeconds: 150},
		{name: "empty contract window", contract: RootGrantsTrustContract{NotBefore: 200, NotAfter: 200}, authority: [2]int64{100, 300}, maxSeconds: 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rootGrantsTrustContractCountersignWindowWithinAuthority(tc.contract, tc.authority[0], tc.authority[1], tc.maxSeconds)
			if got != tc.want {
				t.Fatalf("window accepted=%t, want %t", got, tc.want)
			}
		})
	}
}

// This proves the purpose-specific wire parser accepts one exact synthetic shape and rejects schema, type, order, encoding, binding, and bound violations before any helper can start; authority/2 semantics are supplied by the separately owned validator.
func TestRootGrantsTrustContractCountersignHelperRequestStrictShape(t *testing.T) {
	valid := rootTrustCountersignWireFixture(t)
	original := bytes.Clone(valid)
	parsed, err := rootGrantsTrustContractCountersignParseHelperRequest(valid)
	if err != nil {
		t.Fatalf("synthetic closed helper request was rejected: %v", err)
	}
	if !bytes.Equal(parsed.Contract, rootTrustCountersignTestContract(t, []byte("synthetic scope"), true)) ||
		!bytes.Equal(parsed.ScopeText, []byte("synthetic scope")) || !parsed.ScopeTextAvailable ||
		parsed.Review.Operation != rootGrantsTrustContractCountersignOperation || parsed.Issuance.IssuerKey == "" {
		parsed.clear()
		t.Fatal("synthetic helper request did not preserve exact reviewed bytes and context")
	}
	parsed.clear()
	if !bytes.Equal(valid, original) {
		t.Fatal("helper parser mutated caller-owned request bytes")
	}

	contract := rootTrustCountersignTestContract(t, []byte("synthetic scope"), true)
	wrongContractBytesType := rootTrustReplaceCountersignReviewBytes(t, valid,
		[]byte(`"contract_bytes":`+strconv.Itoa(len(contract))),
		[]byte(`"contract_bytes":"`+strconv.Itoa(len(contract))+`"`))
	reorderedReview := rootTrustReplaceCountersignReviewBytes(t, valid,
		[]byte(`"operation":"`+rootGrantsTrustContractCountersignOperation+`","profile":"`+rootGrantsTrustContractCountersignProfile+`"`),
		[]byte(`"profile":"`+rootGrantsTrustContractCountersignProfile+`","operation":"`+rootGrantsTrustContractCountersignOperation+`"`))
	invalidContractReview := rootTrustRewriteCountersignReview(t, valid, func(review *rootGrantsTrustContractCountersignReviewWire) {
		contract := []byte("x")
		review.ContractBase64 = base64.StdEncoding.EncodeToString(contract)
		review.ContractBytes = len(contract)
		review.ContractSHA256 = rootGrantsHashHex(contract)
	})
	reorderedReviewInvalidContract := rootTrustReplaceCountersignReviewBytes(t, invalidContractReview,
		[]byte(`"operation":"`+rootGrantsTrustContractCountersignOperation+`","profile":"`+rootGrantsTrustContractCountersignProfile+`"`),
		[]byte(`"profile":"`+rootGrantsTrustContractCountersignProfile+`","operation":"`+rootGrantsTrustContractCountersignOperation+`"`))
	invalidContractWrongDigest := rootTrustRewriteCountersignReview(t, invalidContractReview, func(review *rootGrantsTrustContractCountersignReviewWire) {
		review.ContractSHA256 = strings.Repeat("f", 64)
	})
	invalidContractWrongAuthorityDigest := rootTrustRewriteCountersignReview(t, invalidContractReview, func(review *rootGrantsTrustContractCountersignReviewWire) {
		review.AuthoritySHA256 = strings.Repeat("f", 64)
	})
	invalidContractWrongRecordDigest := rootTrustRewriteCountersignReview(t, invalidContractReview, func(review *rootGrantsTrustContractCountersignReviewWire) {
		review.RecordSHA256 = strings.Repeat("f", 64)
	})
	wrongContractBytes := bytes.Repeat([]byte{'x'}, 8193)
	wrongContractDigest := sha256.Sum256(wrongContractBytes)
	tooLargeContract := rootTrustRewriteCountersignReview(t, valid, func(review *rootGrantsTrustContractCountersignReviewWire) {
		review.ContractBase64 = base64.StdEncoding.EncodeToString(wrongContractBytes)
		review.ContractBytes = len(wrongContractBytes)
		review.ContractSHA256 = hex.EncodeToString(wrongContractDigest[:])
	})
	wrongRecord := rootTrustRewriteCountersignReview(t, valid, func(review *rootGrantsTrustContractCountersignReviewWire) {
		record := RootGrantsAuthorityRecord{Service: "different-root", Version: 1, MetadataSHA256: strings.Repeat("1", 64),
			PublicKey: strings.Repeat("4", 64), SealScript: "synthetic"}
		review.RecordJSON, _ = json.Marshal(record)
	})
	cases := []struct {
		name    string
		raw     []byte
		code    string
		phase   string
		outcome string
		status  int32
	}{
		{name: "empty request", raw: nil, code: "invalid_arguments"},
		{name: "over-limit request", raw: make([]byte, 262145), code: "limit_exceeded"},
		{name: "wrong helper schema", raw: rootTrustRewriteCountersignOuter(t, valid, func(outer *rootGrantsGrantV3HelperRequest) { outer.Schema = "keyvault-root-grants-sign-request/3" }), code: "unsupported_version"},
		{name: "wrong helper operation", raw: rootTrustRewriteCountersignOuter(t, valid, func(outer *rootGrantsGrantV3HelperRequest) { outer.Operation = "review-sign-grant-v3" }), code: "unsupported_operation"},
		{name: "reordered outer fields", raw: bytes.Replace(valid, []byte(`"schema":"`+rootGrantsTrustContractCountersignHelperSchema+`","operation":"`+rootGrantsTrustContractCountersignOperation+`"`), []byte(`"operation":"`+rootGrantsTrustContractCountersignOperation+`","schema":"`+rootGrantsTrustContractCountersignHelperSchema+`"`), 1), code: "private_protocol_error"},
		{name: "extra outer field", raw: bytes.Replace(valid, []byte(`"operation":"`+rootGrantsTrustContractCountersignOperation+`","review":`), []byte(`"operation":"`+rootGrantsTrustContractCountersignOperation+`","unexpected":true,"review":`), 1), code: "private_protocol_error"},
		{name: "wrong review operation", raw: rootTrustRewriteCountersignReview(t, valid, func(review *rootGrantsTrustContractCountersignReviewWire) { review.Operation = "review-sign-grant-v3" }), code: "unsupported_operation"},
		{name: "wrong review profile", raw: rootTrustRewriteCountersignReview(t, valid, func(review *rootGrantsTrustContractCountersignReviewWire) {
			review.Profile = "namecoin-landlord-root/2"
		}), code: "unsupported_version"},
		{name: "wrong contract profile", raw: rootTrustRewriteCountersignReview(t, valid, func(review *rootGrantsTrustContractCountersignReviewWire) {
			review.ContractProfile = "swarma-trust-contract/1"
		}), code: "unsupported_version"},
		{name: "extra review field", raw: rootTrustAppendCountersignReviewMember(t, valid), code: "private_protocol_error"},
		{name: "reordered review fields", raw: reorderedReview, code: "private_protocol_error", phase: "review", outcome: "unknown", status: 16},
		{name: "reordered review precedes invalid LIP semantics", raw: reorderedReviewInvalidContract, code: "private_protocol_error", phase: "review", outcome: "unknown", status: 16},
		{name: "wrong field type", raw: wrongContractBytesType, code: "private_protocol_error"},
		{name: "noncanonical base64", raw: rootTrustRewriteCountersignReview(t, valid, func(review *rootGrantsTrustContractCountersignReviewWire) { review.ContractBase64 = "%%%" }), code: "private_protocol_error", phase: "review", outcome: "unknown", status: 16},
		{name: "contract byte count mismatch", raw: rootTrustRewriteCountersignReview(t, valid, func(review *rootGrantsTrustContractCountersignReviewWire) { review.ContractBytes++ }), code: "binding_mismatch", phase: "review", outcome: "not_applied", status: 13},
		{name: "contract digest mismatch", raw: rootTrustRewriteCountersignReview(t, valid, func(review *rootGrantsTrustContractCountersignReviewWire) {
			review.ContractSHA256 = strings.Repeat("f", 64)
		}), code: "binding_mismatch", phase: "review", outcome: "not_applied", status: 13},
		{name: "contract parse precedes digest mismatch", raw: invalidContractWrongDigest, code: "CONTRACT_ENCODING", phase: "contract_parse", outcome: "not_applied", status: 13},
		{name: "contract parse precedes authority digest mismatch", raw: invalidContractWrongAuthorityDigest, code: "CONTRACT_ENCODING", phase: "contract_parse", outcome: "not_applied", status: 13},
		{name: "contract parse precedes record digest mismatch", raw: invalidContractWrongRecordDigest, code: "CONTRACT_ENCODING", phase: "contract_parse", outcome: "not_applied", status: 13},
		{name: "scope text hash mismatch", raw: rootTrustRewriteCountersignReview(t, valid, func(review *rootGrantsTrustContractCountersignReviewWire) {
			review.ScopeTextBase64 = base64.StdEncoding.EncodeToString([]byte("changed scope"))
			review.ScopeTextBytes = len([]byte("changed scope"))
		}), code: "scope_text_hash_mismatch"},
		{name: "unexpected scope bytes", raw: rootTrustRewriteCountersignReview(t, rootTrustCountersignWireFixtureForScopeText(t, grantV3TestK, nil, false), func(review *rootGrantsTrustContractCountersignReviewWire) {
			scopeText := []byte("unexpected")
			review.ScopeTextBase64 = base64.StdEncoding.EncodeToString(scopeText)
			review.ScopeTextBytes = len(scopeText)
			review.ScopeTextSHA256 = rootGrantsHashHex(scopeText)
		}), code: "scope_text_unexpected"},
		{name: "authority pin object is not a full root record", raw: wrongRecord, code: "private_protocol_error"},
		{name: "authority digest mismatch", raw: rootTrustRewriteCountersignReview(t, valid, func(review *rootGrantsTrustContractCountersignReviewWire) {
			review.AuthoritySHA256 = strings.Repeat("f", 64)
		}), code: "binding_mismatch", phase: "review", outcome: "not_applied", status: 13},
		{name: "record digest mismatch", raw: rootTrustRewriteCountersignReview(t, valid, func(review *rootGrantsTrustContractCountersignReviewWire) {
			review.RecordSHA256 = strings.Repeat("f", 64)
		}), code: "binding_mismatch", phase: "review", outcome: "not_applied", status: 13},
		{name: "uppercase retained pair encoding", raw: rootTrustRewriteCountersignOuter(t, valid, func(outer *rootGrantsGrantV3HelperRequest) { outer.PairMetadata = "0A" }), code: "retained_record_mismatch"},
		{name: "LIP contract size boundary", raw: tooLargeContract, code: "CONTRACT_ENCODING", phase: "contract_parse", outcome: "not_applied", status: 13},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rootGrantsTrustContractCountersignParseHelperRequest(tc.raw)
			var failure *RootGrantsGrantV3Failure
			wantOutcome := "not_applied"
			if tc.code == "private_protocol_error" {
				wantOutcome = "unknown"
			}
			if tc.outcome != "" {
				wantOutcome = tc.outcome
			}
			if !errors.As(err, &failure) || failure.Code != tc.code || failure.Outcome != wantOutcome {
				t.Fatalf("request refusal=%v, want code=%q outcome=%s", err, tc.code, wantOutcome)
			}
			if tc.phase != "" && failure.Phase != tc.phase {
				t.Fatalf("request refusal phase=%q, want %q", failure.Phase, tc.phase)
			}
			if tc.status != 0 && RootGrantsTrustContractCountersignHelperStatus(err) != tc.status {
				t.Fatalf("request status=%d, want %d", RootGrantsTrustContractCountersignHelperStatus(err), tc.status)
			}
		})
	}
}

// This proves the helper request parser retains the difference between unavailable text and present empty text after Base64 decoding.
func TestRootGrantsTrustContractCountersignHelperScopeTextPresence(t *testing.T) {
	for _, tc := range []struct {
		name      string
		available bool
	}{
		{name: "unavailable", available: false},
		{name: "present empty", available: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := rootTrustCountersignWireFixtureForScopeText(t, grantV3TestK, nil, tc.available)
			parsed, err := rootGrantsTrustContractCountersignParseHelperRequest(request)
			if err != nil {
				t.Fatalf("synthetic %s scope text request was rejected: %v", tc.name, err)
			}
			defer parsed.clear()
			if parsed.ScopeTextAvailable != tc.available || len(parsed.ScopeText) != 0 {
				t.Fatalf("scope-text state=%t bytes=%d, want available=%t and no bytes", parsed.ScopeTextAvailable, len(parsed.ScopeText), tc.available)
			}
		})
	}
}

// This proves the recheck accepts a canonical public envelope, rejects noncanonical or malformed encoding as UNKNOWN, and keeps a well-formed but invalid envelope distinct; it does not validate ciphertext authenticity or native custody.
// Claim: the full valid helper fixture fits every agreed byte bound; canonical typed nested carriers preserve the LIP failure in-bound and return the bound refusal over-limit. Padded values do not prove semantic authority, record, or issuance acceptance.
func TestRootGrantsTrustContractCountersignNestedBoundsAndPrecedence(t *testing.T) {
	valid := rootTrustCountersignWireFixture(t)
	var outer rootGrantsGrantV3HelperRequest
	if DecodeSingleJSON(valid, &outer) != nil {
		t.Fatal("could not decode full valid helper fixture")
	}
	var review rootGrantsTrustContractCountersignReviewWire
	if DecodeSingleJSON(outer.Review, &review) != nil {
		t.Fatal("could not decode full valid review fixture")
	}
	lengths := rootGrantsTrustContractCountersignJSONSizes{
		issuance: len(review.IssuanceContextJSON), authority: len(review.AuthorityJSON),
		record: len(review.RecordJSON), review: len(outer.Review), payload: len(valid),
	}
	if !rootGrantsTrustContractCountersignJSONSizesWithinBound(lengths) {
		t.Fatalf("full valid fixture exceeds the agreed limits: %#v", lengths)
	}
	t.Logf("valid fixture bytes issuance=%d authority=%d record=%d review=%d payload=%d",
		lengths.issuance, lengths.authority, lengths.record, lengths.review, lengths.payload)
	parsed, err := rootGrantsTrustContractCountersignParseHelperRequest(valid)
	if err != nil {
		t.Fatalf("full valid helper fixture was rejected: %v", err)
	}
	parsed.clear()

	for _, field := range []string{"issuance", "authority", "record"} {
		for _, tc := range []struct {
			nested int
			escape bool
			code   string
			phase  string
			status int32
		}{
			{nested: 32767, code: "CONTRACT_ENCODING", phase: "contract_parse", status: 13},
			{nested: 32768, escape: true, code: "CONTRACT_ENCODING", phase: "contract_parse", status: 13},
			{nested: 32769, code: "limit_exceeded", phase: "preflight", status: 17},
		} {
			t.Run(field+"-"+strconv.Itoa(tc.nested), func(t *testing.T) {
				nestedJSON := rootTrustCountersignNestedJSONAtSize(t, valid, field, tc.nested, tc.escape)
				malformedContract := []byte("x")
				raw := rootTrustRewriteCountersignReview(t, valid, func(review *rootGrantsTrustContractCountersignReviewWire) {
					switch field {
					case "issuance":
						review.IssuanceContextJSON = bytes.Clone(nestedJSON)
					case "authority":
						review.AuthorityJSON = bytes.Clone(nestedJSON)
					case "record":
						review.RecordJSON = bytes.Clone(nestedJSON)
					}
					review.ContractBase64 = base64.StdEncoding.EncodeToString(malformedContract)
					review.ContractBytes = len(malformedContract)
					review.ContractSHA256 = rootGrantsHashHex(malformedContract)
				})
				original := bytes.Clone(raw)
				parsed, err := rootGrantsTrustContractCountersignParseHelperRequest(raw)
				if err == nil {
					parsed.clear()
					t.Fatal("malformed contract unexpectedly produced a parsed helper request")
				}
				var failure *RootGrantsGrantV3Failure
				if !errors.As(err, &failure) || failure.Code != tc.code || failure.Phase != tc.phase || failure.Outcome != "not_applied" ||
					RootGrantsTrustContractCountersignHelperStatus(err) != tc.status || !bytes.Equal(raw, original) {
					t.Fatalf("%s nested=%d refusal=%#v, %v; want %s/%s/not_applied status %d and unchanged input",
						field, tc.nested, failure, err, tc.code, tc.phase, tc.status)
				}
			})
		}
	}
}

// Claim: review and complete-payload maxima are inclusive; the full-payload check rejects aggregate overflow even when review and envelope values fit their independent bounds. A maximum-sized review cannot fit a complete request with mandatory outer fields.
func TestRootGrantsTrustContractCountersignReviewAndPayloadBoundaries(t *testing.T) {
	for _, size := range []int{262143, 262144, 262145} {
		review := rootTrustCountersignPaddedJSONObject(size)
		wantReviewWithin := size <= rootGrantsTrustContractCountersignReviewMaxBytes
		if got := rootGrantsTrustContractCountersignJSONSizesWithinBound(rootGrantsTrustContractCountersignJSONSizes{review: len(review)}); got != wantReviewWithin {
			t.Errorf("review size %d accepted=%v, want %v", size, got, wantReviewWithin)
		}
		_, err := rootGrantsTrustContractCountersignHelperRequest(review, []byte("{\"envelope\":true}"), []byte{0xab})
		var failure *RootGrantsGrantV3Failure
		if !errors.As(err, &failure) || failure.Code != "limit_exceeded" || failure.Phase != "review" || failure.Outcome != "not_applied" ||
			RootGrantsTrustContractCountersignHelperStatus(err) != 17 {
			t.Fatalf("review size %d refusal=%#v, %v; wanted status 17/not_applied", size, failure, err)
		}
	}

	const reviewSize = 200000
	review := rootTrustCountersignPaddedJSONObject(reviewSize)
	baseEnvelope := []byte("{\"pad\":\"\"}")
	pairMetadata := []byte{0xab}
	base, err := rootGrantsTrustContractCountersignHelperRequest(review, baseEnvelope, pairMetadata)
	if err != nil {
		t.Fatal("could not build helper payload sizing fixture", err)
	}
	for _, target := range []int{262143, 262144, 262145} {
		envelopeSize := target - len(base) + len(baseEnvelope)
		envelope := rootTrustCountersignPaddedJSONObject(envelopeSize)
		if len(envelope) > 65536 {
			t.Fatalf("payload sizing envelope %d exceeds the existing envelope bound", len(envelope))
		}
		request, err := rootGrantsTrustContractCountersignHelperRequest(review, envelope, pairMetadata)
		wantWithin := target <= rootGrantsTrustContractCountersignPayloadMaxBytes
		if got := rootGrantsTrustContractCountersignJSONSizesWithinBound(rootGrantsTrustContractCountersignJSONSizes{payload: target}); got != wantWithin {
			t.Errorf("payload size %d accepted=%v, want %v", target, got, wantWithin)
		}
		if wantWithin {
			if err != nil || len(request) != target {
				t.Fatalf("payload size %d produced %d bytes, err=%v", target, len(request), err)
			}
		} else {
			var failure *RootGrantsGrantV3Failure
			if !errors.As(err, &failure) || failure.Code != "limit_exceeded" || failure.Phase != "review" || failure.Outcome != "not_applied" ||
				RootGrantsTrustContractCountersignHelperStatus(err) != 17 {
				t.Fatalf("payload size %d refusal=%#v, %v; want status 17/not_applied", target, failure, err)
			}
		}
	}

	aggregateReview := rootTrustCountersignPaddedJSONObject(230000)
	aggregateEnvelope := rootTrustCountersignPaddedJSONObject(40000)
	if len(aggregateReview) > rootGrantsTrustContractCountersignReviewMaxBytes || len(aggregateEnvelope) > 65536 {
		t.Fatal("aggregate control values must each fit their independent bounds")
	}
	_, err = rootGrantsTrustContractCountersignHelperRequest(aggregateReview, aggregateEnvelope, pairMetadata)
	var failure *RootGrantsGrantV3Failure
	if !errors.As(err, &failure) || failure.Code != "limit_exceeded" || failure.Phase != "review" || failure.Outcome != "not_applied" ||
		RootGrantsTrustContractCountersignHelperStatus(err) != 17 {
		t.Fatalf("aggregate overflow refusal=%#v, %v; want status 17/not_applied", failure, err)
	}
}

// Claim: an exact 8192-byte decoded contract reaches its later LIP note rule, while byte 8193 remains rule1 CONTRACT_ENCODING.
func TestRootGrantsTrustContractCountersignDecodedContractBoundary(t *testing.T) {
	base := rootTrustCountersignTestContract(t, []byte("synthetic scope"), true)
	for _, tc := range []struct {
		size int
		code string
		rule int
	}{{8192, "CONTRACT_NOTE", 7}, {8193, "CONTRACT_ENCODING", 1}} {
		noteBytes := tc.size - len(base)
		if noteBytes < 0 || !bytes.Contains(base, []byte("\"note\":\"\"")) {
			t.Fatal("the canonical fixture has no extendable empty note")
		}
		note := []byte("\"note\":\"" + strings.Repeat("x", noteBytes) + "\"")
		contract := bytes.Replace(base, []byte("\"note\":\"\""), note, 1)
		if len(contract) != tc.size {
			t.Fatalf("constructed contract size=%d, want %d", len(contract), tc.size)
		}
		_, err := ParseRootGrantsTrustContract(contract)
		var failure *RootGrantsTrustError
		if !errors.As(err, &failure) || failure.Code != tc.code || failure.Rule != tc.rule {
			t.Fatalf("decoded contract size %d failure=%#v, %v; want %s rule %d", tc.size, failure, err, tc.code, tc.rule)
		}
	}
}

func TestRootGrantsTrustContractCountersignValidateEnvelope(t *testing.T) {
	record, _ := rootGrantsRecordFixture13(t, "keyvault-recovery/1")
	envelope := rootGrantsEnvelopeFixture13(t, record)
	canonical, err := CanonicalRootGrantsEnvelope(envelope, record)
	if err != nil {
		t.Fatal("could not create the synthetic canonical envelope")
	}
	defer clear(canonical)
	if err := rootGrantsTrustContractCountersignValidateEnvelope(canonical, record); err != nil {
		t.Fatalf("valid canonical envelope was rejected: %v", err)
	}
	if err := rootGrantsTrustContractCountersignValidateEnvelope(append(bytes.Clone(canonical), ' '), record); err == nil {
		t.Fatal("valid JSON with noncanonical trailing whitespace was accepted")
	} else {
		var failure *RootGrantsGrantV3Failure
		if !errors.As(err, &failure) || failure.Code != "private_protocol_error" || failure.Outcome != "unknown" {
			t.Fatalf("noncanonical encoding did not retain the closed UNKNOWN refusal: %v", err)
		}
	}
	if err := rootGrantsTrustContractCountersignValidateEnvelope([]byte(`{"schema":`), record); err == nil {
		t.Fatal("malformed envelope JSON was accepted")
	} else {
		var failure *RootGrantsGrantV3Failure
		if !errors.As(err, &failure) || failure.Code != "private_protocol_error" || failure.Outcome != "unknown" {
			t.Fatalf("malformed JSON did not retain the closed UNKNOWN refusal: %v", err)
		}
	}
	invalid := envelope
	invalid.EnclaveBlob = nil
	invalidJSON, err := json.Marshal(invalid)
	if err != nil {
		t.Fatal("could not encode the synthetic invalid envelope")
	}
	defer clear(invalidJSON)
	if err := rootGrantsTrustContractCountersignValidateEnvelope(invalidJSON, record); err == nil {
		t.Fatal("well-formed envelope with invalid public shape was accepted")
	} else {
		var failure *RootGrantsGrantV3Failure
		if !errors.As(err, &failure) || failure.Code != "invalid_envelope" || failure.Outcome != "not_applied" {
			t.Fatalf("invalid public envelope shape did not map to status12: %v", err)
		}
	}
}

// This proves the purpose-specific helper exchange accepts a valid raw-contract signature and rejects a valid Grant v3 signature for the same public bytes; the host and public scalar-3 test key match the full-record fixture.
func TestRootGrantsTrustContractCountersignHelperExchangePurpose(t *testing.T) {
	var scalar [32]byte
	scalar[31] = 3
	privateKey, _ := btcec.PrivKeyFromBytes(scalar[:])
	clear(scalar[:])
	if privateKey == nil {
		t.Fatal("public scalar-3 helper-test key unavailable")
	}
	issuer := hex.EncodeToString(schnorr.SerializePubKey(privateKey.PubKey()))
	request := rootTrustCountersignWireFixtureForIssuer(t, issuer)
	contract := rootTrustCountersignTestContract(t, []byte("synthetic scope"), true)
	rawDigest := sha256.Sum256(contract)
	rawSignature, err := schnorr.Sign(privateKey, rawDigest[:])
	if err != nil {
		t.Fatal("could not sign the synthetic raw contract digest")
	}
	rawSignatureBytes := rawSignature.Serialize()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	host := &rootTrustExchangeHost{request: bytes.Clone(request), signature: bytes.Clone(rawSignatureBytes)}
	checks := 0
	result, pid, err := rootGrantsTrustContractCountersignHelperExchange(ctx, request, bytes.Repeat([]byte{0x7a}, 20), host,
		func(checkCtx context.Context, data rootGrantsTrustContractCountersignHelperRequestData) error {
			checks++
			if !host.recordDeadline(checkCtx) || !bytes.Equal(data.Contract, contract) || data.Issuance.IssuerKey != issuer ||
				data.Review.ContractBase64 != "" || data.Review.ScopeTextBase64 != "" {
				return errors.New("synthetic helper request changed or retained redundant encoded bytes during recheck")
			}
			data.Contract[0] ^= 0xff
			return nil
		})
	if err != nil || pid != 9417 || !bytes.Equal(result, rawSignatureBytes) || checks != 2 || host.waits.Load() != 1 {
		t.Fatalf("valid raw-contract signature did not cross the full helper barrier: pid=%d checks=%d waits=%d err=%v", pid, checks, host.waits.Load(), err)
	}
	if !bytes.Equal(request, host.request) {
		t.Fatal("helper exchange mutated the caller-owned request")
	}
	clear(result)

	grantDigest, err := rootGrantsGrantV3Digest(contract)
	if err != nil {
		t.Fatal("could not compute the synthetic Grant v3 digest")
	}
	grantSignature, err := schnorr.Sign(privateKey, grantDigest[:])
	if err != nil {
		t.Fatal("could not sign the synthetic Grant v3 digest")
	}
	grantSignatureBytes := grantSignature.Serialize()
	grantHost := &rootTrustExchangeHost{request: bytes.Clone(request), signature: bytes.Clone(grantSignatureBytes)}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, pid, err = rootGrantsTrustContractCountersignHelperExchange(ctx, request, bytes.Repeat([]byte{0x7a}, 20), grantHost,
		func(checkCtx context.Context, data rootGrantsTrustContractCountersignHelperRequestData) error {
			if !grantHost.recordDeadline(checkCtx) || !bytes.Equal(data.Contract, contract) {
				return errors.New("synthetic helper request changed during control recheck")
			}
			return nil
		})
	var failure *RootGrantsGrantV3Failure
	if result != nil || pid != 0 || !errors.As(err, &failure) || failure.Code != "signature_verification_failed" || failure.Outcome != "unknown" ||
		grantHost.starts.Load() != 1 || grantHost.waits.Load() != 1 || !grantHost.signed.Load() {
		t.Fatalf("Grant v3-purpose signature produced a countersign receipt or retry: pid=%d starts=%d waits=%d err=%v", pid, grantHost.starts.Load(), grantHost.waits.Load(), err)
	}
}

// This proves empty and over-limit helper requests receive local preflight outcomes without starting the helper; it does not measure allocations.
func TestRootGrantsTrustContractCountersignHelperExchangeBoundsFailBeforeHelperStart(t *testing.T) {
	host := &rootTrustExchangeHost{}
	var rechecks atomic.Int32
	for _, tc := range []struct {
		name string
		raw  []byte
		code string
	}{
		{name: "empty", raw: nil, code: "invalid_arguments"},
		{name: "over limit", raw: make([]byte, 262145), code: "limit_exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, pid, err := rootGrantsTrustContractCountersignHelperExchange(ctx, tc.raw, bytes.Repeat([]byte{0x7a}, 20), host,
				func(context.Context, rootGrantsTrustContractCountersignHelperRequestData) error {
					rechecks.Add(1)
					return nil
				})
			var failure *RootGrantsGrantV3Failure
			if got != nil || pid != 0 || !errors.As(err, &failure) || failure.Code != tc.code || failure.Outcome != "not_applied" ||
				host.starts.Load() != 0 || rechecks.Load() != 0 {
				t.Fatalf("preflight returned a partial result or started the helper: pid=%d starts=%d err=%v", pid, host.starts.Load(), err)
			}
		})
	}
}

// This proves the shared transport returns synthetic bytes only after ordered KVR3/KVR4, exact ACK, EOF, close, and clean wait; it does not prove cryptographic verification or native behavior.
func TestRootGrantsPrivateSigningExchangePositiveAndCompletedRefusal(t *testing.T) {
	request := []byte("synthetic closed request")
	signature := bytes.Repeat([]byte{0x42}, 64)
	for _, tc := range []struct {
		name                string
		checkErr            error
		refusalCode         uint32
		returnedRefusalCode uint32
		ignoreRefusal       bool
		wantCode            string
		wantOutcome         string
	}{
		{name: "positive"},
		{name: "completed semantic refusal", checkErr: errRootTrustTestBinding, refusalCode: 13, wantCode: "binding_mismatch", wantOutcome: "not_applied"},
		{name: "changed completed refusal", checkErr: errRootTrustTestBinding, refusalCode: 13, returnedRefusalCode: 10, wantCode: "private_protocol_error", wantOutcome: "unknown"},
		{name: "helper continued after parent refusal", checkErr: errRootTrustTestBinding, refusalCode: 13, ignoreRefusal: true, wantCode: "private_protocol_error", wantOutcome: "unknown"},
		{name: "completed cancellation refusal", checkErr: context.Canceled, wantCode: "canceled", wantOutcome: "unknown"},
		{name: "completed timeout refusal", checkErr: context.DeadlineExceeded, wantCode: "timeout", wantOutcome: "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := &rootTrustExchangeHost{request: bytes.Clone(request), signature: bytes.Clone(signature), config: rootTrustExchangeConfig{
				refusalCode: tc.refusalCode, returnedRefusalCode: tc.returnedRefusalCode, ignoreRefusal: tc.ignoreRefusal,
			}}
			original := bytes.Clone(request)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, pid, err := rootGrantsPrivateSigningExchange(ctx, request, bytes.Repeat([]byte{0x7a}, 20), host, rootTrustExchangeCallbacks(host, tc.checkErr))
			if tc.wantCode == "" {
				if err != nil || pid != 9417 || !bytes.Equal(got, signature) {
					t.Fatalf("completed exchange did not return the verified synthetic signature: pid=%d err=%v", pid, err)
				}
			} else {
				var failure *rootTrustExchangeFailure
				if got != nil || pid != 0 || !errors.As(err, &failure) || failure.code != tc.wantCode || failure.outcome != tc.wantOutcome {
					t.Fatalf("completed refusal returned a receipt or wrong result: pid=%d err=%v", pid, err)
				}
			}
			if host.starts.Load() != 1 || !bytes.Equal(request, original) {
				t.Fatalf("exchange retried or mutated caller bytes: starts=%d", host.starts.Load())
			}
			if host.waits.Load() != 1 || host.parentIn.closes.Load() != 1 || host.parentOut.closes.Load() != 1 {
				t.Fatalf("same-child close/wait barrier was incomplete: waits=%d input_closes=%d output_closes=%d", host.waits.Load(), host.parentIn.closes.Load(), host.parentOut.closes.Load())
			}
			if tc.wantCode == "" && (host.checks.Load() != 2 || !host.signed.Load()) {
				t.Fatalf("positive exchange did not complete two checks before synthetic signature: checks=%d signed=%v", host.checks.Load(), host.signed.Load())
			}
			if tc.wantCode == "" {
				deadlines := host.observedDeadlines()
				if len(deadlines) != 2 || !deadlines[0].Equal(deadlines[1]) {
					t.Fatalf("rechecks did not share the original absolute deadline: %v", deadlines)
				}
			}
			if tc.wantCode != "" && host.signed.Load() {
				t.Fatal("completed refusal reached the synthetic signer")
			}
		})
	}
}

// This proves truncated, reordered, extra, close, and wait faults cannot leak a partial receipt or retry; each injected fault is isolated in an in-memory child fixture.
func TestRootGrantsPrivateSigningExchangeFaultsReturnNoReceipt(t *testing.T) {
	request := []byte("synthetic closed request")
	signature := bytes.Repeat([]byte{0x42}, 64)
	for _, tc := range []struct {
		name   string
		config rootTrustExchangeConfig
	}{
		{name: "wrong recheck order", config: rootTrustExchangeConfig{stages: []byte{2, 1}}},
		{name: "duplicate first recheck", config: rootTrustExchangeConfig{stages: []byte{1, 1}}},
		{name: "missing second recheck", config: rootTrustExchangeConfig{stages: []byte{1}}},
		{name: "truncated recheck frame", config: rootTrustExchangeConfig{truncateStage: true}},
		{name: "truncated signature frame", config: rootTrustExchangeConfig{truncateSignature: true}},
		{name: "extra child output", config: rootTrustExchangeConfig{extraOutput: true}},
		{name: "stdin close failure", config: rootTrustExchangeConfig{inputCloseErr: errors.New("synthetic close failure")}},
		{name: "stdout close failure", config: rootTrustExchangeConfig{outputCloseErr: errors.New("synthetic close failure")}},
		{name: "same-child wait failure", config: rootTrustExchangeConfig{waitErr: errors.New("synthetic wait failure")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := &rootTrustExchangeHost{request: bytes.Clone(request), signature: bytes.Clone(signature), config: tc.config}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			got, pid, err := rootGrantsPrivateSigningExchange(ctx, request, bytes.Repeat([]byte{0x7a}, 20), host, rootTrustExchangeCallbacks(host, nil))
			var failure *rootTrustExchangeFailure
			if got != nil || pid != 0 || !errors.As(err, &failure) || failure.code != "private_protocol_error" || failure.outcome != "unknown" ||
				host.starts.Load() != 1 || host.waits.Load() != 1 || host.parentIn.closes.Load() != 1 || host.parentOut.closes.Load() != 1 {
				t.Fatalf("fault returned a partial receipt, non-unknown failure, or retry: pid=%d starts=%d err=%v", pid, host.starts.Load(), err)
			}
		})
	}
}

// This proves incomplete child descriptors are refused without panic, receipt, or retry, with a wait or immediate kill when the waiter is missing.
func TestRootGrantsPrivateSigningExchangeRejectsIncompleteChild(t *testing.T) {
	request := []byte("synthetic closed request")
	for _, tc := range []struct {
		name        string
		missingWait bool
		wantWaits   int32
		wantKills   int32
	}{
		{name: "wait available", wantWaits: 1},
		{name: "wait missing", missingWait: true, wantKills: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := &rootTrustIncompleteExchangeHost{missingWait: tc.missingWait}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, pid, err := rootGrantsPrivateSigningExchange(ctx, request, bytes.Repeat([]byte{0x7a}, 20), host,
				rootGrantsPrivateSigningPurpose{
					verifySignature:  func([]byte, []byte) error { return nil },
					check:            func(context.Context, []byte) error { return nil },
					controlResponse:  func(error) []byte { return []byte{0, 0, 0, 0, 0} },
					refusalFailure:   func(uint32) error { return errors.New("unexpected refusal") },
					refusalCode:      func(error) string { return "private_protocol_error" },
					uncertainRefusal: func(uint32) string { return "private_protocol_error" },
					contextCode: func(err error) string {
						if errors.Is(err, context.DeadlineExceeded) {
							return "timeout"
						}
						return "canceled"
					},
					verificationCode: func(error) string { return "private_protocol_error" },
					failure: func(code, phase string, attempted bool) error {
						return &rootTrustExchangeFailure{code: code, outcome: map[bool]string{true: "unknown", false: "not_applied"}[attempted]}
					},
				})
			var failure *rootTrustExchangeFailure
			if got != nil || pid != 0 || !errors.As(err, &failure) || failure.code != "private_protocol_error" || failure.outcome != "unknown" ||
				host.starts.Load() != 1 || host.terms.Load() != 1 || host.waits.Load() != tc.wantWaits || host.kills.Load() != tc.wantKills {
				t.Fatalf("incomplete child returned a receipt, retried, or skipped cleanup: starts=%d terms=%d kills=%d waits=%d err=%v", host.starts.Load(), host.terms.Load(), host.kills.Load(), host.waits.Load(), err)
			}
		})
	}
}

// This proves cancellation is an unknown no-receipt outcome after one consumed child attempt; it does not execute a real presence prompt or private effect.
func TestRootGrantsPrivateSigningExchangeCancellationDoesNotRetry(t *testing.T) {
	request := []byte("synthetic closed request")
	signature := bytes.Repeat([]byte{0x42}, 64)
	host := &rootTrustExchangeHost{request: bytes.Clone(request), signature: bytes.Clone(signature), config: rootTrustExchangeConfig{}}
	ctx, cancel := context.WithCancel(context.Background())
	callbacks := rootTrustExchangeCallbacks(host, nil)
	callbacks.check = func(ctx context.Context, raw []byte) error {
		host.checks.Add(1)
		if !host.recordDeadline(ctx) || !bytes.Equal(raw, host.request) {
			return errors.New("synthetic recheck mismatch")
		}
		cancel()
		return context.Canceled
	}
	result, pid, err := rootGrantsPrivateSigningExchange(ctx, request, bytes.Repeat([]byte{0x7a}, 20), host, callbacks)
	var failure *rootTrustExchangeFailure
	if result != nil || pid != 0 || !errors.As(err, &failure) || failure.code != "canceled" || failure.outcome != "unknown" || host.starts.Load() != 1 || host.signed.Load() {
		t.Fatalf("canceled attempt produced a receipt, retried, or signed: pid=%d starts=%d signed=%v err=%v", pid, host.starts.Load(), host.signed.Load(), err)
	}
}

// This proves an external cancellation racing a blocked recheck consumes one child attempt and returns no receipt.
func TestRootGrantsPrivateSigningExchangeConcurrentCancelDuringRecheck(t *testing.T) {
	request := []byte("synthetic closed request")
	signature := bytes.Repeat([]byte{0x42}, 64)
	host := &rootTrustExchangeHost{request: bytes.Clone(request), signature: bytes.Clone(signature), config: rootTrustExchangeConfig{}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	type exchangeResult struct {
		payload []byte
		pid     int
		err     error
	}
	result := make(chan exchangeResult, 1)
	callbacks := rootTrustExchangeCallbacks(host, nil)
	callbacks.check = func(ctx context.Context, raw []byte) error {
		host.checks.Add(1)
		if !host.recordDeadline(ctx) || !bytes.Equal(raw, host.request) {
			return errors.New("synthetic recheck mismatch")
		}
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}
	go func() {
		payload, pid, err := rootGrantsPrivateSigningExchange(ctx, request, bytes.Repeat([]byte{0x7a}, 20), host, callbacks)
		result <- exchangeResult{payload: payload, pid: pid, err: err}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("recheck did not start")
	}
	cancel()
	select {
	case got := <-result:
		var failure *rootTrustExchangeFailure
		if got.payload != nil || got.pid != 0 || !errors.As(got.err, &failure) || failure.code != "canceled" || failure.outcome != "unknown" ||
			host.starts.Load() != 1 || host.signed.Load() || host.waits.Load() != 1 || host.parentIn.closes.Load() != 1 || host.parentOut.closes.Load() != 1 {
			t.Fatalf("concurrent cancellation leaked a result, retried, or skipped cleanup: starts=%d waits=%d signed=%v err=%v", host.starts.Load(), host.waits.Load(), host.signed.Load(), got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled exchange did not complete bounded cleanup")
	}
}

// This proves timeout of a blocked recheck is an UNKNOWN no-receipt result with one child attempt and the original deadline.
func TestRootGrantsPrivateSigningExchangeTimeoutDuringRecheck(t *testing.T) {
	request := []byte("synthetic closed request")
	signature := bytes.Repeat([]byte{0x42}, 64)
	host := &rootTrustExchangeHost{request: bytes.Clone(request), signature: bytes.Clone(signature), config: rootTrustExchangeConfig{}}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	callbacks := rootTrustExchangeCallbacks(host, nil)
	callbacks.check = func(ctx context.Context, raw []byte) error {
		host.checks.Add(1)
		if !host.recordDeadline(ctx) || !bytes.Equal(raw, host.request) {
			return errors.New("synthetic recheck mismatch")
		}
		<-ctx.Done()
		return ctx.Err()
	}
	got, pid, err := rootGrantsPrivateSigningExchange(ctx, request, bytes.Repeat([]byte{0x7a}, 20), host, callbacks)
	var failure *rootTrustExchangeFailure
	if got != nil || pid != 0 || !errors.As(err, &failure) || failure.code != "timeout" || failure.outcome != "unknown" ||
		host.starts.Load() != 1 || host.signed.Load() || host.waits.Load() != 1 || host.parentIn.closes.Load() != 1 || host.parentOut.closes.Load() != 1 {
		t.Fatalf("timeout leaked a result, retried, or skipped cleanup: starts=%d waits=%d signed=%v err=%v", host.starts.Load(), host.waits.Load(), host.signed.Load(), err)
	}
}

// This proves cancellation after a synthetic signature frame cannot pass verification/ACK cleanup as a receipt.
func TestRootGrantsPrivateSigningExchangePostSignatureCancelIsUnknown(t *testing.T) {
	request := []byte("synthetic closed request")
	signature := bytes.Repeat([]byte{0x42}, 64)
	host := &rootTrustExchangeHost{request: bytes.Clone(request), signature: bytes.Clone(signature), config: rootTrustExchangeConfig{}}
	ctx, cancel := context.WithCancel(context.Background())
	callbacks := rootTrustExchangeCallbacks(host, nil)
	callbacks.verifySignature = func(raw, got []byte) error {
		if !bytes.Equal(raw, host.request) || !bytes.Equal(got, host.signature) {
			return errors.New("synthetic signature mismatch")
		}
		cancel()
		return nil
	}
	result, pid, err := rootGrantsPrivateSigningExchange(ctx, request, bytes.Repeat([]byte{0x7a}, 20), host, callbacks)
	var failure *rootTrustExchangeFailure
	if result != nil || pid != 0 || !errors.As(err, &failure) || failure.code != "canceled" || failure.outcome != "unknown" ||
		host.starts.Load() != 1 || !host.signed.Load() || host.waits.Load() != 1 || host.parentIn.closes.Load() != 1 || host.parentOut.closes.Load() != 1 {
		t.Fatalf("post-sign cancellation returned a receipt, retried, or skipped cleanup: starts=%d waits=%d signed=%v err=%v", host.starts.Load(), host.waits.Load(), host.signed.Load(), err)
	}
}

// This proves the native-facing authority check refuses local LIP errors before
// loading policy, reports an installed-authority mismatch exactly, and allows a
// matching synthetic authority to reach one record-bound raw-contract signature.
func TestRootGrantsTrustContractCountersignNativeHelperAuthorityAndSign(t *testing.T) {
	raw, authorityJSON := rootTrustCountersignNativeRequestFixture(t)
	defer clear(raw)
	defer clear(authorityJSON)
	rawBefore := bytes.Clone(raw)
	defer clear(rawBefore)

	validLoads := 0
	if err := rootGrantsTrustContractCountersignCheckInstalledAuthorityFromHelper(context.Background(), raw,
		func(address RootGrantsAddress) ([]byte, error) {
			validLoads++
			if address.Service != "example-root" || address.Version != 1 {
				t.Fatalf("authority load used unexpected address: %#v", address)
			}
			return bytes.Clone(authorityJSON), nil
		}); err != nil || validLoads != 1 {
		t.Fatalf("matching installed authority was not accepted once: loads=%d err=%v", validLoads, err)
	}

	badContractRequest := rootTrustRewriteCountersignReview(t, raw, func(review *rootGrantsTrustContractCountersignReviewWire) {
		badContract := []byte("x")
		review.ContractBase64 = base64.StdEncoding.EncodeToString(badContract)
		review.ContractBytes = len(badContract)
		review.ContractSHA256 = rootGrantsHashHex(badContract)
	})
	badContractLoads := 0
	err := rootGrantsTrustContractCountersignCheckInstalledAuthorityFromHelper(context.Background(), badContractRequest,
		func(RootGrantsAddress) ([]byte, error) {
			badContractLoads++
			return bytes.Clone(authorityJSON), nil
		})
	rootTrustCountersignWantHelperFailure(t, err, "CONTRACT_ENCODING", "contract_parse", "not_applied", 13)
	if badContractLoads != 0 {
		t.Fatalf("local LIP refusal read installed authority %d times", badContractLoads)
	}

	mismatchLoads := 0
	err = rootGrantsTrustContractCountersignCheckInstalledAuthorityFromHelper(context.Background(), raw,
		func(RootGrantsAddress) ([]byte, error) {
			mismatchLoads++
			return []byte("different installed authority"), nil
		})
	rootTrustCountersignWantHelperFailure(t, err, "binding_mismatch", "authority", "not_applied", 13)
	if mismatchLoads != 1 {
		t.Fatalf("installed-authority mismatch used %d reads, want one", mismatchLoads)
	}

	data, err := rootGrantsTrustContractCountersignParseHelperRequest(raw)
	if err != nil {
		t.Fatal("positive helper request did not parse", err)
	}
	defer data.clear()

	plaintext := rootTrustCountersignNativePlaintextFixture(t, data.Review.RecordJSON, 3)
	plainBefore := bytes.Clone(plaintext)
	loads := 0
	signature, err := rootGrantsTrustContractCountersignSignFromHelperWithRuntime(context.Background(), raw, plaintext,
		func(RootGrantsAddress) ([]byte, error) {
			loads++
			return bytes.Clone(authorityJSON), nil
		}, bytes.NewReader(make([]byte, 32)), func() int64 { return 100 }, signNostrWithAux)
	if err != nil || loads != 1 || len(signature) != 64 {
		t.Fatalf("valid synthetic plaintext did not produce one signature: loads=%d signature=%d err=%v", loads, len(signature), err)
	}
	if err := rootGrantsTrustContractVerifyRawSignature(data.Contract, data.Issuance.IssuerKey, signature); err != nil {
		t.Fatal("returned signature did not verify over exact raw contract bytes", err)
	}
	if !bytes.Equal(plaintext, make([]byte, len(plaintext))) || !bytes.Equal(raw, rawBefore) || bytes.Equal(plainBefore, plaintext) {
		t.Fatal("signer failed to clear its owned plaintext or changed caller-owned request")
	}
	clear(signature)
	clear(plainBefore)

	wrongBinding := rootTrustCountersignNativePlaintextFixture(t, data.Review.RecordJSON, 3)
	wrongBinding[4] ^= 1
	wrongBindingLoads := 0
	_, err = rootGrantsTrustContractCountersignSignFromHelperWithRuntime(context.Background(), raw, wrongBinding,
		func(RootGrantsAddress) ([]byte, error) {
			wrongBindingLoads++
			return bytes.Clone(authorityJSON), nil
		}, bytes.NewReader(make([]byte, 32)), func() int64 { return 100 }, signNostrWithAux)
	rootTrustCountersignWantHelperFailure(t, err, "binding_mismatch", "unwrap", "not_applied", 13)
	if wrongBindingLoads != 0 || !bytes.Equal(wrongBinding, make([]byte, len(wrongBinding))) {
		t.Fatal("record-binding refusal loaded authority or left owned plaintext uncleared")
	}

	wrongKey := rootTrustCountersignNativePlaintextFixture(t, data.Review.RecordJSON, 4)
	wrongKeyLoads := 0
	_, err = rootGrantsTrustContractCountersignSignFromHelperWithRuntime(context.Background(), raw, wrongKey,
		func(RootGrantsAddress) ([]byte, error) {
			wrongKeyLoads++
			return bytes.Clone(authorityJSON), nil
		}, bytes.NewReader(make([]byte, 32)), func() int64 { return 100 }, signNostrWithAux)
	rootTrustCountersignWantHelperFailure(t, err, "public_pin_mismatch", "unwrap", "not_applied", 9)
	if wrongKeyLoads != 0 || !bytes.Equal(wrongKey, make([]byte, len(wrongKey))) {
		t.Fatal("wrong-key refusal loaded authority or left owned plaintext uncleared")
	}
}

// This proves the operation recheck rejects an oversized installed authority
// before reading the vault; the neighboring native-helper test covers the valid
// installed-authority path with the same synthetic request shape.
func TestRootGrantsTrustContractCountersignRecheckAuthorityBound(t *testing.T) {
	raw, _ := rootTrustCountersignNativeRequestFixture(t)
	defer clear(raw)
	vault := &grantV3OperationVault{}
	loaderCalls := 0
	err := rootGrantsTrustContractCountersignCheckForHelperWithContext(context.Background(), raw, vault,
		func(RootGrantsAddress) ([]byte, error) {
			loaderCalls++
			return bytes.Repeat([]byte{'x'}, rootGrantsTrustContractCountersignNestedMaxBytes+1), nil
		})
	rootTrustCountersignWantHelperFailure(t, err, "limit_exceeded", "recheck", "not_applied", 17)
	if loaderCalls != 1 || vault.calls != 0 {
		t.Fatalf("oversized installed authority reached the vault: loader=%d vault=%d", loaderCalls, vault.calls)
	}
}

func rootTrustCountersignNativeRequestFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	request, authorityJSON, snapshot := rootGrantsTrustCountersignOperationFixture(t)
	defer clear(request.Contract)
	defer clear(authorityJSON)
	defer clear(snapshot.Metadata)
	defer clear(snapshot.Envelope)
	defer clear(snapshot.PairMetadata)
	helper := &trustCountersignOperationHelper{}
	vault := &grantV3OperationVault{snapshot: cloneTrustCountersignSnapshot(snapshot)}
	_, err := rootGrantsTrustContractCountersignWith(context.Background(), request,
		func(RootGrantsAddress) ([]byte, error) { return bytes.Clone(authorityJSON), nil }, vault, helper)
	if err != nil || len(helper.request) == 0 {
		t.Fatalf("could not build a synthetic native helper request: %v", err)
	}
	return bytes.Clone(helper.request), bytes.Clone(authorityJSON)
}

func rootTrustCountersignNativePlaintextFixture(t *testing.T, recordJSON []byte, scalar byte) []byte {
	t.Helper()
	plaintext := make([]byte, 68)
	copy(plaintext[:4], "KVG1")
	hash := sha256.New()
	_, _ = hash.Write([]byte("keyvault-root-grants/plaintext/1\x00"))
	_, _ = hash.Write(recordJSON)
	copy(plaintext[4:36], hash.Sum(nil))
	plaintext[67] = scalar
	return plaintext
}

func rootTrustCountersignWantHelperFailure(t *testing.T, err error, code, phase, outcome string, status int32) {
	t.Helper()
	var failure *RootGrantsGrantV3Failure
	if !errors.As(err, &failure) || failure == nil || failure.Code != code || failure.Phase != phase ||
		failure.Outcome != outcome || RootGrantsTrustContractCountersignHelperStatus(err) != status {
		t.Fatalf("first refusal got err=%v, want code=%s phase=%s outcome=%s status=%d", err, code, phase, outcome, status)
	}
}

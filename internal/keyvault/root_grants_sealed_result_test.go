package keyvault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
)

// PUBLIC structural fixture: the historical envelope deliberately is NOT an
// authentic root seal. A synthetic completion below models private provenance
// for package tests ONLY, never native admission or seal/biometric qualification.
func rootGrantsSealedFixture46(t *testing.T, schema string) ([]byte, []byte, rootGrantsSealedItem, RootGrantsRecord) {
	t.Helper()
	r, _ := rootGrantsRecordFixture13(t, schema)
	metadata, err := CanonicalRootGrantsRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := CanonicalRootGrantsEnvelope(rootGrantsEnvelopeFixture13(t, r), r)
	if err != nil {
		t.Fatal(err)
	}
	raw := rootGrantsRaw13(t, RootGrantsPrivateSealed{Record: metadata, Envelope: envelope})
	return rootGrantsRequest44(t, schema), raw, rootGrantsSealedItem{address: RootGrantsAddress{Service: r.Service, Version: r.Version}, metadata: string(metadata), envelope: string(envelope)}, r
}
func rootGrantsSyntheticResult46(request, sealed []byte) *rootGrantsHelperResult {
	return &rootGrantsHelperResult{completion: &rootGrantsHelperCompletion{pid: 73, request: bytes.Clone(request), sealed: bytes.Clone(sealed)}}
}

// Claim: complete canonical v1/v2 request bindings and public root consistency
// admit one owned plan; aliases cannot replay. Limit: synthetic provenance and
// shape-only ciphertext; not actual helper/native/custody/store qualification.
func TestRootGrantsHelper46SealedAdmission(t *testing.T) {
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		request, sealed, want, _ := rootGrantsSealedFixture46(t, schema)
		result := rootGrantsSyntheticResult46(request, sealed)
		alias := *result
		clear(request)
		clear(sealed)
		plan, err := result.plan()
		if err != nil || plan == nil || plan.state.item != want {
			t.Fatal("valid owned bindings refused")
		}
		if _, err := alias.plan(); err == nil {
			t.Fatal("completion alias replayed")
		}
		if result.completion.pid != 0 || result.completion.request != nil || result.completion.sealed != nil {
			t.Fatal("completion not consumed")
		}
		if raw, err := json.Marshal(result); err == nil || raw != nil {
			t.Fatal("provenance serialized")
		}
		if fmt.Sprintf("%#v", result) != "<root-grants-helper-result>" {
			t.Fatal("opaque completion leaked")
		}
	}
	for _, result := range []*rootGrantsHelperResult{nil, {}, {completion: &rootGrantsHelperCompletion{}}} {
		if plan, err := result.plan(); plan != nil || err == nil {
			t.Fatal("missing invocation constructed plan")
		}
	}
	// The public facade response carries no plan/provenance method. A caller
	// cannot turn public JSON/shape-validation success into this private type.
	if _, ok := any(RootGrantsPrivateSealed{}).(interface {
		plan() (*rootGrantsAttachment, error)
	}); ok {
		t.Fatal("public sealed response acquired plan capability")
	}

}

// A negative fixture must change actual bytes, not merely assign a value that
// happens to equal the retained fixture. The retained GroupID is all zeroes.
func rootGrantsDifferentGroup47(t *testing.T, original string) string {
	t.Helper()
	if len(original) != 32 || !lowerHex(original, 16) {
		t.Fatal("invalid group fixture")
	}
	changed := []byte(original)
	if changed[0] == '0' {
		changed[0] = '1'
	} else {
		changed[0] = '0'
	}
	if string(changed) == original {
		t.Fatal("group negative did not change value")
	}
	return string(changed)
}
func rootGrantsReplace47(t *testing.T, raw, from, to []byte) []byte {
	t.Helper()
	if bytes.Count(raw, from) != 1 {
		t.Fatal("negative replacement is missing or ambiguous")
	}
	changed := bytes.Replace(raw, from, to, 1)
	if bytes.Equal(raw, changed) {
		t.Fatal("negative replacement did not change bytes")
	}
	return changed
}

type rootGrantsRefusalCase47 struct {
	name string
	raw  []byte
	code string
}

// Test-only authenticated-completion fixture under a held PUBLIC fake guard.
// Fixed refusal, consumed completion, nil plan and zero add are all required.
// This proves no real PID/code, correct ciphertext, native custody or ACL.
func rootGrantsConsumedRefusal47(t *testing.T, request, sealed []byte, want string, baseline rootGrantsPrivateRequest, item rootGrantsSealedItem) {
	t.Helper()
	fake := &rootGrantsVault13{t: t, pair: bytes.Clone(baseline.PairMetadata), expected: item, preAddReads: 3}
	preflight, err := beginRootGrantsAttach(context.Background(), fake, item.address, baseline.Pair)
	if err != nil {
		t.Fatal("valid public preflight refused")
	}
	defer preflight.cancel()
	result := rootGrantsSyntheticResult46(request, sealed)
	plan, err := result.plan()
	var refusal *Refusal
	if plan != nil || !errors.As(err, &refusal) || refusal.Code != "recovery_"+want {
		t.Fatalf("expected fixed %s, no plan", want)
	}
	if result.completion.pid != 0 || result.completion.request != nil || result.completion.sealed != nil {
		t.Fatal("failed completion not consumed")
	}
	if again, err := result.plan(); again != nil || !errors.As(err, &refusal) || refusal.Code != "recovery_code_not_admitted" {
		t.Fatal("failed completion reused")
	}
	preflight.cancel()
	if fake.adds != 0 || fake.stored != nil || fake.held || fake.locks != 1 || fake.releases != 1 || !bytes.Equal(fake.pair, baseline.PairMetadata) {
		t.Fatal("refusal reached add/changed pair/retained guard")
	}
}

// Regression: assigning zero GroupID to the all-zero fixture was a NO-OP,
// legitimately accepted as the valid request. Every negative now asserts a
// distinct value/bytes and exact fixed refusal beside valid v1/v2 controls.
// Claims: full public bindings, consumed completion, nil plan and zero add.
// Limits: synthetic invocation/public fake store; no native/code/seal proof.
func TestRootGrantsHelper46SealedRefusals(t *testing.T) {
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		t.Run(schema, func(t *testing.T) {
			request, sealed, item, _ := rootGrantsSealedFixture46(t, schema)
			var q rootGrantsPrivateRequest
			if json.Unmarshal(request, &q) != nil {
				t.Fatal("fixture")
			}
			// Positive control exercises plan/one-add/readback under same guard.
			control := &rootGrantsVault13{t: t, pair: bytes.Clone(q.PairMetadata), expected: item, preAddReads: 3}
			preflight, err := beginRootGrantsAttach(context.Background(), control, item.address, q.Pair)
			if err != nil {
				t.Fatal("valid preflight refused")
			}
			defer preflight.cancel()
			plan, err := rootGrantsSyntheticResult46(request, sealed).plan()
			if err != nil || plan == nil || plan.state.item != item {
				t.Fatal("valid v1/v2 control refused")
			}
			stored, err := preflight.commit(context.Background(), plan)
			if err != nil || stored.Outcome != "stored" || control.adds != 1 || control.locks != 1 || control.releases != 1 || control.held {
				t.Fatal("valid same-guard store control refused")
			}

			requestCodes := map[string]string{"service": "binding_mismatch", "version": "binding_mismatch", "created": "binding_mismatch", "pair": "retained_record_mismatch", "pair_metadata": "retained_record_mismatch", "protocol": "unsupported_version", "engine": "unsupported_version", "profile": "unsupported_version", "mode": "unsupported_operation"}
			for _, field := range []string{"service", "version", "created", "pair", "pair_metadata", "protocol", "engine", "profile", "mode"} {
				changed := q
				switch field {
				case "service":
					changed.Service = "different-root"
				case "version":
					changed.Version++
				case "created":
					changed.Created = "2026-01-03T03:04:05Z"
				case "pair":
					changed.Pair.GroupID = rootGrantsDifferentGroup47(t, q.Pair.GroupID)
				case "pair_metadata":
					changed.PairMetadata = append(bytes.Clone(changed.PairMetadata), ' ')
				case "protocol":
					changed.Protocol = "other/1"
				case "engine":
					changed.Engine = "other/1"
				case "profile":
					changed.Profile = "other/1"
				case "mode":
					changed.Mode = "restore"
				}
				raw := rootGrantsRaw13(t, changed)
				if bytes.Equal(raw, request) {
					t.Fatalf("no-op request mutation: %s", field)
				}
				rootGrantsConsumedRefusal47(t, raw, sealed, requestCodes[field], q, item)
			}

			cases := []rootGrantsRefusalCase47{
				{"empty", nil, "code_not_admitted"}, // invalid completion, never mintable from a success frame
				{"null", []byte("null"), "private_protocol_error"},
				{"missing", []byte("{}"), "private_protocol_error"},
				{"trailing", append(bytes.Clone(sealed), '\n'), "private_protocol_error"},
				{"leading", append([]byte(" "), sealed...), "private_protocol_error"},
				{"second-object", append(bytes.Clone(sealed), []byte("{}")...), "private_protocol_error"},
				{"oversize", bytes.Repeat([]byte{'x'}, 131073), "private_protocol_error"},
				{"alias", rootGrantsReplace47(t, sealed, []byte(`"record":`), []byte(`"Record":`)), "private_protocol_error"},
				{"duplicate", rootGrantsReplace47(t, sealed, []byte(`"record":`), []byte(`"record":null,"record":`)), "private_protocol_error"},
				{"unknown", rootGrantsReplace47(t, sealed, []byte(`"envelope":`), []byte(`"unknown":0,"envelope":`)), "private_protocol_error"},
			}
			var object RootGrantsPrivateSealed
			if json.Unmarshal(sealed, &object) != nil {
				t.Fatal("fixture")
			}
			cases = append(cases,
				rootGrantsRefusalCase47{"null-envelope", rootGrantsRaw13(t, RootGrantsPrivateSealed{Record: object.Record, Envelope: json.RawMessage("null")}), "invalid_envelope"},
				rootGrantsRefusalCase47{"fingerprint", rootGrantsRaw13(t, RootGrantsPrivateSealed{Record: object.Record, Envelope: rootGrantsReplace47(t, object.Envelope, []byte(`"fingerprint":"`), []byte(`"fingerprint":"0`))}), "invalid_envelope"},
				rootGrantsRefusalCase47{"parity", rootGrantsRaw13(t, RootGrantsPrivateSealed{Record: rootGrantsReplace47(t, object.Record, []byte(`"seal_public_key":"02`), []byte(`"seal_public_key":"03`)), Envelope: object.Envelope}), "binding_mismatch"})
			var record RootGrantsRecord
			if json.Unmarshal(object.Record, &record) != nil {
				t.Fatal("fixture")
			}
			for i := 0; i < reflect.TypeOf(record.Pair).NumField(); i++ {
				changed := record
				value := reflect.ValueOf(&changed.Pair).Elem().Field(i)
				if value.Kind() == reflect.String {
					value.SetString("different")
				} else {
					value.SetInt(value.Int() + 1)
				}
				if changed.Pair == record.Pair {
					t.Fatal("no-op result pair mutation")
				}
				cases = append(cases, rootGrantsRefusalCase47{"pair-" + reflect.TypeOf(record.Pair).Field(i).Name, rootGrantsRaw13(t, RootGrantsPrivateSealed{Record: rootGrantsRaw13(t, changed), Envelope: object.Envelope}), "binding_mismatch"})
			}
			retained, err := parseRecoveryRecord(q.PairMetadata)
			if err != nil {
				t.Fatal(err)
			}
			for i, purpose := range []RecoveryPurpose{retained.Nostr, retained.Namecoin} {
				if bytes.Equal(record.WrappingPoint, purpose.WrappingPoint) {
					t.Fatal("wrap reuse negative already equals valid point")
				}
				changed := record
				changed.WrappingPoint = bytes.Clone(purpose.WrappingPoint)
				changed.WrappingFingerprint = purpose.WrappingFingerprint
				envelope := rootGrantsEnvelopeFixture13(t, changed)
				cases = append(cases, rootGrantsRefusalCase47{fmt.Sprintf("wrap-reuse-%d", i), rootGrantsRaw13(t, RootGrantsPrivateSealed{Record: rootGrantsRaw13(t, changed), Envelope: rootGrantsRaw13(t, envelope)}), "wrapping_policy_refused"})
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					if bytes.Equal(tc.raw, sealed) {
						t.Fatal("no-op sealed negative")
					}
					rootGrantsConsumedRefusal47(t, request, tc.raw, tc.code, q, item)
				})
			}

			// Exact top-level alias, not an accidental nested service mutation.
			var fields map[string]json.RawMessage
			if json.Unmarshal(request, &fields) != nil {
				t.Fatal("fixture")
			}
			fields["Service"] = fields["service"]
			delete(fields, "service")
			alias := rootGrantsObject44(t, fields, []string{"protocol", "engine", "profile", "mode", "pair_metadata", "pair", "Service", "version", "created"})
			badRequests := []rootGrantsRefusalCase47{{"empty-request", nil, "invalid_arguments"}, {"null-request", []byte("null"), "invalid_arguments"}, {"trailing-request", append(bytes.Clone(request), '\n'), "invalid_arguments"}, {"alias-request", alias, "invalid_arguments"}, {"oversize-request", bytes.Repeat([]byte{'x'}, 262145), "limit_exceeded"}}
			for _, tc := range badRequests {
				if bytes.Equal(tc.raw, request) {
					t.Fatal("no-op malformed request")
				}
				var refusal *Refusal
				if _, err := rootGrantsHelperRequest(tc.raw); !errors.As(err, &refusal) || refusal.Code != "recovery_"+tc.code {
					t.Fatalf("wrong parser refusal: %s", tc.name)
				}
				admissionCode := tc.code
				if len(tc.raw) == 0 {
					admissionCode = "code_not_admitted"
				}
				rootGrantsConsumedRefusal47(t, tc.raw, sealed, admissionCode, q, item)
			}
		})
	}
}

// Claim: concurrent copies consume a synthetic completion once. No production
// process/authentication or real native preparation is executed by this group.
func TestRootGrantsHelper46CompletionConcurrency(t *testing.T) {
	request, sealed, _, _ := rootGrantsSealedFixture46(t, "keyvault-recovery/1")
	result := rootGrantsSyntheticResult46(request, sealed)
	var wg sync.WaitGroup
	accepted := make(chan struct{}, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if p, e := result.plan(); e == nil && p != nil {
				accepted <- struct{}{}
			}
		}()
	}
	wg.Wait()
	if len(accepted) != 1 {
		t.Fatal("completion consumed other than once")
	}
}

// Claim: validated invocation plans reuse actual existing preflight transfer
// and preserve one-add/readback/UNKNOWN semantics. Fake metadata store only;
// no Security.framework ACL/custody or real transport authentication proof.
func TestRootGrantsHelper46TransferredGuard(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		request, sealed, item, r := rootGrantsSealedFixture46(t, "keyvault-recovery/2")
		var q rootGrantsPrivateRequest
		if json.Unmarshal(request, &q) != nil {
			t.Fatal("fixture")
		}
		fake := &rootGrantsVault13{t: t, pair: bytes.Clone(q.PairMetadata), expected: item, preAddReads: 3}
		if unknown {
			fake.addError = fmt.Errorf("PUBLIC_TEST_PRIVATE_SENTINEL")
			fake.applyOnError = true
		}
		preflight, err := beginRootGrantsAttach(context.Background(), fake, item.address, r.Pair)
		if err != nil {
			t.Fatal(err)
		}
		defer preflight.cancel()
		plan, err := rootGrantsSyntheticResult46(request, sealed).plan()
		if err != nil {
			t.Fatal(err)
		}
		result, err := preflight.commit(context.Background(), plan)
		if unknown {
			rootGrantsAttachFailure13(t, result, err, "mutation_unknown", "commit", "unknown")
		} else if err != nil || result.Outcome != "stored" {
			t.Fatal("valid transfer failed")
		}
		if fake.locks != 1 || fake.releases != 1 || fake.adds != 1 || fake.held {
			t.Fatal("guard reacquired/released or add repeated")
		}
		want := []string{"lock-existing", "pair-public", "collision", "pair-public", "collision", "pair-public", "add-only"}
		if !unknown {
			want = append(want, "root-public", "pair-public")
		}
		want = append(want, "release")
		if !reflect.DeepEqual(fake.calls, want) {
			t.Fatal("preflight transfer ordering changed")
		}
	}
}

// These real caller refusals occur BEFORE its fixed helper factory, so no
// subprocess/tty/native call is executed. Source boundary checks below also
// require factory invocation after beginRootGrantsAttach; no fake caller hook.
func TestRootGrantsHelper46PreflightBeforeInvocation(t *testing.T) {
	for _, mode := range []string{"missing", "pair", "collision", "inventory", "canceled"} {
		request, _, item, _ := rootGrantsSealedFixture46(t, "keyvault-recovery/2")
		var q rootGrantsPrivateRequest
		if json.Unmarshal(request, &q) != nil {
			t.Fatal("fixture")
		}
		fake := &rootGrantsVault13{t: t, pair: bytes.Clone(q.PairMetadata), expected: item}
		ctx, cancel := context.WithCancel(context.Background())
		switch mode {
		case "missing":
			fake.lockError = true
		case "pair":
			fake.pairChangedAt = 1
		case "collision":
			fake.collision = true
		case "inventory":
			fake.inventoryError = true
		case "canceled":
			cancel()
		}
		result, err := attachRootGrantsWithHelper(ctx, fake, request)
		cancel()
		if err == nil || result != (RootGrantsAttachResult{}) || fake.adds != 0 || fake.held {
			t.Fatal("failed preflight advanced helper/add or leaked guard")
		}
		if fake.releases > 1 || fake.locks > 1 {
			t.Fatal("extra guard operation")
		}
	}
}

// Claim: a new invocation plan preserves existing before-add refusal versus
// after-add UNKNOWN distinctions under the SAME transferred guard. Only public
// fixture/fake storage is exercised, not real Keychain/ACL/preserved ciphertext.
func TestRootGrantsHelper46CommitFailureBoundaries(t *testing.T) {
	for _, mode := range []string{"pair-before-add", "readback", "readback-corrupt", "pair-after-add", "duplicate-no-effect", "acl-no-effect", "code-no-effect", "unknown-add", "cancel-after-add"} {
		request, sealed, item, r := rootGrantsSealedFixture46(t, "keyvault-recovery/2")
		var q rootGrantsPrivateRequest
		if json.Unmarshal(request, &q) != nil {
			t.Fatal("fixture")
		}
		fake := &rootGrantsVault13{t: t, pair: bytes.Clone(q.PairMetadata), expected: item, preAddReads: 3}
		ctx, cancel := context.WithCancel(context.Background())
		preflight, err := beginRootGrantsAttach(ctx, fake, item.address, r.Pair)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		wantCode, wantPhase, wantOutcome := "mutation_unknown", "readback", "unknown"
		wantAdds := 1
		switch mode {
		case "pair-before-add":
			fake.pairChangedAt = 2
			wantCode = "retained_record_mismatch"
			wantPhase = "preflight"
			wantOutcome = "not_applied"
			wantAdds = 0
		case "readback":
			fake.readbackError = true
		case "readback-corrupt":
			fake.readbackCorrupt = true
		case "pair-after-add":
			fake.pairChangedAt = 4
		case "duplicate-no-effect":
			fake.addError = &rootGrantsAddNotApplied{reason: rootGrantsAddDuplicate}
			wantCode = "duplicate"
			wantPhase = "commit"
			wantOutcome = "not_applied"
		case "acl-no-effect":
			fake.addError = &rootGrantsAddNotApplied{reason: rootGrantsAddACLRefused}
			wantCode = "acl_refused"
			wantPhase = "commit"
			wantOutcome = "not_applied"
		case "code-no-effect":
			fake.addError = &rootGrantsAddNotApplied{reason: rootGrantsAddCodeRefused}
			wantCode = "code_not_admitted"
			wantPhase = "commit"
			wantOutcome = "not_applied"
		case "unknown-add":
			fake.addError = fmt.Errorf("PUBLIC_TEST_PRIVATE_SENTINEL")
			fake.applyOnError = true
			wantPhase = "commit"
		case "cancel-after-add":
			fake.cancel = cancel
			fake.cancelAt = "add"
		}
		plan, err := rootGrantsSyntheticResult46(request, sealed).plan()
		if err != nil {
			cancel()
			preflight.cancel()
			t.Fatal(err)
		}
		result, err := preflight.commit(ctx, plan)
		cancel()
		preflight.cancel()
		rootGrantsAttachFailure13(t, result, err, wantCode, wantPhase, wantOutcome)
		if fake.locks != 1 || fake.releases != 1 || fake.adds != wantAdds || fake.held {
			t.Fatal("failure boundary retried/reacquired/leaked")
		}
	}
}

// Claim: actual shared v2 exchange runs to ACK/EOF/exit BEFORE a test-only
// invocation is minted, consumed once and committed under the retained guard.
// The peer really gates its next read on ACK+stdin close; buffered extra output
// is refused AFTER ACK (not an early EOF wait). Limits: modeled peer/code and
// public fake store/shape-only seal, not production factory/native/ACL proof.
func TestRootGrantsHelper48HandshakeGuard(t *testing.T) {
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		for _, mode := range []string{"valid", "one-extra-byte", "vanished-before-ACK", "bad-exit"} {
			t.Run(schema+"/"+mode, func(t *testing.T) {
				request, sealed, item, record := rootGrantsSealedFixture46(t, schema)
				q, err := rootGrantsHelperRequest(request)
				if err != nil {
					t.Fatal(err)
				}
				fake := &rootGrantsVault13{t: t, pair: bytes.Clone(q.PairMetadata), expected: item, preAddReads: 3}
				preflight, err := beginRootGrantsAttach(context.Background(), fake, item.address, record.Pair)
				if err != nil {
					t.Fatal(err)
				}
				defer preflight.cancel()
				frame := rootGrantsFrame46(0, sealed)
				if mode == "one-extra-byte" {
					valid := bytes.Clone(frame)
					frame = append(frame, 0)
					if bytes.Equal(frame, valid) || len(frame) != len(valid)+1 {
						t.Fatal("extra-byte negative was a no-op")
					}
				}
				h, w := rootGrantsHostFixture46(frame)
				peer := h.child.output.(*rootGrantsCompletionReader48)
				h.onStart = func() {
					if !fake.held || fake.adds != 0 || fake.locks != 1 || fake.releases != 0 {
						t.Error("preflight not held before process")
					}
				}
				if mode == "vanished-before-ACK" {
					h.afterErr = errors.New("fixture guest gone")
				}
				if mode == "bad-exit" {
					h.exitErr = errors.New("fixture exit")
				}
				wait := h.child.wait
				h.child.wait = func() error {
					if mode != "vanished-before-ACK" && (!peer.ackSeen || peer.postReads != 1 || w.closeCount() < 1) {
						t.Error("wait before ACK/close/post-ACK read")
					}
					if fake.adds != 0 || !fake.held {
						t.Error("plan/add before exit")
					}
					return wait()
				}
				payload, pid, err := rootGrantsExchange46(t, context.Background(), request, h)
				if mode != "valid" {
					want := "private_protocol_error"
					if mode == "vanished-before-ACK" {
						want = "code_not_admitted"
					}
					rootGrantsFixedError48(t, err, want)
					if payload != nil || pid != 0 || fake.adds != 0 || fake.stored != nil {
						t.Fatal("failed completion reached plan/add")
					}
					if mode == "one-extra-byte" && (!peer.ackSeen || peer.postReads != 1 || len(w.bytes()) != 4+len(request)+36) {
						t.Fatal("extra-byte negative did not observe actual ACK/close")
					}
					if mode == "vanished-before-ACK" && len(w.bytes()) != 4+len(request) {
						t.Fatal("vanished peer received ACK")
					}
				} else {
					if err != nil || pid != 73 || !bytes.Equal(payload, sealed) || !peer.ackSeen || peer.postReads != 1 {
						t.Fatal("ACK-wait positive refused")
					}
					// Test-only completion; production mint stays in the fixed Darwin factory.
					result := rootGrantsSyntheticResult46(request, payload)
					plan, err := result.plan()
					if err != nil {
						t.Fatal(err)
					}
					stored, err := preflight.commit(context.Background(), plan)
					if err != nil || stored.Outcome != "stored" || fake.adds != 1 {
						t.Fatal("successful completion failed single add")
					}
					if replay, err := result.plan(); replay != nil || err == nil {
						t.Fatal("invocation reused")
					}
				}
				preflight.cancel()
				if fake.held || fake.locks != 1 || fake.releases != 1 || h.starts != 1 || h.waits != 1 || !reflect.DeepEqual(h.calls, []int{0, 73, 73}) {
					t.Fatal("same-guard/same-PID lifecycle changed")
				}
			})
		}
	}
}

// Claim: full public bindings are checked before the live-PID recheck/ACK,
// including all agreed v1/v2 forms. The invalid control also has a failing
// after-code verifier, so wrong validation order cannot mask its fixed refusal.
// Limits: pure/fake bindings, not ciphertext authenticity or native admission.
func TestRootGrantsHelper48BindingBeforeACK(t *testing.T) {
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		request, sealed, item, _ := rootGrantsSealedFixture46(t, schema)
		q, err := rootGrantsHelperRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"service", "version", "created", "pair", "root", "envelope"} {
			t.Run(schema+"/"+field, func(t *testing.T) {
				var object RootGrantsPrivateSealed
				if json.Unmarshal(sealed, &object) != nil {
					t.Fatal("fixture")
				}
				var r RootGrantsRecord
				if json.Unmarshal(object.Record, &r) != nil {
					t.Fatal("fixture")
				}
				want := "binding_mismatch"
				switch field {
				case "service":
					r.Service = "different-root"
				case "version":
					r.Version++
				case "created":
					r.Created = "2026-01-03T03:04:05Z"
				case "pair":
					r.Pair.GroupID = rootGrantsDifferentGroup47(t, r.Pair.GroupID)
				case "root":
					r.SealPublicKey = "03" + r.PublicKey
				case "envelope":
					object.Envelope = json.RawMessage("null")
					want = "invalid_envelope"
				}
				object.Record = rootGrantsRaw13(t, r)
				changed := rootGrantsRaw13(t, object)
				if bytes.Equal(changed, sealed) {
					t.Fatal("no-op binding negative")
				}
				fake := &rootGrantsVault13{t: t, pair: bytes.Clone(q.PairMetadata), expected: item}
				preflight, err := beginRootGrantsAttach(context.Background(), fake, item.address, q.Pair)
				if err != nil {
					t.Fatal(err)
				}
				defer preflight.cancel()
				h, w := rootGrantsHostFixture46(rootGrantsFrame46(0, changed))
				h.afterErr = errors.New("fixture would fail if reached")
				payload, pid, err := rootGrantsExchange46(t, context.Background(), request, h)
				rootGrantsFixedError48(t, err, want)
				if payload != nil || pid != 0 || len(w.bytes()) != 4+len(request) || !reflect.DeepEqual(h.calls, []int{0, 73}) || fake.adds != 0 || fake.stored != nil {
					t.Fatal("binding failure sent ACK/reached code check/add")
				}
				preflight.cancel()
				if fake.held || fake.locks != 1 || fake.releases != 1 {
					t.Fatal("binding failure leaked guard")
				}
			})
		}
	}
}

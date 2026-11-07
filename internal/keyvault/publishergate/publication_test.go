package publishergate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
)

// These are synthetic protected-authority, replay, held-object and message
// seams. Their state is deliberately in memory and grants NO native authority.
// The software key is ephemeral, never serialized or printed.
type syntheticPublication struct {
	requestDeadline, privateDeadline time.Time

	p                                                              publicationPolicy
	s                                                              replayState
	clock                                                          time.Time
	key                                                            *ecdsa.PrivateKey
	held                                                           publisherKeyPin
	events                                                         []string
	hook                                                           func(string)
	beginErr, reserveErr, resolveErr, fenceErr, signErr, commitErr error
	badSignature                                                   bool
	privateCalls, publications, clockReads, factReads              int
	output                                                         []byte
	busy                                                           bool
}

func publicationFixture(t *testing.T, shared *ecdsa.PrivateKey) (*Receiver, *syntheticBoundary, *syntheticPublication) {
	t.Helper()
	b := fixtureBoundary()
	if shared == nil {
		shared = fixtureConsumer(t).key
	}
	spki, err := x509.MarshalPKIXPublicKey(&shared.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	entries := []byte(`[{"from":"2026-11-06T11:59:00Z","id":"synthetic-revocation","kind":"record"}]`)
	pin := publisherKeyPin{kind: signerclient.KindKey, service: "synthetic-publisher", purpose: "revocations", generation: 3, store: signerclient.StoreEnclave, extraction: signerclient.ExtractionNone, spki: spki}
	o := &syntheticPublication{
		p:     publicationPolicy{admission: b.policy, key: pin, entries: entries, entriesHash: sha256.Sum256(entries), destination: "/synthetic/published.json", cadenceSeconds: 10, stateEpoch: 9},
		s:     replayState{healthy: true, policyEpoch: 7, stateEpoch: 9, lastTime: b.clock.Add(-30 * time.Second), encodedBytes: 64},
		clock: b.clock, key: shared, held: pin, output: []byte("prior synthetic output"),
	}
	return &Receiver{boundary: b, publication: o}, b, o
}

func (o *syntheticPublication) event(s string) {
	o.events = append(o.events, s)
	if o.hook != nil {
		o.hook(s)
	}
}
func (o *syntheticPublication) tryBegin(ctx context.Context, _ *AdmittedRequest) (publicationFence, error) {
	o.requestDeadline, _ = ctx.Deadline()
	o.event("begin")
	if o.beginErr != nil {
		return nil, o.beginErr
	}
	if o.busy {
		return nil, errors.New("synthetic contention")
	}
	o.busy = true
	return o, nil
}
func (o *syntheticPublication) policy() publicationPolicy { o.event("policy"); return o.p }
func (o *syntheticPublication) state() replayState        { o.event("state"); return o.s }
func (o *syntheticPublication) now() time.Time {
	o.clockReads++
	o.event(fmt.Sprintf("clock-%d", o.clockReads))
	return o.clock
}
func (o *syntheticPublication) reserve(_ context.Context, in publicationIntent) error {
	o.event("reserve")
	if o.reserveErr != nil {
		return o.reserveErr
	}
	o.s.records = append(o.s.records, replayRecord{intent: in})
	o.s.lastTime = in.issuedAt
	return nil
}
func (o *syntheticPublication) resolve(context.Context, publisherKeyPin) (heldPublisherKey, error) {
	o.event("resolve")
	if o.resolveErr != nil {
		return nil, o.resolveErr
	}
	return &syntheticHeld{owner: o}, nil
}
func (o *syntheticPublication) revalidate(context.Context, *AdmittedRequest) error {
	o.event("revalidate")
	return o.fenceErr
}
func (o *syntheticPublication) commit(_ context.Context, in publicationIntent, wire []byte) error {
	o.event("commit")
	if o.commitErr != nil {
		return o.commitErr
	}
	o.s.records[len(o.s.records)-1].complete = true
	o.publications++
	o.output = bytes.Clone(wire)
	return nil
}
func (o *syntheticPublication) close() { o.event("close"); o.busy = false }

type syntheticHeld struct{ owner *syntheticPublication }

func (k *syntheticHeld) facts() publisherKeyPin {
	o := k.owner
	o.factReads++
	o.event(fmt.Sprintf("facts-%d", o.factReads))
	return o.held
}
func (k *syntheticHeld) signSilent(ctx context.Context, digest [32]byte) ([]byte, error) {
	o := k.owner
	o.privateDeadline, _ = ctx.Deadline()
	o.privateCalls++
	o.event("sign")
	if o.signErr != nil {
		return nil, o.signErr
	}
	if o.badSignature {
		return []byte("synthetic malformed DER"), nil
	}
	return ecdsa.SignASN1(rand.Reader, o.key, digest[:])
}
func (k *syntheticHeld) release() { k.owner.event("release") }

func assertPublicationPositive(t *testing.T, o *syntheticPublication, receipt PublicationReceipt) {
	t.Helper()
	shared := fixtureConsumer(t)
	shared.key = o.key
	spki, err := x509.MarshalPKIXPublicKey(&o.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	id, err := validatePin(publisherKeyPin{kind: signerclient.KindKey, service: "synthetic-publisher", purpose: "revocations", generation: 3, store: signerclient.StoreEnclave, extraction: signerclient.ExtractionNone, spki: spki})
	if err != nil {
		t.Fatal(err)
	}
	shared.keyID, shared.privateCalls, shared.publications = id, o.privateCalls, o.publications
	shared.output, shared.contentID = o.output, receipt.ContentID()
	assertSyntheticPositive(t, shared)
	if receipt.Duplicate() {
		t.Fatal("new publication marked duplicate")
	}
}

func TestPublishCurrentCausalAdmissionPairs(t *testing.T) {
	shared := fixtureConsumer(t).key
	for _, field := range []string{"peer", "spoofed-field"} {
		for _, refuse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/refuse=%t", field, refuse), func(t *testing.T) {
				r, b, o := publicationFixture(t, shared)
				if refuse {
					if field == "peer" {
						b.peer = "foreign-synthetic-peer"
					} else {
						b.raw = []byte(strings.TrimSuffix(closedRequest, "}") + `,"pid":123}`)
					}
				}
				receipt, err := r.PublishCurrent(context.Background())
				if refuse {
					code := CallerRefused
					if field == "spoofed-field" {
						code = OperationRefused
					}
					requireCode(t, err, code)
					if o.privateCalls != 0 || o.publications != 0 || len(o.events) != 0 || string(o.output) != "prior synthetic output" {
						t.Fatal("admission refusal reached operation")
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					assertPublicationPositive(t, o, receipt)
					if strings.Join(o.events, ",") != "begin,policy,clock-1,state,reserve,resolve,facts-1,revalidate,clock-2,facts-2,sign,commit,release,close" {
						t.Fatalf("wrong private-entry order: %v", o.events)
					}
				}
				t.Logf("private_calls=%d publications=%d code=%v", o.privateCalls, o.publications, err)
			})
		}
	}
}

func TestPublishCurrentPreEntryCausalPairs(t *testing.T) {
	tests := []struct {
		name string
		code Code
		edit func(*syntheticPublication)
	}{
		{"missing-state", StateUnavailable, func(o *syntheticPublication) { o.s.healthy = false }},
		{"wrong-state-epoch", StateUnavailable, func(o *syntheticPublication) { o.s.stateEpoch++ }},
		{"wrong-state-policy", StateUnavailable, func(o *syntheticPublication) { o.s.policyEpoch++ }},
		{"state-clock-rollback", StateUnavailable, func(o *syntheticPublication) { o.s.lastTime = o.clock.Add(time.Nanosecond) }},
		{"corrupt-state-size", StateUnavailable, func(o *syntheticPublication) { o.s.encodedBytes = 0 }},
		{"state-size-cap", StateUnavailable, func(o *syntheticPublication) { o.s.encodedBytes = maxReplayBytes + 1 }},
		{"policy-projection-changed", PolicyUnavailable, func(o *syntheticPublication) { o.p.admission.epoch++ }},
		{"zero-replay-epoch", PolicyUnavailable, func(o *syntheticPublication) { o.p.stateEpoch = 0 }},
		{"cadence-zero", PolicyUnavailable, func(o *syntheticPublication) { o.p.cadenceSeconds = 0 }},
		{"cadence-over-limit", PolicyUnavailable, func(o *syntheticPublication) { o.p.cadenceSeconds = 61 }},
		{"relative-destination", PolicyUnavailable, func(o *syntheticPublication) { o.p.destination = "caller-choice" }},
		{"entries-hash-substitution", PolicyUnavailable, func(o *syntheticPublication) { o.p.entriesHash[0] ^= 1 }},
		{"entries-oversize", PolicyUnavailable, func(o *syntheticPublication) { o.p.entries = bytes.Repeat([]byte(" "), maxEntriesBytes+1) }},
		{"generation-newest", KeyMismatch, func(o *syntheticPublication) { o.p.key.generation = 0 }},
		{"policy-store-unknown", KeyMismatch, func(o *syntheticPublication) { o.p.key.store = signerclient.StoreUnknown }},
		{"policy-presence", OperationRefused, func(o *syntheticPublication) { o.p.key.presence = true }},
		{"held-generation", KeyMismatch, func(o *syntheticPublication) { o.held.generation++ }},
		{"held-store", KeyMismatch, func(o *syntheticPublication) { o.held.store = signerclient.StoreKeychain }},
		{"held-extraction", KeyMismatch, func(o *syntheticPublication) { o.held.extraction = signerclient.ExtractionAgent }},
		{"held-presence", KeyMismatch, func(o *syntheticPublication) { o.held.presence = true }},
		{"held-key-substitution", KeyMismatch, func(o *syntheticPublication) { o.held.spki = []byte("foreign public pin") }},
		{"reserve-failure", StateUnavailable, func(o *syntheticPublication) { o.reserveErr = errors.New("private arbitrary diagnostic") }},
		{"resolve-failure", KeyMismatch, func(o *syntheticPublication) { o.resolveErr = errors.New("private arbitrary diagnostic") }},
		{"revoke-at-final-fence", PolicyStale, func(o *syntheticPublication) { o.fenceErr = errors.New("private arbitrary diagnostic") }},
		{"held-swap-at-fence", KeyMismatch, func(o *syntheticPublication) {
			o.hook = func(s string) {
				if s == "revalidate" {
					o.held.generation++
				}
			}
		}},
		{"expiry-at-fence", ClockRefused, func(o *syntheticPublication) {
			o.hook = func(s string) {
				if s == "revalidate" {
					o.clock = o.p.admission.expires
				}
			}
		}},
		{"slot-changed-at-fence", ClockRefused, func(o *syntheticPublication) {
			o.hook = func(s string) {
				if s == "revalidate" {
					o.clock = o.clock.Add(10 * time.Second)
				}
			}
		}},
		{"clock-backward-at-fence", ClockRefused, func(o *syntheticPublication) {
			o.hook = func(s string) {
				if s == "revalidate" {
					o.clock = o.clock.Add(-time.Nanosecond)
				}
			}
		}},
	}
	shared := fixtureConsumer(t).key
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, negative := range []bool{false, true} {
				r, _, o := publicationFixture(t, shared)
				if negative {
					tt.edit(o)
				}
				receipt, err := r.PublishCurrent(context.Background())
				if !negative {
					if err != nil {
						t.Fatal(err)
					}
					assertPublicationPositive(t, o, receipt)
				} else {
					requireCode(t, err, tt.code)
					if receipt != (PublicationReceipt{}) || o.privateCalls != 0 || o.publications != 0 || string(o.output) != "prior synthetic output" {
						t.Fatalf("pre-entry refusal changed output or used key: calls=%d pubs=%d", o.privateCalls, o.publications)
					}
				}
			}
		})
	}
}

func TestPublishCurrentCancellationAtEachBoundary(t *testing.T) {
	shared := fixtureConsumer(t).key
	for _, stage := range []string{"begin", "policy", "clock-1", "state", "reserve", "resolve", "facts-1", "revalidate", "clock-2", "facts-2"} {
		t.Run(stage, func(t *testing.T) {
			for _, cancelAtBoundary := range []bool{false, true} {
				r, _, o := publicationFixture(t, shared)
				ctx, cancel := context.WithCancel(context.Background())
				o.hook = func(s string) {
					if s == stage && cancelAtBoundary {
						cancel()
					}
				}
				receipt, err := r.PublishCurrent(ctx)
				cancel()
				if cancelAtBoundary {
					requireCode(t, err, OperationRefused)
					if o.privateCalls != 0 || o.publications != 0 || string(o.output) != "prior synthetic output" {
						t.Fatal("cancel entered private operation")
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					assertPublicationPositive(t, o, receipt)
				}
			}
		})
	}
}

func TestPublishCurrentPostEntryNeverRetries(t *testing.T) {
	shared := fixtureConsumer(t).key
	for _, failure := range []string{"native-error", "malformed-signature", "different-key", "cancel-during-sign", "commit-failure"} {
		t.Run(failure, func(t *testing.T) {
			r, _, o := publicationFixture(t, shared)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch failure {
			case "native-error":
				o.signErr = errors.New("secret native error must not leak")
			case "malformed-signature":
				o.badSignature = true
			case "different-key":
				o.key = fixtureConsumer(t).key
			case "cancel-during-sign":
				o.hook = func(s string) {
					if s == "sign" {
						cancel()
					}
				}
			case "commit-failure":
				o.commitErr = errors.New("uncontrolled persistence error")
			}
			receipt, err := r.PublishCurrent(ctx)
			requireCode(t, err, PrivateOutcomeUnknown)
			if receipt != (PublicationReceipt{}) || o.privateCalls != 1 || o.publications != 0 || string(o.output) != "prior synthetic output" || len(o.s.records) != 1 || o.s.records[0].complete {
				t.Fatal("post-entry outcome lost reservation or published")
			}
			_, err = r.PublishCurrent(context.Background())
			requireCode(t, err, StateUnavailable)
			if o.privateCalls != 1 || o.publications != 0 {
				t.Fatal("uncertain operation retried")
			}
			t.Logf("private_calls=%d publications=%d reservation_retained=true", o.privateCalls, o.publications)
		})
	}
}

func TestPublishCurrentReplayAndCadence(t *testing.T) {
	r, b, o := publicationFixture(t, nil)
	first, err := r.PublishCurrent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertPublicationPositive(t, o, first)
	prior := bytes.Clone(o.output)
	duplicate, err := r.PublishCurrent(context.Background())
	if err != nil || !duplicate.Duplicate() || duplicate.ContentID() != first.ContentID() || o.privateCalls != 1 || o.publications != 1 || !bytes.Equal(prior, o.output) {
		t.Fatal("identical retry did not return stored receipt without signing")
	}
	// Same nonce, different exact message bytes refuses even when semantics match.
	b.raw = append([]byte(" "), b.raw...)
	_, err = r.PublishCurrent(context.Background())
	requireCode(t, err, ReplayRefused)
	// New nonce cannot force another signature in the same slot.
	b.raw = bytes.Replace([]byte(closedRequest), []byte(`"request_nonce":"A`), []byte(`"request_nonce":"B`), 1)
	_, err = r.PublishCurrent(context.Background())
	requireCode(t, err, ReplayRefused)
	if o.privateCalls != 1 || o.publications != 1 {
		t.Fatal("replay signed twice")
	}
	// Exactly the next slot permits the new nonce, with the same key/policy.
	o.clock = o.clock.Add(10 * time.Second)
	b.clock = o.clock
	second, err := r.PublishCurrent(context.Background())
	if err != nil || second.Duplicate() || second.ContentID() == first.ContentID() || o.privateCalls != 2 || o.publications != 2 {
		t.Fatalf("next admitted slot failed: %v", err)
	}
}

func TestPublishCurrentRequiresBothSealedBoundaries(t *testing.T) {
	for _, r := range []*Receiver{nil, {}, {boundary: fixtureBoundary()}, {publication: &syntheticPublication{}}} {
		receipt, err := r.PublishCurrent(context.Background())
		requireCode(t, err, NativeUnavailable)
		if receipt != (PublicationReceipt{}) {
			t.Fatal("disabled receiver returned receipt")
		}
	}
}

func TestPublishCurrentApplicationBudgets(t *testing.T) {
	for _, shortParent := range []bool{false, true} {
		r, _, o := publicationFixture(t, nil)
		ctx := context.Background()
		var parentDeadline time.Time
		if shortParent {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Second)
			defer cancel()
			parentDeadline, _ = ctx.Deadline()
		}
		receipt, err := r.PublishCurrent(ctx)
		if err != nil {
			t.Fatal(err)
		}
		assertPublicationPositive(t, o, receipt)
		if o.requestDeadline.IsZero() || o.requestDeadline.After(time.Now().Add(requestBudget)) || o.privateDeadline.IsZero() || o.privateDeadline.After(time.Now().Add(privateBudget)) {
			t.Fatal("application budgets missing or enlarged")
		}
		if shortParent && (o.requestDeadline.After(parentDeadline) || o.privateDeadline.After(parentDeadline)) {
			t.Fatal("caller deadline was extended")
		}
	}
}

func TestPublishCurrentOriginalMessageCausalPairs(t *testing.T) {
	shared := fixtureConsumer(t).key
	for _, variant := range []string{"missing-original", "payload-not-bound", "original-revalidation-refused", "cancel-in-original-revalidation"} {
		t.Run(variant, func(t *testing.T) {
			for _, negative := range []bool{false, true} {
				r, b, o := publicationFixture(t, shared)
				ctx, cancel := context.WithCancel(context.Background())
				if negative {
					switch variant {
					case "missing-original":
						b.noOrigin = true
					case "payload-not-bound":
						b.badOrigin = true
					case "original-revalidation-refused":
						b.originErr = errors.New("synthetic original message disqualified")
					case "cancel-in-original-revalidation":
						b.originHook = cancel
					}
				}
				receipt, err := r.PublishCurrent(ctx)
				cancel()
				if negative {
					code := CallerRefused
					if variant == "cancel-in-original-revalidation" {
						code = OperationRefused
					}
					requireCode(t, err, code)
					if o.privateCalls != 0 || o.publications != 0 || string(o.output) != "prior synthetic output" {
						t.Fatal("missing/inconsistent message evidence entered private operation")
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					assertPublicationPositive(t, o, receipt)
					if b.originChecks != 1 {
						t.Fatal("original message not revalidated at fence")
					}
				}
			}
		})
	}
}

func TestPublishCurrentReplayCapacityPairs(t *testing.T) {
	shared := fixtureConsumer(t).key
	for _, count := range []int{maxReplayRecords - 1, maxReplayRecords} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			r, b, o := publicationFixture(t, shared)
			start := o.clock
			o.clock = start.Add(time.Duration(maxReplayRecords+1) * 10 * time.Second)
			b.clock = o.clock
			b.policy.expires = o.clock.Add(time.Minute)
			o.p.admission = b.policy
			o.s.lastTime = start.Add(time.Duration(count-1) * 10 * time.Second)
			o.s.encodedBytes = maxReplayBytes
			o.s.records = make([]replayRecord, count)
			for i := range o.s.records {
				at := start.Add(time.Duration(i) * 10 * time.Second)
				v := publicationIntent{policyEpoch: 7, stateEpoch: 9, slot: at.Unix() / 10, issuedAt: at, entriesHash: o.p.entriesHash, contentID: "sha256:" + strings.Repeat("0", 64)}
				binary.BigEndian.PutUint64(v.nonce[:8], uint64(i+1))
				o.s.records[i] = replayRecord{intent: v, complete: true}
			}
			receipt, err := r.PublishCurrent(context.Background())
			if count == maxReplayRecords {
				requireCode(t, err, ResourceLimit)
				if o.privateCalls != 0 || o.publications != 0 || string(o.output) != "prior synthetic output" {
					t.Fatal("full replay state evicted protection or signed")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				assertPublicationPositive(t, o, receipt)
			}
		})
	}
}

func TestPublishCurrentCorruptCompletedStateRefuses(t *testing.T) {
	for _, corruption := range []string{"nonce-duplicate", "slot-duplicate", "wrong-entry-revision", "invalid-content-id", "noncompleted-reservation"} {
		t.Run(corruption, func(t *testing.T) {
			r, b, o := publicationFixture(t, nil)
			if _, err := r.PublishCurrent(context.Background()); err != nil {
				t.Fatal(err)
			}
			switch corruption {
			case "nonce-duplicate":
				v := o.s.records[0]
				v.intent.slot++
				v.intent.issuedAt = v.intent.issuedAt.Add(10 * time.Second)
				o.s.records = append(o.s.records, v)
				o.s.lastTime = v.intent.issuedAt
			case "slot-duplicate":
				v := o.s.records[0]
				v.intent.nonce[0] = 1
				o.s.records = append(o.s.records, v)
			case "wrong-entry-revision":
				o.s.records[0].intent.entriesHash[0] ^= 1
			case "invalid-content-id":
				o.s.records[0].intent.contentID = "uncontrolled receipt"
			case "noncompleted-reservation":
				o.s.records[0].complete = false
			}
			o.clock = o.clock.Add(20 * time.Second)
			b.clock = o.clock
			prior := bytes.Clone(o.output)
			_, err := r.PublishCurrent(context.Background())
			requireCode(t, err, StateUnavailable)
			if o.privateCalls != 1 || o.publications != 1 || !bytes.Equal(prior, o.output) {
				t.Fatal("corrupt protected state retried or changed output")
			}
		})
	}
}

func TestProtectedEntriesConflictAndClosedShape(t *testing.T) {
	for _, raw := range []string{
		`[{"from":"2026-11-06T11:59:00Z","id":"a","kind":"record"},{"from":"2026-11-06T11:58:00Z","id":"a","kind":"record"}]`,
		`[{"from":"2026-11-06T11:59:00Z","id":"a","id":"a","kind":"record"}]`,
		`[{"from":"2026-11-06T11:59:00Z","id":"a","kind":"record","pid":1}]`,
		`[{"from":"2026-11-06T12:01:00Z","id":"a","kind":"record"}]`,
	} {
		r, _, o := publicationFixture(t, nil)
		o.p.entries = []byte(raw)
		o.p.entriesHash = sha256.Sum256(o.p.entries)
		_, err := r.PublishCurrent(context.Background())
		requireCode(t, err, OperationRefused)
		if o.privateCalls != 0 || o.publications != 0 {
			t.Fatal("invalid entries used key")
		}
	}
}

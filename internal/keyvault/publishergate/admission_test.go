package publishergate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

// Every authority/peer below is a synthetic test double. It neither observes
// macOS identity nor establishes custody, durable replay or protected policy.
type syntheticBoundary struct {
	policy       admissionPolicy
	raw          []byte
	peer         string
	clock        time.Time
	policyErr    error
	policyReads  int
	authCalls    int
	afterAuth    func()
	finalPolicy  func()
	finalClock   func()
	originErr    error
	originChecks int
	originHook   func()
	noOrigin     bool
	badOrigin    bool
}

func fixtureBoundary() *syntheticBoundary {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	return &syntheticBoundary{
		policy: admissionPolicy{"synthetic-scope", 7, true, now.Add(-time.Minute), now.Add(time.Minute)},
		raw:    []byte(closedRequest), peer: "admitted-synthetic-peer", clock: now,
	}
}

func (s *syntheticBoundary) currentPolicy(context.Context) (admissionPolicy, error) {
	s.policyReads++
	if s.policyReads == 2 && s.finalPolicy != nil {
		s.finalPolicy()
	}
	return s.policy, s.policyErr
}

func (s *syntheticBoundary) authenticateAndCopyMessage(_ context.Context, p admissionPolicy) ([]byte, receivedMessage, error) {
	s.authCalls++
	if s.peer != "admitted-synthetic-peer" {
		return nil, nil, errors.New("synthetic foreign peer; not an OS observation")
	}
	if s.afterAuth != nil {
		s.afterAuth()
	}
	if s.noOrigin {
		return bytes.Clone(s.raw), nil, nil
	}
	hash := sha256.Sum256(s.raw)
	if s.badOrigin {
		hash[0] ^= 1
	}
	return bytes.Clone(s.raw), &syntheticMessage{source: s, policy: p, hash: hash}, nil
}

type syntheticMessage struct {
	source *syntheticBoundary
	policy admissionPolicy
	hash   [32]byte
}

func (m *syntheticMessage) revalidateOriginal(_ context.Context, p admissionPolicy, hash [32]byte) error {
	m.source.originChecks++
	if m.source.originHook != nil {
		m.source.originHook()
	}
	if !sameAdmission(p, m.policy) || hash != m.hash {
		return errors.New("synthetic message binding mismatch")
	}
	return m.source.originErr
}

func (s *syntheticBoundary) now() time.Time {
	if s.policyReads == 2 && s.finalClock != nil {
		s.finalClock()
	}
	return s.clock
}

// syntheticConsumer is a causal test oracle AFTER message admission, not an
// implementation of PublishCurrent. Its fixed in-memory entries/key/output are
// never selected from caller bytes. The ephemeral software private key is not
// printed or serialized. No native private API or existing key is accessed.
type syntheticConsumer struct {
	key          *ecdsa.PrivateKey
	keyID        string
	privateCalls int
	publications int
	output       []byte
	contentID    string
	nonce        [32]byte
}

func fixtureConsumer(t *testing.T) *syntheticConsumer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	id, err := mugrant.KeyIDFromSPKI(spki)
	if err != nil {
		t.Fatal(err)
	}
	return &syntheticConsumer{key: k, keyID: id, output: []byte("prior synthetic output")}
}

func (c *syntheticConsumer) run(ctx context.Context, r *Receiver) error {
	a, err := r.Admit(ctx)
	if err != nil {
		return err
	}
	// This is a test-only positive, not authorization from an AdmittedRequest.
	// A production publisher needs all the separate design §4.3 fences first.
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	p, err := mugrant.BuildSnapshot(c.keyID, now, []mugrant.SnapshotEntry{
		{Kind: "record", ID: "synthetic-revocation", From: "2026-11-06T11:59:00Z"},
	})
	if err != nil {
		return err
	}
	d := p.Digest()
	c.privateCalls++
	der, err := ecdsa.SignASN1(rand.Reader, c.key, d[:])
	if err != nil {
		return err
	}
	wire, err := mugrant.AssembleNative(p, der)
	if err != nil {
		return err
	}
	c.publications++
	c.output, c.contentID, c.nonce = wire, p.ContentID(), a.Request().RequestNonce()
	return nil
}

func assertSyntheticPositive(t *testing.T, c *syntheticConsumer) {
	t.Helper()
	if c.privateCalls != 1 || c.publications != 1 || c.contentID == "" || bytes.Equal(c.output, []byte("prior synthetic output")) {
		t.Fatal("positive did not sign and publish exactly once")
	}
	var envelope struct {
		Version    string          `json:"version"`
		ID         string          `json:"id"`
		Body       json.RawMessage `json:"body"`
		Signatures []struct{ Key, Role, Sig string }
	}
	if err := json.Unmarshal(c.output, &envelope); err != nil || envelope.Version != "swarm-envelope/2" || envelope.ID != c.contentID || len(envelope.Signatures) != 1 {
		t.Fatal("invalid synthetic publication shape")
	}
	var body struct {
		Type     string                  `json:"type"`
		Issuer   string                  `json:"issuer"`
		Complete bool                    `json:"complete"`
		Entries  []mugrant.SnapshotEntry `json:"entries"`
	}
	if err := json.Unmarshal(envelope.Body, &body); err != nil || body.Type != "revocation/1" || body.Issuer != c.keyID || !body.Complete || len(body.Entries) != 1 || body.Entries[0].ID != "synthetic-revocation" {
		t.Fatal("publication did not use the fixed complete snapshot")
	}
	s := envelope.Signatures[0]
	sig, err := base64.RawURLEncoding.DecodeString(s.Sig)
	if err != nil || len(sig) != 64 || s.Key != c.keyID || s.Role != "author" {
		t.Fatal("invalid synthetic signature shape")
	}
	// Verify with stdlib ECDSA as well as AssembleNative's pinned verifier.
	// These ASCII-only fixtures let encoding/json reconstruct the independently
	// specified sorted signing object without relying on the platform builder.
	preimage, err := json.Marshal(map[string]any{
		"body": envelope.Body, "key": c.keyID, "role": "author", "version": "swarm-envelope/2",
	})
	if err != nil {
		t.Fatal(err)
	}
	domain := []byte("swarma-attestation revocation/1\n")
	digest := sha256.Sum256(append(bytes.Clone(domain), preimage...))
	if !ecdsa.Verify(&c.key.PublicKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("stdlib rejects synthetic publication signature")
	}
	idDigest := sha256.Sum256(append(bytes.Clone(domain), envelope.Body...))
	if envelope.ID != "sha256:"+hex.EncodeToString(idDigest[:]) {
		t.Fatal("content id differs from independent body hash")
	}
	if c.nonce != [32]byte{} {
		t.Fatal("receipt correlation changed")
	}
}

func assertSyntheticRefusal(t *testing.T, c *syntheticConsumer, err error, code Code) {
	t.Helper()
	requireCode(t, err, code)
	if c.privateCalls != 0 || c.publications != 0 || !bytes.Equal(c.output, []byte("prior synthetic output")) {
		t.Fatal("refusal reached a synthetic private call or changed prior output")
	}
}

// KV402-L01 pair 1: exactly the SAME VALID closed bytes and fixed operation,
// changing only the synthetic peer. No spoof field can mask the peer check.
func TestKV402L01PeerPair(t *testing.T) {
	shared := fixtureConsumer(t)
	for _, foreign := range []bool{false, true} {
		name := "admitted"
		if foreign {
			name = "foreign"
		}
		t.Run(name, func(t *testing.T) {
			b := fixtureBoundary()
			c := &syntheticConsumer{key: shared.key, keyID: shared.keyID, output: []byte("prior synthetic output")}
			if foreign {
				b.peer = "foreign-synthetic-peer"
			}
			err := c.run(context.Background(), &Receiver{boundary: b})
			if b.authCalls != 1 || string(b.raw) != closedRequest {
				t.Fatal("pair did not exercise authentication on identical valid bytes")
			}
			if foreign {
				assertSyntheticRefusal(t, c, err, CallerRefused)
			} else {
				if err != nil {
					t.Fatal(err)
				}
				assertSyntheticPositive(t, c)
			}
		})
	}
}

// KV402-L01 pair 2: the SAME admitted peer, changing only one extra pid field.
// Authentication succeeds in both cases; closed-schema refusal is independent.
func TestKV402L01SpoofedFieldPair(t *testing.T) {
	shared := fixtureConsumer(t)
	for _, spoof := range []bool{false, true} {
		name := "closed"
		if spoof {
			name = "one-extra-pid"
		}
		t.Run(name, func(t *testing.T) {
			b := fixtureBoundary()
			c := &syntheticConsumer{key: shared.key, keyID: shared.keyID, output: []byte("prior synthetic output")}
			if spoof {
				b.raw = []byte(strings.TrimSuffix(closedRequest, "}") + `,"pid":123}`)
			}
			err := c.run(context.Background(), &Receiver{boundary: b})
			if b.authCalls != 1 || b.peer != "admitted-synthetic-peer" {
				t.Fatal("pair changed peer or bypassed authentication")
			}
			if spoof {
				assertSyntheticRefusal(t, c, err, OperationRefused)
			} else {
				if err != nil {
					t.Fatal(err)
				}
				assertSyntheticPositive(t, c)
			}
		})
	}
}

func TestAdmissionRefusalsStopSyntheticPrivateUse(t *testing.T) {
	tests := []struct {
		name string
		edit func(*syntheticBoundary)
		code Code
	}{
		{"policy-missing", func(b *syntheticBoundary) { b.policyErr = errors.New("untrusted native diagnostic") }, PolicyUnavailable},
		{"disabled", func(b *syntheticBoundary) { b.policy.enabled = false }, PolicyUnavailable},
		{"empty-scope", func(b *syntheticBoundary) { b.policy.scope = "" }, PolicyUnavailable},
		{"zero-policy-epoch", func(b *syntheticBoundary) { b.policy.epoch = 0 }, PolicyUnavailable},
		{"missing-clock", func(b *syntheticBoundary) { b.clock = time.Time{} }, ClockRefused},
		{"not-yet-valid", func(b *syntheticBoundary) { b.clock = b.policy.notBefore.Add(-time.Nanosecond) }, ClockRefused},
		{"expiry-is-exclusive", func(b *syntheticBoundary) { b.clock = b.policy.expires }, ClockRefused},
		{"wrong-scope", func(b *syntheticBoundary) {
			b.raw = bytes.Replace(b.raw, []byte("synthetic-scope"), []byte("foreign-scope"), 1)
		}, OperationRefused},
		{"wrong-epoch", func(b *syntheticBoundary) {
			b.raw = bytes.Replace(b.raw, []byte(`"policy_epoch":7`), []byte(`"policy_epoch":8`), 1)
		}, PolicyStale},
		{"oversize", func(b *syntheticBoundary) { b.raw = append(b.raw, bytes.Repeat([]byte(" "), MaxRequestBytes)...) }, ResourceLimit},
		{"revoke-during-auth", func(b *syntheticBoundary) { b.afterAuth = func() { b.policy.enabled = false } }, PolicyStale},
		{"epoch-during-auth", func(b *syntheticBoundary) { b.afterAuth = func() { b.policy.epoch++ } }, PolicyStale},
		{"policy-loss-during-auth", func(b *syntheticBoundary) { b.afterAuth = func() { b.policyErr = errors.New("gone") } }, PolicyUnavailable},
		{"expiry-during-auth", func(b *syntheticBoundary) { b.afterAuth = func() { b.clock = b.policy.expires } }, ClockRefused},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, c := fixtureBoundary(), fixtureConsumer(t)
			tt.edit(b)
			assertSyntheticRefusal(t, c, c.run(context.Background(), &Receiver{boundary: b}), tt.code)
		})
	}
}

func TestCancelledAdmissionHasNoSyntheticPrivateUse(t *testing.T) {
	for _, during := range []bool{false, true} {
		b, c := fixtureBoundary(), fixtureConsumer(t)
		ctx, cancel := context.WithCancel(context.Background())
		if during {
			b.afterAuth = cancel
		} else {
			cancel()
		}
		assertSyntheticRefusal(t, c, c.run(ctx, &Receiver{boundary: b}), OperationRefused)
		cancel()
	}
}

func TestNoNativeAdapterAndNoCallerConstructor(t *testing.T) {
	r, err := NewReceiver()
	requireCode(t, err, NativeUnavailable)
	if r != nil {
		t.Fatal("missing native adapter returned a usable receiver")
	}
	for _, r := range []*Receiver{nil, {}} {
		c := fixtureConsumer(t)
		assertSyntheticRefusal(t, c, c.run(context.Background(), r), NativeUnavailable)
	}
}

// KV470-M01: each pair keeps bytes, peer, policy, clock and software key fixed.
// Only cancellation inside the final boundary callback changes. These remain
// synthetic admission/consumer controls, not native identity or custody proof.
func TestKV470M01FinalBoundaryCancellation(t *testing.T) {
	for _, boundary := range []string{"policy", "clock"} {
		t.Run(boundary, func(t *testing.T) {
			shared := fixtureConsumer(t)
			for _, cancelled := range []bool{false, true} {
				name := "valid-neighbor"
				if cancelled {
					name = "cancel-in-final-callback"
				}
				t.Run(name, func(t *testing.T) {
					b := fixtureBoundary()
					c := &syntheticConsumer{key: shared.key, keyID: shared.keyID, output: []byte("prior synthetic output")}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					callbacks := 0
					hook := func() {
						callbacks++
						if cancelled {
							cancel()
						}
					}
					if boundary == "policy" {
						b.finalPolicy = hook
					} else {
						b.finalClock = hook
					}
					err := c.run(ctx, &Receiver{boundary: b})
					t.Logf("boundary=%s cancelled=%t callbacks=%d policy_reads=%d auth_calls=%d ctx_err=%v err=%v private_calls=%d publications=%d prior_output_unchanged=%t", boundary, cancelled, callbacks, b.policyReads, b.authCalls, ctx.Err(), err, c.privateCalls, c.publications, bytes.Equal(c.output, []byte("prior synthetic output")))
					if callbacks != 1 || b.policyReads != 2 || b.authCalls != 1 || string(b.raw) != closedRequest || b.peer != "admitted-synthetic-peer" {
						t.Fatal("pair failed to reach the same final boundary with identical valid bytes/peer")
					}
					if cancelled {
						if ctx.Err() != context.Canceled {
							t.Fatal("callback did not synchronously cancel")
						}
						assertSyntheticRefusal(t, c, err, OperationRefused)
					} else {
						if ctx.Err() != nil || err != nil {
							t.Fatalf("valid neighbor refused: %v", err)
						}
						assertSyntheticPositive(t, c)
					}
				})
			}
		})
	}
}

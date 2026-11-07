package publishergate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"time"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

const (
	maxEntriesBytes  = 65536
	maxReplayRecords = 65536
	maxReplayBytes   = 16 << 20
	requestBudget    = 5 * time.Second
	privateBudget    = 15 * time.Second
)

// PublicationReceipt is public correlation data, never a signature or a key
// capability. It is returned only after verified durable publication, or for an
// identical completed request in protected replay state.
type PublicationReceipt struct {
	contentID string
	duplicate bool
}

func (r PublicationReceipt) ContentID() string { return r.contentID }
func (r PublicationReceipt) Duplicate() bool   { return r.duplicate }

// All interfaces below are sealed within this package. There is deliberately
// no production implementation or public injection constructor. Their only
// implementations are synthetic test doubles; an in-memory/file callback is
// not protected authority, durable custody or native sender evidence.
type publicationBoundary interface {
	// tryBegin must acquire the exclusive per-key fence without an unbounded
	// queue. The fence serializes revocation, replay state and private entry.
	// It requires qualified platform, exclusive custody and protected current
	// policy/state before resolving any usable private inputs.
	tryBegin(context.Context, *AdmittedRequest) (publicationFence, error)
}

type publicationFence interface {
	policy() publicationPolicy
	state() replayState
	now() time.Time
	// reserve durably records exact intent before key resolution. Any error
	// blocks further work until protected reconciliation, even if no private
	// call happened. It may not silently create/reset missing replay state.
	reserve(context.Context, publicationIntent) error
	// resolve returns ONE held object. facts and signSilent must refer to the
	// same actual key, with no label lookup, store or generation fallback.
	// facts/resolve/release must not perform private operations or presence probes.
	resolve(context.Context, publisherKeyPin) (heldPublisherKey, error)
	// revalidate must bind the original admitted message (not a PID/connection
	// assertion) to current protected policy, builds, state and revocation.
	// The fence remains held through signing and commit.
	revalidate(context.Context, *AdmittedRequest) error
	// commit atomically/journaledly persists completion and publishes only the
	// verified envelope to policy's destination. Failure keeps the reservation
	// blocked; no implicit retry, eviction, rollback or generic route is allowed.
	commit(context.Context, publicationIntent, []byte) error
	close()
}

type heldPublisherKey interface {
	facts() publisherKeyPin
	signSilent(context.Context, [32]byte) ([]byte, error)
	release()
}

type publisherKeyPin struct {
	kind, service, purpose string
	generation             int
	store                  signerclient.StoreKind
	extraction             string
	presence               bool
	spki                   []byte
}

type publicationPolicy struct {
	admission admissionPolicy
	key       publisherKeyPin
	// Entries are exact canonical JSON bytes from protected, independently
	// admitted state, not an attacker-writable entries file. The authority
	// must enforce complete-set continuity across policy/replay epochs.
	entries        []byte
	entriesHash    [32]byte
	destination    string
	cadenceSeconds int64
	stateEpoch     uint64
}

type publicationIntent struct {
	nonce, messageHash, entriesHash, bodyHash [32]byte
	policyEpoch, stateEpoch                   uint64
	slot                                      int64
	issuedAt                                  time.Time
	contentID                                 string
}

type replayRecord struct {
	intent   publicationIntent
	complete bool
}

// healthy means authenticated current state, including an explicitly admitted
// genesis. It must never be inferred from the absence of a file/record. The
// adapter also enforces encoded state and event-storage bounds at persistence.
type replayState struct {
	healthy                 bool
	policyEpoch, stateEpoch uint64
	lastTime                time.Time
	encodedBytes            int
	records                 []replayRecord
}

// PublishCurrent is the sole typed operation. It receives its own message;
// callers cannot supply an AdmittedRequest, digest, key, entries or destination.
// Production stays unavailable until the missing native/protected boundaries
// exist. No CLI/Manager/helper path is connected to this source component.
func (r *Receiver) PublishCurrent(ctx context.Context) (PublicationReceipt, error) {
	var zero PublicationReceipt
	if r == nil || r.boundary == nil || r.publication == nil {
		return zero, refusal(NativeUnavailable)
	}
	if ctx == nil {
		return zero, refusal(OperationRefused)
	}
	callerCtx := ctx
	ctx, cancelRequest := context.WithTimeout(ctx, requestBudget)
	defer cancelRequest()
	a, err := r.Admit(ctx)
	if err != nil {
		return zero, err
	}
	f, err := r.publication.tryBegin(ctx, a)
	if err != nil || f == nil {
		return zero, refusal(StateUnavailable)
	}
	defer f.close()
	p := f.policy()
	if len(p.entries) > maxEntriesBytes || len(p.key.spki) > 1024 {
		return zero, refusal(PolicyUnavailable)
	}
	// Own every slice before other boundary calls. Protected epochs identify
	// immutable complete policies, not just the small admission projection.
	p.entries = bytes.Clone(p.entries)
	p.key.spki = bytes.Clone(p.key.spki)
	if !sameAdmission(p.admission, a.policy) || p.stateEpoch == 0 || p.cadenceSeconds < 1 || p.cadenceSeconds > 60 || len(p.destination) > 4096 || !filepath.IsAbs(p.destination) || strings.IndexByte(p.destination, 0) >= 0 {
		return zero, refusal(PolicyUnavailable)
	}
	keyID, err := validatePin(p.key)
	if err != nil {
		return zero, err
	}
	entries, err := protectedEntries(p.entries, p.entriesHash)
	if err != nil {
		return zero, err
	}
	now := f.now()
	if err := checkTime(p.admission, now); err != nil {
		return zero, err
	}
	// issued_at and cadence are selected here from qualified service time.
	issued := now.UTC().Truncate(time.Second)
	if issued.Before(p.admission.notBefore) {
		return zero, refusal(ClockRefused)
	}
	plan, err := mugrant.BuildSnapshot(keyID, issued, entries)
	if err != nil {
		return zero, refusal(OperationRefused)
	}
	intent := publicationIntent{
		nonce: a.request.nonce, messageHash: a.messageHash, entriesHash: p.entriesHash,
		bodyHash: sha256.Sum256(plan.Body()), policyEpoch: a.request.epoch,
		stateEpoch: p.stateEpoch, slot: issued.Unix() / p.cadenceSeconds,
		issuedAt: now, contentID: plan.ContentID(),
	}
	s := f.state()
	if !s.healthy || s.policyEpoch != intent.policyEpoch || s.stateEpoch != intent.stateEpoch || s.lastTime.IsZero() || now.Before(s.lastTime) || s.encodedBytes <= 0 || s.encodedBytes > maxReplayBytes || len(s.records) > maxReplayRecords {
		return zero, refusal(StateUnavailable)
	}
	var duplicate *replayRecord
	lastSlot := int64(-1)
	seen := make(map[[32]byte]bool, len(s.records))
	for i := range s.records {
		rec := &s.records[i]
		v := rec.intent
		if !rec.complete || seen[v.nonce] || v.policyEpoch != intent.policyEpoch || v.stateEpoch != intent.stateEpoch || v.entriesHash != p.entriesHash || v.slot <= lastSlot || v.issuedAt.IsZero() || v.issuedAt.Before(p.admission.notBefore) || !v.issuedAt.Before(p.admission.expires) || v.issuedAt.After(s.lastTime) || v.slot != v.issuedAt.Unix()/p.cadenceSeconds || !validContentID(v.contentID) {
			return zero, refusal(StateUnavailable)
		}
		seen[v.nonce] = true
		if v.slot > lastSlot {
			lastSlot = v.slot
		}
		if v.nonce == intent.nonce {
			duplicate = rec
		}
	}
	if ctx.Err() != nil {
		return zero, refusal(OperationRefused)
	}
	if duplicate != nil {
		if duplicate.intent.messageHash != intent.messageHash {
			return zero, refusal(ReplayRefused)
		}
		return PublicationReceipt{contentID: duplicate.intent.contentID, duplicate: true}, nil
	}
	if intent.slot <= lastSlot {
		return zero, refusal(ReplayRefused)
	}
	if len(s.records) == maxReplayRecords {
		return zero, refusal(ResourceLimit)
	}
	if err := f.reserve(ctx, intent); err != nil {
		return zero, refusal(StateUnavailable)
	}
	if ctx.Err() != nil {
		return zero, refusal(OperationRefused)
	}
	k, err := f.resolve(ctx, p.key)
	if err != nil || k == nil {
		return zero, refusal(KeyMismatch)
	}
	defer k.release()
	if !sameKey(k.facts(), p.key) {
		return zero, refusal(KeyMismatch)
	}
	if err := f.revalidate(ctx, a); err != nil {
		return zero, refusal(PolicyStale)
	}
	if a.message == nil {
		return zero, refusal(CallerRefused)
	}
	if err := a.message.revalidateOriginal(ctx, p.admission, a.messageHash); err != nil {
		return zero, refusal(CallerRefused)
	}
	// Recheck after all callbacks; none may cancel, expire, revoke or swap the
	// held key and still enter a private operation. The adapter's fence binds
	// the actual object, not merely this public facts projection.
	finalTime := f.now()
	if err := checkTime(p.admission, finalTime); err != nil {
		return zero, err
	}
	if finalTime.Before(now) || finalTime.Unix()/p.cadenceSeconds != intent.slot {
		return zero, refusal(ClockRefused)
	}
	if !sameKey(k.facts(), p.key) {
		return zero, refusal(KeyMismatch)
	}
	if ctx.Err() != nil {
		return zero, refusal(OperationRefused)
	}
	privateCtx, cancelPrivate := context.WithTimeout(callerCtx, privateBudget)
	defer cancelPrivate()
	if privateCtx.Err() != nil {
		return zero, refusal(OperationRefused)
	}
	der, err := k.signSilent(privateCtx, plan.Digest()) // exactly one attempt; never retry
	if err != nil {
		return zero, refusal(PrivateOutcomeUnknown)
	}
	wire, err := mugrant.AssembleNative(plan, der)
	if err != nil || privateCtx.Err() != nil {
		return zero, refusal(PrivateOutcomeUnknown)
	}
	if err := f.commit(privateCtx, intent, wire); err != nil {
		return zero, refusal(PrivateOutcomeUnknown)
	}
	return PublicationReceipt{contentID: intent.contentID}, nil
}

func sameAdmission(a, b admissionPolicy) bool {
	return a.scope == b.scope && a.epoch == b.epoch && a.enabled == b.enabled && a.notBefore.Equal(b.notBefore) && a.expires.Equal(b.expires)
}

func validatePin(p publisherKeyPin) (string, error) {
	if p.kind != signerclient.KindKey || p.generation <= 0 || signerclient.ValidateName("service", "", p.service) != nil || signerclient.ValidateName("purpose", "", p.purpose) != nil || (p.store != signerclient.StoreKeychain && p.store != signerclient.StoreEnclave) || (p.extraction != signerclient.ExtractionNone && p.extraction != signerclient.ExtractionHuman && p.extraction != signerclient.ExtractionAgent) || len(p.spki) > 1024 {
		return "", refusal(KeyMismatch)
	}
	// This source operation is unattended. It cannot remove presence or request
	// UI to make a presence-constrained key work; all other key paths retain
	// their existing constraints and are outside this disabled component.
	if p.presence {
		return "", refusal(OperationRefused)
	}
	id, err := mugrant.KeyIDFromSPKI(p.spki)
	if err != nil {
		return "", refusal(KeyMismatch)
	}
	return id, nil
}

func sameKey(a, b publisherKeyPin) bool {
	return a.kind == b.kind && a.service == b.service && a.purpose == b.purpose && a.generation == b.generation && a.store == b.store && a.extraction == b.extraction && a.presence == b.presence && bytes.Equal(a.spki, b.spki)
}

func protectedEntries(raw []byte, want [32]byte) ([]mugrant.SnapshotEntry, error) {
	if len(raw) == 0 || len(raw) > maxEntriesBytes || sha256.Sum256(raw) != want {
		return nil, refusal(PolicyUnavailable)
	}
	v, err := record.Parse(raw, maxEntriesBytes, 16)
	if err != nil {
		return nil, refusal(OperationRefused)
	}
	canonical, err := record.Canonical(v)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, refusal(OperationRefused)
	}
	list, ok := v.([]any)
	if !ok || len(list) > mugrant.MaxSnapshotEntries {
		return nil, refusal(ResourceLimit)
	}
	entries := make([]mugrant.SnapshotEntry, 0, len(list))
	seen := make(map[[2]string]string, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok || len(m) != 3 {
			return nil, refusal(OperationRefused)
		}
		kind, k := m["kind"].(string)
		id, i := m["id"].(string)
		from, f := m["from"].(string)
		if !k || !i || !f {
			return nil, refusal(OperationRefused)
		}
		pair := [2]string{kind, id}
		if prior, ok := seen[pair]; ok && prior != from {
			return nil, refusal(OperationRefused)
		}
		seen[pair] = from
		entries = append(entries, mugrant.SnapshotEntry{Kind: kind, ID: id, From: from})
	}
	return entries, nil
}

func validContentID(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	b, err := hex.DecodeString(s[7:])
	return err == nil && hex.EncodeToString(b) == s[7:]
}

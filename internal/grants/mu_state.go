package grants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sort"
	"time"

	"golang.org/x/sys/unix"
)

// Multi-use grant accounting (contract r3 section 3, X10). A separate journal
// from G and G2, on the same framed format, lock and file admission.
var (
	ErrMUState     = errors.New("mu-required-state-unavailable")
	ErrMUUseHeld   = errors.New("mu-grant-use-already-held")
	ErrMUNonceHeld = errors.New("mu-request-nonce-already-held")
	ErrMUUnknown   = errors.New("mu-dispatch-outcome-unknown-use-held")
)

// muMaxReservations bounds replayed state; the 64 MiB journal bound also holds.
const muMaxReservations = 65536

// MUStateConfig names an explicitly provisioned multi-use journal directory
// and its independently configured epoch. It does not resist same-UID
// rollback or tampering; anti-replay holds within one durable state epoch.
type MUStateConfig struct {
	Directory string
	Epoch     [32]byte
}

// MUBinding is the receiver identity the journal is activated for.
type MUBinding struct {
	Audience  string // exact grant/1 aud of this receiver
	GrantRoot string // pinned owner grant-root key id
}

// MUUse is one checked request ready to reserve.
type MUUse struct {
	Once                         bool
	GrantRoot, GrantID           string
	Action, TargetKind, TargetID string
	Requester, Nonce, Audience   string
	RequestHash                  [32]byte
}

type muReservation struct {
	allowance, nonce, grantID, requestHash [32]byte
	once                                   bool
	sequence                               uint64
	intent, complete                       bool
}

type muState struct {
	directory, lock, file *os.File
	link                  journalFrameLink
	binding               MUBinding
	allowances, nonces    map[[32]byte]*muReservation
	reservations          map[uint64]*muReservation
	revoked               map[MURevocation]bool            // monotonic union (r5 constraint 2)
	highWater             map[string]time.Time             // newest accepted snapshot issued_at per signer
	unions                map[string]map[MURevocation]bool // durable union per snapshot signer
	write                 func(*os.File, []byte) (int, error)
	sync                  func(*os.File) error
}

func muActivation(b MUBinding) []byte {
	out := []byte("MUA1")
	for _, s := range []string{b.Audience, b.GrantRoot} {
		out = binary.BigEndian.AppendUint16(out, uint16(len(s)))
		out = append(out, s...)
	}
	return out
}

func validMUBinding(b MUBinding) bool {
	return b.Audience != "" && len(b.Audience) <= 255 && b.GrantRoot != "" && len(b.GrantRoot) <= 255
}

// muAllowanceKey identifies one logical right of a once grant. It never
// contains a request id, nonce, alias or policy label, so none of those can
// refill it; only a new owner-signed grant (new grant id) is a new right.
func muAllowanceKey(u MUUse) [32]byte {
	return a2aRecordKey("swarma-grants/mu-allowance/1", []byte(u.GrantRoot), []byte(u.GrantID), []byte(u.Action), []byte(u.TargetKind), []byte(u.TargetID))
}

// muNonceKey is single-use for a requester and audience across every policy,
// grant and entry.
func muNonceKey(u MUUse) [32]byte {
	return a2aRecordKey("swarma-grants/mu-nonce/1", []byte(u.Requester), []byte(u.Nonce), []byte(u.Audience))
}

// InitializeMUState creates the journal in an already admitted empty private
// directory. It never adopts, repairs or replaces existing state.
func InitializeMUState(config MUStateConfig, binding MUBinding) error {
	if !validMUBinding(binding) {
		return ErrMUState
	}
	dir, err := a2aOpenDirectory(A2AStateConfig(config))
	if err != nil {
		return ErrMUState
	}
	defer dir.Close()
	if entries, err := dir.ReadDir(1); len(entries) != 0 || err != io.EOF {
		return ErrMUState
	}
	lock, err := a2aOpenFile(dir, "mu.lock", true)
	if err != nil {
		return ErrMUState
	}
	defer lock.Close()
	if err := lockStateFile(context.Background(), lock); err != nil {
		return ErrMUState
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	file, err := muOpenJournal(dir, true)
	if err != nil {
		return ErrMUState
	}
	defer file.Close()
	frame, err := encodeJournalFrame(journalActivation, journalFrameLink{sequence: 1, epoch: config.Epoch}, muActivation(binding))
	if err != nil {
		return ErrMUState
	}
	if n, err := file.Write(frame); err != nil || n != len(frame) {
		return ErrMUState
	}
	if file.Sync() != nil || lock.Sync() != nil || dir.Sync() != nil {
		return ErrMUState
	}
	return nil
}

func openMUState(ctx context.Context, config MUStateConfig, binding MUBinding) (*muState, error) {
	if !validMUBinding(binding) {
		return nil, ErrMUState
	}
	dir, err := a2aOpenDirectory(A2AStateConfig(config))
	if err != nil {
		return nil, ErrMUState
	}
	s := &muState{directory: dir, binding: binding, link: journalFrameLink{sequence: 1, epoch: config.Epoch},
		allowances: map[[32]byte]*muReservation{}, nonces: map[[32]byte]*muReservation{}, reservations: map[uint64]*muReservation{}, revoked: map[MURevocation]bool{}, highWater: map[string]time.Time{}, unions: map[string]map[MURevocation]bool{},
		write: func(f *os.File, b []byte) (int, error) { return f.Write(b) }, sync: func(f *os.File) error { return f.Sync() }}
	ready := false
	defer func() {
		if !ready {
			s.close()
		}
	}()
	if s.lock, err = a2aOpenFile(dir, "mu.lock", false); err != nil {
		return nil, ErrMUState
	}
	if lockStateFile(ctx, s.lock) != nil {
		return nil, ErrMUState
	}
	if s.file, err = muOpenJournal(dir, false); err != nil {
		return nil, ErrMUState
	}
	st, err := s.file.Stat()
	if err != nil || st.Size() == 0 || st.Size() > journalScanMaxBytes {
		return nil, ErrMUState
	}
	for {
		frame, err := readJournalFrame(s.file, s.link)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrMUState
		}
		if s.link.sequence == 1 {
			if frame.kind != journalActivation || !bytes.Equal(frame.body, muActivation(binding)) {
				return nil, ErrMUState
			}
		} else if err := s.replay(frame); err != nil {
			return nil, err
		}
		s.link.sequence++
		s.link.previous = frame.digest
	}
	if s.link.sequence == 1 {
		return nil, ErrMUState
	}
	ready = true
	return s, nil
}

func (s *muState) close() {
	if s.file != nil {
		s.file.Close()
	}
	if s.lock != nil {
		_ = unix.Flock(int(s.lock.Fd()), unix.LOCK_UN)
		s.lock.Close()
	}
	if s.directory != nil {
		s.directory.Close()
	}
}

func encodeMUReservation(r *muReservation) []byte {
	b := []byte("MUR1")
	if r.once {
		b = append(b, 1)
	} else {
		b = append(b, 2)
	}
	for _, h := range [][32]byte{r.allowance, r.nonce, r.grantID, r.requestHash} {
		b = append(b, h[:]...)
	}
	return b
}

func (s *muState) replay(f *journalFrame) error {
	switch f.kind {
	case journalReservation:
		if len(f.body) != 133 || string(f.body[:4]) != "MUR1" || (f.body[4] != 1 && f.body[4] != 2) || len(s.reservations) >= muMaxReservations {
			return ErrMUState
		}
		r := &muReservation{sequence: f.link.sequence, once: f.body[4] == 1}
		for i, p := range []*[32]byte{&r.allowance, &r.nonce, &r.grantID, &r.requestHash} {
			copy(p[:], f.body[5+i*32:5+(i+1)*32])
		}
		zero := [32]byte{}
		if r.nonce == zero || r.grantID == zero || r.requestHash == zero || (r.once != (r.allowance != zero)) {
			return ErrMUState
		}
		if s.nonces[r.nonce] != nil || (r.once && s.allowances[r.allowance] != nil) {
			return ErrMUState
		}
		s.nonces[r.nonce] = r
		if r.once {
			s.allowances[r.allowance] = r
		}
		s.reservations[r.sequence] = r
	case journalSignerRevocation:
		signer, entries, ok := decodeMUSignerRevocations(f.body)
		if !ok {
			return ErrMUState
		}
		u := s.unions[signer]
		if u == nil {
			u = map[MURevocation]bool{}
			s.unions[signer] = u
		}
		for _, e := range entries {
			if u[e] {
				return ErrMUState
			}
			u[e] = true
			s.revoked[e] = true
		}
	case journalSnapshotMark:
		key, at, ok := decodeMUSnapshotMark(f.body)
		if !ok {
			return ErrMUState
		}
		if hw, seen := s.highWater[key]; seen && !at.After(hw) {
			return ErrMUState
		}
		s.highWater[key] = at
	case journalRevocation:
		entries, ok := decodeMURevocations(f.body)
		if !ok {
			return ErrMUState
		}
		for _, e := range entries {
			if s.revoked[e] {
				return ErrMUState
			}
			s.revoked[e] = true
		}
	case journalDispatchIntent:
		if len(f.body) != 12 || string(f.body[:4]) != "MUI1" {
			return ErrMUState
		}
		r := s.reservations[binary.BigEndian.Uint64(f.body[4:])]
		if r == nil || r.intent || r.complete {
			return ErrMUState
		}
		r.intent = true
	case journalOutcome:
		if len(f.body) < 16 || string(f.body[:4]) != "MUO1" {
			return ErrMUState
		}
		r := s.reservations[binary.BigEndian.Uint64(f.body[4:])]
		if r == nil || !r.intent || r.complete || binary.BigEndian.Uint32(f.body[12:16]) != uint32(len(f.body)-16) || len(f.body)-16 > 8192 {
			return ErrMUState
		}
		r.complete = true
	default:
		return ErrMUState
	}
	return nil
}

func (s *muState) append(kind journalFrameKind, body []byte) error {
	raw, err := encodeJournalFrame(kind, s.link, body)
	if err != nil {
		return ErrMUState
	}
	st, err := s.file.Stat()
	if err != nil || st.Size()+int64(len(raw)) > journalScanMaxBytes {
		return ErrMUState
	}
	if n, err := s.write(s.file, raw); err != nil || n != len(raw) {
		return ErrMUState
	}
	if s.sync(s.file) != nil {
		return ErrMUState
	}
	f, err := readJournalFrame(bytes.NewReader(raw), s.link)
	if err != nil {
		return ErrMUState
	}
	s.link.previous = f.digest
	s.link.sequence++
	return nil
}

// reserve durably records the use before any effect: the nonce always, the
// allowance only for a once grant. It refuses a held allowance or nonce,
// including one whose earlier attempt ended UNKNOWN.
func (s *muState) reserve(u MUUse) (uint64, error) {
	if u.GrantID == "" || u.Nonce == "" || u.Requester == "" || u.Audience != s.binding.Audience || u.GrantRoot != s.binding.GrantRoot || u.RequestHash == [32]byte{} {
		return 0, ErrMUState
	}
	r := &muReservation{nonce: muNonceKey(u), grantID: sha256.Sum256([]byte(u.GrantID)), requestHash: u.RequestHash, once: u.Once}
	if u.Once {
		r.allowance = muAllowanceKey(u)
		if s.allowances[r.allowance] != nil {
			return 0, ErrMUUseHeld
		}
	}
	if s.nonces[r.nonce] != nil {
		return 0, ErrMUNonceHeld
	}
	if len(s.reservations) >= muMaxReservations {
		return 0, ErrMUState
	}
	r.sequence = s.link.sequence
	if err := s.append(journalReservation, encodeMUReservation(r)); err != nil {
		return 0, ErrMUState
	}
	s.nonces[r.nonce] = r
	if r.once {
		s.allowances[r.allowance] = r
	}
	s.reservations[r.sequence] = r
	return r.sequence, nil
}

// markIntent records the dispatch intent for a reservation, before the effect.
func (s *muState) markIntent(sequence uint64) error {
	r := s.reservations[sequence]
	if r == nil || r.intent || r.complete {
		return ErrMUState
	}
	if err := s.append(journalDispatchIntent, binary.BigEndian.AppendUint64([]byte("MUI1"), sequence)); err != nil {
		return ErrMUState
	}
	r.intent = true
	return nil
}

// recordOutcome records a completed effect receipt (opaque, bounded).
func (s *muState) recordOutcome(sequence uint64, receipt []byte) error {
	r := s.reservations[sequence]
	if r == nil || !r.intent || r.complete || len(receipt) == 0 || len(receipt) > 8192 {
		return ErrMUState
	}
	body := binary.BigEndian.AppendUint64([]byte("MUO1"), sequence)
	body = binary.BigEndian.AppendUint32(body, uint32(len(receipt)))
	if err := s.append(journalOutcome, append(body, receipt...)); err != nil {
		return ErrMUState
	}
	r.complete = true
	return nil
}

// MURevocation is one accepted revocation: Kind "record" (an envelope id) or
// "key" (a key id).
type MURevocation struct{ Kind, ID string }

const muMaxRevocations = 4096

func validMURevocation(e MURevocation) bool {
	return (e.Kind == "record" || e.Kind == "key") && e.ID != "" && len(e.ID) <= 255
}

func encodeMURevocations(entries []MURevocation) []byte {
	b := []byte("MUV1")
	b = binary.BigEndian.AppendUint16(b, uint16(len(entries)))
	for _, e := range entries {
		k := byte(1)
		if e.Kind == "key" {
			k = 2
		}
		b = append(b, k)
		b = binary.BigEndian.AppendUint16(b, uint16(len(e.ID)))
		b = append(b, e.ID...)
	}
	return b
}

func decodeMURevocations(b []byte) ([]MURevocation, bool) {
	if len(b) < 6 || string(b[:4]) != "MUV1" {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(b[4:6]))
	if n == 0 || n > 64 {
		return nil, false
	}
	out := make([]MURevocation, 0, n)
	rest := b[6:]
	for i := 0; i < n; i++ {
		if len(rest) < 3 {
			return nil, false
		}
		kind := "record"
		switch rest[0] {
		case 1:
		case 2:
			kind = "key"
		default:
			return nil, false
		}
		l := int(binary.BigEndian.Uint16(rest[1:3]))
		if len(rest) < 3+l {
			return nil, false
		}
		e := MURevocation{Kind: kind, ID: string(rest[3 : 3+l])}
		if !validMURevocation(e) {
			return nil, false
		}
		out = append(out, e)
		rest = rest[3+l:]
	}
	return out, len(rest) == 0
}

// absorbRevocations durably adds every not yet known revocation to the
// monotonic union. The union only grows; nothing is ever removed.
func (s *muState) absorbRevocations(entries []MURevocation) error {
	var fresh []MURevocation
	seen := map[MURevocation]bool{}
	for _, e := range entries {
		if !validMURevocation(e) {
			return ErrMUState
		}
		if !s.revoked[e] && !seen[e] {
			fresh = append(fresh, e)
			seen[e] = true
		}
	}
	for len(fresh) > 0 {
		chunk := fresh
		if len(chunk) > 64 {
			chunk = chunk[:64]
		}
		if len(s.revoked)+len(chunk) > muMaxRevocations {
			return ErrMUState
		}
		if err := s.append(journalRevocation, encodeMURevocations(chunk)); err != nil {
			return ErrMUState
		}
		for _, e := range chunk {
			s.revoked[e] = true
		}
		fresh = fresh[len(chunk):]
	}
	return nil
}

// muOpenJournal opens mu.journal for append only. The receiver only ever
// writes at the end after a full replay, and with O_APPEND the open also
// succeeds when the operator sets the BSD append-only flag on the file, which
// refuses truncation, rewrite and rename by a same-user process.
func muOpenJournal(dir *os.File, create bool) (*os.File, error) {
	return a2aOpenFileWith(dir, "mu.journal", create, unix.O_APPEND)
}

// markSnapshots durably records each snapshot issued_at that is newer than the
// signer's high-water mark. Equal marks are not rewritten.
func (s *muState) markSnapshots(marks map[string]time.Time) error {
	keys := make([]string, 0, len(marks))
	for k := range marks {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		at := marks[k].UTC()
		if hw, ok := s.highWater[k]; ok && !at.After(hw) {
			continue
		}
		body, ok := encodeMUSnapshotMark(k, at)
		if !ok {
			return ErrMUState
		}
		if err := s.append(journalSnapshotMark, body); err != nil {
			return ErrMUState
		}
		s.highWater[k] = at
	}
	return nil
}

func encodeMUSnapshotMark(key string, at time.Time) ([]byte, bool) {
	if key == "" || len(key) > 255 || at.Unix() <= 0 {
		return nil, false
	}
	b := append([]byte("MUH1"), make([]byte, 8)...)
	binary.BigEndian.PutUint64(b[4:12], uint64(at.Unix()))
	return append(b, key...), true
}

func decodeMUSnapshotMark(b []byte) (string, time.Time, bool) {
	if len(b) < 13 || len(b) > 12+255 || string(b[:4]) != "MUH1" {
		return "", time.Time{}, false
	}
	sec := int64(binary.BigEndian.Uint64(b[4:12]))
	if sec <= 0 {
		return "", time.Time{}, false
	}
	return string(b[12:]), time.Unix(sec, 0).UTC(), true
}

// MUOwnerRootSigner labels the owner-root revocation set in the journal. It
// cannot equal a key id, so the root set never joins a snapshot signer's
// union and is never compared for rollback.
const MUOwnerRootSigner = "owner-root"

// absorbSigned durably adds each entry not yet in signer's union; every
// entry also joins the revoked set. Unions only grow.
func (s *muState) absorbSigned(signer string, entries []MURevocation) error {
	if signer == "" || len(signer) > 255 {
		return ErrMUState
	}
	u := s.unions[signer]
	var fresh []MURevocation
	seen := map[MURevocation]bool{}
	for _, e := range entries {
		if !validMURevocation(e) {
			return ErrMUState
		}
		if !u[e] && !seen[e] {
			fresh = append(fresh, e)
			seen[e] = true
		}
	}
	for len(fresh) > 0 {
		chunk := fresh
		if len(chunk) > 64 {
			chunk = chunk[:64]
		}
		if len(s.revoked)+len(chunk) > muMaxRevocations {
			return ErrMUState
		}
		body := append(append([]byte("MUS1"), byte(len(signer))), signer...)
		if err := s.append(journalSignerRevocation, append(body, encodeMURevocations(chunk)...)); err != nil {
			return ErrMUState
		}
		if s.unions[signer] == nil {
			s.unions[signer] = map[MURevocation]bool{}
		}
		for _, e := range chunk {
			s.unions[signer][e] = true
			s.revoked[e] = true
		}
		fresh = fresh[len(chunk):]
	}
	return nil
}

func decodeMUSignerRevocations(b []byte) (string, []MURevocation, bool) {
	if len(b) < 6 || string(b[:4]) != "MUS1" {
		return "", nil, false
	}
	n := int(b[4])
	if n == 0 || len(b) < 5+n {
		return "", nil, false
	}
	entries, ok := decodeMURevocations(b[5+n:])
	if !ok || len(entries) == 0 {
		return "", nil, false
	}
	return string(b[5 : 5+n]), entries, true
}

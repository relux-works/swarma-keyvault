package grants

import (
	"context"
	"errors"
	"sort"
	"time"

	"golang.org/x/sys/unix"
)

// LinuxVerifiedSnapshot describes a cryptographically admitted, complete snapshot
// from the SAME source reads as Decision, including when the request refuses.
// Callers must not derive this
// evidence from unverified transport data or read the source again afterward.
// Entries retain the existing MU identity-only semantics (immediate holds).
type LinuxVerifiedSnapshot struct {
	Signer   string
	IssuedAt time.Time
	Entries  []MURevocation
}

type LinuxAdmission struct {
	Decision  MUDecision
	Snapshots []LinuxVerifiedSnapshot
}

// InitializeLinuxReceiverState explicitly provisions the MU journal and reapplies
// the protected, authenticated owner-root configuration before activation. An
// empty authenticated roots set is allowed; a missing source is not. A failed
// initialization is left in place, never silently adopted, deleted or repaired.
func InitializeLinuxReceiverState(c MUStateConfig, b MUBinding, roots func() ([]MURevocation, error)) error {
	if roots == nil {
		return ErrMUState
	}
	entries, err := roots()
	if err != nil {
		return ErrMUState
	}
	for _, entry := range entries {
		if !validMURevocation(entry) {
			return ErrMUState
		}
	}
	if err := InitializeMUState(c, b); err != nil {
		return err
	}
	s, err := openMUState(context.Background(), c, b)
	if err != nil {
		return err
	}
	defer s.close()
	if err := s.absorbSigned(MUOwnerRootSigner, entries); err != nil {
		return err
	}
	return nil
}

// RestoreLinuxReceiverState is an explicit custodian operation into a NEW empty
// private directory with a new independently provisioned epoch. The old journal
// is not adopted. A complete restored backup can lack entries and cannot detect
// its own rollback: callers MUST invoke this path after any backup restore and
// reapply all out-of-band owner roots before admitting requests. Old epoch replay
// protection does not carry across epochs; owner policy must cover old grants.
func RestoreLinuxReceiverState(c MUStateConfig, b MUBinding, previousEpoch [32]byte, roots func() ([]MURevocation, error)) error {
	if previousEpoch == [32]byte{} || previousEpoch == c.Epoch {
		return ErrMUState
	}
	return InitializeLinuxReceiverState(c, b, roots)
}

// linuxRevocationState is a transient view of the locked MU journal. It owns
// no descriptor, activation, file or second durable authority.
type linuxRevocationState struct {
	journal *muState
	latest  map[string]LinuxVerifiedSnapshot
}

// Refuse even a dangling symlink or directory at the retired sidecar name.
// Never read, adopt, remove or rewrite historical sidecar bytes.
func openLinuxRevocationState(s *muState) (*linuxRevocationState, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(int(s.directory.Fd()), "linux-revocations.journal", &stat, unix.AT_SYMLINK_NOFOLLOW)
	if !errors.Is(err, unix.ENOENT) {
		return nil, ErrMUState
	}
	rs := &linuxRevocationState{journal: s, latest: map[string]LinuxVerifiedSnapshot{}}
	rs.refreshLatest()
	return rs, nil
}
func (s *linuxRevocationState) close() {}
func validLinuxSnapshot(v LinuxVerifiedSnapshot) bool {
	if !linuxToken(v.Signer, 255) || v.IssuedAt.Unix() <= 0 || v.IssuedAt.Nanosecond() != 0 || len(v.Entries) > 64 {
		return false
	}
	seen := map[MURevocation]bool{}
	for _, e := range v.Entries {
		if !validMURevocation(e) || seen[e] {
			return false
		}
		seen[e] = true
	}
	return true
}

// refreshLatest keeps the historical inspection view; future-only unions have
// no accepted mark and remain in journal.unions until a nonfuture sample arrives.
func (s *linuxRevocationState) refreshLatest() {
	for signer, at := range s.journal.highWater {
		entries := []MURevocation{}
		for entry := range s.journal.unions[signer] {
			entries = append(entries, entry)
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].Kind != entries[j].Kind {
				return entries[i].Kind < entries[j].Kind
			}
			return entries[i].ID < entries[j].ID
		})
		s.latest[signer] = LinuxVerifiedSnapshot{Signer: signer, IssuedAt: at, Entries: entries}
	}
}

func (s *linuxRevocationState) continuity(v LinuxVerifiedSnapshot) error {
	if old, exists := s.journal.highWater[v.Signer]; exists && v.IssuedAt.Before(old) {
		return ErrMURollback
	}
	present := map[MURevocation]bool{}
	for _, e := range v.Entries {
		present[e] = true
	}
	for e := range s.journal.unions[v.Signer] {
		if !present[e] {
			return ErrMURollback
		}
	}
	return nil
}

// observe durably retains signed entries at any age, and raises only nonfuture
// marks, after all of that signer's union entries. These writes never reserve
// a nonce or authorize an effect. Any storage failure requires a fresh reopen.
func (s *linuxRevocationState) observe(mu *muState, snapshots []LinuxVerifiedSnapshot, now time.Time) error {
	if len(snapshots) > 64 {
		return ErrMUState
	}
	seen := map[string]bool{}
	for _, v := range snapshots {
		if !validLinuxSnapshot(v) || seen[v.Signer] {
			return ErrMUState
		}
		seen[v.Signer] = true
	}
	for _, v := range snapshots {
		if s.journal.unions[v.Signer] == nil && len(s.journal.unions) >= 64 {
			return ErrMUState
		}
		if err := s.journal.absorbSigned(v.Signer, v.Entries); err != nil {
			return err
		}
		if !v.IssuedAt.After(now) {
			if err := s.journal.markSnapshots(map[string]time.Time{v.Signer: v.IssuedAt}); err != nil {
				return err
			}
		}
	}
	s.refreshLatest()
	return nil
}

func (s *linuxRevocationState) admit(mu *muState, snapshots []LinuxVerifiedSnapshot, d MUDecision, now time.Time) error {
	if len(snapshots) == 0 || len(snapshots) > 64 {
		return ErrMUState
	}
	seen := map[string]bool{}
	publisher := false
	for _, v := range snapshots {
		if !validLinuxSnapshot(v) || seen[v.Signer] || v.IssuedAt.After(now) || now.Sub(v.IssuedAt) > LinuxPublisherMaxAge {
			return ErrMUState
		}
		seen[v.Signer] = true
		if v.Signer == d.PublisherKey {
			publisher = true
			entries := map[MURevocation]bool{}
			for _, e := range v.Entries {
				entries[e] = true
			}
			if len(entries) != len(d.Revocations) {
				return ErrMUState
			}
			for _, e := range d.Revocations {
				if !entries[e] {
					return ErrMUState
				}
			}
		}
	}
	if !publisher {
		return ErrMUState
	}
	for _, v := range snapshots {
		if err := s.continuity(v); err != nil {
			if persistErr := s.observe(mu, snapshots, now); persistErr != nil {
				return persistErr
			}
			return err
		}
	}
	return s.observe(mu, snapshots, now)
}

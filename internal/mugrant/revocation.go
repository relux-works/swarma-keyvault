package mugrant

import (
	"errors"
	"sort"
	"time"

	"github.com/relux-works/swarma-envelope/record"
)

// ErrSnapshotSpec refuses a revocation snapshot that cannot be built.
var ErrSnapshotSpec = errors.New("mugrant-snapshot-spec-invalid")

// MaxSnapshotEntries is the platform bound for revocation/1 entries.
const MaxSnapshotEntries = 64

// SnapshotEntry is one revocation: Kind "record" (envelope id) or "key".
type SnapshotEntry struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	From string `json:"from"`
}

// BuildSnapshot builds the complete revocation/1 snapshot a grant revocation
// publisher signs: issuer is the publisher key, issued_at is the given UTC
// second, entries are deduplicated and sorted. Nothing is signed.
func BuildSnapshot(publisher string, issuedAt time.Time, entries []SnapshotEntry) (*Plan, error) {
	if record.ValidateKey(publisher) != nil || issuedAt.Location() != time.UTC || issuedAt.Nanosecond() != 0 || len(entries) > MaxSnapshotEntries {
		return nil, ErrSnapshotSpec
	}
	seen := map[SnapshotEntry]bool{}
	var list []SnapshotEntry
	for _, e := range entries {
		if (e.Kind != "record" && e.Kind != "key") || !printableToken(e.ID, 255) {
			return nil, ErrSnapshotSpec
		}
		from, err := time.Parse("2006-01-02T15:04:05Z", e.From)
		if err != nil || from.Format("2006-01-02T15:04:05Z") != e.From || from.After(issuedAt) {
			return nil, ErrSnapshotSpec
		}
		if !seen[e] {
			seen[e] = true
			list = append(list, e)
		}
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Kind != list[j].Kind {
			return list[i].Kind < list[j].Kind
		}
		return list[i].ID < list[j].ID
	})
	wire := make([]any, len(list))
	for i, e := range list {
		wire[i] = map[string]any{"kind": e.Kind, "id": e.ID, "from": e.From}
	}
	body, err := record.Canonical(map[string]any{"type": "revocation/1", "issuer": publisher, "issued_at": wireTime(issuedAt), "complete": true, "entries": wire})
	if err != nil {
		return nil, ErrSnapshotSpec
	}
	return Prepare("revocation/1", publisher, body)
}
